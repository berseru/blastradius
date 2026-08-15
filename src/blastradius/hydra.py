"""Minimal, dependency-light client for the HydraDB HTTP query API.

The server speaks a typed JSON dialect on ``POST /v1/graphs/{graph}/query``:

    {"cell_id": "cell-0", "query": "...", "parameters": {...}}

Responses carry ``columns`` and ``rows``, where every cell is a tagged value
such as ``{"type": "vertex_id", "value": 2}``.  Path values additionally carry
node/relationship property maps in Rust's externally tagged enum form
(``{"Integer": 7}``), so both encodings are normalised here once and never
again anywhere else in the codebase.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Sequence

import httpx

DEFAULT_BASE_URL = "http://127.0.0.1:8443"
DEFAULT_GRAPH = "default"
DEFAULT_NAMESPACE = "default"
DEFAULT_CELL = "cell-0"

# The server rejects a request body over 1 MiB (``DEFAULT_HTTP_MAX_BODY_BYTES``
# in ``client/http.rs``), so batches are split on serialised size as well as on
# row count. 768 KiB leaves room for the query text and the JSON envelope.
MAX_BODY_BYTES = 768 * 1024

HEALTHCHECK_WRITE = (
    "UNWIND $rows AS row MERGE (n {id: row.vertex}) SET n:Healthcheck, n.at = row.at"
)
HEALTHCHECK_READ = "MATCH (n:Healthcheck {id: $id}) RETURN n.id AS id"
HEALTHCHECK_DELETE = "MATCH (n:Healthcheck {id: $id}) DETACH DELETE n"


class HydraError(RuntimeError):
    """A query the server refused, with its error code preserved."""

    def __init__(self, code: str, message: str, status: int, query: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status
        self.query = query


@dataclass
class PathRel:
    edge_type: str
    src: int
    dst: int
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class PathNode:
    id: int
    labels: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class Path:
    nodes: list[PathNode]
    relationships: list[PathRel]

    @property
    def hops(self) -> int:
        return len(self.relationships)


@dataclass
class Result:
    columns: list[str]
    rows: list[list[Any]]
    elapsed_ms: float

    def dicts(self) -> list[dict[str, Any]]:
        return [dict(zip(self.columns, row)) for row in self.rows]

    def scalar(self) -> Any:
        if not self.rows or not self.rows[0]:
            return None
        return self.rows[0][0]

    def column(self, name: str) -> list[Any]:
        idx = self.columns.index(name)
        return [row[idx] for row in self.rows]

    def __len__(self) -> int:
        return len(self.rows)


def _property(value: Any) -> Any:
    """Normalise a Rust externally tagged ``VertexPropertyValue``."""
    if isinstance(value, dict) and len(value) == 1:
        tag, inner = next(iter(value.items()))
        if tag in {"Integer", "SignedInteger", "Bool", "String", "Float"}:
            return inner
    return value


def _properties(raw: dict[str, Any] | None) -> dict[str, Any]:
    return {key: _property(value) for key, value in (raw or {}).items()}


def _value(cell: Any) -> Any:
    """Normalise one tagged HTTP query value into a plain Python value."""
    if not isinstance(cell, dict) or "type" not in cell:
        return cell
    kind = cell["type"]
    value = cell.get("value")
    if kind == "null":
        return None
    if kind == "list":
        return [_value(item) for item in value or []]
    if kind == "path":
        return Path(
            nodes=[
                PathNode(
                    id=node["id"],
                    labels=list(node.get("labels") or []),
                    properties=_properties(node.get("properties")),
                )
                for node in value.get("nodes", [])
            ],
            relationships=[
                PathRel(
                    edge_type=rel["edge_type"],
                    src=rel["src"],
                    dst=rel["dst"],
                    properties=_properties(rel.get("properties")),
                )
                for rel in value.get("relationships", [])
            ],
        )
    return value


class HydraClient:
    """Synchronous HydraDB client.

    One instance owns one ``httpx.Client``; use it as a context manager.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        token: str = "",
        graph: str = DEFAULT_GRAPH,
        namespace: str = DEFAULT_NAMESPACE,
        cell: str = DEFAULT_CELL,
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.graph = graph
        self.cell = cell
        # An empty token is sent as *no* header rather than as ``Bearer `` with a
        # trailing space: httpx refuses that value outright, and the resulting
        # LocalProtocolError blames the client library for what is really a
        # missing HYDRA_TOKEN. Without the header the server answers 401, which
        # is the truth and says so.
        headers = {
            "X-Graph-Namespace": namespace,
            "Content-Type": "application/json",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(timeout=timeout, headers=headers)
        self.queries_run = 0
        self.total_query_ms = 0.0

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> "HydraClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def wait_ready(self, admin_url: str = "http://127.0.0.1:9090", timeout_s: float = 180.0) -> float:
        """Block until /readyz answers *and* a real round trip succeeds.

        A listening port is not proof the node works, so readiness ends with a
        write/read round trip on a scratch vertex.
        """
        deadline = time.monotonic() + timeout_s
        started = time.monotonic()
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                response = httpx.get(f"{admin_url.rstrip('/')}/readyz", timeout=5.0)
                if response.status_code == 200:
                    break
            except Exception as exc:  # noqa: BLE001 - retried until the deadline
                last = exc
            time.sleep(1.0)
        else:
            raise TimeoutError(f"/readyz never became ready in {timeout_s}s (last error: {last})")

        while time.monotonic() < deadline:
            try:
                # The write has to be the batch form. A bare
                # ``MERGE (n {id: $id}) SET ...`` is rejected outright -
                # "MERGE with following clauses is not executable" - because
                # only ``UNWIND``-driven batches may follow a MERGE with SET.
                self.run(HEALTHCHECK_WRITE, {"rows": [{"vertex": 0, "at": int(time.time())}]})
                if self.run(HEALTHCHECK_READ, {"id": 0}).scalar() == 0:
                    self.run(HEALTHCHECK_DELETE, {"id": 0})
                    return time.monotonic() - started
            except Exception as exc:  # noqa: BLE001 - the engine may still be opening storage
                last = exc
            time.sleep(1.0)
        raise TimeoutError(f"node answered /readyz but no query round-tripped (last error: {last})")

    # -- queries -----------------------------------------------------------

    def run(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
        *,
        consistency: str | None = None,
        timeout_ms: int | None = None,
        page_size: int | None = None,
    ) -> Result:
        """Run one statement and return every row, following cursors."""
        body: dict[str, Any] = {"cell_id": self.cell, "query": query}
        if parameters:
            body["parameters"] = parameters
        if consistency:
            body["consistency"] = consistency
        if timeout_ms:
            body["timeout_ms"] = timeout_ms
        if page_size:
            body["page_size"] = page_size

        url = f"{self.base_url}/v1/graphs/{self.graph}/query"
        started = time.perf_counter()
        columns: list[str] = []
        rows: list[list[Any]] = []
        cursor: int | None = None
        while True:
            if cursor is not None:
                body["cursor"] = cursor
            response = self._client.post(url, json=body)
            if response.status_code >= 400:
                self._raise(response, query)
            payload = response.json()
            columns = payload.get("columns") or columns
            rows.extend([[_value(cell) for cell in row] for row in payload.get("rows", [])])
            cursor = payload.get("next_cursor")
            if cursor is None:
                break
        elapsed = (time.perf_counter() - started) * 1000
        self.queries_run += 1
        self.total_query_ms += elapsed
        return Result(columns=columns, rows=rows, elapsed_ms=elapsed)

    def _raise(self, response: httpx.Response, query: str) -> None:
        code, message = "http_error", response.text[:400]
        try:
            error = response.json().get("error", {})
            code = error.get("code", code)
            message = error.get("message", message)
        except Exception:  # noqa: BLE001 - non-JSON error bodies are possible
            pass
        raise HydraError(code, message, response.status_code, query)

    # -- batched writes ----------------------------------------------------

    def batch(
        self,
        query: str,
        rows: Iterable[dict[str, Any]],
        *,
        chunk_size: int = 1000,
        param: str = "rows",
        progress: str | None = None,
    ) -> int:
        """Send ``UNWIND $rows`` batches, returning the number of rows written.

        A batch is the only way to write more than one thing per round trip:
        outside ``UNWIND``, a MERGE cannot be followed by SET at all. Chunks are
        bounded twice, by row count and by serialised size, because the server
        caps a request body at 1 MiB.
        """
        written = 0
        started = time.perf_counter()
        for chunk in _chunks(rows, chunk_size):
            self.run(query, {param: chunk})
            written += len(chunk)
            if progress and written % (chunk_size * 20) == 0:
                rate = written / max(time.perf_counter() - started, 1e-6)
                print(f"  {progress}: {written:,} rows ({rate:,.0f}/s)", flush=True)
        return written


def check_row(row: dict[str, Any], *, where: str = "row") -> dict[str, Any]:
    """Reject a row the server would reject, with a message that names the field.

    HydraDB properties are scalars only - there is no null property value, and a
    ``None`` anywhere in a parameter is answered with a flat
    ``invalid_parameter`` for the whole request
    (``http_parameter_to_property`` in ``client/http.rs``). Catching it here
    turns one opaque 400 into the field that caused it.
    """
    for key, value in row.items():
        if value is None:
            raise ValueError(f"{where}: field {key!r} is None; HydraDB has no null property")
        if not isinstance(value, (str, int, float, bool)):
            raise ValueError(
                f"{where}: field {key!r} is {type(value).__name__}; only scalars are storable"
            )
    return row


def _chunks(rows: Iterable[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    """Split rows into chunks of at most ``size`` rows and ``MAX_BODY_BYTES``."""
    batch: list[dict[str, Any]] = []
    batch_bytes = 0
    for index, row in enumerate(rows):
        check_row(row, where=f"row {index}")
        row_bytes = len(json.dumps(row, ensure_ascii=False, default=str).encode("utf-8")) + 1
        if batch and (len(batch) >= size or batch_bytes + row_bytes > MAX_BODY_BYTES):
            yield batch
            batch, batch_bytes = [], 0
        batch.append(row)
        batch_bytes += row_bytes
    if batch:
        yield batch


def paths_from(result: Result, column: str = "path") -> Sequence[Path]:
    """Extract path values from a procedure result."""
    if column not in result.columns:
        return []
    return [value for value in result.column(column) if isinstance(value, Path)]
