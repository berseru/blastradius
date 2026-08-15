"""The contract checks, run against servers that misbehave on purpose.

A test that only proves "the checks pass against a good server" proves nothing:
the reason this module exists is to catch a server that leaks data to a wrong
token, answers a wrong graph with an empty result, or replies 200 to a write it
never stored. So each behaviour is tested twice - once against a fake that obeys
the contract, and once against a fake that breaks exactly one clause of it, where
the corresponding check *must* fail.

The fake speaks the real wire protocol over real HTTP on an ephemeral port; only
the storage engine is fake, and it dispatches on exact statement identity so an
edited statement is a loud failure rather than a silent empty answer.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from blastradius import contract
from blastradius.contract import PROBE_BASE, run_contract

TOKEN = "the-right-token"
GRAPH = "default"
NAMESPACE = "default"
CELL = "cell-0"
MAX_BODY = 1 << 20


class FakeHydra:
    """A tiny stand-in for the parts of HydraDB the contract asks about.

    Flags turn individual clauses off, which is how the "broken server" tests
    are written: ``FakeHydra(open_door=True)`` is a server that never checks the
    token, and the auth checks must notice.
    """

    def __init__(
        self,
        *,
        open_door: bool = False,
        empty_on_wrong_graph: bool = False,
        forget_writes: bool = False,
        duplicate_on_rewrite: bool = False,
        accept_anything: bool = False,
    ) -> None:
        self.open_door = open_door
        self.empty_on_wrong_graph = empty_on_wrong_graph
        self.forget_writes = forget_writes
        self.duplicate_on_rewrite = duplicate_on_rewrite
        self.accept_anything = accept_anything
        self.server_error_on_wrong_address = False
        self.vertices: dict[int, dict] = {}
        self.writes = 0

    # -- the engine -------------------------------------------------------

    def query(self, statement: str, parameters: dict) -> tuple[list[str], list[list]]:
        if statement == contract.PROBE_WRITE:
            self.writes += 1
            if not self.forget_writes:
                for row in parameters.get("rows", []):
                    key = row["id"] + (len(self.vertices) if self.duplicate_on_rewrite else 0)
                    self.vertices[key] = dict(row)
            return [], []
        if statement == contract.PROBE_COUNT:
            run = parameters.get("run")
            return ["rows"], [[sum(1 for v in self.vertices.values() if v.get("run") == run)]]
        if statement == contract.TRIVIAL_READ:
            return ["rows"], [[len(self.vertices)]]
        if statement == contract.PROBE_READ_ONE:
            found = self.vertices.get(parameters.get("id"))
            return ["note", "seq"], [[found["note"], found["seq"]]] if found else []
        if statement == contract.PROBE_DELETE:
            for row in parameters.get("rows", []):
                self.vertices.pop(row["id"], None)
            return [], []
        if " IN " in statement and not self.accept_anything:
            raise Unsupported("unsupported_expression", "IN is not supported")
        if self.accept_anything:
            return ["id"], []
        raise Unsupported("unknown_statement", f"the fake was never taught {statement[:60]!r}")


class Unsupported(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def make_server(engine: FakeHydra) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args) -> None:  # keep the test output readable
            return

        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, code: str, message: str) -> None:
            self._json(status, {"error": {"code": code, "message": message}})

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            if length > MAX_BODY:
                self._error(413, "body_too_large", f"{length} bytes over the 1 MiB cap")
                return

            token = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            if not engine.open_door and token != TOKEN:
                self._error(401, "unauthorized", "bad or missing token")
                return

            parts = [part for part in self.path.split("/") if part]
            graph = parts[2] if len(parts) > 2 else ""
            namespace = self.headers.get("X-Graph-Namespace", "")
            body = json.loads(raw or b"{}")

            wrong_address = (
                graph != GRAPH or namespace != NAMESPACE or body.get("cell_id") != CELL
            )
            if wrong_address:
                if engine.empty_on_wrong_graph:
                    self._json(200, {"columns": ["rows"], "rows": [], "next_cursor": None})
                elif engine.server_error_on_wrong_address and body.get("cell_id") != CELL:
                    self._error(500, "internal", "no such cell")
                else:
                    self._error(404, "not_found", f"no graph {graph}/{namespace}")
                return

            try:
                columns, rows = engine.query(body.get("query", ""), body.get("parameters") or {})
            except Unsupported as error:
                self._error(400, error.code, error.message)
                return
            self._json(200, {
                "columns": columns,
                "rows": [[{"type": "integer", "value": cell} if isinstance(cell, int)
                          else {"type": "string", "value": cell} for cell in row] for row in rows],
                "next_cursor": None,
            })

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def run_against(engine: FakeHydra):
    server = make_server(engine)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        return run_contract(
            base_url=f"http://{host}:{port}",
            token=TOKEN,
            graph=GRAPH,
            namespace=NAMESPACE,
            cell=CELL,
        )
    finally:
        server.shutdown()
        server.server_close()


def failed(report, name: str) -> bool:
    return any(check.name == name and not check.ok for check in report.checks)


def detail(report, name: str) -> str:
    return next(check.detail for check in report.checks if check.name == name)


# -- a server that behaves ------------------------------------------------


@pytest.fixture(scope="module")
def clean():
    return run_against(FakeHydra())


def test_every_check_passes_against_a_correct_server(clean):
    assert clean.failures == [], [check.as_dict() for check in clean.failures]
    assert len(clean.checks) >= 12


def test_the_run_cleans_up_after_itself(clean):
    assert "0 left" in detail(clean, "probe_cleanup")


def test_write_check_reports_both_sides_of_the_round_trip(clean):
    assert "readable afterwards" in detail(clean, "write_is_readable")


# -- servers that break one clause each -----------------------------------


def test_an_open_door_is_caught():
    report = run_against(FakeHydra(open_door=True))
    assert failed(report, "auth_wrong_token")
    assert failed(report, "auth_empty_token")
    assert failed(report, "auth_no_header")
    assert "ACCEPTED" in detail(report, "auth_wrong_token")


def test_a_server_error_for_a_wrong_address_is_reported_but_does_not_fail_the_run():
    """A 500 for a caller error is worth reporting; it is not worth failing on.

    The clause is "a wrong address must not be answered as if it were empty",
    and a 500 honours it. HydraDB 0.1.1 answers an unknown cell with 500, so
    this is the behaviour the artifact records rather than hides.
    """
    engine = FakeHydra()
    engine.server_error_on_wrong_address = True
    report = run_against(engine)
    assert not failed(report, "cell_unknown")
    assert detail(report, "cell_unknown").startswith(contract.DEVIATION)
    assert "500" in detail(report, "cell_unknown")


def test_a_wrong_graph_answered_with_an_empty_result_is_caught():
    report = run_against(FakeHydra(empty_on_wrong_graph=True))
    assert failed(report, "graph_unknown")
    assert failed(report, "namespace_unknown")
    assert failed(report, "cell_unknown")
    assert "must not look like an empty answer" in detail(report, "graph_unknown").replace(
        "\n", " "
    )


def test_a_write_that_is_accepted_but_not_stored_is_caught():
    report = run_against(FakeHydra(forget_writes=True))
    assert failed(report, "write_is_readable")
    assert "the graph holds 0" in detail(report, "write_is_readable")


def test_a_rewrite_that_duplicates_rows_is_caught():
    report = run_against(FakeHydra(duplicate_on_rewrite=True))
    assert failed(report, "rewrite_is_idempotent")


def test_a_server_that_accepts_an_unsupported_statement_is_caught():
    report = run_against(FakeHydra(accept_anything=True))
    assert failed(report, "server_error_surfaces")


# -- the pieces on their own ----------------------------------------------


def test_probe_rows_are_storable_scalars():
    rows = contract.probe_rows(run=7, count=3)
    assert [row["id"] for row in rows] == [PROBE_BASE, PROBE_BASE + 1, PROBE_BASE + 2]
    assert all(isinstance(value, (str, int)) for row in rows for value in row.values())


def test_a_null_property_is_refused_before_it_reaches_the_wire():
    from blastradius.hydra import check_row

    with pytest.raises(ValueError, match="note"):
        check_row({"id": 1, "note": None})
