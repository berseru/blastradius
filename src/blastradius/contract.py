"""Prove the failure paths, not just the happy path, against a live node.

``selftest`` answers "does every query work". This module answers the three
questions that decide whether the answers can be trusted at all:

1. **Is the door locked?** A wrong or missing auth token must be refused with
   401. A read-only demo that quietly serves data to an unauthenticated caller
   is not a demo, it is a leak.
2. **Are we talking to the right graph?** A wrong graph or namespace - the
   moral equivalent of the wrong tenant - must fail loudly. The dangerous
   failure is not an error, it is ``200 OK`` with zero rows, which reads like
   "your services are clean" when it actually means "you asked the wrong
   database".
3. **Did the write actually land?** ``UNWIND`` batches answer 200 as soon as the
   server accepts them. Accepted is not stored: this module writes rows, reads
   them back out of the graph, counts them, rewrites them to prove the MERGE is
   idempotent, mutates one and re-reads it, and only then deletes them. A
   rejected batch is checked for the worst outcome of all, a half-written graph.

Every check records what the server actually did - status code, error code,
counts - so the artifact is evidence rather than a tally. Failures are recorded,
not raised, so one run reports every problem at once.

The probe vertices use their own label and a run-scoped id range, and are
deleted at the end whether or not the checks pass.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable

import httpx

from .hydra import HydraClient, HydraError
from .selftest import Check, SelfTestReport, _run_check

# Far above the fixture ids in selftest.py and far below real blake2b ids.
DEVIATION = "upstream deviation: "


def deviation(text: str) -> str:
    """Mark a check as passed-with-a-caveat.

    The check's own clause held, but the server did something worth reporting.
    Hiding that would make the artifact a tally; failing on it would make the
    build depend on someone else's choice of status code.
    """
    return f"{DEVIATION}{text}"


PROBE_BASE = 900_000
PROBE_ROWS = 2_500

PROBE_WRITE = (
    "UNWIND $rows AS row MERGE (n {id: row.id}) "
    "SET n:Probe, n.run = row.run, n.seq = row.seq, n.note = row.note"
)
PROBE_COUNT = "MATCH (n:Probe) WHERE n.run = $run RETURN count(*) AS rows"
PROBE_READ_ONE = "MATCH (n:Probe {id: $id}) RETURN n.note AS note, n.seq AS seq"
PROBE_DELETE = "UNWIND $rows AS row MATCH (n {id: row.id}) DETACH DELETE n"
TRIVIAL_READ = "MATCH (n:Probe) RETURN count(*) AS rows"


def probe_rows(run: int, count: int = PROBE_ROWS, note: str = "written") -> list[dict[str, Any]]:
    return [
        {"id": PROBE_BASE + index, "run": run, "seq": index, "note": note}
        for index in range(count)
    ]


def _client(base_url: str, token: str, graph: str, namespace: str, cell: str) -> HydraClient:
    return HydraClient(
        base_url=base_url, token=token, graph=graph, namespace=namespace, cell=cell
    )


def run_contract(
    *,
    base_url: str,
    token: str,
    graph: str,
    namespace: str,
    cell: str,
) -> SelfTestReport:
    """Run every negative and durability check, and clean up after itself."""
    report = SelfTestReport()
    started = time.perf_counter()
    run_id = int(time.time())

    client = _client(base_url, token, graph, namespace, cell)

    # -- 1. authentication -------------------------------------------------

    def control() -> str:
        """The control: without this, a 401 below could mean 'server is down'."""
        rows = client.run(TRIVIAL_READ).scalar()
        assert rows is not None, "the valid token did not get an answer"
        return f"valid token answered, {rows} probe vertices present"

    _run_check(report, "auth_valid_token", "auth", control)

    def refused(bad_token: str, label: str) -> Callable[[], str]:
        def body() -> str:
            other = _client(base_url, bad_token, graph, namespace, cell)
            try:
                result = other.run(TRIVIAL_READ)
            except HydraError as error:
                assert error.status == 401, (
                    f"{label} was refused with {error.status}, expected 401 ({error.code})"
                )
                return f"401 {error.code or 'unauthorized'}"
            finally:
                other.close()
            raise AssertionError(
                f"{label} was ACCEPTED and returned {len(result)} rows - the door is open"
            )

        return body

    _run_check(report, "auth_wrong_token", "auth", refused("not-the-real-token", "a wrong token"))
    _run_check(report, "auth_empty_token", "auth", refused("", "an empty token"))

    def unauthenticated() -> str:
        """No Authorization header at all, sent by hand: httpx, not our client."""
        response = httpx.post(
            f"{base_url.rstrip('/')}/v1/graphs/{graph}/query",
            json={"cell_id": cell, "query": TRIVIAL_READ},
            headers={"X-Graph-Namespace": namespace},
            timeout=30.0,
        )
        assert response.status_code == 401, (
            f"a request with no Authorization header got {response.status_code}"
        )
        return f"401 without the header ({response.text[:80]!r})"

    _run_check(report, "auth_no_header", "auth", unauthenticated)

    # -- 2. addressing the wrong graph ------------------------------------

    def wrong(where: str, **overrides: str) -> Callable[[], str]:
        """The clause being tested is 'it must not answer as if it were empty'.

        Which 4xx the server picks is its business; that it refuses at all is
        ours. A status outside 4xx is still reported - as a deviation, with the
        code the server actually returned - because a server error for a caller
        error is worth knowing about even when it does not endanger an answer.
        """

        def body() -> str:
            settings = {
                "base_url": base_url, "token": token, "graph": graph,
                "namespace": namespace, "cell": cell,
            }
            settings.update(overrides)
            other = _client(**settings)  # type: ignore[arg-type]
            try:
                result = other.run(TRIVIAL_READ)
            except HydraError as error:
                if 400 <= error.status < 500:
                    return f"{error.status} {error.code}"
                return deviation(
                    f"{where} was refused with {error.status} {error.code}; a caller error "
                    "should be a 4xx. Refused is what matters, so this does not fail the run"
                )
            finally:
                other.close()
            raise AssertionError(
                f"{where} answered 200 with {len(result)} rows - a wrong address must not "
                "look like an empty answer"
            )

        return body

    _run_check(report, "graph_unknown", "address", wrong("an unknown graph", graph="no-such-graph"))
    _run_check(
        report, "namespace_unknown", "address",
        wrong("an unknown namespace", namespace="no-such-namespace"),
    )
    _run_check(report, "cell_unknown", "address", wrong("an unknown cell", cell="cell-404"))

    # -- 3. a write is not done until it can be read back ------------------

    def write_lands() -> str:
        rows = probe_rows(run_id)
        started_write = time.perf_counter()
        written = client.batch(PROBE_WRITE, rows, chunk_size=1000)
        elapsed = (time.perf_counter() - started_write) * 1000
        assert written == len(rows), f"batch reported {written} of {len(rows)}"
        stored = client.run(PROBE_COUNT, {"run": run_id}).scalar()
        assert stored == len(rows), (
            f"the server accepted {written} rows but the graph holds {stored}"
        )
        return f"{written} rows sent in {elapsed:.0f}ms, {stored} readable afterwards"

    _run_check(report, "write_is_readable", "durability", write_lands)

    def rewrite_is_idempotent() -> str:
        """The same batch twice must not double the graph: MERGE, not CREATE."""
        client.batch(PROBE_WRITE, probe_rows(run_id), chunk_size=1000)
        stored = client.run(PROBE_COUNT, {"run": run_id}).scalar()
        assert stored == PROBE_ROWS, f"a second identical write left {stored} rows, not {PROBE_ROWS}"
        return f"still {stored} rows after writing the same batch twice"

    _run_check(report, "rewrite_is_idempotent", "durability", rewrite_is_idempotent)

    def update_is_visible() -> str:
        """SET must change stored state, not merely be accepted."""
        client.batch(PROBE_WRITE, probe_rows(run_id, count=1, note="updated"), chunk_size=1000)
        row = client.run(PROBE_READ_ONE, {"id": PROBE_BASE}).dicts()
        assert row and row[0].get("note") == "updated", f"the update did not stick: {row}"
        return "property update round-tripped"

    _run_check(report, "update_is_visible", "durability", update_is_visible)

    def rejected_write_is_not_partial() -> str:
        """A bad row must stop the whole batch before the wire, leaving no debris."""
        before = client.run(PROBE_COUNT, {"run": run_id}).scalar()
        bad = probe_rows(run_id, count=10)
        bad[7]["note"] = None  # HydraDB has no null property value
        try:
            client.batch(PROBE_WRITE, bad, chunk_size=1000)
        except ValueError as error:
            after = client.run(PROBE_COUNT, {"run": run_id}).scalar()
            assert after == before, f"a refused batch changed the graph: {before} -> {after}"
            assert "note" in str(error), f"the error did not name the field: {error}"
            return f"refused before sending ({str(error)[:70]}), graph unchanged at {after}"
        raise AssertionError("a null property was accepted; the graph would be silently wrong")

    _run_check(report, "rejected_write_is_not_partial", "durability", rejected_write_is_not_partial)

    def server_error_surfaces() -> str:
        """An unsupported statement must arrive as an error with the server's code."""
        try:
            client.run("MATCH (n:Probe) WHERE n.note IN ['a'] RETURN n.id AS id")
        except HydraError as error:
            assert error.status >= 400, f"status was {error.status}"
            assert error.code, "the server's error code was lost on the way up"
            return f"{error.status} {error.code}: {error.message[:80]}"
        raise AssertionError("an unsupported statement was accepted silently")

    _run_check(report, "server_error_surfaces", "durability", server_error_surfaces)

    def oversized_row_is_reported() -> str:
        """One row larger than the 1 MiB body cap cannot be split - it must error.

        A transport-level refusal counts, because a server may drop the
        connection instead of answering 413 - but only after this proves the node
        is reachable *right now*. Without that control, an absent server refuses
        the connection too, and this check would pass against nothing at all.
        """
        assert client.run(PROBE_COUNT, {"run": run_id}).scalar() is not None, (
            "the node must be reachable for a refusal to mean anything"
        )
        huge = [{"id": PROBE_BASE + 999_000, "run": run_id, "seq": 0, "note": "x" * 1_200_000}]
        try:
            client.batch(PROBE_WRITE, huge, chunk_size=1)
        except HydraError as error:
            return f"{error.status} {error.code}"
        except httpx.HTTPError as error:
            return f"transport refused it: {type(error).__name__} (node reachable)"
        raise AssertionError("a 1.2 MB property was accepted; the body cap is not enforced")

    _run_check(report, "oversized_row_is_reported", "durability", oversized_row_is_reported)

    def cleanup() -> str:
        client.batch(
            PROBE_DELETE,
            [{"id": PROBE_BASE + index} for index in range(PROBE_ROWS)] +
            [{"id": PROBE_BASE + 999_000}],
            chunk_size=1000,
        )
        left = client.run(PROBE_COUNT, {"run": run_id}).scalar()
        assert left == 0, f"{left} probe vertices survived the cleanup"
        return f"{PROBE_ROWS} probe vertices removed, 0 left"

    _run_check(report, "probe_cleanup", "durability", cleanup)

    client.close()
    report.seconds = time.perf_counter() - started
    return report


def write_report(report: SelfTestReport, out: str | Path) -> None:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.as_dict(), indent=2), encoding="utf-8")


def contract_from_env() -> SelfTestReport:
    return run_contract(
        base_url=os.environ.get("HYDRA_URL", "http://127.0.0.1:8443"),
        token=os.environ.get("HYDRA_TOKEN", ""),
        graph=os.environ.get("HYDRA_GRAPH", "default"),
        namespace=os.environ.get("HYDRA_NAMESPACE", "default"),
        cell=os.environ.get("HYDRA_CELL", "cell-0"),
    )


__all__ = [
    "Check",
    "DEVIATION",
    "deviation",
    "PROBE_BASE",
    "PROBE_ROWS",
    "PROBE_WRITE",
    "contract_from_env",
    "probe_rows",
    "run_contract",
    "write_report",
]
