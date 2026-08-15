"""Offline coverage for the self test's own bookkeeping.

The self test is the first thing CI runs, and until now the only thing that
exercised it was the Docker job: a bug in *its* reporting would have been
invisible to ``pytest tests/unit``, which is the suite a reader runs. Answering
the fixture's questions needs a real graph engine, so what is checked here is
what the runner itself owns and what a wrong answer costs a reader: a rejected
statement is recorded with the server's code instead of raising, a wrong answer
is recorded as a wrong answer, one failure does not abort the rest of the run,
the fixture is deleted even after failures, and the report counts what happened.
"""

from __future__ import annotations

import pytest

from blastradius import selftest
from blastradius.hydra import HydraError


class FakeResult:
    def __init__(self, rows: list[dict] | None = None) -> None:
        self.rows = rows or []

    def dicts(self) -> list[dict]:
        return self.rows

    def scalar(self):
        if not self.rows:
            return None
        return next(iter(self.rows[0].values()))


class FakeClient:
    """A node that answers nothing useful: every read comes back empty.

    That is deliberate. An empty answer is the failure mode the self test exists
    to catch (a statement the server accepts but cannot answer), so every check
    below the writes should be reported as failed, not raise out of the runner.
    """

    base_url = "http://fake"
    graph = "default"
    cell = "cell-0"
    queries_run = 0
    total_query_ms = 0.0

    def __init__(self, *, reject: str | None = None) -> None:
        self.reject = reject
        self.batched: list[tuple[str, int]] = []
        self.deleted: list[int] = []

    def batch(self, statement: str, rows: list[dict]) -> int:
        if self.reject and self.reject in statement:
            raise HydraError("unsupported_clause", "statement rejected by the server", 400, statement)
        self.batched.append((statement, len(rows)))
        if statement == selftest.CLEANUP:
            self.deleted.extend(row["vertex"] for row in rows)
        return len(rows)

    def run(self, statement: str, params: dict | None = None) -> FakeResult:
        self.queries_run += 1
        return FakeResult([])


def test_every_check_is_reported_and_nothing_raises():
    report = selftest.run_selftest(FakeClient())
    names = [check.name for check in report.checks]
    assert "packages" in names and "blast_radius" in names and "cleanup" in names
    assert len(names) == len(set(names)), f"a check was recorded twice: {names}"
    assert report.as_dict()["checks"] == len(report.checks)


def test_a_read_that_answers_nothing_is_a_failure_not_a_pass():
    """The dangerous case: the server says 200 and returns no rows."""
    report = selftest.run_selftest(FakeClient())
    failed = {check.name for check in report.failures}
    assert "direct_hits" in failed and "graph_size" in failed
    # An empty answer must be reported as a wrong answer, never as a pass.
    assert all(check.ok is False for check in report.checks if check.kind == "read")


def test_a_rejected_statement_keeps_the_server_code_and_does_not_stop_the_run():
    client = FakeClient(reject=selftest.model.ALL_STATEMENTS["packages"])
    report = selftest.run_selftest(client)
    packages = next(check for check in report.checks if check.name == "packages")
    assert packages.ok is False
    assert packages.code == "unsupported_clause"
    # The point of the module: one run reports every problem, not just the first.
    assert len(report.checks) > 10


def test_the_fixture_is_deleted_even_when_checks_failed():
    client = FakeClient()
    report = selftest.run_selftest(client)
    assert report.failures, "this fake cannot answer, so failures are expected"
    assert sorted(client.deleted) == sorted(selftest.FIXTURE_IDS)


def test_the_writes_use_the_production_statements():
    client = FakeClient()
    selftest.run_selftest(client)
    written = {statement for statement, _ in client.batched}
    for bucket in ("packages", "versions", "advisories", "depends", "affects"):
        assert selftest.model.ALL_STATEMENTS[bucket] in written


def test_render_marks_failures_and_counts_them():
    report = selftest.run_selftest(FakeClient())
    rendered = report.render()
    assert "FAIL" in rendered
    assert f"/{len(report.checks)} checks passed" in rendered


def test_write_report_writes_the_json_receipt(tmp_path):
    report = selftest.run_selftest(FakeClient())
    out = tmp_path / "nested" / "selftest.json"
    selftest.write_report(report, out)
    import json

    payload = json.loads(out.read_text())
    assert payload["checks"] == len(report.checks)
    assert payload["failed"] == len(report.failures)
    assert len(payload["results"]) == len(report.checks)


@pytest.mark.parametrize("bucket", sorted(selftest.fixture_rows()))
def test_every_fixture_bucket_has_a_statement(bucket):
    assert bucket in selftest.model.ALL_STATEMENTS
