"""Regressions for the third review pass.

Each test below fails against the code as it stood before that pass. The theme
is the same as the earlier rounds: an answer that was stated more confidently
than the data supports, or an encoding that is right for the wrong layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from blastradius import queries
from blastradius.crosscheck import compare
from blastradius.incident import exposed_services
from blastradius.lockfile import parse_lockfile

APP_HTML = Path(queries.__file__).parent / "static" / "app.html"


# -- a stated timezone offset is an instant, not a label --------------------


def _lockfile(captured: str) -> str:
    return (
        '{"name": "checkout", "lockfileVersion": 3, "blastradiusCapturedAt": "%s",'
        ' "packages": {"": {"dependencies": {"leftpad": "^1.0.0"}},'
        ' "node_modules/leftpad": {"version": "1.0.0"}}}' % captured
    )


def test_a_non_utc_capture_time_is_converted_not_relabelled():
    lock = parse_lockfile(_lockfile("2023-06-01T00:00:00+05:00"), "checkout")
    expected = int(datetime(2023, 6, 1, 0, 0, tzinfo=timezone(timedelta(hours=5))).timestamp())
    assert lock.captured_at == expected


def test_utc_and_offset_forms_of_the_same_instant_agree():
    same = [
        "2023-06-01T05:00:00Z",
        "2023-06-01T05:00:00+00:00",
        "2023-06-01T10:00:00+05:00",
        "2023-06-01T00:00:00-05:00",
    ]
    stamps = {parse_lockfile(_lockfile(value), "checkout").captured_at for value in same}
    assert len(stamps) == 1, f"the same instant produced {stamps}"


def test_a_naive_capture_time_still_falls_back_to_utc():
    lock = parse_lockfile(_lockfile("2023-06-01T00:00:00"), "checkout")
    assert lock.captured_at == int(datetime(2023, 6, 1, tzinfo=timezone.utc).timestamp())


# -- "0 hops" means direct, so it is never printed for an unknown depth -----


class _NoChains:
    """A graph that ships the package but explains no chain within the limit."""

    def __init__(self) -> None:
        self.queries_run = 0
        self.total_query_ms = 0.0

    def run(self, statement: str, params: dict | None = None):
        rows: list[dict] = []
        if "Svc" in statement and "USES" in statement:
            rows = [{
                "service": "checkout",
                "version": "leftpad@1.0.0",
                "direct": False,
                "captured_at": 1_700_000_000,
                "id": 1,
            }]

        class Result:
            def __init__(self, rows):
                self.rows = rows

            def dicts(self):
                return self.rows

            def scalar(self):
                return None

        return Result(rows)


def test_an_unexplained_exposure_never_claims_zero_hops():
    answer, rows, _chains = exposed_services(_NoChains(), "leftpad", max_depth=6)
    assert rows, "the fake ships the package, so there is something to report"
    assert "0 hop(s)" not in answer.summary
    assert "hop depth unknown" in answer.summary
    assert "no chain inside 6 hops" in answer.summary


# -- semver prerelease precedence is numeric, not lexicographic -------------


def test_numeric_prerelease_identifiers_compare_as_numbers():
    assert compare("1.0.0-9", "1.0.0-10") == -1
    assert compare("1.0.0-rc.2", "1.0.0-rc.10") == -1
    assert compare("1.0.0-rc.10", "1.0.0-rc.2") == 1


def test_numeric_prereleases_sort_below_alphanumeric_ones():
    assert compare("1.0.0-1", "1.0.0-alpha") == -1
    assert compare("1.0.0-alpha", "1.0.0-alpha.1") == -1
    assert compare("1.0.0-alpha.1", "1.0.0") == -1
    assert compare("1.0.0-rc.1", "1.0.0-rc.1") == 0


# -- a repeated key is one key ---------------------------------------------


def test_key_list_literal_deduplicates_both_sides():
    literal, refused = queries.key_list_literal(
        ["a@1.0.0", "a@1.0.0", "b@2.0.0", "bad key", "bad key"]
    )
    assert literal == "['a@1.0.0', 'b@2.0.0']"
    assert refused == ["bad key"]


def test_key_list_literal_still_refuses_a_quote():
    literal, refused = queries.key_list_literal(["ok@1.0.0", "b'; DROP"])
    assert "'" not in literal.replace("'ok@1.0.0'", "")
    assert refused == ["b'; DROP"]


# -- the UI has no javascript-in-attribute sink left -----------------------


def test_the_ui_builds_no_inline_handlers_from_data():
    """An attribute is HTML first and JavaScript second: a name interpolated
    into onclick="show('...')" is decoded back into JavaScript by the parser, so
    HTML escaping is the wrong encoding for that sink. Values travel in data
    attributes instead, which are only ever read back as text."""
    html = APP_HTML.read_text(encoding="utf-8")
    offenders = [
        line.strip()
        for line in html.splitlines()
        if "onclick=" in line and "${" in line
    ]
    assert not offenders, f"inline handler built from data: {offenders}"
    assert 'document.addEventListener("click"' in html
    assert "data-go" in html and "dataset.arg" in html
