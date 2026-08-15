"""Regressions for the accuracy findings from the second review pass.

Each of these fails against the code as it stood before that pass: an answer
that was stated with more confidence than the graph could support, or a cap
that dropped inputs without saying so.
"""

from __future__ import annotations

from blastradius import limits
from blastradius.crosscheck import Comparison
from blastradius.incident import resolved_while_live


def _exposure(captured: int | None) -> list[dict]:
    return [{"service": "checkout", "version": "leftpad@1.0.0", "captured_at": captured}]


def _advisory(fixed: str | None) -> dict:
    return {
        "advisory": "GHSA-x",
        "affected_versions": ["leftpad@1.0.0"],
        "fixed": fixed,
        "has_fix": fixed is not None,
        "disclosed_at": "2020-06-01",
    }


def test_missing_fixed_version_is_unknown_not_a_hit():
    """A fix exists but its release is not a node: the window has no end."""
    answer = resolved_while_live(
        "leftpad",
        _exposure(2_000_000),
        [_advisory("1.0.1")],
        {"leftpad@1.0.0": 1_000_000},  # the fixed release is absent
    )
    assert [row["verdict"] for row in answer.rows] == ["unknown: fixed version not in graph"]


def test_window_with_no_fix_still_answers_yes():
    answer = resolved_while_live(
        "leftpad", _exposure(2_000_000), [_advisory(None)], {"leftpad@1.0.0": 1_000_000}
    )
    assert answer.rows[0]["verdict"].startswith("yes")


def test_known_fixed_release_closes_the_window():
    answer = resolved_while_live(
        "leftpad",
        _exposure(3_000_000),
        [_advisory("1.0.1")],
        {"leftpad@1.0.0": 1_000_000, "leftpad@1.0.1": 2_000_000},
    )
    assert answer.rows[0]["verdict"] == "no: a fixed version was already available"


def test_capped_reports_truncation():
    values, truncated = limits.capped(list(range(30)), 25)
    assert len(values) == 25 and truncated is True
    values, truncated = limits.capped(list(range(3)), 25)
    assert values == [0, 1, 2] and truncated is False


def test_web_and_cli_share_one_set_of_bounds():
    """The bounds used to be retyped at each call site and could drift."""
    from blastradius import cli, queries, web

    assert web.CHAIN_MAX_LEN is limits.CHAIN_MAX_LEN
    assert cli.DEPTH_MAX_LEN is limits.DEPTH_MAX_LEN
    import inspect

    assert inspect.signature(queries.blast_radius).parameters["max_len"].default == (
        limits.CHAIN_MAX_LEN
    )


def test_unreachable_advisories_are_not_counted_as_agreement(monkeypatch, tmp_path):
    from blastradius import crosscheck as cc

    hits = [
        {"version": "a@1.0.0", "advisory": "GHSA-1"},
        {"version": "b@1.0.0", "advisory": "GHSA-2"},
    ]

    def fake_sample(_path):
        return hits

    def fake_compare(hit):
        if hit["advisory"] == "GHSA-2":
            return Comparison(hit["version"], hit["advisory"], True, "offline", unreachable=True)
        return Comparison(hit["version"], hit["advisory"], True, "ok")

    monkeypatch.setattr(cc, "sample_hits", fake_sample)
    monkeypatch.setattr(cc, "compare_hit", fake_compare)
    report = cc.crosscheck(tmp_path / "samples")
    assert report["checked"] == 2
    assert report["compared"] == 1
    assert report["agreed"] == 1
    assert report["unreachable"] == 1
