"""Regressions for four bugs found in review; each fails against the old code."""

from __future__ import annotations

import json
import zipfile

import pytest

from blastradius import crosscheck
from blastradius.incident import offending_versions
from blastradius.npmdata import MAX_BACKOFF, retry_after_seconds
from blastradius.pipeline import load_advisories


def _advisory_doc(osv_id: str, package: str, withdrawn: str | None = None) -> dict:
    doc = {
        "id": osv_id,
        "published": "2020-01-01T00:00:00Z",
        "modified": "2020-02-01T00:00:00Z",
        "summary": "test",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": package},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    if withdrawn:
        doc["withdrawn"] = withdrawn
    return doc


def test_withdrawn_advisories_never_enter_the_graph(tmp_path):
    archive = tmp_path / "osv.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("live.json", json.dumps(_advisory_doc("GHSA-live", "leftpad")))
        bundle.writestr(
            "gone.json",
            json.dumps(_advisory_doc("GHSA-gone", "leftpad", withdrawn="2020-03-01T00:00:00Z")),
        )
    kept, scanned = load_advisories(archive, {"leftpad"})
    assert scanned == 2
    assert [advisory.id for advisory in kept["leftpad"]] == ["GHSA-live"]


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def dicts(self):
        return self._rows


class _FakeClient:
    """Answers the two statements ``offending_versions`` runs."""

    def __init__(self, versions):
        self.versions = versions

    def run(self, statement, parameters=None):
        if "AFFECTS" in statement:
            return _FakeResult(
                [
                    {
                        "advisory": "GHSA-x",
                        "kind": "vulnerability",
                        "severity": "HIGH",
                        "has_fix": True,
                        "disclosed_at": 1_600_000_000,
                        "introduced": "1.0.0",
                        "fixed": "1.20.0",
                        "version": f"pkg@{version}",
                        "version_published": 0,
                    }
                    for version in self.versions
                ]
            )
        return _FakeResult(
            [{"version": f"pkg@{version}", "published_at": 1_500_000_000} for version in self.versions]
        )


def test_first_affected_version_is_semver_ordered_not_lexicographic():
    _, rows = offending_versions(_FakeClient(["1.9.0", "1.10.0", "1.2.0"]), "pkg")
    assert rows[0]["first_affected_version"] == "pkg@1.2.0"
    assert rows[0]["affected_versions"] == ["pkg@1.2.0", "pkg@1.9.0", "pkg@1.10.0"]


def test_crosscheck_survives_a_hit_with_no_disclosure_date(monkeypatch):
    monkeypatch.setattr(
        crosscheck,
        "fetch",
        lambda vuln_id, retries=3: {
            "affected": [{"package": {"ecosystem": "npm", "name": "pkg"}, "versions": ["1.0.0"]}],
            "published": "2020-01-01T00:00:00Z",
            "database_specific": {"severity": "HIGH"},
        },
    )
    hit = {
        "version": "pkg@1.0.0",
        "advisory": "MAL-1",
        "disclosed_at": None,
        "severity": "HIGH",
        "has_fix": False,
        "kind": "malicious",
    }
    comparison = crosscheck.compare_hit(hit)  # used to raise TypeError
    assert comparison.agrees is False
    assert any("no disclosure date" in difference for difference in comparison.differences)


class _Response:
    def __init__(self, value):
        self.headers = {"Retry-After": value}


@pytest.mark.parametrize("stated,expected", [("3600", 3600.0), ("0.5", 0.5)])
def test_retry_after_is_read_verbatim_but_bounded_by_the_backoff_ceiling(stated, expected):
    seconds = retry_after_seconds(_Response(stated))
    assert seconds == expected
    assert min(seconds, MAX_BACKOFF) <= MAX_BACKOFF
