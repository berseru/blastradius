"""The OSV cross-check, exercised offline against handmade records.

The network is never touched here: ``fetch`` is replaced. What is tested is the
judgement - that the comparison notices a wrong date, a wrong severity, a
version outside the affected range, and a fix that does not exist - because a
cross-check that cannot disagree is decoration.
"""

from __future__ import annotations

import json

import pytest

from blastradius import crosscheck


def record(**overrides) -> dict:
    base = {
        "id": "GHSA-test-test-test",
        "published": "2024-09-10T00:00:00Z",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lib"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}
                ],
            }
        ],
    }
    base.update(overrides)
    return base


def hit(**overrides) -> dict:
    base = {
        "version": "lib@1.1.0",
        "advisory": "GHSA-test-test-test",
        "kind": "vulnerability",
        "severity": "HIGH",
        "has_fix": True,
        "disclosed_at": 1_725_926_400,  # 2024-09-10
    }
    base.update(overrides)
    return base


class TestSemver:
    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("1.0.0", "1.0.0", 0),
            ("1.0.1", "1.0.0", 1),
            ("1.2.0", "1.10.0", -1),
            ("2.0.0", "10.0.0", -1),
            ("1.0.0", "1.0.0-rc.1", 1),
            ("1.0.0-alpha", "1.0.0-beta", -1),
            ("1.0.0+build", "1.0.0", 0),
            ("4.17.21", "4.17.3", 1),
        ],
    )
    def test_ordering(self, left, right, expected):
        assert crosscheck.compare(left, right) == expected

    def test_a_release_outranks_its_own_prerelease(self):
        assert crosscheck.compare("1.2.0", "1.2.0-rc.9") > 0


class TestAffectedness:
    def test_a_version_inside_the_range(self):
        affected, grounds = crosscheck.osv_affects(record(), "lib", "1.1.0")
        assert affected and grounds == "range [1.0.0, 1.2.0)"

    def test_the_fixed_version_is_not_affected(self):
        affected, _ = crosscheck.osv_affects(record(), "lib", "1.2.0")
        assert not affected

    def test_a_version_before_the_range_is_not_affected(self):
        affected, _ = crosscheck.osv_affects(record(), "lib", "0.9.0")
        assert not affected

    def test_last_affected_is_inclusive(self):
        spans = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "2.0.0"}]}]
        data = record(affected=[{"package": {"ecosystem": "npm", "name": "lib"},
                                 "ranges": spans}])
        assert crosscheck.osv_affects(data, "lib", "2.0.0")[0]
        assert not crosscheck.osv_affects(data, "lib", "2.0.1")[0]

    def test_an_explicit_version_list_is_honoured(self):
        data = record(affected=[{"package": {"ecosystem": "npm", "name": "lib"},
                                 "versions": ["1.1.0", "1.1.1"]}])
        assert crosscheck.osv_affects(data, "lib", "1.1.0")[0]
        assert not crosscheck.osv_affects(data, "lib", "1.5.0")[0]

    def test_another_package_in_the_same_advisory_is_not_us(self):
        data = record(affected=[{"package": {"ecosystem": "npm", "name": "other"},
                                 "ranges": record()["affected"][0]["ranges"]}])
        assert not crosscheck.osv_affects(data, "lib", "1.1.0")[0]

    def test_a_different_ecosystem_is_not_us(self):
        data = record(affected=[{"package": {"ecosystem": "PyPI", "name": "lib"},
                                 "ranges": record()["affected"][0]["ranges"]}])
        assert not crosscheck.osv_affects(data, "lib", "1.1.0")[0]

    def test_an_open_range_covers_malware(self):
        data = record(affected=[{"package": {"ecosystem": "npm", "name": "lib"},
                                 "ranges": [{"type": "SEMVER",
                                             "events": [{"introduced": "0"}]}]}])
        assert crosscheck.osv_affects(data, "lib", "99.0.0")[0]


class TestComparison:
    @pytest.fixture(autouse=True)
    def offline(self, monkeypatch):
        self.answer = record()
        monkeypatch.setattr(crosscheck, "fetch", lambda vuln_id, retries=3: self.answer)

    def test_an_agreeing_hit(self):
        result = crosscheck.compare_hit(hit())
        assert result.agrees and result.differences == []

    def test_a_version_outside_the_range_disagrees(self):
        result = crosscheck.compare_hit(hit(version="lib@3.0.0"))
        assert not result.agrees
        assert "does not mark 3.0.0 affected" in result.differences[0]

    def test_a_wrong_disclosure_date_disagrees(self):
        result = crosscheck.compare_hit(hit(disclosed_at=1_600_000_000))
        assert not result.agrees and "disclosed" in result.differences[0]

    def test_a_wrong_severity_disagrees(self):
        result = crosscheck.compare_hit(hit(severity="LOW"))
        assert not result.agrees and "severity LOW here, HIGH at OSV" in result.differences[0]

    def test_a_fix_that_osv_does_not_have_disagrees(self):
        self.answer = record(affected=[{"package": {"ecosystem": "npm", "name": "lib"},
                                        "ranges": [{"type": "SEMVER",
                                                    "events": [{"introduced": "0"}]}]}])
        result = crosscheck.compare_hit(hit())
        assert not result.agrees and "fix available" in " ".join(result.differences)

    def test_malware_must_be_labelled_malware(self):
        result = crosscheck.compare_hit(hit(advisory="MAL-2025-1", kind="vulnerability"))
        assert not result.agrees and "kind" in " ".join(result.differences)

    def test_an_unreachable_advisory_is_skipped_not_failed(self, monkeypatch):
        def boom(vuln_id, retries=3):
            raise RuntimeError("could not fetch: network down")

        monkeypatch.setattr(crosscheck, "fetch", boom)
        result = crosscheck.compare_hit(hit())
        assert result.unreachable and result.agrees, (
            "a network outage must not be reported as the data being wrong"
        )


class TestSampling:
    def test_samples_come_from_both_ends_of_every_service(self, tmp_path):
        for service, count in (("alpha", 10), ("beta", 3)):
            hits = [hit(version=f"lib@1.1.{index}", advisory=f"GHSA-{service}-{index}")
                    for index in range(count)]
            (tmp_path / f"api_services_{service}.json").write_text(
                json.dumps({"service": service, "hits": hits})
            )
        sampled = crosscheck.sample_hits(tmp_path, per_service=4)
        advisories = {row["advisory"] for row in sampled}
        assert "GHSA-alpha-0" in advisories and "GHSA-alpha-9" in advisories, (
            "sampling only the first hits would never check the tail of the list"
        )
        assert len(advisories) == len(sampled), "the same advisory was sampled twice"

    def test_an_empty_directory_samples_nothing(self, tmp_path):
        assert crosscheck.sample_hits(tmp_path) == []
