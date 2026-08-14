"""Advisory normalisation, including the shapes that actually appear in OSV."""

from blastradius.osv import parse_advisory, parse_timestamp


def test_parse_timestamp_handles_both_osv_forms():
    # OSV mixes plain Z-suffixed times with fractional seconds.
    assert parse_timestamp("2025-11-11T05:50:15Z") == 1762840215
    assert parse_timestamp("2026-07-30T18:22:04.456425Z") == 1785435724
    assert parse_timestamp(None) is None
    assert parse_timestamp("nonsense") is None


def test_malicious_advisory_is_classified_and_has_no_fix():
    advisory = parse_advisory(
        {
            "id": "MAL-2025-98359",
            "published": "2025-11-11T05:50:15Z",
            "modified": "2025-11-11T05:50:15Z",
            "summary": "Malicious code in siska-lepet14-pore (npm)",
            "affected": [
                {
                    "package": {"name": "siska-lepet14-pore", "ecosystem": "npm"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                }
            ],
        }
    )
    assert advisory.kind == "malicious"
    assert advisory.is_malicious
    assert not advisory.has_fix
    assert advisory.packages == ["siska-lepet14-pore"]
    assert advisory.affected[0].ranges[0].introduced == "0"
    assert advisory.severity == "UNKNOWN"


def test_vulnerability_keeps_introduced_and_fixed_pairs():
    advisory = parse_advisory(
        {
            "id": "GHSA-1234-5678-90ab",
            "published": "2026-03-01T00:00:00Z",
            "summary": "Prototype pollution",
            "database_specific": {"severity": "HIGH"},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}],
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                        }
                    ],
                }
            ],
        }
    )
    assert advisory.kind == "vulnerability"
    assert advisory.has_fix
    assert advisory.severity == "HIGH"
    assert advisory.cvss_vector.startswith("CVSS:3.1/")
    assert advisory.affected[0].ranges[0].fixed == "4.17.21"


def test_multiple_windows_in_one_range_are_split():
    # OSV encodes several windows as a flat event list; each `introduced`
    # opens a new one. Collapsing them would over-report exposure.
    advisory = parse_advisory(
        {
            "id": "GHSA-multi",
            "affected": [
                {
                    "package": {"name": "pkg", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "1.2.0"},
                                {"introduced": "2.0.0"},
                                {"fixed": "2.1.0"},
                            ],
                        }
                    ],
                }
            ],
        }
    )
    windows = advisory.affected[0].ranges
    assert [(w.introduced, w.fixed) for w in windows] == [
        ("1.0.0", "1.2.0"),
        ("2.0.0", "2.1.0"),
    ]


def test_non_semver_ranges_are_ignored_but_versions_kept():
    advisory = parse_advisory(
        {
            "id": "GHSA-ecosystem",
            "affected": [
                {
                    "package": {"name": "pkg", "ecosystem": "npm"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    "versions": ["1.0.0", "1.0.1"],
                }
            ],
        }
    )
    assert advisory.affected[0].ranges == []
    assert advisory.affected[0].versions == ["1.0.0", "1.0.1"]


def test_affected_entry_without_a_package_name_is_dropped():
    advisory = parse_advisory({"id": "X", "affected": [{"ranges": []}]})
    assert advisory.affected == []
