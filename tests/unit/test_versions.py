"""Semver rules the blast radius depends on being exactly right.

If ``is_affected`` is wrong the graph gets wrong edges, and every answer built
on it is confidently wrong — the worst failure mode a security tool has.
"""

from blastradius.versions import is_affected, range_admits, sort_versions


class TestIsAffected:
    def test_open_ended_range_affects_everything_from_introduced(self):
        assert is_affected("1.0.0", introduced="0")
        assert is_affected("99.0.0", introduced="0")

    def test_fixed_is_exclusive(self):
        assert is_affected("4.17.20", introduced="0", fixed="4.17.21")
        assert not is_affected("4.17.21", introduced="0", fixed="4.17.21")
        assert not is_affected("4.18.0", introduced="0", fixed="4.17.21")

    def test_last_affected_is_inclusive(self):
        assert is_affected("1.2.3", introduced="1.0.0", last_affected="1.2.3")
        assert not is_affected("1.2.4", introduced="1.0.0", last_affected="1.2.3")

    def test_versions_before_introduced_are_clean(self):
        assert not is_affected("1.9.9", introduced="2.0.0", fixed="2.1.0")
        assert is_affected("2.0.0", introduced="2.0.0", fixed="2.1.0")

    def test_prereleases_compare_below_their_release(self):
        assert is_affected("2.0.0-beta.1", introduced="1.0.0", fixed="2.0.0")
        assert not is_affected("2.0.0", introduced="1.0.0", fixed="2.0.0")

    def test_unparseable_version_is_not_affected(self):
        # Never guess. An unknown version must not be reported as compromised.
        assert not is_affected("not-a-version", introduced="0")
        assert not is_affected("", introduced="0")


class TestRangeAdmits:
    def test_caret_allows_minor_and_patch(self):
        assert range_admits("^4.17.0", "4.17.21")
        assert range_admits("^4.17.0", "4.18.0")
        assert not range_admits("^4.17.0", "5.0.0")
        assert not range_admits("^4.17.0", "4.16.9")

    def test_tilde_allows_patch_only(self):
        assert range_admits("~1.3.8", "1.3.9")
        assert not range_admits("~1.3.8", "1.4.0")

    def test_exact_pin_admits_only_itself(self):
        assert range_admits("1.1.1", "1.1.1")
        assert not range_admits("1.1.1", "1.1.2")

    def test_wildcards_admit_everything(self):
        for requirement in ("", "*", "latest", "x"):
            assert range_admits(requirement, "9.9.9")

    def test_non_registry_requirements_admit_nothing(self):
        # A git or file dependency never resolves from the registry, so
        # counting it as exposure would inflate the blast radius.
        for requirement in (
            "git+https://github.com/x/y.git",
            "file:../local",
            "npm:other@^1.0.0",
            "workspace:*",
        ):
            assert not range_admits(requirement, "1.0.0")

    def test_prerelease_only_matches_a_comparator_on_the_same_version(self):
        # npm's rule, verified against node-semver rather than assumed: a
        # prerelease is admitted only when some comparator in the range carries
        # a prerelease on the *same* major.minor.patch tuple.
        assert not range_admits("^1.0.0", "1.2.0-beta.1")
        assert not range_admits(">=1.0.0-0", "1.2.0-beta.1")
        assert range_admits(">=1.2.0-0 <1.3.0", "1.2.0-beta.1")
        assert range_admits("^1.2.0-0", "1.2.0-beta.1")


def test_sort_versions_is_semver_not_lexicographic():
    assert sort_versions(["2.0.0", "1.0.0", "1.10.0", "1.2.0"]) == [
        "1.0.0",
        "1.2.0",
        "1.10.0",
        "2.0.0",
    ]


def test_sort_versions_drops_unparseable_entries():
    assert sort_versions(["1.0.0", "bogus", "2.0.0"]) == ["1.0.0", "2.0.0"]
