"""Row building: the part that decides what the graph will say."""

import pytest

from blastradius.lockfile import Edge, Lockfile, Pin
from blastradius.npmdata import PackageMeta, ResolvedGraph
from blastradius.osv import Advisory, Affected, AffectedRange
from blastradius.typosquat import UNKNOWN_DOWNLOADS
from blastradius.pipeline import Rows, build_rows, match_versions, read_seeds


def advisory(osv_id, kind, package, ranges=(), versions=()):
    return Advisory(
        id=osv_id,
        kind=kind,
        published=1_700_000_000,
        modified=1_700_000_000,
        withdrawn=None,
        summary=f"{kind} in {package}",
        aliases=[],
        severity="HIGH" if kind == "vulnerability" else "UNKNOWN",
        cvss_vector="",
        affected=[Affected(package=package, ranges=list(ranges), versions=list(versions))],
    )


class TestSeeds:
    def test_scoped_names_survive_the_split(self, tmp_path):
        path = tmp_path / "seeds.txt"
        path.write_text("# comment\n\n@babel/core@8.0.1\nexpress@4.18.2\n")
        assert read_seeds(path) == [("@babel/core", "8.0.1"), ("express", "4.18.2")]

    def test_limit_is_respected(self, tmp_path):
        path = tmp_path / "seeds.txt"
        path.write_text("a@1.0.0\nb@2.0.0\nc@3.0.0\n")
        assert len(read_seeds(path, limit=2)) == 2

    def test_an_unpinned_seed_is_rejected_loudly(self, tmp_path):
        # A floating seed would silently change the graph between runs, which
        # would make every benchmark number unreproducible.
        path = tmp_path / "seeds.txt"
        path.write_text("express\n")
        with pytest.raises(ValueError, match="name@version"):
            read_seeds(path)


class TestRowDeduplication:
    def test_identical_ids_are_queued_once(self):
        rows = Rows()
        rows.add("packages", {"id": 1, "name": "a"})
        rows.add("packages", {"id": 1, "name": "a"})
        rows.add("packages", {"id": 2, "name": "b"})
        assert rows.counts() == {"packages": 2}

    def test_edges_dedupe_on_their_own_id(self):
        rows = Rows()
        rows.add("affects", {"edge_id": 9, "kind": "malicious"})
        rows.add("affects", {"edge_id": 9, "kind": "malicious"})
        assert rows.total() == 1

    def test_same_id_in_different_buckets_is_kept(self):
        rows = Rows()
        rows.add("packages", {"id": 1})
        rows.add("versions", {"id": 1})
        assert rows.total() == 2


class TestMatchVersions:
    def test_malicious_advisory_covers_every_version(self):
        # MAL records carry `introduced: 0` and no fix, so every version of the
        # package is affected - which is the whole point: there is nothing to
        # upgrade to.
        found = match_versions(
            advisory("MAL-1", "malicious", "expess", ranges=[AffectedRange(introduced="0")]),
            "expess",
            {"4.18.2", "1.0.0"},
        )
        assert set(found) == {"4.18.2", "1.0.0"}
        assert all(window == ("0", "") for window in found.values())

    def test_window_bounds_are_respected(self):
        found = match_versions(
            advisory(
                "GHSA-x",
                "vulnerability",
                "lodash",
                ranges=[AffectedRange(introduced="4.0.0", fixed="4.17.21")],
            ),
            "lodash",
            {"3.10.1", "4.17.15", "4.17.21"},
        )
        assert set(found) == {"4.17.15"}
        assert found["4.17.15"] == ("4.0.0", "4.17.21")

    def test_explicit_version_lists_are_honoured(self):
        found = match_versions(
            advisory("GHSA-y", "vulnerability", "pkg", versions=["1.0.0"]),
            "pkg",
            {"1.0.0", "1.0.1"},
        )
        assert set(found) == {"1.0.0"}

    def test_other_packages_in_the_same_advisory_are_ignored(self):
        adv = advisory("GHSA-z", "vulnerability", "other", ranges=[AffectedRange(introduced="0")])
        assert match_versions(adv, "mine", {"1.0.0"}) == {}


class TestBuildRows:
    def _inputs(self):
        seeds = [("express", "4.18.2")]
        metas = {
            "express": PackageMeta(
                name="express",
                versions={"4.18.2": 1_600_000_000, "4.17.1": 1_500_000_000},
                maintainers=["dougwilson"],
            ),
            "accepts": PackageMeta(name="accepts", versions={"1.3.8": 1_550_000_000}, maintainers=[]),
        }
        resolved = [
            ResolvedGraph(
                root=("express", "4.18.2"),
                nodes=[("express", "4.18.2"), ("accepts", "1.3.8")],
                edges=[(0, 1, "~1.3.8")],
            )
        ]
        lockfiles = [
            Lockfile(
                service="checkout-api",
                lockfile_version=3,
                pins=[Pin("express", "4.18.2", direct=True), Pin("accepts", "1.3.8")],
                edges=[Edge("express@4.18.2", "accepts@1.3.8", "~1.3.8")],
            )
        ]
        advisories = {
            "express": [
                advisory(
                    "GHSA-1",
                    "vulnerability",
                    "express",
                    ranges=[AffectedRange(introduced="4.0.0", fixed="4.19.0")],
                )
            ]
        }
        return seeds, metas, resolved, advisories, lockfiles

    def test_every_layer_of_the_graph_is_produced(self):
        rows, stats, book = build_rows(*self._inputs(), captured_at=1_700_000_500)
        counts = rows.counts()
        assert counts["packages"] == 2
        assert counts["versions"] == 2
        assert counts["depends"] == 1
        assert counts["uses"] == 2
        assert counts["services"] == 1
        assert counts["affects"] == 1
        assert stats.versions == 2
        assert len(book) >= 5

    def test_versions_carry_their_publication_time(self):
        rows, _stats, _book = build_rows(*self._inputs())
        published = {row["key"]: row["published_at"] for row in rows.buckets["versions"]}
        assert published["express@4.18.2"] == 1_600_000_000
        assert published["accepts@1.3.8"] == 1_550_000_000

    def test_direct_and_transitive_pins_are_distinguished(self):
        rows, _stats, book = build_rows(*self._inputs())
        direct = {row["version_id"]: row["direct"] for row in rows.buckets["uses"]}
        assert direct[book.version("express", "4.18.2")] is True
        assert direct[book.version("accepts", "1.3.8")] is False

    def test_a_version_nobody_pins_is_not_invented(self):
        # express 4.17.1 exists in the registry metadata but nothing depends on
        # it, so it must not appear as a node.
        rows, _stats, _book = build_rows(*self._inputs())
        assert "express@4.17.1" not in {row["key"] for row in rows.buckets["versions"]}

    def test_service_snapshot_time_reaches_the_row(self):
        rows, _stats, _book = build_rows(*self._inputs(), captured_at=1_700_000_500)
        assert rows.buckets["services"][0]["captured_at"] == 1_700_000_500

    def test_lockfile_edges_are_marked_direct_at_the_pinned_version(self):
        """The whole point of the fix: a pin must have an outgoing edge."""
        rows, _stats, book = build_rows(*self._inputs())
        depends = {
            (row["from_id"], row["to_id"]): row for row in rows.buckets["depends"]
        }
        key = (book.version("express", "4.18.2"), book.version("accepts", "1.3.8"))
        assert depends[key]["direct"] is True
        assert depends[key]["requirement"] == "~1.3.8"

    def test_a_registry_edge_for_a_version_nobody_ships_does_not_replace_it(self):
        """Lockfile edges win: they are queued first, so the `direct` flag stays."""
        seeds, metas, resolved, advisories, lockfiles = self._inputs()
        resolved[0].edges = [(0, 1, "^1.0.0")]
        rows, _stats, _book = build_rows(seeds, metas, resolved, advisories, lockfiles)
        assert len(rows.buckets["depends"]) == 1
        assert rows.buckets["depends"][0]["direct"] is True

    def test_a_maintainer_carries_the_number_of_packages_it_can_publish(self):
        """A published 0 would read as "this account owns nothing"."""
        seeds, metas, resolved, advisories, lockfiles = self._inputs()
        metas["accepts"].maintainers = ["dougwilson"]
        rows, _stats, book = build_rows(seeds, metas, resolved, advisories, lockfiles)
        counts = {row["login"]: row["package_count"] for row in rows.buckets["maintainers"]}
        assert counts == {"dougwilson": 2}

    def test_a_maintainer_row_is_written_once_with_the_final_count(self):
        seeds, metas, resolved, advisories, lockfiles = self._inputs()
        metas["accepts"].maintainers = ["dougwilson"]
        rows, _stats, _book = build_rows(seeds, metas, resolved, advisories, lockfiles)
        assert len(rows.buckets["maintainers"]) == 1
        assert len(rows.buckets["maintains"]) == 2

    def test_download_counts_reach_the_package_rows(self):
        seeds, metas, resolved, advisories, lockfiles = self._inputs()
        rows, _stats, _book = build_rows(
            seeds, metas, resolved, advisories, lockfiles,
            downloads={"express": 127_296_948},
        )
        counts = {row["name"]: row["downloads"] for row in rows.buckets["packages"]}
        assert counts["express"] == 127_296_948
        assert counts["accepts"] == UNKNOWN_DOWNLOADS

    def test_typosquat_edge_is_built_for_a_malicious_lookalike(self):
        seeds, metas, resolved, advisories, lockfiles = self._inputs()
        metas["expess"] = PackageMeta(
            name="expess", versions={"4.18.2": 1_600_000_000}, maintainers=[]
        )
        lockfiles[0].pins.append(Pin("expess", "4.18.2", direct=True))
        advisories["expess"] = [
            advisory("MAL-2025-1", "malicious", "expess", ranges=[AffectedRange(introduced="0")])
        ]
        rows, stats, book = build_rows(
            seeds, metas, resolved, advisories, lockfiles,
            downloads={"express": 127_296_948, "expess": 138},
        )
        assert stats.similar_edges == 1
        edge = rows.buckets["similar"][0]
        assert edge["from_id"] == book.package("expess")
        assert edge["to_id"] == book.package("express")
        assert edge["distance"] == 1
        assert 0 < edge["downloads_ratio"] < 0.0001
