"""Guard the HydraDB rules that a server, not a reviewer, enforces.

Every rule checked here was learned from a rejection or from the engine source
(``query/opencypher.rs``, ``client/service.rs``, ``client/http.rs``):

* outside an ``UNWIND`` batch, ``MERGE`` cannot be followed by any clause, so
  every write in this project is a batch;
* a vertex upsert must be ``MERGE`` on ``id`` alone, followed by ``SET``;
* every field a statement reads must exist in every row it is sent;
* properties are scalars, and there is no null.

These are cheap tests for expensive mistakes: without them the first sign of a
violation is a failed CI run several minutes in.
"""

from __future__ import annotations

import json
import re

import pytest

from blastradius import model, pipeline, queries, selftest
from blastradius.hydra import MAX_BODY_BYTES, HEALTHCHECK_WRITE, _chunks, check_row
from blastradius.queries import known_time

ROW_FIELD = re.compile(r"\brow\.([A-Za-z_][A-Za-z0-9_]*)")

VERTEX_BUCKETS = ("packages", "versions", "maintainers", "advisories", "services")
EDGE_BUCKETS = ("of", "depends", "uses", "maintains", "affects", "similar")


def fields_read(statement: str) -> set[str]:
    return set(ROW_FIELD.findall(statement))


class TestStatementShape:
    @pytest.mark.parametrize("name", VERTEX_BUCKETS + EDGE_BUCKETS)
    def test_every_write_is_an_unwind_batch(self, name):
        # A bare "MERGE ... SET ..." is answered with "MERGE with following
        # clauses is not executable in Query engine".
        statement = model.ALL_STATEMENTS[name].strip()
        assert statement.startswith("UNWIND $rows AS row")

    @pytest.mark.parametrize("name", VERTEX_BUCKETS)
    def test_a_vertex_upsert_merges_on_id_alone(self, name):
        # Folding properties into the MERGE pattern is rejected: the pattern is
        # the identity being matched on.
        statement = model.ALL_STATEMENTS[name]
        assert "MERGE (n {id: row.id})" in statement
        assert re.search(r"MERGE \(n:\w", statement) is None

    @pytest.mark.parametrize("name", EDGE_BUCKETS)
    def test_an_edge_batch_matches_both_endpoints_first(self, name):
        statement = model.ALL_STATEMENTS[name]
        assert "MATCH (" in statement
        assert statement.count("MERGE") == 1
        # One relationship pattern per batch, single hop, directed.
        assert statement.count("]->") == 1
        assert "<-[" not in statement

    def test_the_healthcheck_is_a_batch_too(self):
        assert HEALTHCHECK_WRITE.startswith("UNWIND $rows AS row")


class TestRowsCarryEveryField:
    """A missing field is rejected per row: "UNWIND row N is missing field X"."""

    @pytest.mark.parametrize("name", VERTEX_BUCKETS + EDGE_BUCKETS)
    def test_the_selftest_fixture_satisfies_its_statement(self, name):
        rows = selftest.fixture_rows()[name]
        expected = fields_read(model.ALL_STATEMENTS[name])
        assert rows, f"{name} has no fixture rows"
        for row in rows:
            assert expected <= set(row), f"{name} row misses {expected - set(row)}"

    def test_the_ingest_rows_satisfy_their_statements(self):
        rows, _stats, _book = _built_rows()
        for name, batch in rows.buckets.items():
            expected = fields_read(model.ALL_STATEMENTS[name])
            for row in batch:
                assert expected <= set(row), f"{name} row misses {expected - set(row)}"


class TestNoNulls:
    def test_check_row_names_the_offending_field(self):
        with pytest.raises(ValueError, match="published_at"):
            check_row({"id": 1, "published_at": None})

    def test_check_row_rejects_a_list_property(self):
        with pytest.raises(ValueError, match="maintainers"):
            check_row({"id": 1, "maintainers": ["a", "b"]})

    def test_ingest_rows_are_all_scalar(self):
        # The registry does not date every version, and OSV does not date every
        # advisory, so the ingest has to substitute its sentinel rather than
        # sending null - which the HTTP layer rejects for the whole request.
        rows, _stats, _book = _built_rows(undated=True)
        for name, batch in rows.buckets.items():
            for index, row in enumerate(batch):
                check_row(row, where=f"{name}[{index}]")

    def test_an_undated_version_becomes_the_sentinel(self):
        rows, _stats, _book = _built_rows(undated=True)
        published = {row["key"]: row["published_at"] for row in rows.buckets["versions"]}
        assert published["undated@1.0.0"] == pipeline.UNKNOWN_TIME

    def test_the_sentinel_reads_back_as_unknown(self):
        assert known_time(0) is None
        assert known_time(None) is None
        assert known_time(True) is None
        assert known_time(1_700_000_000) == 1_700_000_000


class TestChunking:
    def test_a_chunk_never_exceeds_the_body_limit(self):
        big = [{"id": index, "summary": "x" * 4000} for index in range(400)]
        for chunk in _chunks(big, 10_000):
            size = len(json.dumps(chunk).encode("utf-8"))
            assert size <= MAX_BODY_BYTES

    def test_every_row_is_sent_exactly_once(self):
        rows = [{"id": index} for index in range(2500)]
        sent = [row for chunk in _chunks(rows, 500) for row in chunk]
        assert sent == rows

    def test_a_null_is_caught_before_the_request_is_built(self):
        with pytest.raises(ValueError, match="row 1"):
            list(_chunks([{"id": 0}, {"id": None}], 10))


def _built_rows(*, undated: bool = False):
    from blastradius.lockfile import Lockfile, Pin
    from blastradius.npmdata import PackageMeta, ResolvedGraph
    from blastradius.osv import Advisory, Affected, AffectedRange

    metas = {
        "express": PackageMeta(
            name="express",
            versions={"4.18.2": 1_600_000_000},
            maintainers=["dougwilson"],
        )
    }
    nodes = [("express", "4.18.2")]
    pins = [Pin("express", "4.18.2", direct=True)]
    edges = []
    if undated:
        # A package the registry gave us no timestamps for at all, plus an
        # advisory with no publication date: both are real in the corpus.
        metas["undated"] = PackageMeta(name="undated", versions={}, maintainers=[])
        nodes.append(("undated", "1.0.0"))
        pins.append(Pin("undated", "1.0.0"))
        edges.append((0, 1, "^1.0.0"))

    published = None if undated else 1_700_000_000
    advisories = {
        "express": [
            Advisory(
                id="GHSA-1",
                kind="vulnerability",
                published=published,
                modified=published,
                withdrawn=None,
                summary="synthetic",
                aliases=[],
                severity="HIGH",
                cvss_vector="",
                affected=[
                    Affected(
                        package="express",
                        ranges=[AffectedRange(introduced="4.0.0", fixed="4.19.0")],
                        versions=[],
                    )
                ],
            )
        ]
    }
    return pipeline.build_rows(
        [("express", "4.18.2")],
        metas,
        [ResolvedGraph(root=("express", "4.18.2"), nodes=nodes, edges=edges)],
        advisories,
        [Lockfile(service="checkout-api", lockfile_version=3, pins=pins)],
        captured_at=1_760_000_000,
    )


class TestReadQueryShape:
    """The rules the read path rejected on the first live run."""

    READS = (
        "DIRECT_HITS", "BLAST_RADIUS", "DEPTH_AT", "MAINTAINER_REACH",
        "MAINTAINER_FOOTPRINT", "EXPOSURE_WINDOW", "CHOKE_POINTS",
        "SERVICE_ENTRY_POINTS", "TYPOSQUAT_NEIGHBOURS", "COUNT_BY_LABEL",
        "COUNT_BY_EDGE",
    )

    @pytest.mark.parametrize("name", READS)
    def test_no_aggregate_takes_a_bare_binding(self, name):
        # count(n) is refused; only count(*) or count(n.property) are legal.
        statement = getattr(queries, name)
        for call in re.findall(r"\b(?:count|sum|avg|collect)\(([^)]*)\)", statement):
            assert call == "*" or "." in call, f"{name} aggregates over {call!r}"

    @pytest.mark.parametrize("name", READS)
    def test_no_anonymous_node_carries_a_label(self, name):
        # "node labels and non-id properties require a named node"
        statement = getattr(queries, name)
        assert "(:" not in statement, f"{name} has an unnamed labelled node"

    @pytest.mark.parametrize("name", READS)
    def test_no_list_is_passed_as_a_parameter(self, name):
        # A list parameter is only legal as UNWIND input, so the path procedure
        # selectors are formatted in as literals.
        statement = getattr(queries, name)
        assert "$bad_keys" not in statement and "$service_keys" not in statement

    def test_selectors_are_rendered_as_a_literal_list(self):
        literal, refused = queries.key_list_literal(["express@4.18.2", "@babel/core@8.0.1"])
        assert literal == "['express@4.18.2', '@babel/core@8.0.1']"
        assert refused == []

    def test_a_key_that_could_break_out_of_the_literal_is_refused(self):
        literal, refused = queries.key_list_literal(["ok@1.0.0", "evil'] })-- @1"])
        assert literal == "['ok@1.0.0']"
        assert refused == ["evil'] })-- @1"]

    def test_hop_bounds_are_still_literals_in_range(self):
        with pytest.raises(ValueError, match="hop bound"):
            queries.depth_profile(None, 1, max_len=99)
