"""The six track questions, answered without a database.

HydraDB cannot run here, so the client is a fake that answers this project's own
statements - dispatching on statement identity, so an edited query that the fake
has not been taught about fails loudly instead of returning nothing. The graph it
describes is deliberately awkward:

    web-app@1.0.0 -DEPENDS-> helper@2.0.0 -DEPENDS-> evil@1.2.3   (three hops)
    batch-job@1.0.0 -USES-> evil@1.2.3                            (pinned direct)

`evil@1.2.3` went live on 2026-01-01 and was disclosed on 2026-03-01. The web app
snapshot is from 2026-02-01 (inside the window, *before* disclosure), the batch
job's from 2025-06-01 (before the bad release existed). Those two must not get
the same answer, which is the whole point of question 3.
"""

from __future__ import annotations

import pytest

from blastradius import queries
from blastradius.hydra import Path, PathNode, PathRel, Result
from blastradius.incident import UnknownPackage, investigate

EVIL = "evil@1.2.3"
LIVE_FROM = 1_767_225_600  # 2026-01-01
DISCLOSED = 1_772_323_200  # 2026-03-01
WEB_SNAPSHOT = 1_769_904_000  # 2026-02-01, inside the window and before disclosure
BATCH_SNAPSHOT = 1_748_736_000  # 2025-06-01, before the bad version existed


def _chain() -> Path:
    nodes = [
        PathNode(id=1, labels=["Ver"], properties={"key": EVIL}),
        PathNode(id=2, labels=["Ver"], properties={"key": "helper@2.0.0"}),
        PathNode(id=3, labels=["Ver"], properties={"key": "web-app@1.0.0"}),
    ]
    rels = [
        PathRel(edge_type="DEPENDS", src=2, dst=1, properties={"requirement": "^1.0.0"}),
        PathRel(edge_type="DEPENDS", src=3, dst=2, properties={"requirement": "^2.0.0"}),
    ]
    return Path(nodes=nodes, relationships=rels)


class FakeClient:
    def __init__(self, *, known: bool = True) -> None:
        self.known = known
        self.seen: list[str] = []

    def run(self, statement: str, parameters: dict | None = None) -> Result:
        parameters = parameters or {}
        self.seen.append(statement)

        if statement == queries.PACKAGE_VERSIONS:
            if not self.known:
                return Result(["version", "published_at"], [], 0.0)
            return Result(["version", "published_at"], [[EVIL, LIVE_FROM]], 0.0)

        if statement == queries.INCIDENT_DIRECT_USERS:
            return Result(
                ["service", "captured_at", "version", "version_published", "direct", "dev"],
                [["batch-job", BATCH_SNAPSHOT, EVIL, LIVE_FROM, True, False]],
                0.0,
            )

        if statement.startswith("\nMATCH (p:Pkg {name: $name})<-[:OF]-(bad:Ver)<-[:DEPENDS"):
            # INCIDENT_REACHED_AT, one hop count at a time: the web app is two
            # hops away, so every other depth must come back empty.
            if "*2..2" in statement:
                return Result(
                    ["service", "captured_at", "version", "entry_point", "direct", "dev"],
                    [["web-app", WEB_SNAPSHOT, EVIL, "web-app@1.0.0", True, False]],
                    0.0,
                )
            return Result(
                ["service", "captured_at", "version", "entry_point", "direct", "dev"], [], 0.0
            )

        if statement == queries.INCIDENT_ADVISORIES:
            return Result(
                ["advisory", "kind", "severity", "has_fix", "disclosed_at", "introduced",
                 "fixed", "version", "version_published"],
                [["MAL-2026-1", "malicious", "UNKNOWN", False, DISCLOSED, "1.2.3", "",
                  EVIL, LIVE_FROM]],
                0.0,
            )

        if statement == queries.SHARED_MAINTAINERS:
            return Result(
                ["login", "package_count", "package", "downloads"],
                [["someone", 3, "evil", 10], ["someone", 3, "other-thing", 5_000_000]],
                0.0,
            )

        if statement == queries.MAINTAINER_REACH_BY_LOGIN:
            return Result(
                ["service", "package", "version", "direct"],
                [["batch-job", "other-thing", "other-thing@1.0.0", True]],
                0.0,
            )

        if statement == queries.TYPOSQUAT_NEIGHBOURS_BY_NAME:
            return Result(
                ["looks_like", "distance", "downloads_ratio", "target_downloads"],
                [["eval", 1, 0.000002, 5_000_000]],
                0.0,
            )

        if statement == queries.LOOKALIKES_OF:
            return Result(
                ["suspect", "distance", "downloads_ratio", "suspect_downloads"], [], 0.0
            )

        if statement.startswith("\nCALL algo.MSpaths"):
            return Result(["path"], [[_chain()]], 0.0)

        raise AssertionError(f"the fake was not taught this statement:\n{statement}")


def answers(report):
    return {answer.number: answer for answer in report.answers}


def test_unknown_package_is_not_an_all_clear():
    """A name absent from the graph must raise, not report zero exposure."""
    with pytest.raises(UnknownPackage):
        investigate(FakeClient(known=False), "never-heard-of-it")


def test_question_one_finds_both_the_direct_pin_and_the_transitive_one():
    answer = answers(investigate(FakeClient(), "evil"))[1]
    reached = {row["service"]: row["depth"] for row in answer.rows}
    assert reached == {"batch-job": 0, "web-app": 2}
    assert "batch-job" in answer.summary and "web-app" in answer.summary


def test_question_two_reports_the_range_and_that_there_is_no_fix():
    answer = answers(investigate(FakeClient(), "evil"))[2]
    row = answer.rows[0]
    assert row["introduced"] == "1.2.3"
    assert row["fixed"] == "" and row["has_fix"] is False
    assert row["first_affected_published"] == "2026-01-01"
    assert row["disclosed_at"] == "2026-03-01"


def test_question_three_separates_the_snapshot_inside_the_window_from_the_one_before_it():
    """The heart of it: two apps, same package, different answers."""
    answer = answers(investigate(FakeClient(), "evil"))[3]
    verdicts = {row["service"]: row["verdict"] for row in answer.rows}
    assert verdicts["web-app"].startswith("yes")
    assert "before anyone disclosed it" in verdicts["web-app"]
    assert verdicts["batch-job"].startswith("no")
    assert "predates" in verdicts["batch-job"]
    assert "1 application" in answer.summary


def test_question_three_abstains_when_the_snapshot_date_is_unknown():
    """A missing capture date is reported as unknown, never as a hit."""
    client = FakeClient()
    original = client.run

    def blank_capture(statement, parameters=None):
        result = original(statement, parameters)
        if statement == queries.INCIDENT_DIRECT_USERS:
            return Result(result.columns, [["batch-job", 0, EVIL, LIVE_FROM, True, False]], 0.0)
        return result

    client.run = blank_capture  # type: ignore[method-assign]
    answer = answers(investigate(client, "evil"))[3]
    verdict = next(row["verdict"] for row in answer.rows if row["service"] == "batch-job")
    assert verdict.startswith("unknown")


def test_question_four_reports_what_else_the_publisher_owns():
    answer = answers(investigate(FakeClient(), "evil"))[4]
    row = answer.rows[0]
    assert row["login"] == "someone"
    assert row["examples"] == ["other-thing"]
    assert row["services_reachable"] == ["batch-job"]


def test_question_five_reads_both_directions_of_the_similar_edge():
    answer = answers(investigate(FakeClient(), "evil"))[5]
    assert [row["relation"] for row in answer.rows] == ["this name impersonates"]
    assert answer.rows[0]["other"] == "eval"


def test_question_six_returns_the_chain_not_just_a_count():
    answer = answers(investigate(FakeClient(), "evil"))[6]
    assert answer.rows[0]["chain"] == "evil@1.2.3 -> helper@2.0.0 -> web-app@1.0.0"
    assert answer.rows[0]["hops"] == 2
    assert "2 service(s)" in answer.summary


def test_every_answer_carries_the_statements_it_ran():
    """The artifact has to show the query, or the answer cannot be checked."""
    report = investigate(FakeClient(), "evil")
    assert len(report.answers) == 6
    for answer in report.answers:
        assert answer.statements, f"answer {answer.number} recorded no statement"
        assert all("MATCH" in text or "CALL" in text for text in answer.statements)
    payload = report.as_dict()
    assert payload["package"] == "evil"
    assert [entry["number"] for entry in payload["answers"]] == [1, 2, 3, 4, 5, 6]
