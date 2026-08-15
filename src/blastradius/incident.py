"""One package was just called malicious. Answer the six questions.

The track states them as the questions a defender has to answer when a package
is compromised, and this module answers each one with a query that runs against
the graph, in the order a responder would ask them:

1. Which internal services are transitively exposed?
2. Which version of the dependency introduced the vulnerability?
3. Which applications resolved the compromised version while it was live?
4. Which other packages share maintainers or infrastructure with it?
5. Are there likely typosquat packages nearby?
6. What is the complete blast radius?

Everything else in this project reads the graph from a service we own outwards.
This reads it from a name we do not own inwards, which is the direction the
question actually arrives in: at 09:00 someone posts a package name, and the
answer is needed before 09:06. Each answer records the statements it ran and how
long they took, so the claim "this takes seconds" is a measurement in the
artifact rather than a sentence in a README.

Nothing here is derived from a second system: the dependency edges, ownership,
timestamps and lookalike edges are all in HydraDB, so every answer below is a
traversal.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from . import queries
from .hydra import HydraClient
from .queries import known_time

#: The questions, quoted from the track description they come from.
QUESTIONS = (
    "Which internal services are transitively exposed?",
    "Which version of the dependency introduced the vulnerability?",
    "Which applications resolved the compromised version while it was live?",
    "Which other packages share maintainers or infrastructure with it?",
    "Are there likely typosquat packages nearby?",
    "What is the complete blast radius?",
)

DAY = 86_400


class UnknownPackage(LookupError):
    """The name is not in the graph, which is an answer, not an empty result."""


@dataclass
class Answer:
    number: int
    question: str
    statements: list[str]
    summary: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    ms: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "question": self.question,
            "summary": self.summary,
            "statements": self.statements,
            "rows": self.rows,
            "ms": round(self.ms, 1),
        }


@dataclass
class Incident:
    package: str
    answers: list[Answer] = field(default_factory=list)
    seconds: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "seconds": round(self.seconds, 2),
            "answers": [answer.as_dict() for answer in self.answers],
        }

    def render(self) -> str:
        lines = [f"incident: {self.package}"]
        for answer in self.answers:
            lines.append("")
            lines.append(f"{answer.number}. {answer.question}")
            lines.append(f"   {answer.summary}   [{answer.ms:.0f} ms]")
            for row in answer.rows[:8]:
                lines.append("     " + _render_row(row))
            if len(answer.rows) > 8:
                lines.append(f"     ... {len(answer.rows) - 8} more in the artifact")
        lines.append("")
        lines.append(f"answered in {self.seconds:.1f}s")
        return "\n".join(lines)


def _render_row(row: dict[str, Any]) -> str:
    return "  ".join(f"{key}={value}" for key, value in row.items() if value not in (None, ""))


def _timed(client: HydraClient, statement: str, parameters: dict | None = None):
    started = time.perf_counter()
    rows = client.run(statement, parameters or {}).dicts()
    return rows, (time.perf_counter() - started) * 1000


def _versions(client: HydraClient, package: str) -> list[dict[str, Any]]:
    return client.run(queries.PACKAGE_VERSIONS, {"name": package}).dicts()


def _iso(stamp: int | None) -> str | None:
    if not stamp:
        return None
    return time.strftime("%Y-%m-%d", time.gmtime(stamp))


# -- question 1 -------------------------------------------------------------


def exposed_services(
    client: HydraClient, package: str, *, max_depth: int = 6
) -> tuple[Answer, list[dict[str, Any]], list[queries.Chain]]:
    """Every service that ships this package, and how far down it sits.

    *Who* is exposed needs no traversal: a lockfile is the fully resolved tree,
    so a service that gets the package six levels down still has a USES edge to
    that exact pinned version. One statement therefore answers the question
    completely - and, unlike a reverse closure, it cannot miss a service because
    a hop limit was too small.

    *How* it gets in is the traversal, and it runs against the arrow direction
    (from the compromised version up to a direct dependency), which only the path
    procedures can do - see the note in ``queries``. The shortest chain to one of
    the service's own direct dependencies is its depth: 0 means the service pins
    the package itself, 3 means it is three levels under something it chose.
    """
    statements = [queries.INCIDENT_DIRECT_USERS]
    pinned, total_ms = _timed(client, queries.INCIDENT_DIRECT_USERS, {"name": package})

    found: dict[tuple[str, str], dict[str, Any]] = {}
    service_ids: dict[str, int] = {}
    for row in pinned:
        service = row["service"]
        if isinstance(row.get("service_id"), int):
            service_ids[service] = int(row["service_id"])
        found[(service, row["version"])] = {
            "service": service,
            "version": row["version"],
            "depth": 0 if row.get("direct") else None,
            "entry_point": row["version"] if row.get("direct") else None,
            "direct": bool(row.get("direct")),
            "dev": bool(row.get("dev")),
            "captured_at": known_time(row.get("captured_at")),
        }

    # The direct dependencies of every exposed service: the chains have to end
    # somewhere the service actually chose, not at an arbitrary pinned version.
    entry_owners: dict[str, set[str]] = {}
    if any(entry["depth"] is None for entry in found.values()):
        statements.append(queries.SERVICE_ENTRY_POINTS)
        for service, service_id in sorted(service_ids.items()):
            started = time.perf_counter()
            for key in queries.entry_points(client, service_id):
                entry_owners.setdefault(key, set()).add(service)
            total_ms += (time.perf_counter() - started) * 1000

    bad_keys = sorted({row["version"] for row in found.values()})
    chains: list[queries.Chain] = []
    if entry_owners and bad_keys:
        statements.append(queries.BLAST_RADIUS)
        started = time.perf_counter()
        chains = queries.blast_radius(
            client, bad_keys, sorted(entry_owners), max_len=max_depth
        )
        total_ms += (time.perf_counter() - started) * 1000

    for chain in chains:
        if len(chain.keys) < 2:
            continue
        bad, entry = chain.keys[0], chain.keys[-1]
        for service in entry_owners.get(entry, ()):
            row = found.get((service, bad))
            if row is None:  # a chain into a service that does not pin it
                continue
            if row["depth"] is None or chain.hops < row["depth"]:
                row["depth"] = chain.hops
                row["entry_point"] = entry

    rows = sorted(
        found.values(),
        key=lambda row: (row["depth"] is None, row["depth"] or 0, row["service"], row["version"]),
    )
    services = sorted({row["service"] for row in rows})
    unexplained = [row for row in rows if row["depth"] is None]
    if rows:
        deepest = max((row["depth"] for row in rows if row["depth"] is not None), default=0)
        summary = (
            f"{len(services)} service(s) exposed: {', '.join(services)}"
            f" — {len(rows)} pinned version(s), reached at up to {deepest} hop(s)"
        )
        if unexplained:
            # Honest about the limit rather than quietly calling them direct:
            # the lockfile proves they ship it, the graph has no chain within
            # max_depth hops that explains why.
            summary += (
                f"; {len(unexplained)} of them with no chain inside {max_depth} hops"
            )
    else:
        summary = "no service in this graph ships it, directly or transitively"
    return Answer(1, QUESTIONS[0], statements, summary, rows, total_ms), rows, chains


# -- question 2 -------------------------------------------------------------


def offending_versions(client: HydraClient, package: str) -> tuple[Answer, list[dict[str, Any]]]:
    """Which release started it, which release ends it, and when each happened.

    ``introduced``/``fixed`` are the advisory's own range boundaries, carried on
    the AFFECTS edge; the publication dates come from the version nodes, so the
    window below is read out of the graph rather than recomputed.
    """
    advisories, ms = _timed(client, queries.INCIDENT_ADVISORIES, {"name": package})
    published = {row["version"]: known_time(row.get("published_at")) for row in _versions(client, package)}
    grouped: dict[str, dict[str, Any]] = {}
    for row in advisories:
        entry = grouped.setdefault(
            row["advisory"],
            {
                "advisory": row["advisory"],
                "kind": row.get("kind"),
                "severity": row.get("severity"),
                "introduced": row.get("introduced") or "0",
                "fixed": row.get("fixed") or "",
                "has_fix": bool(row.get("has_fix")),
                "disclosed_at": _iso(known_time(row.get("disclosed_at"))),
                "affected_versions": [],
            },
        )
        entry["affected_versions"].append(row["version"])
    rows = []
    for entry in grouped.values():
        affected = sorted(set(entry["affected_versions"]))
        entry["affected_versions"] = affected
        first = affected[0] if affected else None
        entry["affected_in_graph"] = len(affected)
        entry["first_affected_version"] = first
        entry["first_affected_published"] = _iso(published.get(first)) if first else None
        entry["fix_published"] = _iso(published.get(f"{package}@{entry['fixed']}")) if entry["fixed"] else None
        rows.append(entry)
    rows.sort(key=lambda row: (row["kind"] != "malicious", row["advisory"]))
    if rows:
        first = rows[0]
        fix = f"fixed in {first['fixed']}" if first["fixed"] else "no fixed version exists"
        summary = (
            f"{len(rows)} advisory/advisories; {first['advisory']} covers "
            f"{first['introduced']} onwards ({fix})"
        )
    else:
        summary = "no advisory in this graph names any version of it"
    return Answer(2, QUESTIONS[1], [queries.INCIDENT_ADVISORIES, queries.PACKAGE_VERSIONS],
                  summary, rows, ms), rows


# -- question 3 -------------------------------------------------------------


def resolved_while_live(
    package: str, exposure: list[dict[str, Any]], advisories: list[dict[str, Any]],
    version_published: dict[str, int | None],
) -> Answer:
    """Was each app's snapshot taken inside the window the bad version was live?

    The window opens when the affected version was published and closes when a
    fixed version was published - or stays open when there is no fix, which is
    the normal case for malware. An app whose lockfile was captured inside that
    window shipped the compromised release while it was live, and if the capture
    predates disclosure it did so before anyone had said a word.

    A service whose snapshot date is unknown is reported as unknown. Guessing
    "today" here would turn every app into a victim.
    """
    affected_by: dict[str, list[dict[str, Any]]] = {}
    for advisory in advisories:
        for version in advisory.get("affected_versions", ()):
            affected_by.setdefault(version, []).append(advisory)

    rows: list[dict[str, Any]] = []
    for row in exposure:
        if not row["version"].startswith(f"{package}@"):
            continue
        captured = row.get("captured_at")
        for advisory in affected_by.get(row["version"], []):
            opened = version_published.get(row["version"])
            closed = None
            if advisory.get("fixed"):
                closed = version_published.get(f"{package}@{advisory['fixed']}")
            disclosed = advisory.get("disclosed_at")
            entry = {
                "service": row["service"],
                "version": row["version"],
                "advisory": advisory["advisory"],
                "snapshot": _iso(captured),
                "version_live_from": _iso(opened),
                "version_live_until": _iso(closed) or ("still live" if not advisory["has_fix"] else None),
                "disclosed": disclosed,
            }
            if captured is None or opened is None:
                entry["verdict"] = "unknown: no snapshot date" if captured is None else \
                    "unknown: no publication date for the affected version"
            elif captured < opened:
                entry["verdict"] = "no: the snapshot predates the affected release"
            elif closed is not None and captured >= closed:
                entry["verdict"] = "no: a fixed version was already available"
            else:
                days = round((captured - opened) / DAY, 1)
                blind = (
                    disclosed is not None
                    and _iso(captured) is not None
                    and _iso(captured) < disclosed
                )
                entry["verdict"] = (
                    f"yes: shipping it {days} days after it went live"
                    + (", before anyone disclosed it" if blind else "")
                )
                entry["days_live_at_snapshot"] = days
            rows.append(entry)

    rows.sort(key=lambda row: (not row["verdict"].startswith("yes"), row["service"]))
    hits = [row for row in rows if row["verdict"].startswith("yes")]
    blind = [row for row in hits if "before anyone disclosed it" in row["verdict"]]
    if hits:
        summary = (
            f"{len({row['service'] for row in hits})} application(s) resolved it while it was live"
            + (f", {len(blind)} of them before disclosure" if blind else "")
        )
    elif rows:
        summary = "every snapshot falls outside the live window"
    else:
        summary = "no application in this graph pins an affected version of it"
    return Answer(3, QUESTIONS[2], [queries.INCIDENT_DIRECT_USERS, queries.PACKAGE_VERSIONS],
                  summary, rows, 0.0)


# -- question 4 -------------------------------------------------------------


def shared_maintainers(client: HydraClient, package: str) -> Answer:
    """Who else can publish, and what else they own.

    Ownership is an edge, so "the same npm account also publishes these" is one
    traversal. A lockfile scanner cannot answer this at all: the relationship
    does not exist in a lockfile.
    """
    rows, ms = _timed(client, queries.SHARED_MAINTAINERS, {"name": package})
    by_login: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = by_login.setdefault(
            row["login"],
            {"login": row["login"], "packages_in_graph": [], "package_count": row.get("package_count")},
        )
        if row["package"] != package:
            entry["packages_in_graph"].append(row["package"])

    reach_ms = 0.0
    out: list[dict[str, Any]] = []
    for entry in sorted(by_login.values(), key=lambda item: -len(item["packages_in_graph"])):
        reach, ms_one = _timed(client, queries.MAINTAINER_REACH_BY_LOGIN, {"login": entry["login"]})
        reach_ms += ms_one
        others = sorted(set(entry["packages_in_graph"]))
        out.append({
            "login": entry["login"],
            "also_publishes_in_graph": len(others),
            "examples": others[:6],
            "packages_in_graph_total": entry["package_count"],
            "services_reachable": sorted({row["service"] for row in reach}),
        })
    if out:
        widest = out[0]
        summary = (
            f"{len(out)} npm account(s) can publish it; {widest['login']} also publishes "
            f"{widest['also_publishes_in_graph']} other package(s) in this graph"
        )
    else:
        summary = "no maintainer is recorded for it in this graph"
    return Answer(4, QUESTIONS[3], [queries.SHARED_MAINTAINERS, queries.MAINTAINER_REACH_BY_LOGIN],
                  summary, out, ms + reach_ms)


# -- question 5 -------------------------------------------------------------


def nearby_lookalikes(client: HydraClient, package: str) -> Answer:
    """Names close enough to be confused with this one, in both directions."""
    impersonates, ms_out = _timed(client, queries.TYPOSQUAT_NEIGHBOURS_BY_NAME, {"name": package})
    impersonated_by, ms_in = _timed(client, queries.LOOKALIKES_OF, {"name": package})
    rows = [
        {
            "relation": "this name impersonates",
            "other": row["looks_like"],
            "edit_distance": row.get("distance"),
            "downloads_ratio": row.get("downloads_ratio"),
            "other_downloads": row.get("target_downloads"),
        }
        for row in impersonates
    ] + [
        {
            "relation": "impersonated by",
            "other": row["suspect"],
            "edit_distance": row.get("distance"),
            "downloads_ratio": row.get("downloads_ratio"),
            "other_downloads": row.get("suspect_downloads"),
        }
        for row in impersonated_by
    ]
    if rows:
        summary = (
            f"{len(impersonates)} name(s) this one impersonates, "
            f"{len(impersonated_by)} name(s) impersonating it"
        )
    else:
        summary = "no lookalike name for it in this graph"
    return Answer(5, QUESTIONS[4],
                  [queries.TYPOSQUAT_NEIGHBOURS_BY_NAME, queries.LOOKALIKES_OF],
                  summary, rows, ms_out + ms_in)


# -- question 6 -------------------------------------------------------------


def complete_blast_radius(
    package: str, exposure: list[dict[str, Any]], chains: list[queries.Chain]
) -> Answer:
    """Every chain from a bad version of this package to something we deploy.

    Questions 1 and 3 say *who* and *when*; this says *how*, which is what a
    responder has to act on: the chain names the intermediate package to pin, or
    the direct dependency to drop. The chains are the ones question 1 already
    walked - re-running the traversal here would double the cost of the report
    and could disagree with it.
    """
    ms = 0.0
    rows = [{"hops": chain.hops, "chain": chain.render()} for chain in chains]
    rows.sort(key=lambda row: (-row["hops"], row["chain"]))
    services = sorted({row["service"] for row in exposure})
    direct = [row for row in exposure if row["depth"] == 0]
    if exposure:
        summary = (
            f"{len(services)} service(s), {len(exposure)} pinned version(s), "
            f"{len(direct)} of them pinned directly, {len(rows)} dependency chain(s)"
        )
    else:
        summary = "nothing in this graph reaches it"
    return Answer(6, QUESTIONS[5], [queries.BLAST_RADIUS], summary, rows, ms)


# -- the whole thing --------------------------------------------------------


def investigate(client: HydraClient, package: str, *, max_depth: int = 6) -> Incident:
    """Answer all six, in order, against a live graph."""
    started = time.perf_counter()
    versions = _versions(client, package)
    if not versions:
        raise UnknownPackage(package)
    published = {row["version"]: known_time(row.get("published_at")) for row in versions}

    answer_one, exposure, chains = exposed_services(client, package, max_depth=max_depth)
    answer_two, advisories = offending_versions(client, package)
    answer_three = resolved_while_live(package, exposure, advisories, published)
    answers = [
        answer_one,
        answer_two,
        answer_three,
        shared_maintainers(client, package),
        nearby_lookalikes(client, package),
        complete_blast_radius(package, exposure, chains),
    ]
    return Incident(package=package, answers=answers, seconds=time.perf_counter() - started)
