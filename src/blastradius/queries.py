"""The six questions the product answers, as HydraDB queries.

Every statement here obeys two constraints that were read out of the HydraDB
source rather than guessed at, because both of them change the schema:

1. ``WHERE`` has no ``IN``, so a set of candidates is never filtered in Cypher.
   Fan-out selection happens in the native path procedures, which take a list.
2. ``algo.MSpaths`` resolves ``sourceValues``/``targetValues`` through the
   **string** vertex-property index (``VertexPropertyValue::String`` in
   ``shard/path_procedure.rs``). Integer ids are unusable as selectors, which is
   why every node carries a string handle: ``Ver.key``, ``Pkg.name``,
   ``Maint.login``, ``Adv.osv``, ``Svc.name``. Property indexes are written
   automatically on upsert, so no index DDL is needed.

``maxLen`` cannot exceed the server's ``max_traversal_hops`` (16 by default),
so every traversal below is explicitly bounded well under that.

Variable-length hop bounds are read straight off the AST as integer literals
against an *empty* parameter map (``lower_hop_range`` in ``query/opencypher.rs``),
so ``[:DEPENDS*1..$max_len]`` cannot work. Those bounds are formatted into the
query text from a range-checked ``int``, never from user input.

None of these have been executed yet: the sandbox cannot run HydraDB, so
`blastradius.cli verify` is what proves them, in CI, against a real node.
Until that run is green these are unverified drafts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .hydra import HydraClient, Path, paths_from

# --------------------------------------------------------------------------
# 1. Direct hits: which pinned versions are named by an advisory?
# --------------------------------------------------------------------------

DIRECT_HITS = """
MATCH (s:Svc {id: $service_id})-[u:USES]->(v:Ver)<-[a:AFFECTS]-(adv:Adv)
RETURN v.key AS version, adv.osv AS advisory, adv.kind AS kind,
       adv.severity AS severity, adv.published_at AS advisory_published,
       v.published_at AS version_published, adv.has_fix AS has_fix,
       u.direct AS direct, u.dev AS dev
"""

# --------------------------------------------------------------------------
# 2. Blast radius: the actual dependency chains from a bad version to us.
#    This is the query a lockfile scanner cannot answer - it reports "you have
#    it", never "here is the chain that drags it in".
# --------------------------------------------------------------------------

BLAST_RADIUS = """
CALL algo.MSpaths({
  sourceLabel: 'Ver', sourceProperty: 'key', sourceValues: $bad_keys,
  targetLabel: 'Ver', targetProperty: 'key', targetValues: $service_keys,
  relTypes: ['DEPENDS'], relDirection: 'incoming',
  maxLen: $max_len, pathCount: $path_count, resultLimit: $result_limit
}) YIELD path RETURN path
"""

# --------------------------------------------------------------------------
# 3. Depth profile: how deep in the tree the exposure sits. "Direct dependency"
#    and "six levels down under three transitive owners" are different problems.
# --------------------------------------------------------------------------

DEPTH_AT = """
MATCH (s:Svc {id: $service_id})-[:USES]->(:Ver)-[:DEPENDS*%d..%d]->(dep:Ver)<-[:AFFECTS]-(adv:Adv)
RETURN count(adv) AS hits
"""

# --------------------------------------------------------------------------
# 4. Maintainer pivot: if one npm account is taken over, what reaches us?
#    Ownership is an edge, so this is one traversal - in a lockfile scanner it
#    is not a question you can ask at all.
# --------------------------------------------------------------------------

MAINTAINER_REACH = """
MATCH (m:Maint {id: $maintainer_id})-[:MAINTAINS]->(p:Pkg)<-[:OF]-(v:Ver)<-[u:USES]-(s:Svc)
RETURN s.name AS service, p.name AS package, v.key AS version,
       u.direct AS direct, count(v) AS versions
"""

MAINTAINER_FOOTPRINT = """
MATCH (m:Maint {id: $maintainer_id})-[:MAINTAINS]->(p:Pkg)
RETURN count(p) AS packages, sum(p.version_count) AS versions
"""

# --------------------------------------------------------------------------
# 5. Exposure window: not "am I vulnerable" but "since when, and for how long".
#    Both timestamps are epoch seconds on the nodes, so the arithmetic is done
#    in the query, not after it.
# --------------------------------------------------------------------------

EXPOSURE_WINDOW = """
MATCH (s:Svc {id: $service_id})-[:USES]->(v:Ver)<-[a:AFFECTS]-(adv:Adv)
RETURN v.key AS version, adv.osv AS advisory, adv.kind AS kind,
       adv.published_at AS disclosed_at, v.published_at AS pinned_version_published,
       s.captured_at AS captured_at
"""

# --------------------------------------------------------------------------
# 6. Choke points: the versions that the most paths run through. Patch these
#    and the most exposure disappears - a ranking a flat list cannot produce.
# --------------------------------------------------------------------------

CHOKE_POINTS = """
MATCH (s:Svc {id: $service_id})-[:USES]->(entry:Ver)-[:DEPENDS*1..%d]->(mid:Ver)
RETURN mid.key AS version, count(entry) AS reached_through
"""

SERVICE_ENTRY_POINTS = """
MATCH (s:Svc {id: $service_id})-[u:USES {direct: true}]->(v:Ver)
RETURN v.key AS version
"""

TYPOSQUAT_NEIGHBOURS = """
MATCH (p:Pkg {id: $package_id})-[r:SIMILAR]->(other:Pkg)
RETURN other.name AS candidate, r.distance AS distance,
       r.downloads_ratio AS downloads_ratio
"""

MAX_TRAVERSAL_HOPS = 16  # server default for max_traversal_hops

COUNT_BY_LABEL = "MATCH (n:%s) RETURN count(n) AS total"
COUNT_BY_EDGE = "MATCH ()-[r:%s]->() RETURN count(r) AS total"


# --------------------------------------------------------------------------
# Python side
# --------------------------------------------------------------------------


def known_time(value: object) -> int | None:
    """0 is the ingest's "unknown timestamp" sentinel, since properties cannot be
    null. Turning it back into ``None`` here keeps every date calculation honest
    instead of quietly reporting exposure since 1970."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value or None


@dataclass
class Hit:
    """One advisory landing on one pinned version."""

    version: str
    advisory: str
    kind: str
    severity: str
    direct: bool
    dev: bool
    disclosed_at: int | None
    version_published: int | None
    has_fix: bool

    @property
    def is_malicious(self) -> bool:
        return self.kind == "malicious"


@dataclass
class Chain:
    """A dependency chain from something bad to something we ship."""

    keys: list[str]
    hops: int
    requirement_at_root: str | None = None

    @classmethod
    def from_path(cls, path: Path) -> "Chain":
        keys = [node.properties.get("key") or str(node.id) for node in path.nodes]
        requirement = None
        if path.relationships:
            requirement = path.relationships[0].properties.get("requirement")
        return cls(keys=keys, hops=path.hops, requirement_at_root=requirement)

    def render(self) -> str:
        return " -> ".join(self.keys)


@dataclass
class ServiceReport:
    service: str
    hits: list[Hit] = field(default_factory=list)
    chains: list[Chain] = field(default_factory=list)
    choke_points: list[dict[str, Any]] = field(default_factory=list)
    depth_profile: dict[int, int] = field(default_factory=dict)
    timings_ms: dict[str, float] = field(default_factory=dict)

    @property
    def malicious_hits(self) -> list[Hit]:
        return [hit for hit in self.hits if hit.is_malicious]

    @property
    def unfixable_hits(self) -> list[Hit]:
        """Hits with nowhere to upgrade to - the argument for the product."""
        return [hit for hit in self.hits if not hit.has_fix]


def direct_hits(client: HydraClient, service_id: int) -> list[Hit]:
    result = client.run(DIRECT_HITS, {"service_id": service_id})
    return [
        Hit(
            version=row["version"],
            advisory=row["advisory"],
            kind=row.get("kind") or "unknown",
            severity=row.get("severity") or "UNKNOWN",
            direct=bool(row.get("direct")),
            dev=bool(row.get("dev")),
            disclosed_at=known_time(row.get("advisory_published")),
            version_published=known_time(row.get("version_published")),
            has_fix=bool(row.get("has_fix")),
        )
        for row in result.dicts()
    ]


def blast_radius(
    client: HydraClient,
    bad_keys: list[str],
    service_keys: list[str],
    *,
    max_len: int = 8,
    path_count: int = 3,
    result_limit: int = 500,
) -> list[Chain]:
    """Enumerate the chains that drag ``bad_keys`` into ``service_keys``."""
    if not bad_keys or not service_keys:
        return []
    result = client.run(
        BLAST_RADIUS,
        {
            "bad_keys": bad_keys,
            "service_keys": service_keys,
            "max_len": max_len,
            "path_count": path_count,
            "result_limit": result_limit,
        },
    )
    return [Chain.from_path(path) for path in paths_from(result)]


def entry_points(client: HydraClient, service_id: int) -> list[str]:
    """The service's direct dependencies - the roots every chain starts from."""
    return [
        row["version"]
        for row in client.run(SERVICE_ENTRY_POINTS, {"service_id": service_id}).dicts()
        if row.get("version")
    ]


def maintainer_reach(client: HydraClient, maintainer_id: int) -> list[dict[str, Any]]:
    return client.run(MAINTAINER_REACH, {"maintainer_id": maintainer_id}).dicts()


def exposure_windows(client: HydraClient, service_id: int) -> list[dict[str, Any]]:
    """Days between disclosure and the snapshot, per hit."""
    rows = client.run(EXPOSURE_WINDOW, {"service_id": service_id}).dicts()
    for row in rows:
        disclosed = known_time(row.get("disclosed_at"))
        captured = known_time(row.get("captured_at"))
        row["disclosed_at"] = disclosed
        row["exposed_days"] = (
            round((captured - disclosed) / 86400, 1)
            if isinstance(disclosed, int) and isinstance(captured, int) and captured > disclosed
            else None
        )
    return sorted(
        rows,
        key=lambda row: (row["exposed_days"] is None, -(row["exposed_days"] or 0)),
    )


def _hop_bound(value: int) -> int:
    """Hop bounds are literals in the query text, so they are checked here."""
    bound = int(value)
    if not 1 <= bound <= MAX_TRAVERSAL_HOPS:
        raise ValueError(f"hop bound must be 1..{MAX_TRAVERSAL_HOPS}, got {value}")
    return bound


def depth_profile(client: HydraClient, service_id: int, *, max_len: int = 6) -> dict[int, int]:
    """How many advisory hits sit at each depth: 1 hop out, 2 hops out, ...

    Asked one depth at a time because the hop range has to be a literal, which
    also keeps each query cheap and separately timeable.
    """
    profile: dict[int, int] = {}
    for depth in range(1, _hop_bound(max_len) + 1):
        result = client.run(DEPTH_AT % (depth, depth), {"service_id": service_id})
        profile[depth] = int(result.scalar() or 0)
    return profile


def choke_points(
    client: HydraClient, service_id: int, *, max_len: int = 6, top: int = 15
) -> list[dict[str, Any]]:
    rows = client.run(CHOKE_POINTS % _hop_bound(max_len), {"service_id": service_id}).dicts()
    return sorted(rows, key=lambda row: -(row.get("reached_through") or 0))[:top]


def graph_size(client: HydraClient) -> dict[str, int]:
    """Node and edge counts, used as the ingest receipt."""
    from .model import EDGE_TYPES, LABELS

    sizes: dict[str, int] = {}
    for label in LABELS:
        sizes[label] = int(client.run(COUNT_BY_LABEL % label).scalar() or 0)
    for edge in EDGE_TYPES:
        sizes[edge] = int(client.run(COUNT_BY_EDGE % edge).scalar() or 0)
    return sizes
