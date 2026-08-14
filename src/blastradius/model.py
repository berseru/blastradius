"""The graph schema, and the exact Cypher that writes it.

Every statement here is written against the subset HydraDB actually accepts,
which is narrower than OpenCypher and shapes the model more than any design
preference does:

* nodes are matched on an **integer id**, so names never appear in a pattern;
* a vertex upsert must be ``MERGE`` by id followed by ``SET``;
* one relationship pattern per batch, single hop, directed;
* ``WHERE`` has no ``IN``, so fan-out selection happens through the native path
  procedures rather than through a list predicate.

Shape
-----

    (Svc)  -[:USES {direct, dev}]->        (Ver)
    (Ver)  -[:DEPENDS {requirement}]->     (Ver)
    (Ver)  -[:OF]->                        (Pkg)
    (Maint)-[:MAINTAINS]->                 (Pkg)
    (Adv)  -[:AFFECTS {introduced, fixed}]->(Ver)
    (Pkg)  -[:SIMILAR {distance}]->        (Pkg)

``Ver.published_at`` and ``Adv.published_at`` are epoch seconds, which is what
turns "are we exposed" into "were we exposed, and for how long".
Property values are scalars only — HydraDB has no list-valued properties — so
anything list-shaped is stored as a count and the members live as edges.
"""

from __future__ import annotations

# -- vertex upserts --------------------------------------------------------

UPSERT_PACKAGES = """
UNWIND $rows AS row
MERGE (n {id: row.id})
SET n:Pkg, n.name = row.name, n.version_count = row.version_count,
    n.first_published = row.first_published, n.downloads = row.downloads
"""

UPSERT_VERSIONS = """
UNWIND $rows AS row
MERGE (n {id: row.id})
SET n:Ver, n.key = row.key, n.name = row.name, n.version = row.version,
    n.published_at = row.published_at, n.deprecated = row.deprecated
"""

UPSERT_MAINTAINERS = """
UNWIND $rows AS row
MERGE (n {id: row.id})
SET n:Maint, n.login = row.login, n.package_count = row.package_count
"""

UPSERT_ADVISORIES = """
UNWIND $rows AS row
MERGE (n {id: row.id})
SET n:Adv, n.osv = row.osv, n.kind = row.kind, n.severity = row.severity,
    n.published_at = row.published_at, n.has_fix = row.has_fix, n.summary = row.summary
"""

UPSERT_SERVICES = """
UNWIND $rows AS row
MERGE (n {id: row.id})
SET n:Svc, n.name = row.name, n.pin_count = row.pin_count, n.captured_at = row.captured_at
"""

# -- edges -----------------------------------------------------------------

LINK_VERSION_OF_PACKAGE = """
UNWIND $rows AS row
MATCH (v:Ver {id: row.version_id}), (p:Pkg {id: row.package_id})
MERGE (v)-[r:OF {id: row.edge_id}]->(p)
SET r.name = row.name
"""

LINK_DEPENDS = """
UNWIND $rows AS row
MATCH (a:Ver {id: row.from_id}), (b:Ver {id: row.to_id})
MERGE (a)-[r:DEPENDS {id: row.edge_id}]->(b)
SET r.requirement = row.requirement, r.direct = row.direct
"""

LINK_USES = """
UNWIND $rows AS row
MATCH (s:Svc {id: row.service_id}), (v:Ver {id: row.version_id})
MERGE (s)-[r:USES {id: row.edge_id}]->(v)
SET r.direct = row.direct, r.dev = row.dev
"""

LINK_MAINTAINS = """
UNWIND $rows AS row
MATCH (m:Maint {id: row.maintainer_id}), (p:Pkg {id: row.package_id})
MERGE (m)-[r:MAINTAINS {id: row.edge_id}]->(p)
SET r.login = row.login
"""

LINK_AFFECTS = """
UNWIND $rows AS row
MATCH (a:Adv {id: row.advisory_id}), (v:Ver {id: row.version_id})
MERGE (a)-[r:AFFECTS {id: row.edge_id}]->(v)
SET r.introduced = row.introduced, r.fixed = row.fixed, r.kind = row.kind
"""

LINK_SIMILAR = """
UNWIND $rows AS row
MATCH (a:Pkg {id: row.from_id}), (b:Pkg {id: row.to_id})
MERGE (a)-[r:SIMILAR {id: row.edge_id}]->(b)
SET r.distance = row.distance, r.downloads_ratio = row.downloads_ratio
"""

ALL_STATEMENTS = {
    "packages": UPSERT_PACKAGES,
    "versions": UPSERT_VERSIONS,
    "maintainers": UPSERT_MAINTAINERS,
    "advisories": UPSERT_ADVISORIES,
    "services": UPSERT_SERVICES,
    "of": LINK_VERSION_OF_PACKAGE,
    "depends": LINK_DEPENDS,
    "uses": LINK_USES,
    "maintains": LINK_MAINTAINS,
    "affects": LINK_AFFECTS,
    "similar": LINK_SIMILAR,
}

LABELS = ("Pkg", "Ver", "Maint", "Adv", "Svc")
EDGE_TYPES = ("OF", "DEPENDS", "USES", "MAINTAINS", "AFFECTS", "SIMILAR")


KIND_EDGE = 15


def edge_id(source: int, target: int, edge_type: str) -> int:
    """A stable id for a relationship, so ``MERGE`` is genuinely idempotent.

    Relationship ids live in their own space on the server, but they are tagged
    like vertices anyway so a stray id in a result is always self-describing.
    """
    from .ids import make_id

    return make_id(KIND_EDGE, f"{edge_type}:{source}:{target}")
