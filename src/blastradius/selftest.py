"""Exercise every statement in the project against a real node, on 11 vertices.

Why this exists: HydraDB's Cypher subset is narrow, and a rejected statement is
only ever discovered by a server. Before this module the first thing that could
tell us "this query is unsupported" was a full ingest, which fetches a 220 MB
advisory dump first, so one incompatibility cost a whole run and only ever
reported the *first* problem.

The self test writes a tiny synthetic graph with the production statements,
runs every production query against it, checks the answers, and deletes it
again - in a couple of seconds. One run reports every incompatibility at once,
with the server's own error message next to the statement that caused it.

The fixture is a miniature of the real thing:

    selftest-service ─USES(direct)→ selftest-app@1.0.0
                     ─USES→ selftest-lib@2.0.0 ←AFFECTS─ SELFTEST-0001
    selftest-app@1.0.0 ─DEPENDS→ selftest-lib@2.0.0
        ─DEPENDS→ selftest-lib@2.0.1 ←AFFECTS─ SELFTEST-0001
        ─DEPENDS→ selftest-lib-typo@9.9.9 ←AFFECTS─ MAL-SELFTEST-0002
    selftest-maint ─MAINTAINS→ selftest-lib
    selftest-lib ─SIMILAR(distance 1)→ selftest-lib-typo

so it has a direct hit, a three-hop chain, a malicious package, a maintainer
pivot and a typosquat neighbour: one of every shape the product answers.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import model, queries
from .hydra import HydraClient, HydraError, check_row

# Real ids are 62-bit blake2b digests, so these single digits cannot collide
# with ingested data. They are deleted at the end of a run regardless.
PKG_APP, PKG_LIB, PKG_TYPO = 1, 2, 3
VER_APP, VER_LIB, VER_LIB_PATCH, VER_TYPO = 4, 5, 6, 7
MAINT = 8
ADV_VULN, ADV_MAL = 9, 10
SVC = 11
FIXTURE_IDS = (
    PKG_APP, PKG_LIB, PKG_TYPO, VER_APP, VER_LIB, VER_LIB_PATCH, VER_TYPO,
    MAINT, ADV_VULN, ADV_MAL, SVC,
)

APP_KEY = "selftest-app@1.0.0"
LIB_KEY = "selftest-lib@2.0.0"
PATCH_KEY = "selftest-lib@2.0.1"
TYPO_KEY = "selftest-lib-typo@9.9.9"

CLEANUP = "UNWIND $rows AS row MATCH (n {id: row.vertex}) DETACH DELETE n"


def _pkg(identifier: int, name: str, versions: int, downloads: int = 1000) -> dict[str, Any]:
    return {
        "id": identifier, "name": name, "version_count": versions,
        "first_published": 1600000000, "downloads": downloads,
    }


def _ver(identifier: int, key: str, published: int) -> dict[str, Any]:
    name, _, version = key.rpartition("@")
    return {
        "id": identifier, "key": key, "name": name, "version": version,
        "published_at": published, "deprecated": False,
    }


def _of(version_id: int, package_id: int, name: str) -> dict[str, Any]:
    return {
        "version_id": version_id, "package_id": package_id, "name": name,
        "edge_id": model.edge_id(version_id, package_id, "OF"),
    }


def _depends(from_id: int, to_id: int, requirement: str, direct: bool) -> dict[str, Any]:
    return {
        "from_id": from_id, "to_id": to_id, "requirement": requirement, "direct": direct,
        "edge_id": model.edge_id(from_id, to_id, "DEPENDS"),
    }


def fixture_rows() -> dict[str, list[dict[str, Any]]]:
    """Every row the self test writes, keyed by statement name in ``model``."""
    rows: dict[str, list[dict[str, Any]]] = {
        "packages": [
            _pkg(PKG_APP, "selftest-app", 1, downloads=42),
            _pkg(PKG_LIB, "selftest-lib", 2, downloads=1_000_000),
            _pkg(PKG_TYPO, "selftest-lib-typo", 1, downloads=1),
        ],
        "versions": [
            _ver(VER_APP, APP_KEY, 1700000000),
            _ver(VER_LIB, LIB_KEY, 1600000000),
            _ver(VER_LIB_PATCH, PATCH_KEY, 1650000000),
            _ver(VER_TYPO, TYPO_KEY, 1750000000),
        ],
        "maintainers": [{"id": MAINT, "login": "selftest-maint", "package_count": 1}],
        "advisories": [
            {
                "id": ADV_VULN, "osv": "SELFTEST-0001", "kind": "vulnerability",
                "severity": "CRITICAL", "published_at": 1710000000, "has_fix": True,
                "summary": "synthetic advisory used by the self test",
            },
            {
                "id": ADV_MAL, "osv": "MAL-SELFTEST-0002", "kind": "malicious",
                "severity": "UNKNOWN", "published_at": 1755000000, "has_fix": False,
                "summary": "synthetic malicious package used by the self test",
            },
        ],
        "services": [
            {"id": SVC, "name": "selftest-service", "pin_count": 3, "captured_at": 1760000000},
        ],
        "of": [
            _of(VER_APP, PKG_APP, "selftest-app"),
            _of(VER_LIB, PKG_LIB, "selftest-lib"),
            _of(VER_LIB_PATCH, PKG_LIB, "selftest-lib"),
            _of(VER_TYPO, PKG_TYPO, "selftest-lib-typo"),
        ],
        "depends": [
            _depends(VER_APP, VER_LIB, "^2.0.0", True),
            _depends(VER_LIB, VER_LIB_PATCH, "2.0.1", False),
            _depends(VER_LIB_PATCH, VER_TYPO, "9.9.9", False),
        ],
        "uses": [
            {
                "service_id": SVC, "version_id": VER_APP, "direct": True, "dev": False,
                "edge_id": model.edge_id(SVC, VER_APP, "USES"),
            },
            {
                "service_id": SVC, "version_id": VER_LIB, "direct": False, "dev": False,
                "edge_id": model.edge_id(SVC, VER_LIB, "USES"),
            },
            {
                "service_id": SVC, "version_id": VER_TYPO, "direct": False, "dev": False,
                "edge_id": model.edge_id(SVC, VER_TYPO, "USES"),
            },
        ],
        "maintains": [
            {
                "maintainer_id": MAINT, "package_id": PKG_LIB, "login": "selftest-maint",
                "edge_id": model.edge_id(MAINT, PKG_LIB, "MAINTAINS"),
            },
        ],
        "affects": [
            {
                "advisory_id": ADV_VULN, "version_id": VER_LIB, "introduced": "0",
                "fixed": "2.0.2", "kind": "vulnerability",
                "edge_id": model.edge_id(ADV_VULN, VER_LIB, "AFFECTS"),
            },
            {
                "advisory_id": ADV_VULN, "version_id": VER_LIB_PATCH, "introduced": "0",
                "fixed": "2.0.2", "kind": "vulnerability",
                "edge_id": model.edge_id(ADV_VULN, VER_LIB_PATCH, "AFFECTS"),
            },
            {
                "advisory_id": ADV_MAL, "version_id": VER_TYPO, "introduced": "0",
                "fixed": "", "kind": "malicious",
                "edge_id": model.edge_id(ADV_MAL, VER_TYPO, "AFFECTS"),
            },
        ],
        "similar": [
            # Both directions are written on purpose: the ingest emits
            # suspect -> popular, while the neighbour lookup below walks out of
            # the popular package, and a one-way edge would make one of the two
            # queries silently return nothing.
            {
                "from_id": PKG_LIB, "to_id": PKG_TYPO, "distance": 5,
                "downloads_ratio": 0.001,
                "edge_id": model.edge_id(PKG_LIB, PKG_TYPO, "SIMILAR"),
            },
            {
                "from_id": PKG_TYPO, "to_id": PKG_LIB, "distance": 1,
                "downloads_ratio": 0.000001,
                "edge_id": model.edge_id(PKG_TYPO, PKG_LIB, "SIMILAR"),
            },
        ],
    }
    for bucket, batch in rows.items():
        for index, row in enumerate(batch):
            check_row(row, where=f"{bucket}[{index}]")
    return rows


@dataclass
class Check:
    """One statement, and what the server did with it."""

    name: str
    kind: str
    ok: bool = False
    detail: str = ""
    code: str = ""
    ms: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "kind": self.kind, "ok": self.ok,
            "detail": self.detail, "code": self.code, "ms": round(self.ms, 1),
        }


@dataclass
class SelfTestReport:
    checks: list[Check] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def failures(self) -> list[Check]:
        return [check for check in self.checks if not check.ok]

    def as_dict(self) -> dict[str, Any]:
        return {
            "checks": len(self.checks),
            "failed": len(self.failures),
            "seconds": round(self.seconds, 2),
            "results": [check.as_dict() for check in self.checks],
        }

    def render(self) -> str:
        lines = []
        for check in self.checks:
            mark = "ok  " if check.ok else "FAIL"
            lines.append(f"  {mark} {check.kind:<6} {check.name:<22} {check.ms:>7.1f}ms  {check.detail}")
        lines.append(
            f"  {len(self.checks) - len(self.failures)}/{len(self.checks)} checks passed "
            f"in {self.seconds:.1f}s"
        )
        return "\n".join(lines)


def _run_check(report: SelfTestReport, name: str, kind: str, body: Callable[[], str]) -> None:
    """Run one check, recording a rejection or a wrong answer rather than raising."""
    check = Check(name=name, kind=kind)
    started = time.perf_counter()
    try:
        check.detail = body() or ""
        check.ok = True
    except HydraError as error:
        check.code, check.detail = error.code, error.message[:300]
    except AssertionError as error:
        check.code, check.detail = "wrong_result", str(error)[:300]
    except Exception as error:  # noqa: BLE001 - a bug here must still be reported
        check.code, check.detail = type(error).__name__, str(error)[:300]
    check.ms = (time.perf_counter() - started) * 1000
    report.checks.append(check)


def run_selftest(client: HydraClient) -> SelfTestReport:
    """Write the fixture, ask every question, check the answers, clean up."""
    report = SelfTestReport()
    started = time.perf_counter()
    rows = fixture_rows()

    def write(bucket: str) -> Callable[[], str]:
        def body() -> str:
            written = client.batch(model.ALL_STATEMENTS[bucket], rows[bucket])
            assert written == len(rows[bucket]), f"wrote {written} of {len(rows[bucket])}"
            return f"{written} rows"

        return body

    for bucket in ("packages", "versions", "maintainers", "advisories", "services",
                   "of", "depends", "uses", "maintains", "affects", "similar"):
        _run_check(report, bucket, "write", write(bucket))

    def counts() -> str:
        sizes = queries.graph_size(client)
        expected = {
            "Pkg": 3, "Ver": 4, "Maint": 1, "Adv": 2, "Svc": 1,
            "OF": 4, "DEPENDS": 3, "USES": 3, "MAINTAINS": 1, "AFFECTS": 3, "SIMILAR": 2,
        }
        missing = {
            key: (sizes.get(key), value)
            for key, value in expected.items()
            if sizes.get(key, 0) < value
        }
        assert not missing, f"counts below the fixture: {missing}"
        return ", ".join(f"{key}={sizes.get(key)}" for key in expected)

    _run_check(report, "graph_size", "read", counts)

    def direct() -> str:
        hits = queries.direct_hits(client, SVC)
        keys = sorted(hit.version for hit in hits)
        assert LIB_KEY in keys, f"expected {LIB_KEY} among direct hits, got {keys}"
        hit = next(hit for hit in hits if hit.version == LIB_KEY)
        assert hit.severity == "CRITICAL", f"severity came back as {hit.severity!r}"
        assert hit.has_fix is True, "has_fix did not survive the round trip"
        assert hit.disclosed_at == 1710000000, f"disclosed_at came back as {hit.disclosed_at!r}"
        return f"{len(hits)} hits: {keys}"

    _run_check(report, "direct_hits", "read", direct)

    def entries() -> str:
        found = queries.entry_points(client, SVC)
        assert found == [APP_KEY], f"expected only the direct pin, got {found}"
        return str(found)

    _run_check(report, "entry_points", "read", entries)

    def depths() -> str:
        profile = queries.depth_profile(client, SVC, max_len=4)
        assert sum(profile.values()) >= 3, f"expected hits at several depths, got {profile}"
        return str(profile)

    _run_check(report, "depth_profile", "read", depths)

    def chokes() -> str:
        points = queries.choke_points(client, SVC, max_len=4, top=5)
        keys = [point.get("version") for point in points]
        assert PATCH_KEY in keys, f"expected {PATCH_KEY} to be a choke point, got {keys}"
        return str(keys)

    _run_check(report, "choke_points", "read", chokes)

    def reach() -> str:
        found = queries.maintainer_reach(client, MAINT)
        services = sorted({row.get("service") for row in found})
        assert "selftest-service" in services, f"maintainer pivot found {services}"
        return f"{len(found)} rows via {services}"

    _run_check(report, "maintainer_reach", "read", reach)

    def footprint() -> str:
        row = client.run(queries.MAINTAINER_FOOTPRINT, {"maintainer_id": MAINT}).dicts()
        assert row and row[0].get("packages") == 1, f"footprint returned {row}"
        return str(row[0])

    _run_check(report, "maintainer_footprint", "read", footprint)

    def windows() -> str:
        found = queries.exposure_windows(client, SVC)
        assert found, "no exposure windows came back"
        best = found[0]
        assert best["exposed_days"] and best["exposed_days"] > 0, f"window was {best}"
        return f"worst {best['exposed_days']} days on {best['version']}"

    _run_check(report, "exposure_windows", "read", windows)

    def typos() -> str:
        found = client.run(queries.TYPOSQUAT_NEIGHBOURS, {"package_id": PKG_LIB}).dicts()
        names = [row.get("candidate") for row in found]
        assert "selftest-lib-typo" in names, f"neighbours came back as {names}"
        return str(names)

    _run_check(report, "typosquat_neighbours", "read", typos)

    def lookalikes() -> str:
        found = queries.service_lookalikes(client, SVC)
        pairs = [(row.get("suspect"), row.get("looks_like")) for row in found]
        assert ("selftest-lib-typo", "selftest-lib") in pairs, f"lookalikes came back as {pairs}"
        row = next(row for row in found if row.get("suspect") == "selftest-lib-typo")
        assert row.get("target_downloads") == 1_000_000, f"downloads did not survive: {row}"
        return str(pairs)

    _run_check(report, "service_lookalikes", "read", lookalikes)

    def chains() -> str:
        found = queries.blast_radius(client, [PATCH_KEY, TYPO_KEY], [APP_KEY], max_len=6)
        assert found, "no chain found from a bad version to the app"
        rendered = [chain.render() for chain in found]
        assert any(chain.hops >= 2 for chain in found), f"chains were all one hop: {rendered}"
        return " | ".join(rendered[:3])

    _run_check(report, "blast_radius", "read", chains)

    def cleanup() -> str:
        client.batch(CLEANUP, [{"vertex": identifier} for identifier in FIXTURE_IDS])
        left = client.run("MATCH (s:Svc {id: $id}) RETURN s.id AS id", {"id": SVC}).rows
        assert not left, "fixture survived the cleanup"
        return f"{len(FIXTURE_IDS)} vertices removed"

    _run_check(report, "cleanup", "write", cleanup)

    report.seconds = time.perf_counter() - started
    return report


def write_report(report: SelfTestReport, out: str | Path) -> None:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.as_dict(), indent=2), encoding="utf-8")
