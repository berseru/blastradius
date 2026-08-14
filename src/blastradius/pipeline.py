"""Turn public registry data into a graph, in one pass, with receipts.

The ingest is deliberately boring: build every row in memory, then push it in
batches, then count what landed. Counting afterwards is the point - an ingest
that reports success without reading the graph back proves nothing.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import model
from .hydra import HydraClient
from .ids import IdBook
from .lockfile import Lockfile
from .npmdata import Fetcher, PackageMeta, ResolvedGraph
from .osv import Advisory, iter_advisories
from .typosquat import UNKNOWN_DOWNLOADS, find_typosquats
from .versions import is_affected

# HydraDB has no null property value, so "we do not know when this was
# published" is written as 0 rather than omitted. Every consumer of a timestamp
# treats 0 as unknown; nothing in this corpus is genuinely dated 1970-01-01.
UNKNOWN_TIME = 0


@dataclass
class Rows:
    """Every batch the ingest will send, keyed by the statement that takes it."""

    buckets: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))

    seen: set[tuple[str, int]] = field(default_factory=set)

    def add(self, bucket: str, row: dict) -> None:
        """Append a row unless an identical id was already queued.

        ``MERGE`` would make a duplicate harmless on the server, but a row count
        that double-counts is a lie in the benchmark, so duplicates are dropped
        here instead of being papered over downstream.
        """
        identifier = row.get("id") or row.get("edge_id")
        if identifier is not None:
            marker = (bucket, int(identifier))
            if marker in self.seen:
                return
            self.seen.add(marker)
        self.buckets[bucket].append(row)

    def counts(self) -> dict[str, int]:
        return {name: len(rows) for name, rows in sorted(self.buckets.items())}

    def total(self) -> int:
        return sum(len(rows) for rows in self.buckets.values())


@dataclass
class IngestStats:
    seeds: int = 0
    packages: int = 0
    versions: int = 0
    advisories_scanned: int = 0
    advisories_kept: int = 0
    affects_edges: int = 0
    similar_edges: int = 0
    rows_written: int = 0
    fetch_seconds: float = 0.0
    parse_seconds: float = 0.0
    write_seconds: float = 0.0
    graph_size: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "seeds": self.seeds,
            "packages": self.packages,
            "versions": self.versions,
            "advisories_scanned": self.advisories_scanned,
            "advisories_kept": self.advisories_kept,
            "affects_edges": self.affects_edges,
            "similar_edges": self.similar_edges,
            "rows_written": self.rows_written,
            "fetch_seconds": round(self.fetch_seconds, 2),
            "parse_seconds": round(self.parse_seconds, 2),
            "write_seconds": round(self.write_seconds, 2),
            "graph_size": self.graph_size,
        }


def read_seeds(path: str | Path, limit: int | None = None) -> list[tuple[str, str]]:
    """Read ``name@version`` seed lines. Pinned on purpose: judges rerunning
    this should get the same graph, which floating "latest" would not give."""
    seeds: list[tuple[str, str]] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "@" not in line.lstrip("@"):
            raise ValueError(f"seed must be name@version, got {line!r}")
        name, _, version = line.rpartition("@")
        seeds.append((name, version))
        if limit and len(seeds) >= limit:
            break
    return seeds


async def fetch_inputs(
    seeds: list[tuple[str, str]],
    cache_dir: str | Path,
    extra_names: Iterable[str] = (),
) -> tuple[dict[str, PackageMeta], list[ResolvedGraph], dict[str, int]]:
    """Resolve the seeds first, then fetch metadata for everything they pull in.

    The order matters: the transitive closure is only known after resolution,
    and it is far larger than the seed list. ``extra_names`` carries the packages
    that only appear in a lockfile, which still need metadata and download
    counts even though no seed pulls them in.
    """
    async with Fetcher(cache_dir=cache_dir) as fetcher:
        resolved = await fetcher.gather_resolved(seeds)
        names = {name for name, _ in seeds} | set(extra_names)
        for graph in resolved:
            names.update(name for name, _version in graph.nodes)
        metas = await fetcher.gather_package_meta(sorted(names))
        downloads = await fetcher.weekly_downloads(sorted(names | set(metas)))
        if fetcher.failures:
            print(f"  {len(fetcher.failures)} fetches failed, e.g. {fetcher.failures[:3]}",
                  flush=True)
    return metas, resolved, downloads


def build_rows(
    seeds: list[tuple[str, str]],
    metas: dict[str, PackageMeta],
    resolved: list[ResolvedGraph],
    advisories: dict[str, list[Advisory]],
    lockfiles: list[Lockfile],
    *,
    downloads: dict[str, int] | None = None,
    captured_at: int | None = None,
) -> tuple[Rows, IngestStats, IdBook]:
    """Assemble every row. Pure function of its inputs, so it is testable."""
    rows, book = Rows(), IdBook()
    stats = IngestStats(seeds=len(seeds))
    captured_at = captured_at or int(time.time())
    downloads = downloads or {}

    versions_by_package: dict[str, set[str]] = defaultdict(set)
    for graph in resolved:
        for name, version in graph.nodes:
            versions_by_package[name].add(version)
    for lock in lockfiles:
        for pin in lock.pins:
            versions_by_package[pin.name].add(pin.version)

    # -- packages, versions, maintainers ---------------------------------
    for name, versions in sorted(versions_by_package.items()):
        meta = metas.get(name)
        package_id = book.package(name)
        rows.add(
            "packages",
            {
                "id": package_id,
                "name": name,
                "version_count": len(meta.versions) if meta else len(versions),
                "first_published": (meta.first_published if meta else 0) or UNKNOWN_TIME,
                "downloads": int(downloads.get(name, UNKNOWN_DOWNLOADS)),
            },
        )
        for version in sorted(versions):
            version_id = book.version(name, version)
            rows.add(
                "versions",
                {
                    "id": version_id,
                    "key": f"{name}@{version}",
                    "name": name,
                    "version": version,
                    "published_at": (meta.versions.get(version, 0) if meta else 0)
                    or UNKNOWN_TIME,
                    "deprecated": bool(meta and version in meta.deprecated),
                },
            )
            rows.add(
                "of",
                {
                    "version_id": version_id,
                    "package_id": package_id,
                    "edge_id": model.edge_id(version_id, package_id, "OF"),
                    "name": name,
                },
            )
        for login in meta.maintainers if meta else []:
            maintainer_id = book.maintainer(login)
            rows.add("maintainers", {"id": maintainer_id, "login": login, "package_count": 0})
            rows.add(
                "maintains",
                {
                    "maintainer_id": maintainer_id,
                    "package_id": package_id,
                    "edge_id": model.edge_id(maintainer_id, package_id, "MAINTAINS"),
                    "login": login,
                },
            )

    stats.packages = len(rows.buckets["packages"])
    stats.versions = len(rows.buckets["versions"])

    # -- dependency edges -------------------------------------------------
    # Lockfile edges come first and are marked `direct` when the parent is a
    # version the service pins itself. They are the ones that matter: the
    # registry resolution below describes *today's* releases of the seeds, which
    # are usually newer than what a real deployment ships, so on their own they
    # leave every pinned version without an outgoing edge and every blast-radius
    # traversal dead on arrival (measured 2026-08-14: 0 chains, depth 0 only).
    seen_edges: set[int] = set()
    for lock in lockfiles:
        direct_keys = {pin.key for pin in lock.direct}
        for edge in lock.edges:
            parent_name, _, parent_version = edge.parent.rpartition("@")
            child_name, _, child_version = edge.child.rpartition("@")
            from_id = book.version(parent_name, parent_version)
            to_id = book.version(child_name, child_version)
            identifier = model.edge_id(from_id, to_id, "DEPENDS")
            if identifier in seen_edges:
                continue
            seen_edges.add(identifier)
            rows.add(
                "depends",
                {
                    "from_id": from_id,
                    "to_id": to_id,
                    "edge_id": identifier,
                    "requirement": edge.requirement or "",
                    "direct": edge.parent in direct_keys,
                },
            )

    for graph in resolved:
        for parent_key, child_key, requirement in graph.edge_keys():
            parent_name, _, parent_version = parent_key.rpartition("@")
            child_name, _, child_version = child_key.rpartition("@")
            from_id = book.version(parent_name, parent_version)
            to_id = book.version(child_name, child_version)
            identifier = model.edge_id(from_id, to_id, "DEPENDS")
            if identifier in seen_edges:
                continue
            seen_edges.add(identifier)
            rows.add(
                "depends",
                {
                    "from_id": from_id,
                    "to_id": to_id,
                    "edge_id": identifier,
                    "requirement": requirement or "",
                    "direct": False,
                },
            )

    # -- services ---------------------------------------------------------
    for lock in lockfiles:
        service_id = book.service(lock.service)
        rows.add(
            "services",
            {
                "id": service_id,
                "name": lock.service,
                "pin_count": len(lock.pins),
                "captured_at": captured_at,
            },
        )
        for pin in lock.pins:
            version_id = book.version(pin.name, pin.version)
            rows.add(
                "uses",
                {
                    "service_id": service_id,
                    "version_id": version_id,
                    "edge_id": model.edge_id(service_id, version_id, "USES"),
                    "direct": pin.direct,
                    "dev": pin.dev,
                },
            )

    # -- advisories, matched version by version ---------------------------
    for name, package_advisories in advisories.items():
        known_versions = versions_by_package.get(name)
        if not known_versions:
            continue
        for advisory in package_advisories:
            hits = match_versions(advisory, name, known_versions)
            if not hits:
                continue
            advisory_id = book.advisory(advisory.id)
            rows.add(
                "advisories",
                {
                    "id": advisory_id,
                    "osv": advisory.id,
                    "kind": advisory.kind,
                    "severity": advisory.severity,
                    "published_at": advisory.published or UNKNOWN_TIME,
                    "has_fix": advisory.has_fix,
                    "summary": (advisory.summary or "")[:300],
                },
            )
            for version, window in sorted(hits.items()):
                version_id = book.version(name, version)
                rows.add(
                    "affects",
                    {
                        "advisory_id": advisory_id,
                        "version_id": version_id,
                        "edge_id": model.edge_id(advisory_id, version_id, "AFFECTS"),
                        "introduced": window[0],
                        "fixed": window[1],
                        "kind": advisory.kind,
                    },
                )

    # -- typosquat edges --------------------------------------------------
    # Run last, because "already known to be malware" is one of the signals and
    # that is only known once the advisories have been matched.
    malicious_names = {
        name
        for name, package_advisories in advisories.items()
        if any(advisory.is_malicious for advisory in package_advisories)
    }
    for pair in find_typosquats(
        versions_by_package, downloads, always_suspect=malicious_names
    ):
        from_id = book.package(pair.suspect)
        to_id = book.package(pair.target)
        rows.add(
            "similar",
            {
                "from_id": from_id,
                "to_id": to_id,
                "edge_id": model.edge_id(from_id, to_id, "SIMILAR"),
                "distance": pair.distance,
                "downloads_ratio": pair.downloads_ratio,
            },
        )

    stats.advisories_kept = len(rows.buckets["advisories"])
    stats.affects_edges = len(rows.buckets["affects"])
    stats.similar_edges = len(rows.buckets["similar"])
    return rows, stats, book


def match_versions(
    advisory: Advisory, name: str, versions: set[str]
) -> dict[str, tuple[str, str]]:
    """Which of ``versions`` this advisory actually covers, and through which window.

    Keeping the window that matched (not just the fact of a match) is what lets
    the graph answer "since when", so it is carried onto the edge.
    """
    hits: dict[str, tuple[str, str]] = {}
    for affected in advisory.affected:
        if affected.package != name:
            continue
        for version in versions:
            if version in affected.versions:
                hits.setdefault(version, ("", ""))
            for window in affected.ranges:
                if is_affected(version, window.introduced, window.fixed, window.last_affected):
                    hits[version] = (window.introduced or "", window.fixed or "")
                    break
    return hits


def load_advisories(archive: str | Path, names: set[str]) -> tuple[dict[str, list[Advisory]], int]:
    """Stream the OSV dump once, keeping only advisories for packages we hold."""
    kept: dict[str, list[Advisory]] = defaultdict(list)
    scanned = 0
    for advisory in iter_advisories(archive):
        scanned += 1
        # An advisory can list the same package in several `affected` entries
        # (one per version window), so the package names are deduplicated here
        # or the advisory would be ingested once per entry.
        for package in dict.fromkeys(advisory.packages):
            if package in names:
                kept[package].append(advisory)
    return kept, scanned


def write_rows(client: HydraClient, rows: Rows, *, chunk_size: int = 500) -> int:
    """Vertices before edges, because an edge needs both endpoints to exist."""
    order = ["packages", "versions", "maintainers", "advisories", "services",
             "of", "depends", "uses", "maintains", "affects", "similar"]
    written = 0
    for bucket in order:
        batch = rows.buckets.get(bucket)
        if not batch:
            continue
        statement = model.ALL_STATEMENTS[bucket]
        started = time.perf_counter()
        written += client.batch(statement, batch, chunk_size=chunk_size)
        print(
            f"  {bucket:<11} {len(batch):>7,} rows in {time.perf_counter() - started:6.1f}s",
            flush=True,
        )
    return written


def ingest(
    client: HydraClient,
    seeds_path: str | Path,
    archive: str | Path,
    lockfiles: list[Lockfile],
    *,
    limit: int | None = None,
    cache_dir: str | Path = "data/cache",
) -> IngestStats:
    seeds = read_seeds(seeds_path, limit)
    print(f"seeds: {len(seeds)}", flush=True)

    lock_names: set[str] = set()
    for lock in lockfiles:
        lock_names |= lock.names()

    started = time.perf_counter()
    metas, resolved, downloads = asyncio.run(fetch_inputs(seeds, cache_dir, lock_names))
    fetch_seconds = time.perf_counter() - started
    print(f"fetched {len(metas)} packuments, {len(resolved)} resolved graphs "
          f"in {fetch_seconds:.1f}s", flush=True)

    names = set(metas) | {name for name, _ in seeds}
    for lock in lockfiles:
        names |= lock.names()

    started = time.perf_counter()
    advisories, scanned = load_advisories(archive, names)
    parse_seconds = time.perf_counter() - started
    print(f"scanned {scanned:,} advisories in {parse_seconds:.1f}s, "
          f"{len(advisories)} of our packages are named", flush=True)

    rows, stats, _book = build_rows(
        seeds, metas, resolved, advisories, lockfiles, downloads=downloads
    )
    stats.fetch_seconds = fetch_seconds
    stats.parse_seconds = parse_seconds
    stats.advisories_scanned = scanned
    print(f"rows to write: {rows.counts()}", flush=True)

    started = time.perf_counter()
    stats.rows_written = write_rows(client, rows)
    stats.write_seconds = time.perf_counter() - started
    return stats
