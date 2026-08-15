"""Fetch the public npm facts the graph is built from.

Two sources, both free and unauthenticated:

* ``registry.npmjs.org/{package}`` — the full packument, which is the only
  place that carries a **publish timestamp for every version** plus the current
  maintainer list.  The abbreviated packument is ~2.5x smaller but drops
  ``time``, and timestamps are the whole point of the temporal analysis, so the
  full document is what gets fetched.
* ``api.deps.dev/v3alpha/.../:dependencies`` — the *resolved* dependency graph
  for one version, including the requirement string on every edge.  Resolution
  is what turns "^4.17.0" into a concrete node, and doing it ourselves would
  mean re-implementing npm.

Everything is cached on disk as gzipped JSON, so a re-run costs nothing and CI
can restore the cache instead of hammering public infrastructure.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import httpx

from .osv import parse_timestamp

REGISTRY_URL = "https://registry.npmjs.org"
DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week"
DEPSDEV_URL = "https://api.deps.dev/v3alpha"
USER_AGENT = "blastradius/0.1 (+https://github.com/blastradius)"


class HostLimit:
    """A ceiling for one host: how many requests at once, and how close together.

    The download counter is the reason this exists. Scoped names (``@babel/…``)
    cannot go through its bulk endpoint, so they are asked for one at a time, and
    a first run with a cold cache asks for hundreds of them. At twelve in flight
    it answers 429 in bulk, the retries expire, and the run ends with hundreds of
    packages whose popularity is unknown - which silently loses typosquat edges,
    because a lookalike is only reported when the *target* is popular. Slower and
    complete beats fast and wrong.
    """

    def __init__(self, concurrency: int = 1, min_interval: float = 0.0) -> None:
        self._semaphore = asyncio.Semaphore(concurrency)
        self.min_interval = min_interval
        self._next_at = 0.0

    async def __aenter__(self) -> "HostLimit":
        await self._semaphore.acquire()
        loop = asyncio.get_event_loop()
        wait = self._next_at - loop.time()
        if wait > 0:
            await asyncio.sleep(wait)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        self._next_at = asyncio.get_event_loop().time() + self.min_interval
        self._semaphore.release()


#: A backoff longer than this is worse than the failure: the run stalls.
MAX_BACKOFF = 20.0

#: 4-5 requests a second to the counter, one at a time. Measured against the
#: 86 lost documents a 12-way cold run produced.
DEFAULT_HOST_LIMITS: dict[str, tuple[int, float]] = {
    "api.npmjs.org": (1, 0.22),
}


def retry_after_seconds(response: httpx.Response) -> float | None:
    """``Retry-After`` in seconds, when the server bothered to say."""
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw.strip()))
    except ValueError:  # an HTTP-date; the backoff is used instead
        return None


@dataclass
class PackageMeta:
    name: str
    versions: dict[str, int]  # version -> published epoch seconds
    maintainers: list[str]
    deprecated: set[str] = field(default_factory=set)
    latest: str | None = None

    @property
    def first_published(self) -> int | None:
        return min(self.versions.values()) if self.versions else None


@dataclass
class ResolvedGraph:
    """deps.dev's resolved graph for one root version."""

    root: tuple[str, str]
    nodes: list[tuple[str, str]]
    edges: list[tuple[int, int, str]]  # from index, to index, requirement

    def edge_keys(self) -> list[tuple[str, str, str]]:
        """Edges as ``(from key, to key, requirement)`` with ``name@version`` keys."""
        keys = [f"{name}@{version}" for name, version in self.nodes]
        out = []
        for source, target, requirement in self.edges:
            if 0 <= source < len(keys) and 0 <= target < len(keys):
                out.append((keys[source], keys[target], requirement))
        return out


class Fetcher:
    """Cached, concurrent, polite HTTP access to the two public sources."""

    def __init__(
        self,
        cache_dir: str | Path = "data/cache",
        concurrency: int = 12,
        timeout: float = 60.0,
        retries: int = 4,
        throttle_retries: int = 8,
        host_limits: dict[str, tuple[int, float]] | None = None,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.retries = retries
        # A 429 is not an error, it is an instruction, so it gets its own budget:
        # spending the error budget on being told to slow down is how documents
        # got lost.
        self.throttle_retries = throttle_retries
        self._host_limits = {
            host: HostLimit(concurrency, interval)
            for host, (concurrency, interval) in (
                DEFAULT_HOST_LIMITS if host_limits is None else host_limits
            ).items()
        }
        self._semaphore = asyncio.Semaphore(concurrency)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
        )
        self.hits = 0
        self.misses = 0
        self.failures: list[str] = []

    async def __aenter__(self) -> "Fetcher":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self._client.aclose()

    # -- cache -------------------------------------------------------------

    def _cache_path(self, bucket: str, key: str) -> Path:
        safe = key.replace("/", "__").replace("@", "_at_")
        # Two-character fan-out keeps directories from growing past a few
        # thousand entries, which matters on the runner's filesystem.
        return self.cache_dir / bucket / safe[:2] / f"{safe}.json.gz"

    def _read_cache(self, bucket: str, key: str) -> Any | None:
        path = self._cache_path(bucket, key)
        if not path.exists():
            return None
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                self.hits += 1
                return json.load(handle)
        except (OSError, json.JSONDecodeError):
            path.unlink(missing_ok=True)
            return None

    def _write_cache(self, bucket: str, key: str, payload: Any) -> None:
        path = self._cache_path(bucket, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        with gzip.open(temporary, "wt", encoding="utf-8") as handle:
            json.dump(payload, handle)
        temporary.replace(path)

    # -- http --------------------------------------------------------------

    async def _get_json(self, url: str, bucket: str, key: str) -> Any | None:
        """Fetch one document, or record *why* it could not be fetched.

        Every path out of this function that returns ``None`` has to leave a
        trace in ``failures``. A package lost to a rate limit is a package whose
        versions, dependencies and maintainers never enter the graph, and a blast
        radius that is too small is worse than one that is missing outright: it
        reads as safety. This used to be silent when the retry budget was spent
        on 429s rather than on exceptions.
        """
        cached = self._read_cache(bucket, key)
        if cached is not None:
            return cached
        limit = self._host_limits.get(httpx.URL(url).host or "")
        async with self._semaphore:
            delay = 1.0
            last = "no attempt made"
            attempts = 0
            errors_left = self.retries
            throttles_left = self.throttle_retries
            while True:
                try:
                    attempts += 1
                    if limit is not None:
                        async with limit:
                            response = await self._client.get(url)
                    else:
                        response = await self._client.get(url)
                    if response.status_code == 404:
                        self._write_cache(bucket, key, {})
                        return {}
                    if response.status_code == 429:
                        # Being asked to wait is not a failure until the budget
                        # for waiting runs out, and the server's own number is
                        # better than any backoff this code can invent.
                        last = "HTTP 429"
                        throttles_left -= 1
                        if throttles_left <= 0:
                            break
                        await asyncio.sleep(
                            retry_after_seconds(response) or min(delay, MAX_BACKOFF)
                        )
                        delay = min(delay * 2, MAX_BACKOFF)
                        continue
                    if response.status_code in (500, 502, 503, 504):
                        last = f"HTTP {response.status_code}"
                        errors_left -= 1
                        if errors_left <= 0:
                            break
                        await asyncio.sleep(min(delay, MAX_BACKOFF))
                        delay = min(delay * 2, MAX_BACKOFF)
                        continue
                    response.raise_for_status()
                    payload = response.json()
                    self._write_cache(bucket, key, payload)
                    self.misses += 1
                    return payload
                except (httpx.HTTPError, json.JSONDecodeError) as error:
                    last = f"{type(error).__name__}: {error}"[:120]
                    errors_left -= 1
                    if errors_left <= 0:
                        break
                    await asyncio.sleep(min(delay, MAX_BACKOFF))
                    delay = min(delay * 2, MAX_BACKOFF)
        self.failures.append(f"{url} ({last} after {attempts} attempts)")
        return None

    # -- sources -----------------------------------------------------------

    async def package_meta(self, name: str) -> PackageMeta | None:
        document = await self._get_json(f"{REGISTRY_URL}/{name}", "registry", name)
        if not document:
            return None
        times = document.get("time") or {}
        versions: dict[str, int] = {}
        for version, published in times.items():
            if version in {"created", "modified"}:
                continue
            stamp = parse_timestamp(published)
            if stamp is not None:
                versions[version] = stamp
        deprecated = {
            version
            for version, entry in (document.get("versions") or {}).items()
            if isinstance(entry, dict) and entry.get("deprecated")
        }
        maintainers = []
        for maintainer in document.get("maintainers") or []:
            login = maintainer.get("name") if isinstance(maintainer, dict) else None
            if login:
                maintainers.append(login)
        return PackageMeta(
            name=document.get("name") or name,
            versions=versions,
            maintainers=maintainers,
            deprecated=deprecated,
            latest=(document.get("dist-tags") or {}).get("latest"),
        )

    async def resolved_graph(self, name: str, version: str) -> ResolvedGraph | None:
        url = f"{DEPSDEV_URL}/systems/npm/packages/{_quote(name)}/versions/{_quote(version)}:dependencies"
        document = await self._get_json(url, "depsdev", f"{name}@{version}")
        if not document or "nodes" not in document:
            return None
        nodes: list[tuple[str, str]] = []
        for node in document.get("nodes") or []:
            key = node.get("versionKey") or {}
            nodes.append((key.get("name", ""), key.get("version", "")))
        edges: list[tuple[int, int, str]] = []
        for edge in document.get("edges") or []:
            edges.append(
                (
                    int(edge.get("fromNode", -1)),
                    int(edge.get("toNode", -1)),
                    str(edge.get("requirement") or ""),
                )
            )
        return ResolvedGraph(root=(name, version), nodes=nodes, edges=edges)

    async def weekly_downloads(self, names: Iterable[str]) -> dict[str, int]:
        """Last week's download count per package, from npm's public counter.

        Popularity is what separates a typosquat from an ordinary small library,
        so it is measured rather than assumed. The bulk endpoint takes many
        unscoped names at once; scoped names have to be asked for one by one,
        which is why the two are split here.
        """
        unique = sorted({name for name in names if name})
        scoped = [name for name in unique if name.startswith("@")]
        plain = [name for name in unique if not name.startswith("@")]
        # 64 keeps the URL well inside the length the endpoint accepts.
        batches = [plain[index : index + 64] for index in range(0, len(plain), 64)]
        payloads = await asyncio.gather(
            *(self._downloads_batch(batch) for batch in batches),
            *(self._downloads_batch([name]) for name in scoped),
        )
        counts: dict[str, int] = {}
        for payload in payloads:
            counts.update(payload)
        return counts

    async def _downloads_batch(self, batch: list[str]) -> dict[str, int]:
        if not batch:
            return {}
        digest = hashlib.sha1(",".join(batch).encode("utf-8")).hexdigest()[:12]
        url = f"{DOWNLOADS_URL}/{','.join(batch)}"
        document = await self._get_json(url, "downloads", f"{batch[0]}-{len(batch)}-{digest}")
        if not isinstance(document, dict) or not document:
            return {}
        # One name in the path returns a single record, several return a map of
        # them, and a name the counter has never seen returns null in that map.
        if "downloads" in document and "package" in document:
            name = document.get("package") or batch[0]
            return {str(name): int(document.get("downloads") or 0)}
        counts: dict[str, int] = {}
        for name, record in document.items():
            if isinstance(record, dict):
                counts[name] = int(record.get("downloads") or 0)
        return counts

    async def gather_package_meta(self, names: Iterable[str]) -> dict[str, PackageMeta]:
        unique = sorted(set(names))
        results = await asyncio.gather(*(self.package_meta(name) for name in unique))
        return {meta.name: meta for meta in results if meta}

    async def gather_resolved(
        self, pairs: Iterable[tuple[str, str]]
    ) -> list[ResolvedGraph]:
        unique = sorted(set(pairs))
        results = await asyncio.gather(
            *(self.resolved_graph(name, version) for name, version in unique)
        )
        return [graph for graph in results if graph]


def _quote(value: str) -> str:
    """deps.dev wants path segments percent-encoded, including ``/`` in scopes."""
    from urllib.parse import quote

    return quote(value, safe="")
