"""A read-only HTTP API and single-page UI over the graph.

Two constraints shaped this file.

The first is that a supply-chain answer nobody can click through is an answer
nobody checks. ``verify`` writes a JSON receipt, which proves the queries run but
asks a reader to trust a file. The same questions are exposed here as URLs, and
the page in ``static/app.html`` is the same data with the chains drawn, so
"``elliptic@6.6.1`` reaches ``webpack@4.43.0`` through four hops" can be followed
hop by hop instead of taken on faith.

The second is dependency weight: the whole product runs on ``httpx`` and
``node-semver``, and a web framework to serve six read-only routes would be the
largest dependency in the project. ``http.server`` is enough, so the API adds no
dependency at all. It is bound to localhost by default and every route is a read;
there is no write path to expose.

Search is a database operation, not a filter in Python: HydraDB matches inline
non-id properties in a pattern and supports ``STARTS WITH`` in ``WHERE`` (it does
not support ``CONTAINS`` or ``IN``), so prefix search over package and maintainer
names is a query, and both ``LIMIT`` and ``SKIP`` take parameters.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

from . import queries
from .hydra import HydraClient, HydraError

STATIC = Path(__file__).parent / "static"
CHAIN_MAX_LEN = 6
DEPTH_MAX_LEN = 4
SEARCH_LIMIT = 25


class NotFound(Exception):
    """A name that is not in the graph, answered as 404 rather than as empty."""


@dataclass
class Api:
    """The question-answering layer. Holds no state beyond one client.

    One ``HydraClient`` is shared and guarded by a lock: the queries are short,
    the traffic is a demo UI, and a connection pool per request would spend more
    time on TLS handshakes than on traversals.
    """

    client: HydraClient
    lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.lock is None:
            self.lock = threading.Lock()

    # -- helpers ----------------------------------------------------------

    def run(self, statement: str, parameters: dict[str, Any] | None = None) -> list[dict]:
        with self.lock:
            return self.client.run(statement, parameters or {}).dicts()

    def service_id(self, name: str) -> int:
        for row in self.run(queries.SERVICE_LIST):
            if row.get("name") == name:
                return int(row["id"])
        raise NotFound(f"no service named {name!r}")

    # -- routes -----------------------------------------------------------

    def health(self, _: dict, __: dict) -> dict:
        with self.lock:
            size = queries.graph_size(self.client)
        return {"ok": all(size.get(label, 0) > 0 for label in ("Pkg", "Ver", "Svc")), "graph": size}

    def services(self, _: dict, __: dict) -> dict:
        rows = self.run(queries.SERVICE_LIST)
        out = []
        for row in rows:
            with self.lock:
                hits = queries.direct_hits(self.client, int(row["id"]))
            out.append(
                {
                    "service": row.get("name"),
                    "pinned_versions": row.get("pin_count"),
                    "captured_at": queries.known_time(row.get("captured_at")),
                    "hits": len(hits),
                    "malicious": sum(hit.is_malicious for hit in hits),
                    "unfixable": sum(not hit.has_fix for hit in hits),
                }
            )
        return {"services": out}

    def service(self, path: dict, _: dict) -> dict:
        name = path["name"]
        service_id = self.service_id(name)
        timings: dict[str, float] = {}

        with self.lock:
            started = time.perf_counter()
            hits = queries.direct_hits(self.client, service_id)
            timings["direct_hits"] = (time.perf_counter() - started) * 1000

            started = time.perf_counter()
            depth = queries.depth_profile(self.client, service_id, max_len=DEPTH_MAX_LEN)
            timings["depth_profile"] = (time.perf_counter() - started) * 1000

            started = time.perf_counter()
            chokes = queries.choke_points(self.client, service_id, max_len=DEPTH_MAX_LEN, top=10)
            timings["choke_points"] = (time.perf_counter() - started) * 1000

            started = time.perf_counter()
            windows = queries.exposure_windows(self.client, service_id)
            timings["exposure_windows"] = (time.perf_counter() - started) * 1000

            started = time.perf_counter()
            lookalikes = queries.service_lookalikes(self.client, service_id)
            timings["lookalikes"] = (time.perf_counter() - started) * 1000

            # A path needs two distinct endpoints, so the bad versions are the
            # sources and the service's own direct pins are the targets.
            bad_keys = sorted({hit.version for hit in hits})[:25]
            entry_keys = queries.entry_points(self.client, service_id)[:25]
            started = time.perf_counter()
            chains = queries.blast_radius(self.client, bad_keys, entry_keys, max_len=CHAIN_MAX_LEN)
            timings["blast_radius"] = (time.perf_counter() - started) * 1000

        return {
            "service": name,
            "hits": [
                {
                    "version": hit.version,
                    "advisory": hit.advisory,
                    "kind": hit.kind,
                    "severity": hit.severity,
                    "direct": hit.direct,
                    "dev": hit.dev,
                    "has_fix": hit.has_fix,
                    "disclosed_at": hit.disclosed_at,
                }
                for hit in sorted(hits, key=lambda hit: (not hit.is_malicious, hit.version))
            ],
            "counts": {
                "hits": len(hits),
                "malicious": sum(hit.is_malicious for hit in hits),
                "unfixable": sum(not hit.has_fix for hit in hits),
                "chains": len(chains),
            },
            "depth_profile": depth,
            "choke_points": chokes,
            "exposure": [row for row in windows if row.get("exposed_days")][:10],
            "lookalikes": lookalikes,
            "chains": [{"keys": chain.keys, "hops": chain.hops} for chain in chains[:40]],
            "timings_ms": {key: round(value, 1) for key, value in timings.items()},
        }

    def search(self, _: dict, query: dict) -> dict:
        prefix = (query.get("q") or "").strip()
        if not prefix:
            return {"packages": [], "maintainers": []}
        limit = min(int(query.get("limit") or SEARCH_LIMIT), 100)
        packages = self.run(queries.PACKAGE_SEARCH, {"prefix": prefix, "limit": limit})
        maintainers = self.run(queries.MAINTAINER_SEARCH, {"prefix": prefix, "limit": limit})
        return {"packages": packages, "maintainers": maintainers}

    def package(self, path: dict, _: dict) -> dict:
        name = path["name"]
        versions = self.run(queries.PACKAGE_VERSIONS, {"name": name})
        if not versions:
            raise NotFound(f"no package named {name!r}")
        advisories = self.run(queries.PACKAGE_ADVISORIES, {"name": name})
        shipped_by = self.run(queries.PACKAGE_SERVICES, {"name": name})
        maintainers = self.run(queries.PACKAGE_MAINTAINERS, {"name": name})
        lookalikes = self.run(queries.TYPOSQUAT_NEIGHBOURS_BY_NAME, {"name": name})

        # The headline question: this package was just called malicious - which
        # service does it reach, and through which chain? Sources are its own
        # versions, targets are the direct pins of every service in the graph.
        keys = sorted({row["version"] for row in versions if row.get("version")})[:25]
        targets: list[str] = []
        for row in self.run(queries.SERVICE_LIST):
            with self.lock:
                targets.extend(queries.entry_points(self.client, int(row["id"])))
        with self.lock:
            started = time.perf_counter()
            found = queries.blast_radius(
                self.client, keys, sorted(set(targets))[:60], max_len=CHAIN_MAX_LEN
            )
            elapsed = (time.perf_counter() - started) * 1000
        return {
            "package": name,
            "versions": versions,
            "advisories": advisories,
            "shipped_by": shipped_by,
            "maintainers": maintainers,
            "lookalikes": lookalikes,
            "chains": [{"keys": chain.keys, "hops": chain.hops} for chain in found[:40]],
            "chain_count": len(found),
            "timings_ms": {"blast_radius": round(elapsed, 1)},
        }

    def maintainer(self, path: dict, _: dict) -> dict:
        login = path["login"]
        started = time.perf_counter()
        rows = self.run(queries.MAINTAINER_REACH_BY_LOGIN, {"login": login})
        elapsed = (time.perf_counter() - started) * 1000
        if not rows:
            # An account with no reach into the example services is still a real
            # account, so tell the two cases apart rather than 404-ing both.
            known = self.run(queries.MAINTAINER_SEARCH, {"prefix": login, "limit": 1})
            if not any(row.get("login") == login for row in known):
                raise NotFound(f"no maintainer named {login!r}")
        services = sorted({row["service"] for row in rows if row.get("service")})
        packages = sorted({row["package"] for row in rows if row.get("package")})
        return {
            "maintainer": login,
            "services": services,
            "packages": packages,
            "reach": rows[:200],
            "counts": {"services": len(services), "packages": len(packages), "versions": len(rows)},
            "timings_ms": {"maintainer_reach": round(elapsed, 1)},
        }

    def lookalikes(self, _: dict, __: dict) -> dict:
        rows = self.run(queries.LOOKALIKES_ALL)
        rows.sort(key=lambda row: (row.get("downloads_ratio") or 0.0, row.get("suspect") or ""))
        return {"lookalikes": rows, "count": len(rows)}


# --------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------

Handler = Callable[[dict, dict], dict]


def routes(api: Api) -> list[tuple[list[str], Handler]]:
    """Path segments to handler. A segment of ``:name`` captures one segment.

    A table this small does not need a regex router, and matching on split
    segments means a package name is never confused with a path: it arrives
    percent-encoded and is unquoted once, so ``@types/node`` is one segment.
    """
    return [
        (["api", "health"], api.health),
        (["api", "services"], api.services),
        (["api", "services", ":name"], api.service),
        (["api", "search"], api.search),
        (["api", "packages", ":name"], api.package),
        (["api", "maintainers", ":login"], api.maintainer),
        (["api", "lookalikes"], api.lookalikes),
    ]


def match_route(
    table: list[tuple[list[str], Handler]], segments: list[str]
) -> tuple[Handler, dict] | None:
    for pattern, handler in table:
        if len(pattern) != len(segments):
            continue
        captured: dict[str, str] = {}
        for expected, actual in zip(pattern, segments):
            if expected.startswith(":"):
                captured[expected[1:]] = actual
            elif expected != actual:
                break
        else:
            return handler, captured
    return None


def make_handler(api: Api) -> type[BaseHTTPRequestHandler]:
    table = routes(api)
    page = STATIC / "app.html"

    class RequestHandler(BaseHTTPRequestHandler):
        server_version = "blastradius"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # quieter than default
            print(f"  http {fmt % args}", flush=True)

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: dict) -> None:
            self._send(status, json.dumps(payload, default=str).encode(), "application/json")

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            parsed = urlparse(self.path)
            segments = [unquote(part) for part in parsed.path.split("/") if part]
            query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}

            if not segments or segments == ["index.html"]:
                if not page.exists():
                    self._json(500, {"error": "ui asset missing"})
                    return
                self._send(200, page.read_bytes(), "text/html; charset=utf-8")
                return

            found = match_route(table, segments)
            if found is None:
                self._json(404, {"error": "no such route", "path": parsed.path})
                return

            handler, captured = found
            try:
                self._json(200, handler(captured, query))
            except NotFound as error:
                self._json(404, {"error": str(error)})
            except HydraError as error:
                self._json(502, {"error": str(error)[:400], "code": error.code})
            except Exception as error:  # pragma: no cover - defensive
                self._json(500, {"error": f"{type(error).__name__}: {error}"[:400]})

    return RequestHandler


def serve(client: HydraClient, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    """Build a server without starting it, so callers own the loop."""
    return ThreadingHTTPServer((host, port), make_handler(Api(client)))
