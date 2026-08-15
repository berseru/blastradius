"""What happens to a source document that never arrives.

The registry answers 429 when it is asked too much, and the fetcher retries with
a backoff. The case that matters is the one where the retries run out: the
package is then missing from the graph, so its versions, its dependencies and
its maintainers are missing too, and every blast radius that would have crossed
it comes back smaller than the truth. Smaller reads as safety.

So each test here is about the *record* the fetcher leaves behind, not about the
value it returns. The bug these were written for returned ``None`` and recorded
nothing at all when the retry budget was spent on rate limits rather than on
exceptions.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from blastradius import npmdata


class Handler(BaseHTTPRequestHandler):
    """Answers whatever ``server.script`` says, per path."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        answer = self.server.script(self.path)
        status, body = answer[0], answer[1]
        headers = answer[2] if len(answer) > 2 else {}
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: object) -> None:
        pass


def start(script) -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.script = script  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def registry(monkeypatch):
    """Point the fetcher's registry at a local server with a scripted answer."""

    servers: list[ThreadingHTTPServer] = []

    def _serve(script):
        server, base = start(script)
        servers.append(server)
        monkeypatch.setattr(npmdata, "REGISTRY_URL", base)
        return base

    yield _serve
    for server in servers:
        server.shutdown()


def fetch(tmp_path, name="left-pad", retries=2, throttle_retries=2, host_limits=None):
    async def main():
        async with npmdata.Fetcher(
            cache_dir=tmp_path,
            retries=retries,
            throttle_retries=throttle_retries,
            host_limits=host_limits or {},
        ) as fetcher:
            meta = await fetcher.package_meta(name)
            return meta, list(fetcher.failures), fetcher.hits, fetcher.misses

    return asyncio.run(main())


def test_sustained_rate_limiting_is_recorded_not_swallowed(registry, tmp_path):
    registry(lambda path: (429, {"error": "slow down"}))

    meta, failures, _hits, _misses = fetch(tmp_path)

    assert meta is None
    assert len(failures) == 1, "a package lost to rate limiting left no trace"
    assert "429" in failures[0] and "left-pad" in failures[0]
    assert "2 attempts" in failures[0]


def test_sustained_server_error_is_recorded(registry, tmp_path):
    registry(lambda path: (503, {"error": "unavailable"}))

    meta, failures, _hits, _misses = fetch(tmp_path)

    assert meta is None
    assert len(failures) == 1 and "503" in failures[0]


def test_a_missing_package_is_an_answer_not_a_failure(registry, tmp_path):
    """404 means "no such package", which is knowledge, not a lost document."""
    registry(lambda path: (404, {"error": "Not found"}))

    meta, failures, _hits, _misses = fetch(tmp_path)

    assert meta is None  # nothing to build a PackageMeta from
    assert failures == []


def test_a_good_answer_is_cached_and_counted(registry, tmp_path):
    document = {
        "name": "left-pad",
        "versions": {"1.3.0": {"dependencies": {}, "maintainers": [{"name": "stringy"}]}},
        "time": {"1.3.0": "2016-03-22T00:00:00.000Z"},
        "maintainers": [{"name": "stringy"}],
    }
    registry(lambda path: (200, document))

    meta, failures, _hits, misses = fetch(tmp_path)

    assert failures == [] and misses == 1
    assert meta is not None and meta.name == "left-pad"
    cached = list(tmp_path.rglob("*.json.gz"))
    assert cached, "a successful fetch was not written to the cache"
    with gzip.open(cached[0], "rt", encoding="utf-8") as handle:
        assert json.load(handle)["name"] == "left-pad"


def test_the_second_call_is_served_from_cache(registry, tmp_path):
    calls: list[str] = []

    def script(path: str):
        calls.append(path)
        return 200, {"name": "left-pad", "versions": {}, "time": {}, "maintainers": []}

    registry(script)
    fetch(tmp_path)
    fetch(tmp_path)

    assert len(calls) == 1, "the cache was not used on the second run"


def test_ingest_stats_carry_the_failures(tmp_path):
    """The count has to reach the artifact, or CI cannot fail the run on it."""
    from blastradius.pipeline import IngestStats

    stats = IngestStats(seeds=3)
    stats.fetch_failures = 2
    stats.fetch_failure_examples = ["https://registry.npmjs.org/x (HTTP 429 after 4 attempts)"]

    payload = stats.as_dict()

    assert payload["fetch_failures"] == 2
    assert payload["fetch_failure_examples"][0].startswith("https://registry.npmjs.org/x")


PACKUMENT = {"name": "left-pad", "versions": {}, "time": {}, "maintainers": []}


def test_the_servers_own_retry_after_is_obeyed(registry, tmp_path):
    """A 429 carrying Retry-After is an instruction, not a failure.

    The old loop spent its whole retry budget on rate limits and then dropped the
    document. Here the counter says "one second", so one second later the fetch
    has to succeed - with the package present, not merely with a nicer message.
    """
    calls: list[float] = []

    def script(path: str):
        calls.append(time.monotonic())
        if len(calls) == 1:
            return 429, {"error": "slow down"}, {"Retry-After": "1"}
        return 200, PACKUMENT

    registry(script)
    started = time.monotonic()
    meta, failures, _hits, _misses = fetch(tmp_path)

    assert meta is not None and failures == []
    assert len(calls) == 2
    assert time.monotonic() - started >= 1.0, "the Retry-After delay was ignored"


def test_one_host_is_asked_one_request_at_a_time(registry, tmp_path):
    """The download counter gets a queue, not twelve parallel requests.

    Its bulk endpoint refuses scoped names, so those are asked for one by one -
    hundreds of them on a cold run. Without this ceiling the counter answers 429
    to most of them, and a package with no download count silently drops out of
    the typosquat comparison.
    """
    arrivals: list[float] = []

    def script(path: str):
        arrivals.append(time.monotonic())
        return 200, PACKUMENT

    registry(script)

    async def main():
        async with npmdata.Fetcher(
            cache_dir=tmp_path, host_limits={"127.0.0.1": (1, 0.2)}
        ) as fetcher:
            await asyncio.gather(*(fetcher.package_meta(f"pkg-{index}") for index in range(3)))
            return list(fetcher.failures)

    assert asyncio.run(main()) == []
    assert len(arrivals) == 3
    gaps = [second - first for first, second in zip(arrivals, arrivals[1:])]
    assert all(gap >= 0.15 for gap in gaps), f"requests arrived {gaps}s apart"


def test_the_limiter_only_applies_to_the_host_it_names(registry, tmp_path):
    arrivals: list[float] = []

    def script(path: str):
        arrivals.append(time.monotonic())
        return 200, PACKUMENT

    registry(script)

    async def main():
        async with npmdata.Fetcher(
            cache_dir=tmp_path, host_limits={"api.npmjs.org": (1, 5.0)}
        ) as fetcher:
            await asyncio.gather(*(fetcher.package_meta(f"pkg-{index}") for index in range(3)))

    started = time.monotonic()
    asyncio.run(main())
    assert time.monotonic() - started < 5.0, "an unrelated host was throttled"
    assert len(arrivals) == 3
