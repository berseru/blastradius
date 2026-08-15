"""Command line entry point: ``wait``, ``selftest``, ``contract``, ``ingest``, ``verify``, ``serve``, ``ask``.

CI runs the first four in order. ``selftest`` proves every statement against a
real node on an 11-vertex fixture in seconds, so an unsupported query is caught
before the 220 MB ingest rather than after it. ``verify`` then runs every query
against the real graph and writes a JSON receipt, so a green run means the
queries executed, not merely that the code imported.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

from . import queries
from .hydra import HydraClient, HydraError
from .lockfile import Lockfile, load_lockfile
from .pipeline import ingest as run_ingest
from .queries import ServiceReport

OSV_NPM_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
DEFAULT_ARCHIVE = Path("data/osv-npm.zip")
DEFAULT_SEEDS = Path("scripts/seed_packages.txt")
DEFAULT_LOCKFILES = Path("examples")


def client_from_env() -> HydraClient:
    return HydraClient(
        base_url=os.environ.get("HYDRA_URL", "http://127.0.0.1:8443"),
        token=os.environ.get("HYDRA_TOKEN", ""),
        graph=os.environ.get("HYDRA_GRAPH", "default"),
        namespace=os.environ.get("HYDRA_NAMESPACE", "default"),
        cell=os.environ.get("HYDRA_CELL", "cell-0"),
    )


def ensure_archive(path: Path = DEFAULT_ARCHIVE) -> Path:
    """Download the OSV npm dump once; it is ~220 MB, so never twice."""
    if path.exists() and path.stat().st_size > 1_000_000:
        print(f"osv archive: {path} ({path.stat().st_size:,} bytes, cached)", flush=True)
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {OSV_NPM_URL}", flush=True)
    started = time.perf_counter()
    with urllib.request.urlopen(OSV_NPM_URL, timeout=300) as response, path.open("wb") as handle:
        while chunk := response.read(1 << 20):
            handle.write(chunk)
    print(f"  {path.stat().st_size:,} bytes in {time.perf_counter() - started:.1f}s", flush=True)
    return path


def discover_lockfiles(directory: Path = DEFAULT_LOCKFILES) -> list[Lockfile]:
    if not directory.exists():
        return []
    return [
        load_lockfile(path, service=path.stem.replace(".lock", ""))
        for path in sorted(directory.glob("*.lock.json"))
    ]


def cmd_wait(args: argparse.Namespace) -> int:
    with client_from_env() as client:
        elapsed = client.wait_ready(
            admin_url=os.environ.get("HYDRA_ADMIN_URL", "http://127.0.0.1:9090"),
            timeout_s=args.timeout,
        )
    print(f"hydradb ready and round-tripping after {elapsed:.1f}s")
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """Prove every statement against a real node before trusting a full run."""
    from .selftest import run_selftest, write_report

    with client_from_env() as client:
        report = run_selftest(client)
    print(report.render())
    write_report(report, args.out)
    if report.failures:
        print(
            f"{len(report.failures)} of {len(report.checks)} checks failed",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_contract(args: argparse.Namespace) -> int:
    """Prove the failure paths: refused tokens, wrong graphs, writes that landed."""
    from .contract import contract_from_env, write_report

    from .contract import DEVIATION

    report = contract_from_env()
    print(report.render(), flush=True)
    if args.out:
        write_report(report, args.out)
    deviations = [check for check in report.checks if check.detail.startswith(DEVIATION)]
    for check in deviations:
        # Printed, not buried in the artifact: this is a finding about the
        # server, and a finding nobody reads is not a finding.
        print(f"note: {check.name}: {check.detail}", flush=True)
    if report.failures:
        print(
            f"{len(report.failures)} contract checks failed: "
            f"{[check.name for check in report.failures]}",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_crosscheck(args: argparse.Namespace) -> int:
    """Compare a sample of the run's answers against the live OSV API.

    Everything upstream of this command reads one snapshot through one parser,
    so a parsing mistake would be invisible: every test would agree with the
    code that made it. This asks a different source, per advisory, over the
    network, with a semver implementation written separately from the one the
    pipeline uses.
    """
    from .crosscheck import crosscheck

    report = crosscheck(
        Path(args.samples), Path(args.out) if args.out else None
    )
    for comparison in report["comparisons"]:
        mark = "ok  " if comparison["agrees"] else "FAIL"
        if comparison["unreachable"]:
            mark = "skip"
        detail = "; ".join(comparison["differences"]) or comparison["grounds"]
        print(f"  {mark} {comparison['version']:<30} {comparison['advisory']:<24} {detail[:80]}")
    print(
        f"{report['agreed']}/{report['checked']} sampled hits agree with {report['source']} "
        f"on affectedness, disclosure date, severity, fix availability and kind"
        + (f" ({report['unreachable']} unreachable)" if report["unreachable"] else "")
    )
    if report["checked"] == 0:
        print("no samples found to check", file=sys.stderr)
        return 1
    disagreements = [c for c in report["comparisons"] if not c["agrees"]]
    if disagreements:
        print(f"{len(disagreements)} disagreements with OSV", file=sys.stderr)
        return 1
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    archive = ensure_archive(Path(args.archive))
    lockfiles = discover_lockfiles(Path(args.examples))
    print(f"lockfiles: {[lock.service for lock in lockfiles]}", flush=True)
    with client_from_env() as client:
        stats = run_ingest(
            client,
            seeds_path=args.seeds_file,
            archive=archive,
            lockfiles=lockfiles,
            limit=args.seeds,
            cache_dir=args.cache_dir,
        )
        stats.graph_size = queries.graph_size(client)
    print(json.dumps(stats.as_dict(), indent=2))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(stats.as_dict(), indent=2), encoding="utf-8")
    if stats.rows_written == 0:
        print("ingest wrote nothing", file=sys.stderr)
        return 1
    return 0


def _service_ids(client: HydraClient) -> list[tuple[int, str]]:
    rows = client.run("MATCH (s:Svc) RETURN s.id AS id, s.name AS name").dicts()
    return [(int(row["id"]), row["name"]) for row in rows if row.get("id") is not None]


def verify(client: HydraClient) -> dict:
    """Run every query against a real node and report what came back."""
    report: dict = {"graph_size": queries.graph_size(client), "services": [], "failures": []}

    for service_id, name in _service_ids(client):
        service = ServiceReport(service=name)
        try:
            started = time.perf_counter()
            service.hits = queries.direct_hits(client, service_id)
            service.timings_ms["direct_hits"] = (time.perf_counter() - started) * 1000

            started = time.perf_counter()
            service.depth_profile = queries.depth_profile(client, service_id, max_len=4)
            service.timings_ms["depth_profile"] = (time.perf_counter() - started) * 1000

            started = time.perf_counter()
            service.choke_points = queries.choke_points(client, service_id, max_len=4, top=10)
            service.timings_ms["choke_points"] = (time.perf_counter() - started) * 1000

            started = time.perf_counter()
            windows = queries.exposure_windows(client, service_id)
            service.timings_ms["exposure_windows"] = (time.perf_counter() - started) * 1000

            started = time.perf_counter()
            lookalikes = queries.service_lookalikes(client, service_id)
            service.timings_ms["lookalikes"] = (time.perf_counter() - started) * 1000

            # Sources are the versions an advisory names; targets are the
            # service's own direct dependencies. Pointing both ends at the same
            # set would return nothing, since a path needs two distinct nodes.
            bad_keys = sorted({hit.version for hit in service.hits})[:25]
            entry_keys = queries.entry_points(client, service_id)[:25]
            started = time.perf_counter()
            service.chains = queries.blast_radius(client, bad_keys, entry_keys, max_len=6)
            service.timings_ms["blast_radius"] = (time.perf_counter() - started) * 1000
        except HydraError as error:
            report["failures"].append(
                {"service": name, "code": error.code, "message": str(error)[:400]}
            )
            continue

        report["services"].append(
            {
                "service": name,
                "hits": len(service.hits),
                "malicious_hits": len(service.malicious_hits),
                "unfixable_hits": len(service.unfixable_hits),
                "depth_profile": service.depth_profile,
                "choke_points": service.choke_points[:5],
                "worst_exposure_days": windows[0]["exposed_days"] if windows else None,
                "chains": [chain.render() for chain in service.chains[:5]],
                "chain_count": len(service.chains),
                "lookalikes": lookalikes[:5],
                "timings_ms": {key: round(value, 1) for key, value in service.timings_ms.items()},
            }
        )
    return report


def cmd_verify(args: argparse.Namespace) -> int:
    with client_from_env() as client:
        report = verify(client)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps(report, indent=2, default=str)[:4000])

    if report["failures"]:
        print(f"{len(report['failures'])} query failures", file=sys.stderr)
        return 1
    if not report["services"]:
        print("no services in the graph - nothing was verified", file=sys.stderr)
        return 1
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    """Ad-hoc question against a running node, for demos and debugging."""
    with client_from_env() as client:
        rows = client.run("MATCH (s:Svc) RETURN s.id AS id, s.name AS name").dicts()
        match = next((row for row in rows if row["name"] == args.service), None)
        if not match:
            print(f"unknown service {args.service!r}; have {[row['name'] for row in rows]}",
                  file=sys.stderr)
            return 1
        service_id = int(match["id"])
        hits = queries.direct_hits(client, service_id)
        print(f"{args.service}: {len(hits)} advisory hits "
              f"({sum(hit.is_malicious for hit in hits)} malicious, "
              f"{sum(not hit.has_fix for hit in hits)} with no fixed version)")
        for hit in hits[:20]:
            fix = "no fix" if not hit.has_fix else "fix available"
            print(f"  {hit.version:<45} {hit.advisory:<22} {hit.kind:<13} {fix}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Serve the read-only API and the UI, or prove both against a live node.

    ``--selfcheck`` is the CI half: it binds an ephemeral port, drives every
    route over real HTTP and asserts the shape of what came back, so a broken
    route fails the build instead of being discovered in a demo.
    """
    from .web import serve as build_server

    with client_from_env() as client:
        server = build_server(client, host=args.host, port=0 if args.selfcheck else args.port)
        host, port = server.server_address[0], server.server_address[1]
        if not args.selfcheck:
            print(f"blastradius ui on http://{host}:{port}  (ctrl-c to stop)", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("\nstopped")
            finally:
                server.server_close()
            return 0

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            report = api_selfcheck(
                f"http://{host}:{port}",
                dump_dir=Path(args.dump_dir) if args.dump_dir else None,
            )
        finally:
            server.shutdown()
            server.server_close()

    print(json.dumps(report, indent=2)[:4000])
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    failures = [check for check in report["checks"] if not check["ok"]]
    print(f"{len(report['checks']) - len(failures)}/{len(report['checks'])} api checks passed")
    if failures:
        print(f"{len(failures)} api checks failed: {[c['route'] for c in failures]}", file=sys.stderr)
        return 1
    return 0


def api_selfcheck(base: str, dump_dir: Path | None = None) -> dict:
    """Drive every route over HTTP and check the answers are answers.

    The assertions are deliberately about content, not status codes: a route
    returning ``200 {}`` is the failure mode worth catching, and "the UI showed
    nothing" is exactly what a green build must not hide.

    With ``dump_dir`` every response is also written out. CI is the only place a
    populated graph exists, so those files are the only way the UI can be shown -
    in a README, in a demo - with the real corpus behind it rather than a fixture.
    """
    import urllib.error

    def get(path: str, method: str = "GET") -> tuple[int, Any]:
        request = urllib.request.Request(f"{base}{path}", method=method)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                body = response.read()
                return response.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as error:
            raw = error.read() or b"{}"
            try:
                return error.code, json.loads(raw)
            except json.JSONDecodeError:
                return error.code, {"body": raw[:200].decode("utf-8", "replace")}

    checks: list[dict] = []

    def check(
        route: str, predicate: Callable[[int, Any], bool], note: str = "", method: str = "GET"
    ) -> Any:
        started = time.perf_counter()
        status, payload = get(route, method)
        elapsed = (time.perf_counter() - started) * 1000
        try:
            ok = bool(predicate(status, payload))
            detail = note
        except Exception as error:  # a malformed payload is a failure, not a crash
            ok, detail = False, f"{type(error).__name__}: {error}"
        checks.append({"route": route, "ok": ok, "status": status, "ms": round(elapsed, 1),
                       "detail": detail or json.dumps(payload)[:160]})
        if dump_dir is not None and status == 200:
            name = route.lstrip("/").replace("/", "_").replace("?", "_").replace("=", "-")
            dump_dir.mkdir(parents=True, exist_ok=True)
            (dump_dir / f"{name}.json").write_text(
                json.dumps(payload, indent=2, default=str), encoding="utf-8"
            )
        return payload

    health = check("/api/health", lambda status, body: status == 200 and body["ok"])
    listing = check(
        "/api/services",
        lambda status, body: status == 200 and len(body["services"]) > 0
        and all(row["hits"] >= 0 for row in body["services"]),
    )
    names = [row["service"] for row in listing.get("services", [])]
    worst = max(
        listing.get("services", []), key=lambda row: row.get("malicious") or 0, default={}
    ).get("service")

    for name in names:
        check(
            f"/api/services/{name}",
            lambda status, body: status == 200
            and body["counts"]["hits"] > 0
            and len(body["hits"]) == body["counts"]["hits"]
            and sum(body["depth_profile"].values()) > 0,
        )

    if worst:
        service = check(
            f"/api/services/{worst}",
            lambda status, body: status == 200 and body["counts"]["chains"] > 0
            and len(body["lookalikes"]) > 0,
            note="worst service has chains and lookalikes",
        )
        first_hit = (service.get("hits") or [{}])[0].get("version", "")
        package_name = "@".join(first_hit.split("@")[:-1]) or first_hit
        if package_name:
            check(
                f"/api/packages/{package_name}",
                lambda status, body: status == 200 and len(body["versions"]) > 0
                and len(body["shipped_by"]) > 0,
                note=f"package view for {package_name}",
            )
            maintainers = (
                check(f"/api/packages/{package_name}", lambda status, body: status == 200)
                .get("maintainers")
                or []
            )
            if maintainers:
                login = maintainers[0]["login"]
                check(
                    f"/api/maintainers/{login}",
                    lambda status, body: status == 200 and body["counts"]["packages"] > 0,
                    note=f"takeover reach for {login}",
                )

    check("/api/search?q=ex", lambda status, body: status == 200 and len(body["packages"]) > 0)
    check("/api/lookalikes", lambda status, body: status == 200 and body["count"] > 0)
    # The negative half. A route that answers 200 with an empty body for a name
    # that does not exist is the failure worth catching: on this UI it reads as
    # "nothing found, you are clean" when the truth is "you asked for nonsense".
    check("/api/nope", lambda status, body: status == 404 and "error" in body,
          note="unknown route is 404, not the UI page")
    check("/api/packages/definitely-not-a-package",
          lambda status, body: status == 404 and "error" in body,
          note="unknown package is 404, not an empty package view")
    check("/api/services/definitely-not-a-service",
          lambda status, body: status == 404 and "error" in body,
          note="unknown service is 404, not an empty report")
    check("/api/maintainers/definitely-not-a-maintainer",
          lambda status, body: status == 404 and "error" in body,
          note="unknown maintainer is 404, not an empty blast radius")
    check("/api/search", lambda status, body: status == 200
          and body["packages"] == [] and body["maintainers"] == [],
          note="search with no term is an empty answer, not an error and not everything")
    check("/api/search?q=ex&limit=banana", lambda status, body: status == 400 and "error" in body,
          note="a bad limit is the caller's 400, not the server's 500")
    check("/api/search?q=ex&limit=0", lambda status, body: status == 400 and "error" in body,
          note="a nonsensical limit is refused")
    check("/api/services", lambda status, body: status == 405 and "error" in body,
          note="the API is read-only: POST is refused", method="POST")
    check("/api/services/checkout-api", lambda status, body: status == 405,
          note="read-only holds for DELETE too", method="DELETE")

    return {"base": base, "graph": health.get("graph", {}), "checks": checks}


def cmd_stats(args: argparse.Namespace) -> int:
    """Re-derive the ecosystem counts quoted in the README. Needs no database."""
    from .osv import iter_advisories, summarise

    archive = ensure_archive(Path(args.archive))
    started = time.perf_counter()
    stats = summarise(iter_advisories(archive))
    elapsed = time.perf_counter() - started

    def day(value: int | None) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(value)) if value else "-"

    print(f"advisories                    {stats.advisories:>9,}")
    print(f"  malicious packages (MAL)    {stats.malicious:>9,}  "
          f"({stats.malicious_share:.1%})")
    print(f"    ...offering a fix         {stats.malicious_with_fix:>9,}")
    print(f"  vulnerabilities (GHSA)      {stats.vulnerabilities:>9,}")
    print(f"    ...with no fix available  {stats.vulnerabilities_without_fix:>9,}")
    print(f"  withdrawn                   {stats.withdrawn:>9,}")
    print(f"distinct packages named       {stats.packages:>9,}")
    print(f"published between             {day(stats.first_published)} and "
          f"{day(stats.last_published)}")
    print(f"parsed in                     {elapsed:>9.1f}s")

    if args.out:
        payload = {
            "archive": str(archive),
            "archive_bytes": archive.stat().st_size,
            "parse_seconds": round(elapsed, 2),
            "first_published": day(stats.first_published),
            "last_published": day(stats.last_published),
            **{
                key: getattr(stats, key)
                for key in (
                    "advisories",
                    "malicious",
                    "malicious_with_fix",
                    "vulnerabilities",
                    "vulnerabilities_without_fix",
                    "withdrawn",
                    "packages",
                )
            },
        }
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blastradius", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    wait = sub.add_parser("wait", help="block until HydraDB round-trips a query")
    wait.add_argument("--timeout", type=float, default=240.0)
    wait.set_defaults(func=cmd_wait)

    selftest = sub.add_parser(
        "selftest", help="run every statement against a real node on a tiny fixture"
    )
    selftest.add_argument("--out", default="artifacts/selftest.json")
    selftest.set_defaults(func=cmd_selftest)

    contract = sub.add_parser(
        "contract",
        help="prove the failure paths: 401 on a bad token, 404 on a wrong graph, "
             "and that writes are readable afterwards",
    )
    contract.add_argument("--out", default="artifacts/contract.json")
    contract.set_defaults(func=cmd_contract)

    crosscheck_cmd = sub.add_parser(
        "crosscheck",
        help="verify sampled hits against the live OSV API, with an independent "
             "semver implementation",
    )
    crosscheck_cmd.add_argument("--samples", default="artifacts/api-samples")
    crosscheck_cmd.add_argument("--out", default="artifacts/osv-crosscheck.json")
    crosscheck_cmd.set_defaults(func=cmd_crosscheck)

    ingest = sub.add_parser("ingest", help="build the graph from public data")
    ingest.add_argument("--seeds", type=int, default=None, help="how many seed packages")
    ingest.add_argument("--seeds-file", default=str(DEFAULT_SEEDS))
    ingest.add_argument("--archive", default=str(DEFAULT_ARCHIVE))
    ingest.add_argument("--examples", default=str(DEFAULT_LOCKFILES))
    ingest.add_argument("--cache-dir", default="data/cache")
    ingest.add_argument("--out", default="artifacts/ingest.json")
    ingest.set_defaults(func=cmd_ingest)

    verify_cmd = sub.add_parser("verify", help="run every query and write a receipt")
    verify_cmd.add_argument("--out", default="artifacts/results.json")
    verify_cmd.set_defaults(func=cmd_verify)

    stats = sub.add_parser("stats", help="ecosystem counts from the OSV dump, no database needed")
    stats.add_argument("--archive", default=str(DEFAULT_ARCHIVE))
    stats.add_argument("--out", default="artifacts/corpus.json")
    stats.set_defaults(func=cmd_stats)

    serve_cmd = sub.add_parser("serve", help="serve the read-only API and UI")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8080)
    serve_cmd.add_argument(
        "--selfcheck", action="store_true", help="drive every route once and exit"
    )
    serve_cmd.add_argument("--out", default="artifacts/api.json")
    serve_cmd.add_argument(
        "--dump-dir",
        default="artifacts/api-samples",
        help="write every response body here, so the UI can be shown with real data",
    )
    serve_cmd.set_defaults(func=cmd_serve)

    ask = sub.add_parser("ask", help="show the hits for one service")
    ask.add_argument("service")
    ask.set_defaults(func=cmd_ask)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
