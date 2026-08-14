"""Command line entry point: ``wait``, ``ingest``, ``verify``, ``ask``.

CI runs the first three in order. ``verify`` is the important one - it runs
every query in :mod:`blastradius.queries` against a real node and writes a JSON
receipt, so a green run means the queries executed, not merely that the code
imported.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blastradius", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    wait = sub.add_parser("wait", help="block until HydraDB round-trips a query")
    wait.add_argument("--timeout", type=float, default=240.0)
    wait.set_defaults(func=cmd_wait)

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

    ask = sub.add_parser("ask", help="show the hits for one service")
    ask.add_argument("service")
    ask.set_defaults(func=cmd_ask)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
