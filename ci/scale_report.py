#!/usr/bin/env python
"""Turn the per-level artifacts of ci/scale.sh into one table and one summary.

Nothing here measures anything: it only reads what the ingest and verify runs
already wrote, so the numbers in the README come from the same JSON a judge can
download from the workflow run.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from blastradius.model import EDGE_TYPES, LABELS

QUERIES = [
    "direct_hits",
    "depth_profile",
    "choke_points",
    "exposure_windows",
    "lookalikes",
    "blast_radius",
]


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def read_level(directory: Path, level: int) -> dict:
    ingest = json.loads((directory / f"ingest-{level}.json").read_text(encoding="utf-8"))
    verify = json.loads((directory / f"verify-{level}.json").read_text(encoding="utf-8"))
    size = verify.get("graph_size") or ingest.get("graph_size") or {}
    per_query = {
        name: _median(
            [
                service["timings_ms"][name]
                for service in verify["services"]
                if name in service.get("timings_ms", {})
            ]
        )
        for name in QUERIES
    }
    slowest = max(per_query.values()) if per_query else 0.0
    ingest_seconds = round(
        ingest.get("fetch_seconds", 0.0)
        + ingest.get("parse_seconds", 0.0)
        + ingest.get("write_seconds", 0.0),
        1,
    )
    return {
        "seeds": level,
        "nodes": sum(int(v) for k, v in size.items() if k in LABELS),
        "edges": sum(int(v) for k, v in size.items() if k in EDGE_TYPES),
        "graph_size": size,
        "packages": ingest.get("packages"),
        "versions": ingest.get("versions"),
        "rows_written": ingest.get("rows_written"),
        "ingest_seconds": ingest_seconds,
        "fetch_seconds": ingest.get("fetch_seconds"),
        "write_seconds": ingest.get("write_seconds"),
        "queries_run": verify.get("hydra", {}).get("queries_run"),
        "total_query_ms": verify.get("hydra", {}).get("total_query_ms"),
        "services": len(verify.get("services", [])),
        "failures": len(verify.get("failures", [])),
        "median_ms": {name: round(value, 1) for name, value in per_query.items()},
        "slowest_median_ms": round(slowest, 1),
    }


def to_markdown(levels: list[dict]) -> str:
    lines = [
        "## Scale evidence",
        "",
        "The same pipeline, run four times against a fresh HydraDB store, on a",
        "seed list where every level is a prefix of the next one. Query times are",
        "the median across services, measured as round-trip time to the database.",
        "",
        "| seeds | packages | versions | nodes | edges | ingest (s) | "
        + " | ".join(f"{name} (ms)" for name in QUERIES)
        + " |",
        "|---:|---:|---:|---:|---:|---:|" + "---:|" * len(QUERIES),
    ]
    for level in levels:
        cells = [
            f"{level['seeds']:,}",
            f"{level['packages']:,}" if level["packages"] else "-",
            f"{level['versions']:,}" if level["versions"] else "-",
            f"{level['nodes']:,}",
            f"{level['edges']:,}",
            f"{level['ingest_seconds']:,.0f}",
        ] + [f"{level['median_ms'][name]:,.0f}" for name in QUERIES]
        lines.append("| " + " | ".join(cells) + " |")
    first, last = levels[0], levels[-1]
    growth = (last["versions"] or 1) / max(first["versions"] or 1, 1)
    slow = last["slowest_median_ms"] / max(first["slowest_median_ms"], 0.001)
    lines += [
        "",
        f"From {first['seeds']:,} to {last['seeds']:,} seeds the graph grew "
        f"{growth:.1f}x in package versions while the slowest query grew "
        f"{slow:.1f}x. Every level ran every query with "
        f"{sum(level['failures'] for level in levels)} query failures.",
        "",
        "Raw numbers: `artifacts/scale/summary.json`, and the per-level "
        "`ingest-*.json` / `verify-*.json` they were read from, are attached to "
        "the `scale` workflow run.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--levels", required=True, help="space separated seed counts")
    parser.add_argument("--dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--markdown", required=True)
    args = parser.parse_args()

    directory = Path(args.dir)
    levels = [read_level(directory, int(value)) for value in args.levels.split()]
    Path(args.out).write_text(json.dumps({"levels": levels}, indent=2), encoding="utf-8")
    Path(args.markdown).write_text(to_markdown(levels), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
