#!/usr/bin/env python3
"""Generate the example lockfiles in ``examples/`` from real resolved trees.

The demo services deliberately pin *older* versions, because that is what real
applications look like a year after they were written - and because a graph
built only from today's latest versions shows almost nothing: popular packages
at their newest are mostly clean. Measured on 2026-08-14, 25 seed packages
pinned to latest produced only 10 advisories and zero malware, while the same
pipeline over these outdated services is what makes the exposure visible.

Every version below is resolved through deps.dev, so the lockfiles contain real
transitive trees rather than invented ones. Run this only when the service
definitions change; the output is committed so the ingest is reproducible.

    python scripts/make_example_lockfiles.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import quote

import httpx

DEPSDEV = "https://api.deps.dev/v3alpha"
OUT_DIR = Path("examples")

# name -> (version, is_dev). Chosen to look like an application that shipped a
# while ago and never got its dependencies bumped.
SERVICES: dict[str, dict[str, tuple[str, bool]]] = {
    "checkout-api": {
        "express": ("4.17.1", False),
        "body-parser": ("1.19.0", False),
        "lodash": ("4.17.15", False),
        "jsonwebtoken": ("8.5.1", False),
        "axios": ("0.21.1", False),
        "moment": ("2.24.0", False),
        "mocha": ("7.2.0", True),
    },
    "admin-dashboard": {
        "react": ("16.13.1", False),
        "react-dom": ("16.13.1", False),
        "axios": ("0.19.2", False),
        "styled-components": ("5.1.1", False),
        "lodash": ("4.17.11", False),
        "webpack": ("4.43.0", True),
        "eslint": ("6.8.0", True),
    },
    "data-worker": {
        "node-fetch": ("2.6.0", False),
        "ws": ("7.2.0", False),
        "minimist": ("1.2.0", False),
        "tar": ("4.4.10", False),
        "mongoose": ("5.9.0", False),
        "yargs-parser": ("13.1.1", False),
        "debug": ("2.6.9", False),
    },
}


# A fourth service reproduces the case the product exists for: a developer
# typo'd a dependency name and installed real malware. The package names and the
# MAL advisories are real OSV records; the *versions* are reconstructed, because
# npm has already removed the malicious releases - checked on 2026-08-14, every
# one of these names now resolves to a single placeholder release,
# `0.0.1-security`, with the original versions gone. That is exactly why the
# advisories offer no fixed version to upgrade to.
TYPOSQUAT_SERVICE = "typosquat-incident"
TYPOSQUAT_PINS: dict[str, str] = {
    "expess": "4.18.2",     # typo of express,   MAL-2025-20061
    "chalkk": "5.3.0",      # typo of chalk,     MAL-2025-16776
    "comander": "9.4.1",    # typo of commander, MAL-2025-17378
    "fodash": "4.17.21",    # typo of lodash,    MAL-2025-20735
    "axioss": "1.6.2",      # typo of axios,     MAL-2025-15242
}
# The healthy dependencies this service also has, so the malware sits inside a
# realistic tree rather than alone.
TYPOSQUAT_HEALTHY: dict[str, tuple[str, bool]] = {
    "express": ("4.18.2", False),
    "chalk": ("4.1.2", False),
}


async def resolve(client: httpx.AsyncClient, name: str, version: str) -> dict:
    url = (
        f"{DEPSDEV}/systems/npm/packages/{quote(name, safe='')}"
        f"/versions/{quote(version, safe='')}:dependencies"
    )
    response = await client.get(url)
    if response.status_code != 200:
        raise SystemExit(f"deps.dev has no resolution for {name}@{version} ({response.status_code})")
    return response.json()


async def build(service: str, pins: dict[str, tuple[str, bool]]) -> dict:
    packages: dict[str, dict] = {}
    root_dependencies: dict[str, str] = {}
    root_dev: dict[str, str] = {}
    # (name, version) -> {child name: requirement}. A real npm lockfile records
    # these per entry, and they are the only thing that says *who* pulled a
    # transitive package in - without them the tree is a flat bag of versions.
    requirements: dict[tuple[str, str], dict[str, str]] = {}

    async with httpx.AsyncClient(timeout=60) as client:
        for name, (version, is_dev) in pins.items():
            document = await resolve(client, name, version)
            (root_dev if is_dev else root_dependencies)[name] = f"^{version}"
            nodes = document.get("nodes") or []
            keys: list[tuple[str, str] | None] = []
            for node in nodes:
                key = node.get("versionKey") or {}
                node_name, node_version = key.get("name"), key.get("version")
                keys.append((node_name, node_version) if node_name and node_version else None)
            for edge in document.get("edges") or []:
                parent = keys[edge["fromNode"]] if edge.get("fromNode", -1) < len(keys) else None
                child = keys[edge["toNode"]] if edge.get("toNode", -1) < len(keys) else None
                if not parent or not child:
                    continue
                requirements.setdefault(parent, {})[child[0]] = edge.get("requirement") or "*"
            for node in nodes:
                node_name = (node.get("versionKey") or {}).get("name")
                node_version = (node.get("versionKey") or {}).get("version")
                if not node_name or not node_version:
                    continue
                path = f"node_modules/{node_name}"
                entry = packages.get(path)
                if entry is None:
                    packages[path] = {"version": node_version, **({"dev": True} if is_dev else {})}
                elif entry["version"] != node_version:
                    # A real lockfile nests a conflicting version under the
                    # dependent that needs it, so mirror that instead of
                    # silently overwriting the first resolution.
                    packages[f"node_modules/{name}/node_modules/{node_name}"] = {
                        "version": node_version,
                        **({"dev": True} if is_dev else {}),
                    }
                elif not is_dev:
                    entry.pop("dev", None)

    # Attach each entry's requirement map, matched on the exact version that
    # entry pins - a name alone would attach the wrong package's requirements
    # whenever two versions of it coexist in the tree.
    for path, entry in packages.items():
        name = path.rsplit("node_modules/", 1)[-1]
        entry_requirements = requirements.get((name, entry["version"]))
        if entry_requirements:
            entry["dependencies"] = dict(sorted(entry_requirements.items()))

    root: dict = {"name": service, "dependencies": root_dependencies}
    if root_dev:
        root["devDependencies"] = root_dev
    return {
        "name": service,
        "lockfileVersion": 3,
        # A lockfile has no date of its own. Real repositories answer this with
        # the commit that last touched the file (blastradius reads that when the
        # clone has it); these examples state it, so every run agrees on when
        # each service's snapshot was taken.
        "blastradiusCapturedAt": CAPTURED_AT[service],
        "requires": True,
        "packages": {"": root, **dict(sorted(packages.items()))},
    }


#: When each example snapshot was taken. The spread is the point: the incident
#: lockfile is days old, the admin dashboard's is from last November - before the
#: advisory that names one of its versions was published.
CAPTURED_AT = {
    "checkout-api": "2026-06-02T09:14:00Z",
    "admin-dashboard": "2025-11-18T16:40:00Z",
    "data-worker": "2026-02-10T11:05:00Z",
    "typosquat-incident": "2026-08-11T08:30:00Z",
}


async def build_typosquat() -> dict:
    lock = await build(TYPOSQUAT_SERVICE, TYPOSQUAT_HEALTHY)
    root = lock["packages"][""]
    for name, version in TYPOSQUAT_PINS.items():
        root["dependencies"][name] = f"^{version}"
        lock["packages"][f"node_modules/{name}"] = {"version": version}
    lock["packages"] = {"": root, **dict(sorted(
        (path, entry) for path, entry in lock["packages"].items() if path
    ))}
    lock["comment"] = (
        "Reconstructed incident snapshot: the typosquat package names and their "
        "MAL advisories are real OSV records, the malicious version numbers are "
        "reconstructed because npm removed the original releases."
    )
    return lock


async def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for service, pins in SERVICES.items():
        lock = await build(service, pins)
        path = OUT_DIR / f"{service}.lock.json"
        path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        print(f"{path}: {len(lock['packages']) - 1} resolved packages")

    lock = await build_typosquat()
    path = OUT_DIR / f"{TYPOSQUAT_SERVICE}.lock.json"
    path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"{path}: {len(lock['packages']) - 1} resolved packages "
          f"({len(TYPOSQUAT_PINS)} of them malicious)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
