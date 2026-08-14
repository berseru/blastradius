"""Parse npm lockfiles into the exact set of versions a service ships.

A lockfile is the only artefact that states what a deployment *actually*
resolved, which is why it is the product's input: no guessing, no re-resolution,
no "well it depends on your registry cache".

Three formats are supported:

* v1 (``dependencies`` tree, npm 6)
* v2 (both ``packages`` and ``dependencies``, npm 7-8)
* v3 (``packages`` only, npm 9+)

``yarn.lock`` is deliberately out of scope; it is not JSON and the mapping from
its resolution entries to a concrete tree needs a second parser.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Pin:
    """One resolved package version inside a lockfile."""

    name: str
    version: str
    direct: bool = False
    dev: bool = False

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class Lockfile:
    service: str
    lockfile_version: int
    pins: list[Pin] = field(default_factory=list)
    requirements: dict[str, str] = field(default_factory=dict)

    @property
    def direct(self) -> list[Pin]:
        return [pin for pin in self.pins if pin.direct]

    def names(self) -> set[str]:
        return {pin.name for pin in self.pins}

    def __len__(self) -> int:
        return len(self.pins)


def _name_from_path(path: str) -> str:
    """``node_modules/a/node_modules/@scope/b`` → ``@scope/b``."""
    marker = "node_modules/"
    index = path.rfind(marker)
    if index == -1:
        return path
    return path[index + len(marker) :]


def parse_lockfile(text: str, service: str | None = None) -> Lockfile:
    document = json.loads(text)
    version = int(document.get("lockfileVersion", 1))
    name = service or document.get("name") or "service"
    pins: dict[str, Pin] = {}
    requirements: dict[str, str] = {}

    packages = document.get("packages")
    if isinstance(packages, dict) and packages:
        root = packages.get("", {})
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for dependency, requirement in (root.get(section) or {}).items():
                requirements[dependency] = requirement
        direct_names = set(requirements)
        for path, entry in packages.items():
            if not path or not isinstance(entry, dict):
                continue
            if entry.get("link"):
                continue
            package_name = entry.get("name") or _name_from_path(path)
            package_version = entry.get("version")
            if not package_version:
                continue
            pin = Pin(
                name=package_name,
                version=package_version,
                direct=package_name in direct_names and path.count("node_modules/") == 1,
                dev=bool(entry.get("dev")),
            )
            pins[pin.key] = pin

    # v1, and the legacy mirror kept inside v2 lockfiles.
    if not pins:
        def walk(tree: dict, depth: int) -> None:
            for package_name, entry in (tree or {}).items():
                if not isinstance(entry, dict):
                    continue
                package_version = entry.get("version")
                if package_version:
                    pin = Pin(
                        name=package_name,
                        version=package_version,
                        direct=depth == 0,
                        dev=bool(entry.get("dev")),
                    )
                    pins[pin.key] = pin
                    if depth == 0:
                        requirements.setdefault(package_name, entry.get("requires") or "")
                walk(entry.get("dependencies") or {}, depth + 1)

        walk(document.get("dependencies") or {}, 0)

    return Lockfile(
        service=name,
        lockfile_version=version,
        pins=sorted(pins.values(), key=lambda pin: pin.key),
        requirements=requirements,
    )


def load_lockfile(path: str | Path, service: str | None = None) -> Lockfile:
    file_path = Path(path)
    return parse_lockfile(file_path.read_text(), service or file_path.parent.name)


def merge_names(lockfiles: Iterable[Lockfile]) -> set[str]:
    names: set[str] = set()
    for lockfile in lockfiles:
        names |= lockfile.names()
    return names
