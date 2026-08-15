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
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .versions import range_admits, sort_versions

#: npm ignores unknown top-level keys, so an example lockfile can state the date
#: it represents without becoming an invalid lockfile.
CAPTURED_AT_FIELD = "blastradiusCapturedAt"


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


@dataclass(frozen=True)
class Edge:
    """One "this pinned version needs that pinned version" link.

    Read out of the lockfile itself rather than re-resolved from the registry:
    the registry only knows what *today's* releases need, while the deployment
    that is being audited shipped the versions in this file. Building the graph
    from anything else silently attaches the paths to the wrong nodes.
    """

    parent: str  # name@version
    child: str  # name@version
    requirement: str = ""

    @property
    def edge_key(self) -> tuple[str, str]:
        return (self.parent, self.child)


@dataclass
class Lockfile:
    service: str
    lockfile_version: int
    pins: list[Pin] = field(default_factory=list)
    requirements: dict[str, str] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    #: When this file was last changed, epoch seconds, or ``None`` when unknown.
    #: A lockfile has no timestamp of its own, so this comes from the commit that
    #: last touched it. It is what turns "you are exposed" into "you were already
    #: shipping this on 18 November, three weeks before anyone disclosed it" - and
    #: when it is unknown it stays ``None`` rather than quietly becoming today.
    captured_at: int | None = None
    #: How ``direct`` was decided. ``"manifest"`` means a package.json (or the
    #: v2/v3 root entry) named the dependencies outright. ``"inferred"`` means a
    #: v1 lockfile with no manifest next to it: npm 6 hoists transitive packages
    #: to the top level, so "top level" alone does not mean "direct", and the
    #: flag says so instead of letting the number be read as fact.
    direct_source: str = "manifest"

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


DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def _scopes(path: str) -> list[str]:
    """Where npm looks for a dependency of ``path``, nearest scope first.

    ``node_modules/a/node_modules/b`` searches its own folder, then ``a``'s,
    then the root - which is how two versions of the same package can coexist
    and why a name alone is not enough to identify an edge.
    """
    prefixes = [path]
    while True:
        cut = path.rfind("/node_modules/")
        if cut == -1:
            break
        path = path[:cut]
        prefixes.append(path)
    prefixes.append("")
    return prefixes


def _resolve_child(
    parent_path: str,
    child: str,
    requirement: str,
    entries: dict[str, Pin],
    by_name: dict[str, list[Pin]],
) -> Pin | None:
    """Find the pin a requirement resolves to, npm's lookup order first."""
    for scope in _scopes(parent_path):
        candidate = f"{scope}/node_modules/{child}" if scope else f"node_modules/{child}"
        pin = entries.get(candidate)
        if pin is not None:
            return pin
    # A lockfile can be hand-written or trimmed, so fall back to the pins that
    # carry the right name - but only to one the requirement actually admits.
    # A lone candidate used to be returned without that check, which invented an
    # edge to a version the parent could never have resolved; the promise in the
    # line below is that an unresolvable requirement produces no edge at all.
    candidates = by_name.get(child) or []
    if not requirement:
        return candidates[0] if len(candidates) == 1 else None
    admitted = [pin for pin in candidates if range_admits(requirement, pin.version)]
    if len(admitted) == 1:
        return admitted[0]
    if admitted:
        # Several pins satisfy it; the highest is what npm would have installed.
        newest = sort_versions([pin.version for pin in admitted])[-1:]
        for pin in admitted:
            if newest and pin.version == newest[0]:
                return pin
        return admitted[0]
    return None


def _manifest_dependencies(source: Path | None) -> dict[str, str] | None:
    """The package.json next to a lockfile, when there is one.

    npm 6 hoists transitive packages into the top level of a v1 lockfile, so the
    lockfile alone cannot say which dependencies a service actually declared.
    The manifest can, and when it is there it is the answer.
    """
    if source is None:
        return None
    manifest = source.parent / "package.json"
    try:
        document = json.loads(manifest.read_text())
    except (OSError, ValueError):
        return None
    declared: dict[str, str] = {}
    for section in DEPENDENCY_SECTIONS:
        for name, requirement in (document.get(section) or {}).items():
            declared[name] = str(requirement)
    return declared


def parse_lockfile(
    text: str, service: str | None = None, *, source: Path | None = None
) -> Lockfile:
    # NB: ``path`` is used as a loop variable below for lockfile entry paths, so
    # the file this text came from is called ``source`` on purpose.
    document = json.loads(text)
    version = int(document.get("lockfileVersion", 1))
    name = service or document.get("name") or "service"
    pins: dict[str, Pin] = {}
    requirements: dict[str, str] = {}
    edges: dict[tuple[str, str], Edge] = {}

    packages = document.get("packages")
    if isinstance(packages, dict) and packages:
        root = packages.get("", {})
        for section in DEPENDENCY_SECTIONS:
            for dependency, requirement in (root.get(section) or {}).items():
                requirements[dependency] = requirement
        direct_names = set(requirements)
        entries: dict[str, Pin] = {}
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
            entries[path] = pin

        by_name: dict[str, list[Pin]] = {}
        for pin in pins.values():
            by_name.setdefault(pin.name, []).append(pin)
        for path, entry in packages.items():
            parent = entries.get(path)
            if parent is None or not isinstance(entry, dict):
                continue
            for section in DEPENDENCY_SECTIONS:
                for child, requirement in (entry.get(section) or {}).items():
                    resolved = _resolve_child(path, child, requirement or "", entries, by_name)
                    if resolved is None or resolved.key == parent.key:
                        continue
                    edge = Edge(parent.key, resolved.key, requirement or "")
                    edges.setdefault(edge.edge_key, edge)

    # v1, and the legacy mirror kept inside v2 lockfiles.
    direct_source = "manifest"
    if not pins:
        declared = _manifest_dependencies(source)
        if declared is None:
            # No manifest: a top-level entry that some other package requires is
            # more likely hoisted than declared, so it is not called direct. The
            # verdict is marked inferred either way.
            direct_source = "inferred"
            required_names: set[str] = set()

            def collect(tree: dict) -> None:
                for entry in (tree or {}).values():
                    if not isinstance(entry, dict):
                        continue
                    required_names.update((entry.get("requires") or {}).keys())
                    collect(entry.get("dependencies") or {})

            collect(document.get("dependencies") or {})
        else:
            required_names = set()
        # v1 nests the tree instead of listing paths, so the scope chain is
        # built while walking: a package resolves a requirement in its own
        # `dependencies` first, then in each enclosing level.
        pending: list[tuple[Pin, dict, list[dict[str, Pin]]]] = []

        def walk(tree: dict, depth: int, chain: list[dict[str, Pin]]) -> None:
            level: dict[str, Pin] = {}
            for package_name, entry in (tree or {}).items():
                if not isinstance(entry, dict):
                    continue
                package_version = entry.get("version")
                if not package_version:
                    continue
                if declared is not None:
                    is_direct = package_name in declared
                else:
                    is_direct = depth == 0 and package_name not in required_names
                pin = Pin(
                    name=package_name,
                    version=package_version,
                    direct=is_direct,
                    dev=bool(entry.get("dev")),
                )
                pins[pin.key] = pin
                level[package_name] = pin
                if declared is not None and package_name in declared:
                    # The requirement is what the manifest asked for. Inventing
                    # `^{version}` from the resolved pin, as this used to, states
                    # a range the project never wrote down.
                    requirements.setdefault(package_name, declared[package_name])
            scope = [level, *chain]
            for package_name, entry in (tree or {}).items():
                if not isinstance(entry, dict) or package_name not in level:
                    continue
                nested = entry.get("dependencies") or {}
                walk(nested, depth + 1, scope)
                pending.append((level[package_name], entry, scope))

        walk(document.get("dependencies") or {}, 0, [])

        nested_levels: dict[str, dict[str, Pin]] = {}
        for pin, entry, _scope in pending:
            nested_levels[pin.key] = {
                child_name: pins[f"{child_name}@{child['version']}"]
                for child_name, child in (entry.get("dependencies") or {}).items()
                if isinstance(child, dict) and child.get("version")
                and f"{child_name}@{child['version']}" in pins
            }
        for pin, entry, scope in pending:
            requires = entry.get("requires")
            if not isinstance(requires, dict):
                continue
            for child_name, requirement in requires.items():
                child_pin = nested_levels.get(pin.key, {}).get(child_name)
                if child_pin is None:
                    for level in scope:
                        if child_name in level:
                            child_pin = level[child_name]
                            break
                if child_pin is None or child_pin.key == pin.key:
                    continue
                edge = Edge(pin.key, child_pin.key, str(requirement or ""))
                edges.setdefault(edge.edge_key, edge)

    return Lockfile(
        service=name,
        lockfile_version=version,
        pins=sorted(pins.values(), key=lambda pin: pin.key),
        requirements=requirements,
        edges=sorted(edges.values(), key=lambda edge: edge.edge_key),
        captured_at=_captured_at(document, source),
        direct_source=direct_source,
    )


def git_commit_time(path: Path) -> int | None:
    """When the repository last changed this lockfile, epoch seconds.

    This is the real-world source of a snapshot date: a lockfile carries no
    timestamp, and a file's mtime is the moment it was checked out, not the
    moment it was written. Returns ``None`` outside a repository, on a shallow
    clone that does not contain the last commit to touch the file, or when git
    is not installed - all of which are normal, and none of which may be
    answered with a guess.
    """
    try:
        finished = subprocess.run(
            ["git", "log", "-1", "--format=%ct", "--", path.name],
            cwd=path.parent, capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    stamp = finished.stdout.strip()
    return int(stamp) if finished.returncode == 0 and stamp.isdigit() else None


def _captured_at(document: dict, path: Path | None) -> int | None:
    """The snapshot date: what the file says, else what the repository says."""
    stated = document.get(CAPTURED_AT_FIELD)
    if isinstance(stated, str) and stated:
        try:
            parsed = datetime.fromisoformat(stated.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            # UTC is the fallback for a naive timestamp, never an override for a
            # stated one: replacing a real +05:00 offset with UTC would keep the
            # wall clock and move the instant, and this field is what every
            # "were you shipping it while it was live" answer is measured from.
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp())
    if isinstance(stated, int) and not isinstance(stated, bool):
        return stated
    return git_commit_time(path) if path is not None else None


def load_lockfile(path: str | Path, service: str | None = None) -> Lockfile:
    file_path = Path(path)
    return parse_lockfile(
        file_path.read_text(), service or file_path.parent.name, source=file_path
    )


def merge_names(lockfiles: Iterable[Lockfile]) -> set[str]:
    names: set[str] = set()
    for lockfile in lockfiles:
        names |= lockfile.names()
    return names
