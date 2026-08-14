"""Parse the OSV npm advisory corpus into flat, ingestable records.

The corpus is one JSON document per advisory inside ``npm/all.zip``
(226,795 files / 372 MB uncompressed as of 2026-08-13).  Two very different
populations live in that file and the difference drives the whole product:

* ``MAL-*`` — malicious packages (96.8% of the corpus).  These almost never
  carry a ``fixed`` event, because a malicious package is not patched, it is
  removed.  The only meaningful question is *were you exposed, and when*.
* ``GHSA-*`` — reviewed vulnerabilities in legitimate packages, which do carry
  ``introduced``/``fixed`` ranges and are answered by "upgrade past the fix".

Both are normalised into :class:`Advisory` with an explicit ``kind`` so the
graph can answer them differently.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

OSV_NPM_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"


def parse_timestamp(value: str | None) -> int | None:
    """RFC3339 → epoch seconds.  OSV mixes ``Z`` and offset forms."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


@dataclass
class AffectedRange:
    """One ``introduced``/``fixed`` window for a package.

    ``fixed`` is exclusive (the first version that is safe), ``last_affected``
    is inclusive.  OSV guarantees at most one of the two.
    """

    introduced: str = "0"
    fixed: str | None = None
    last_affected: str | None = None


@dataclass
class Affected:
    package: str
    ranges: list[AffectedRange] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)


@dataclass
class Advisory:
    id: str
    kind: str  # "malicious" | "vulnerability"
    published: int | None
    modified: int | None
    withdrawn: int | None
    summary: str
    aliases: list[str]
    severity: str  # CRITICAL | HIGH | MODERATE | LOW | UNKNOWN
    cvss_vector: str
    affected: list[Affected]

    @property
    def is_malicious(self) -> bool:
        return self.kind == "malicious"

    @property
    def packages(self) -> list[str]:
        return [entry.package for entry in self.affected]

    @property
    def has_fix(self) -> bool:
        return any(rng.fixed for entry in self.affected for rng in entry.ranges)


_CVSS_PREFERENCE = {"CVSS_V4": 1, "CVSS_V3": 2, "CVSS_V2": 3}
SEVERITIES = ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")


def _cvss_vector(raw: list[dict]) -> str:
    """OSV stores CVSS as a vector string, never a base score.

    Deriving a numeric score would mean implementing the CVSS formula, so the
    vector is carried verbatim and the qualitative label from
    ``database_specific.severity`` is used for ranking instead.
    """
    best: tuple[int, str] | None = None
    for entry in raw or []:
        rank = _CVSS_PREFERENCE.get(entry.get("type", ""), 9)
        score = str(entry.get("score") or "")
        if score and (best is None or rank < best[0]):
            best = (rank, score)
    return best[1] if best else ""


def parse_advisory(document: dict) -> Advisory:
    identifier = document.get("id", "")
    database_specific = document.get("database_specific") or {}
    affected: list[Affected] = []
    for entry in document.get("affected", []):
        package = (entry.get("package") or {}).get("name")
        if not package:
            continue
        ranges: list[AffectedRange] = []
        for raw_range in entry.get("ranges", []):
            if raw_range.get("type") != "SEMVER":
                continue
            current = AffectedRange()
            opened = False
            for event in raw_range.get("events", []):
                if "introduced" in event:
                    if opened:
                        ranges.append(current)
                    current = AffectedRange(introduced=event["introduced"])
                    opened = True
                elif "fixed" in event:
                    current.fixed = event["fixed"]
                elif "last_affected" in event:
                    current.last_affected = event["last_affected"]
            if opened:
                ranges.append(current)
        affected.append(
            Affected(
                package=package,
                ranges=ranges,
                versions=list(entry.get("versions") or []),
            )
        )

    return Advisory(
        id=identifier,
        kind="malicious" if identifier.startswith("MAL-") else "vulnerability",
        published=parse_timestamp(document.get("published")),
        modified=parse_timestamp(document.get("modified")),
        withdrawn=parse_timestamp(document.get("withdrawn")),
        summary=(document.get("summary") or "").strip()[:400],
        aliases=list(document.get("aliases") or []),
        severity=str(database_specific.get("severity") or "UNKNOWN").upper(),
        cvss_vector=_cvss_vector(document.get("severity", [])),
        affected=affected,
    )


@dataclass(frozen=True)
class CorpusStats:
    """The ecosystem counts quoted in the README, derived not hand-counted."""

    advisories: int = 0
    malicious: int = 0
    malicious_with_fix: int = 0
    vulnerabilities: int = 0
    vulnerabilities_without_fix: int = 0
    withdrawn: int = 0
    packages: int = 0
    first_published: int | None = None
    last_published: int | None = None

    @property
    def malicious_share(self) -> float:
        return self.malicious / self.advisories if self.advisories else 0.0


def summarise(advisories: Iterable[Advisory]) -> CorpusStats:
    """Fold a stream of advisories into the corpus counts.

    Streaming, because the npm dump does not fit comfortably in memory as parsed
    objects and the whole point is that these numbers stay reproducible.
    """
    counts = dict(
        advisories=0,
        malicious=0,
        malicious_with_fix=0,
        vulnerabilities=0,
        vulnerabilities_without_fix=0,
        withdrawn=0,
    )
    packages: set[str] = set()
    first: int | None = None
    last: int | None = None

    for advisory in advisories:
        counts["advisories"] += 1
        if advisory.withdrawn is not None:
            counts["withdrawn"] += 1
        if advisory.is_malicious:
            counts["malicious"] += 1
            if advisory.has_fix:
                counts["malicious_with_fix"] += 1
        else:
            counts["vulnerabilities"] += 1
            if not advisory.has_fix:
                counts["vulnerabilities_without_fix"] += 1
        packages.update(advisory.packages)
        if advisory.published is not None:
            first = advisory.published if first is None else min(first, advisory.published)
            last = advisory.published if last is None else max(last, advisory.published)

    return CorpusStats(
        packages=len(packages), first_published=first, last_published=last, **counts
    )


def iter_advisories(archive_path: str | Path, limit: int | None = None) -> Iterator[Advisory]:
    """Stream advisories out of the OSV zip without unpacking it to disk."""
    with zipfile.ZipFile(archive_path) as archive:
        for index, name in enumerate(archive.namelist()):
            if limit is not None and index >= limit:
                return
            if not name.endswith(".json"):
                continue
            yield parse_advisory(json.loads(archive.read(name)))


def advisories_by_package(archive_path: str | Path) -> dict[str, list[Advisory]]:
    """Index the corpus by affected package name.

    Kept deliberately simple: the whole corpus is ~370 MB of JSON but only the
    normalised subset is retained, which fits comfortably in memory.
    """
    index: dict[str, list[Advisory]] = {}
    for advisory in iter_advisories(archive_path):
        if advisory.withdrawn:
            continue
        for entry in advisory.affected:
            index.setdefault(entry.package, []).append(advisory)
    return index
