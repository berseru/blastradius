"""Check the graph's answers against the live OSV API, independently.

The pipeline learns everything it knows from one 220 MB snapshot of the OSV npm
dump, parsed by this project's own code. If that parsing is subtly wrong -- a
range boundary off by one, a prerelease compared as a release, the wrong
timestamp field read as the disclosure date -- every number downstream is wrong
in the same direction, and every test written against the same parser agrees
with it.

So this module asks a different source (``api.osv.dev``, per advisory, live)
and compares five things per sampled hit: that OSV agrees the exact version is
affected, the disclosure date, the severity, whether a fix exists, and whether
the advisory is malware or a vulnerability.

The semver comparison here is written from scratch and does **not** import the
project's ``versions`` module. That is the entire point: agreement between two
independent implementations is evidence, agreement between a module and itself
is a tautology.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OSV_API = "https://api.osv.dev/v1/vulns"


# -- an independent semver, deliberately not the project's ------------------


def parse_version(text: str) -> tuple[list[int], str]:
    core, _, _build = text.partition("+")
    core, _, prerelease = core.partition("-")
    parts = (core.split(".") + ["0", "0"])[:3]
    numbers = [int(part) if part.isdigit() else 0 for part in parts]
    return numbers, prerelease


def _prerelease_key(prerelease: str) -> list[tuple[int, int, str]]:
    """SemVer §11 precedence: dot-separated identifiers, numeric ones compared as
    numbers and always below alphanumeric ones. Comparing the raw strings instead
    would order ``1.0.0-9`` above ``1.0.0-10``, and this comparator exists to
    disagree with the pipeline when the pipeline is wrong, not to invent its own
    wrong answers."""
    key: list[tuple[int, int, str]] = []
    for identifier in prerelease.split("."):
        if identifier.isdigit():
            key.append((0, int(identifier), ""))
        else:
            key.append((1, 0, identifier))
    return key


def compare(left: str, right: str) -> int:
    (left_numbers, left_pre), (right_numbers, right_pre) = parse_version(left), parse_version(right)
    if left_numbers != right_numbers:
        return -1 if left_numbers < right_numbers else 1
    if left_pre == right_pre:
        return 0
    if not left_pre:  # 1.0.0 > 1.0.0-rc.1
        return 1
    if not right_pre:
        return -1
    left_key, right_key = _prerelease_key(left_pre), _prerelease_key(right_pre)
    if left_key == right_key:
        return 0
    return -1 if left_key < right_key else 1


def osv_affects(record: dict, name: str, version: str) -> tuple[bool, str]:
    """Does OSV itself say this exact version is affected, and on what grounds?"""
    for entry in record.get("affected", []):
        package = entry.get("package") or {}
        if package.get("ecosystem") != "npm" or package.get("name") != name:
            continue
        listed = entry.get("versions") or []
        if listed and version in listed:
            return True, f"listed among {len(listed)} affected versions"
        for span in entry.get("ranges") or []:
            if span.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced = fixed = last_affected = None
            for event in span.get("events") or []:
                introduced = event.get("introduced", introduced)
                fixed = event.get("fixed", fixed)
                last_affected = event.get("last_affected", last_affected)
            if introduced is None:
                continue
            started = introduced in ("0", "0.0.0") or compare(version, introduced) >= 0
            if not started:
                continue
            if fixed and compare(version, fixed) >= 0:
                continue
            if last_affected and compare(version, last_affected) > 0:
                continue
            return True, f"range [{introduced}, {fixed or last_affected or 'open'})"
        if listed:
            return False, f"not among the {len(listed)} listed versions"
    return False, "no npm entry for this package"


def osv_has_fix(record: dict, name: str) -> bool:
    for entry in record.get("affected", []):
        if (entry.get("package") or {}).get("name") != name:
            continue
        for span in entry.get("ranges") or []:
            for event in span.get("events") or []:
                if event.get("fixed"):
                    return True
    return False


def fetch(vuln_id: str, *, retries: int = 3) -> dict:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(f"{OSV_API}/{vuln_id}", timeout=30) as response:
                return json.loads(response.read())
        except Exception as error:  # noqa: BLE001 - retried, then reported
            last = error
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"could not fetch {vuln_id}: {last}")


# -- the comparison ---------------------------------------------------------


@dataclass
class Comparison:
    version: str
    advisory: str
    agrees: bool
    grounds: str = ""
    differences: list[str] = field(default_factory=list)
    unreachable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version, "advisory": self.advisory, "agrees": self.agrees,
            "grounds": self.grounds, "differences": self.differences,
            "unreachable": self.unreachable,
        }


def compare_hit(hit: dict) -> Comparison:
    name, _, version = str(hit["version"]).rpartition("@")
    try:
        record = fetch(hit["advisory"])
    except RuntimeError as error:
        return Comparison(hit["version"], hit["advisory"], True, str(error), unreachable=True)

    affected, grounds = osv_affects(record, name, version)
    differences: list[str] = []
    if not affected:
        differences.append(f"OSV does not mark {version} affected: {grounds}")

    # The graph writes an unknown timestamp as 0 and the API hands it back as
    # null, so this field can legitimately be missing. int(None) used to end the
    # whole crosscheck in a TypeError - one undated advisory taking down the only
    # check that reads a second source.
    raw_disclosed = hit.get("disclosed_at")
    ours_disclosed = (
        time.strftime("%Y-%m-%d", time.gmtime(int(raw_disclosed)))
        if isinstance(raw_disclosed, (int, float)) and raw_disclosed
        else None
    )
    theirs = (record.get("published") or "")[:10]
    if theirs and ours_disclosed is None:
        differences.append(f"no disclosure date here, {theirs} at OSV")
    elif theirs and theirs != ours_disclosed:
        differences.append(f"disclosed {ours_disclosed} here, {theirs} at OSV")

    ours_severity = (hit.get("severity") or "UNKNOWN").upper()
    theirs_severity = ((record.get("database_specific") or {}).get("severity") or "UNKNOWN").upper()
    if ours_severity != theirs_severity:
        differences.append(f"severity {ours_severity} here, {theirs_severity} at OSV")

    if bool(hit.get("has_fix")) != osv_has_fix(record, name):
        differences.append(f"fix available {hit.get('has_fix')} here, {not hit.get('has_fix')} at OSV")

    ours_kind = hit.get("kind")
    theirs_kind = "malicious" if str(hit["advisory"]).startswith("MAL-") else "vulnerability"
    if ours_kind != theirs_kind:
        differences.append(f"kind {ours_kind} here, {theirs_kind} at OSV")

    return Comparison(hit["version"], hit["advisory"], not differences, grounds, differences)


def sample_hits(directory: Path, per_service: int = 7) -> list[dict]:
    """Take hits from both ends of each service's list, not just the first few."""
    chosen: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(directory.glob("api_services_*.json")):
        payload = json.loads(path.read_text())
        hits = payload.get("hits") or []
        half = max(per_service // 2, 1)
        for hit in hits[:half] + hits[-half:]:
            key = (hit["version"], hit["advisory"])
            if key not in seen:
                seen.add(key)
                chosen.append(hit)
    return chosen


def crosscheck(samples: Path, out: Path | None = None) -> dict:
    hits = sample_hits(samples)
    comparisons = [compare_hit(hit) for hit in hits]
    # A hit OSV could not be fetched for was never compared, so it can neither
    # agree nor disagree: counting it as agreement inflates the headline.
    unreachable = [c for c in comparisons if c.unreachable]
    compared = [c for c in comparisons if not c.unreachable]
    disagreements = [c for c in compared if not c.agrees]
    report = {
        "source": OSV_API,
        "checked": len(comparisons),
        "compared": len(compared),
        "agreed": len(compared) - len(disagreements),
        "unreachable": len(unreachable),
        "comparisons": [c.as_dict() for c in comparisons],
    }
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
