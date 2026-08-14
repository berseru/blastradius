"""Find package names that are one keystroke away from a popular package.

Two names being similar is not interesting on its own: ``es-errors`` and
``es-error`` differ by one character and both are ordinary libraries. What makes
a pair worth an edge is the *asymmetry*: a name almost nobody installs sitting
one typo away from a name everybody installs. That is the shape of a typosquat,
so download counts are part of the test and not decoration.

Detection is exact, not heuristic: candidates are found with deletion
neighbourhoods (cheap, no all-pairs comparison) and then confirmed with a real
Damerau-Levenshtein distance, so an edge always means "one insertion, deletion,
substitution or transposition apart".
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

# Shorter names produce mostly noise: `ms` vs `mz`, `qs` vs `q`. Real npm
# typosquat campaigns target names long enough to misread.
MIN_NAME_LENGTH = 4
# The popular side has to actually be popular, or every pair of two unknown
# packages qualifies.
MIN_TARGET_DOWNLOADS = 10_000
# The suspect side has to be obscure relative to it. 1% is deliberately strict:
# real forks and scoped rewrites usually sit far above it.
MAX_DOWNLOADS_RATIO = 0.01
# Downloads are fetched from a public endpoint that can be missing or rate
# limited; unknown counts are written as -1 so a reader never mistakes them for
# "measured zero" (and because HydraDB has no null property value).
UNKNOWN_DOWNLOADS = -1


@dataclass(frozen=True)
class SimilarPair:
    """``suspect`` looks like ``target``, which is far more widely installed."""

    suspect: str
    target: str
    distance: int
    downloads_ratio: float
    suspect_downloads: int
    target_downloads: int


def deletion_keys(name: str) -> set[str]:
    """``name`` plus every string one deletion away from it."""
    keys = {name}
    for index in range(len(name)):
        keys.add(name[:index] + name[index + 1 :])
    return keys


def damerau_distance_within(left: str, right: str, limit: int = 1) -> int | None:
    """Damerau-Levenshtein distance, or ``None`` once it exceeds ``limit``.

    Only the small-limit case is needed, so this stops early instead of filling
    a full matrix for names that are obviously unrelated.
    """
    if abs(len(left) - len(right)) > limit:
        return None
    if left == right:
        return 0
    if len(left) == len(right):
        differences = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
        if len(differences) == 1:
            return 1
        if len(differences) == 2:
            first, second = differences
            if (
                second == first + 1
                and left[first] == right[second]
                and left[second] == right[first]
            ):
                return 1  # transposition
        return None
    longer, shorter = (left, right) if len(left) > len(right) else (right, left)
    for index in range(len(longer)):
        if longer[:index] + longer[index + 1 :] == shorter:
            return 1
    return None


def candidate_pairs(names: Iterable[str]) -> list[tuple[str, str]]:
    """Unordered pairs within Damerau-Levenshtein distance 1.

    Scoped names are compared on their unscoped part as well, because
    ``@types/express`` is not a typosquat of ``express`` but ``expresss`` is.
    """
    buckets: dict[str, set[str]] = defaultdict(set)
    unique = {name for name in names if len(name) >= MIN_NAME_LENGTH}
    for name in unique:
        for key in deletion_keys(name):
            buckets[key].add(name)
    pairs: set[tuple[str, str]] = set()
    for bucket in buckets.values():
        if len(bucket) < 2:
            continue
        ordered = sorted(bucket)
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                if damerau_distance_within(left, right) == 1:
                    pairs.add((left, right))
    return sorted(pairs)


def find_typosquats(
    names: Iterable[str],
    downloads: dict[str, int],
    *,
    min_target_downloads: int = MIN_TARGET_DOWNLOADS,
    max_ratio: float = MAX_DOWNLOADS_RATIO,
    always_suspect: Iterable[str] = (),
) -> list[SimilarPair]:
    """Keep only the pairs where one side is popular and the other is not.

    ``always_suspect`` names (for example packages an advisory already calls
    malware) are kept when the download endpoint has no data for them, which is
    the normal case after npm removes a malicious release. It does **not** waive
    the popularity gap, and an earlier version of this function that did was
    wrong in a way worth recording: it emitted ``color -> colord`` and
    ``synckit -> asynckit``, because OSV names ``color`` and ``synckit`` in
    malicious-release advisories and both are far *more* installed than the
    package they were paired with. Being compromised is not the same as
    impersonating: a compromised popular package is already reported through its
    advisory, and calling it a typosquat of a smaller neighbour is a false
    accusation. Impersonation requires the suspect to be the obscure side.
    """
    forced = set(always_suspect)
    found: list[SimilarPair] = []
    for left, right in candidate_pairs(names):
        left_downloads = downloads.get(left, UNKNOWN_DOWNLOADS)
        right_downloads = downloads.get(right, UNKNOWN_DOWNLOADS)
        for suspect, target, suspect_downloads, target_downloads in (
            (left, right, left_downloads, right_downloads),
            (right, left, right_downloads, left_downloads),
        ):
            if target_downloads < min_target_downloads:
                continue
            if suspect_downloads < 0:
                if suspect not in forced:
                    continue
                ratio = 0.0
            else:
                ratio = suspect_downloads / target_downloads
                if ratio > max_ratio:
                    continue
            found.append(
                SimilarPair(
                    suspect=suspect,
                    target=target,
                    distance=1,
                    # Six significant digits, not six decimals: these ratios are
                    # routinely below 1e-7 and rounding by decimals flattens
                    # them all to the same number.
                    downloads_ratio=float(f"{ratio:.6g}"),
                    suspect_downloads=suspect_downloads,
                    target_downloads=target_downloads,
                )
            )
    return sorted(found, key=lambda pair: (pair.suspect, pair.target))
