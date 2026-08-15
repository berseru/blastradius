"""Semver questions the graph cannot answer on its own.

Two different jobs live here and they are easy to confuse:

* :func:`is_affected` — does a *concrete* version fall inside an advisory's
  affected window?  This decides whether an ``AFFECTS`` edge exists at all.
* :func:`range_admits` — would a *requirement range* in a lockfile edge have
  resolved to a given version?  This is what makes the temporal question
  answerable: a service pinned to ``^4.17.0`` was reachable by the malicious
  ``4.17.21`` the moment it was published, even if the lockfile today shows a
  later, clean version.

``node-semver`` implements npm's own comparison rules, so neither is
re-implemented here.
"""

from __future__ import annotations

from functools import lru_cache

import nodesemver as node_semver

# node-semver's Python port takes ``loose`` as a required positional argument
# on some entry points and as a keyword on others; every call site below passes
# it explicitly so a signature mismatch fails loudly instead of being swallowed
# by an over-broad ``except`` and silently reported as "not affected".
_SEMVER_ERRORS = (ValueError, AttributeError, IndexError)


@lru_cache(maxsize=200_000)
def _valid(version: str) -> bool:
    if not version:
        return False
    try:
        return node_semver.valid(version, True) is not None
    except _SEMVER_ERRORS:
        return False


@lru_cache(maxsize=500_000)
def _compare(left: str, right: str) -> int | None:
    try:
        return node_semver.compare(left, right, True)
    except _SEMVER_ERRORS:
        return None


def is_affected(
    version: str,
    introduced: str = "0",
    fixed: str | None = None,
    last_affected: str | None = None,
) -> bool:
    """OSV window membership: ``introduced <= version``, then the upper bound.

    ``fixed`` is exclusive, ``last_affected`` is inclusive, and OSV guarantees
    at most one of them per range.  An unparseable version is treated as *not*
    affected rather than guessed at, and the caller counts those separately.
    """
    if not _valid(version):
        return False
    if introduced not in ("0", "", None):
        result = _compare(version, introduced)
        if result is None or result < 0:
            return False
    if fixed:
        result = _compare(version, fixed)
        if result is None or result >= 0:
            return False
    if last_affected:
        result = _compare(version, last_affected)
        if result is None or result > 0:
            return False
    return True


@lru_cache(maxsize=200_000)
def range_admits(requirement: str, version: str) -> bool:
    """Would ``requirement`` have resolved to ``version``?

    Empty, ``*`` and ``latest`` requirements admit everything.  Non-registry
    requirements (git URLs, ``file:`` paths, aliases) admit nothing, because
    they never resolve from the registry and pretending otherwise would inflate
    the blast radius.
    """
    if not version or not _valid(version):
        return False
    requirement = (requirement or "").strip()
    if requirement in ("", "*", "latest", "x", "X"):
        return True
    if any(
        requirement.startswith(prefix)
        for prefix in ("git", "http", "file:", "link:", "npm:", "workspace:", "github:")
    ):
        return False
    try:
        return bool(node_semver.satisfies(version, requirement, True))
    except _SEMVER_ERRORS:  # an unparseable range is not exposure
        return False


def sort_versions(versions: list[str]) -> list[str]:
    """Ascending semver order, ignoring anything unparseable."""
    valid = [version for version in versions if _valid(version)]
    return sorted(valid, key=_SortKey)


class _SortKey:
    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __lt__(self, other: "_SortKey") -> bool:
        result = _compare(self.value, other.value)
        return bool(result is not None and result < 0)
