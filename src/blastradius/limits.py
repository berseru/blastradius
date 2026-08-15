"""The bounds every caller shares, in one place, with truncation made visible.

Two separate problems used to live in the call sites. The traversal bounds were
written as bare numbers next to each query, so the CLI, the web API and the
self-test could drift apart without anything failing. And the sample caps -
``[:25]``, ``[:60]`` - silently dropped inputs in lexicographic order, so a
service with thirty vulnerable versions was answered from the first twenty-five
and the answer said nothing about the other five.

Both are answered here: the constants are imported rather than retyped, and
:func:`capped` returns the flag that lets a response admit it was truncated.
"""

from __future__ import annotations

from typing import Sequence, TypeVar

#: Longest DEPENDS chain a blast-radius path may take.
CHAIN_MAX_LEN = 6
#: Deepest hop counted when profiling a service's dependency depth.
DEPTH_MAX_LEN = 4
#: How many path endpoints (bad versions, entry points) one request samples.
ENDPOINT_SAMPLE = 25
#: How many service entry points a whole-graph package query samples.
GRAPH_TARGET_SAMPLE = 60

T = TypeVar("T")


def capped(values: Sequence[T], limit: int) -> tuple[list[T], bool]:
    """Return ``(values[:limit], was_truncated)``.

    The caller is expected to carry the flag into its response. A cap that is
    not reported is an answer that quietly stopped being complete.
    """
    return list(values[:limit]), len(values) > limit
