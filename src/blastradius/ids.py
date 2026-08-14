"""Deterministic integer identities for graph vertices.

HydraDB matches nodes on a non-negative integer ``id``; there is no string
primary key and ``WHERE ... IN`` does not exist, so every entity name has to
become a stable number *before* it reaches the database.  Hashing rather than
counting keeps the mapping deterministic across machines and across runs, which
means an ingest can resume, and a query built on one host resolves the same ids
on another.

Ids are 62-bit so they stay well inside both JSON's safe integer range for
consumers and the server's ``u64`` vertex space.  Every id carries a 4-bit
type tag in its low bits, which makes an id self-describing when it shows up
in a path result.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# Type tags. Keep stable: changing one invalidates every stored graph.
KIND_PACKAGE = 0
KIND_VERSION = 1
KIND_MAINTAINER = 2
KIND_ADVISORY = 3
KIND_SERVICE = 4

KIND_NAMES = {
    KIND_PACKAGE: "Pkg",
    KIND_VERSION: "Ver",
    KIND_MAINTAINER: "Maint",
    KIND_ADVISORY: "Adv",
    KIND_SERVICE: "Svc",
}

_TAG_BITS = 4
_TAG_MASK = (1 << _TAG_BITS) - 1
_MAX_ID = (1 << 62) - 1


def make_id(kind: int, key: str) -> int:
    """Hash ``key`` into a tagged, stable vertex id."""
    if kind < 0 or kind > _TAG_MASK:
        raise ValueError(f"kind {kind} does not fit in {_TAG_BITS} bits")
    digest = hashlib.blake2b(key.encode("utf-8"), digest_size=8).digest()
    value = int.from_bytes(digest, "big") >> (64 - 62 + _TAG_BITS)
    return ((value << _TAG_BITS) | kind) & _MAX_ID


def kind_of(vertex_id: int) -> int:
    return vertex_id & _TAG_MASK


def kind_name(vertex_id: int) -> str:
    return KIND_NAMES.get(kind_of(vertex_id), "Unknown")


def package_id(name: str) -> int:
    return make_id(KIND_PACKAGE, name)


def version_id(name: str, version: str) -> int:
    return make_id(KIND_VERSION, f"{name}@{version}")


def maintainer_id(login: str) -> int:
    return make_id(KIND_MAINTAINER, login.lower())


def advisory_id(osv_id: str) -> int:
    return make_id(KIND_ADVISORY, osv_id)


def service_id(name: str) -> int:
    return make_id(KIND_SERVICE, name)


@dataclass
class IdBook:
    """Remembers what each generated id stood for.

    The graph stores names as properties too, but the ingest needs a local
    reverse map to build queries and to prove that no two distinct names
    collided onto one id — a silent collision would merge two packages and
    quietly corrupt every blast-radius answer, so it raises instead.
    """

    names: dict[int, str] = field(default_factory=dict)
    collisions: int = 0

    def record(self, vertex_id: int, name: str) -> int:
        existing = self.names.get(vertex_id)
        if existing is None:
            self.names[vertex_id] = name
            return vertex_id
        if existing != name:
            self.collisions += 1
            raise ValueError(
                f"vertex id collision: {vertex_id} claimed by {existing!r} and {name!r}"
            )
        return vertex_id

    def package(self, name: str) -> int:
        return self.record(package_id(name), name)

    def version(self, name: str, version: str) -> int:
        return self.record(version_id(name, version), f"{name}@{version}")

    def maintainer(self, login: str) -> int:
        return self.record(maintainer_id(login), login.lower())

    def advisory(self, osv_id: str) -> int:
        return self.record(advisory_id(osv_id), osv_id)

    def service(self, name: str) -> int:
        return self.record(service_id(name), name)

    def __len__(self) -> int:
        return len(self.names)
