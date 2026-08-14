"""Lockfile parsing and the id scheme the whole graph hangs off."""

import json

import pytest

from blastradius.ids import IdBook, kind_name, package_id, version_id
from blastradius.lockfile import parse_lockfile
from blastradius.model import edge_id

V3 = json.dumps(
    {
        "name": "checkout-api",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "checkout-api", "dependencies": {"express": "^4.17.0"}},
            "node_modules/express": {
                "version": "4.18.2",
                "dependencies": {"accepts": "~1.3.8", "debug": "2.6.9"},
            },
            "node_modules/accepts": {"version": "1.3.8", "dependencies": {"debug": "^4.0.0"}},
            "node_modules/debug": {"version": "4.3.4"},
            "node_modules/express/node_modules/debug": {"version": "2.6.9"},
            "node_modules/typescript": {"version": "5.4.0", "dev": True},
            "node_modules/local-link": {"resolved": "../shared", "link": True},
        },
    }
)

V1 = json.dumps(
    {
        "name": "legacy-worker",
        "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "version": "4.16.0",
                "requires": {"debug": "2.6.9", "accepts": "~1.3.5"},
                "dependencies": {
                    "debug": {"version": "2.6.9"},
                    "accepts": {"version": "1.3.5"},
                },
            },
            "mocha": {"version": "9.0.0", "dev": True},
        },
    }
)


class TestLockfile:
    def test_v3_collects_every_resolved_version(self):
        lock = parse_lockfile(V3)
        assert lock.service == "checkout-api"
        assert lock.lockfile_version == 3
        keys = {pin.key for pin in lock.pins}
        assert keys == {
            "express@4.18.2",
            "accepts@1.3.8",
            "debug@2.6.9",
            "debug@4.3.4",
            "typescript@5.4.0",
        }

    def test_v3_marks_direct_and_dev_dependencies(self):
        lock = parse_lockfile(V3)
        assert [pin.name for pin in lock.direct] == ["express"]
        assert {pin.name for pin in lock.pins if pin.dev} == {"typescript"}

    def test_v3_keeps_the_declared_requirement_range(self):
        # The range is what makes the temporal question answerable later.
        assert parse_lockfile(V3).requirements == {"express": "^4.17.0"}

    def test_links_are_skipped(self):
        assert "local-link" not in parse_lockfile(V3).names()

    def test_nested_duplicates_are_distinct_pins(self):
        lock = parse_lockfile(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {},
                        "node_modules/debug": {"version": "4.3.4"},
                        "node_modules/express/node_modules/debug": {"version": "2.6.9"},
                    },
                }
            )
        )
        assert sorted(pin.version for pin in lock.pins if pin.name == "debug") == [
            "2.6.9",
            "4.3.4",
        ]

    def test_v1_tree_is_walked_recursively(self):
        lock = parse_lockfile(V1)
        assert lock.lockfile_version == 1
        assert {pin.key for pin in lock.pins} == {
            "express@4.16.0",
            "debug@2.6.9",
            "accepts@1.3.5",
            "mocha@9.0.0",
        }
        assert {pin.name for pin in lock.direct} == {"express", "mocha"}

    def test_scoped_names_survive_nesting(self):
        lock = parse_lockfile(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {},
                        "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
                    },
                }
            )
        )
        assert lock.pins[0].name == "@scope/b"


class TestLockfileEdges:
    """The edges are the product: without them nothing can be traversed."""

    def test_v3_edges_use_the_versions_this_lockfile_pins(self):
        lock = parse_lockfile(V3)
        assert ("express@4.18.2", "accepts@1.3.8") in {
            (edge.parent, edge.child) for edge in lock.edges
        }

    def test_nearest_nested_copy_wins_over_the_hoisted_one(self):
        """`express` requires debug 2.6.9, nested next to it; the root has 4.3.4."""
        lock = parse_lockfile(V3)
        children = {
            edge.child for edge in lock.edges if edge.parent == "express@4.18.2"
        }
        assert "debug@2.6.9" in children
        assert "debug@4.3.4" not in children

    def test_hoisted_copy_is_used_when_there_is_no_nested_one(self):
        lock = parse_lockfile(V3)
        children = {
            edge.child for edge in lock.edges if edge.parent == "accepts@1.3.8"
        }
        assert children == {"debug@4.3.4"}

    def test_requirement_is_carried_onto_the_edge(self):
        lock = parse_lockfile(V3)
        requirements = {
            (edge.parent, edge.child): edge.requirement for edge in lock.edges
        }
        assert requirements[("express@4.18.2", "accepts@1.3.8")] == "~1.3.8"

    def test_v1_requires_map_becomes_edges(self):
        lock = parse_lockfile(V1)
        pairs = {(edge.parent, edge.child) for edge in lock.edges}
        assert ("express@4.16.0", "debug@2.6.9") in pairs
        assert ("express@4.16.0", "accepts@1.3.5") in pairs

    def test_no_self_edges_and_no_duplicates(self):
        lock = parse_lockfile(V3)
        pairs = [(edge.parent, edge.child) for edge in lock.edges]
        assert len(pairs) == len(set(pairs))
        assert all(parent != child for parent, child in pairs)

    def test_unresolvable_requirement_produces_no_edge(self):
        text = json.dumps(
            {
                "name": "svc",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "svc", "dependencies": {"a": "^1.0.0"}},
                    "node_modules/a": {"version": "1.0.0", "dependencies": {"ghost": "^2"}},
                },
            }
        )
        lock = parse_lockfile(text)
        assert lock.edges == []


class TestIds:
    def test_ids_are_stable_and_typed(self):
        assert package_id("express") == package_id("express")
        assert kind_name(package_id("express")) == "Pkg"
        assert kind_name(version_id("express", "4.18.2")) == "Ver"

    def test_same_name_different_kinds_do_not_clash(self):
        assert package_id("express") != version_id("express", "4.18.2")

    def test_ids_stay_inside_the_safe_integer_range(self):
        # Ids travel through JSON, so they must not exceed 2**53 - 1 ... they do
        # not fit in that, so the guarantee is 62-bit and consumers must treat
        # them as opaque integers, never as JavaScript numbers.
        assert 0 < package_id("express") < 2**62

    def test_id_book_rejects_a_collision(self):
        book = IdBook()
        book.record(42, "one")
        book.record(42, "one")  # idempotent
        with pytest.raises(ValueError, match="collision"):
            book.record(42, "two")

    def test_edge_ids_are_directional(self):
        assert edge_id(1, 2, "DEPENDS") != edge_id(2, 1, "DEPENDS")
        assert edge_id(1, 2, "DEPENDS") != edge_id(1, 2, "USES")
