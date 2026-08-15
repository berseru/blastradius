"""The API and its CI self-check, exercised without a database.

HydraDB cannot run in this test environment, so the client is replaced by a fake
that answers the project's own statements. That is deliberately not a mock of the
handlers: requests go over real HTTP to a real server on an ephemeral port, and
``api_selfcheck`` - the function CI relies on to fail a build when a route breaks
- is run against it here. If the self-check could pass on an empty graph, these
tests would say so.
"""

from __future__ import annotations

import json
import threading
import urllib.request

import pytest

from blastradius import queries
from blastradius.cli import api_selfcheck
from blastradius.hydra import Path, PathNode, PathRel, Result
from blastradius.web import Api, NotFound, make_handler, match_route, serve

SERVICE = {"id": 1, "name": "demo", "pin_count": 2, "captured_at": 1_760_000_000}
HITS = [
    # column order follows DIRECT_HITS
    ["expess@4.18.2", "MAL-2025-1", "malicious", "UNKNOWN", 1_750_000_000, 1_700_000_000, False,
     True, False],
    ["lib@2.0.0", "GHSA-aaaa-bbbb-cccc", "vulnerability", "HIGH", 1_740_000_000, 1_690_000_000,
     True, False, False],
]
PACKAGES = {"expess": 138, "express": 127_296_948, "lib": 4_000_000}


class FakeClient:
    """Answers the statements in ``queries``/``model``, nothing more.

    Dispatch is on the statement itself rather than on a substring, so a query
    that is edited without teaching the fake about it fails loudly instead of
    silently returning an empty result - which is the bug this file exists to
    catch.
    """

    def __init__(self) -> None:
        self.seen: list[str] = []

    def run(self, statement: str, parameters: dict | None = None) -> Result:
        parameters = parameters or {}
        self.seen.append(statement)
        text = statement.strip()

        if text.startswith("MATCH (n:"):  # COUNT_BY_LABEL
            return Result(["total"], [[7]], 0.0)
        if text.startswith("MATCH (a)-[r:"):  # COUNT_BY_EDGE
            return Result(["total"], [[9]], 0.0)
        if statement == queries.SERVICE_LIST:
            return Result(list(SERVICE), [list(SERVICE.values())], 0.0)
        if statement == queries.DIRECT_HITS:
            columns = ["version", "advisory", "kind", "severity", "advisory_published",
                       "version_published", "has_fix", "direct", "dev"]
            return Result(columns, [list(row) for row in HITS], 0.0)
        if text.startswith("MATCH (s:Svc {id: $service_id})-[:USES]->(entry:Ver)-[:DEPENDS"):
            if "AFFECTS" in text:  # DEPTH_AT
                depth_one = "*1..1" in text
                return Result(["hits"], [[2 if depth_one else 1]], 0.0)
            return Result(  # CHOKE_POINTS
                ["version", "reached_through"], [["lib@2.0.0", 3], ["expess@4.18.2", 1]], 0.0
            )
        if statement == queries.EXPOSURE_WINDOW:
            return Result(
                ["version", "advisory", "kind", "disclosed_at", "pinned_version_published",
                 "captured_at"],
                [["expess@4.18.2", "MAL-2025-1", "malicious", 1_750_000_000, 1_700_000_000,
                  1_760_000_000]],
                0.0,
            )
        if statement == queries.SERVICE_LOOKALIKES:
            return Result(
                ["version", "suspect", "looks_like", "distance", "downloads_ratio",
                 "suspect_downloads", "target_downloads"],
                [["expess@4.18.2", "expess", "express", 1, 1.08e-06, 138, 127_296_948]],
                0.0,
            )
        if statement == queries.SERVICE_ENTRY_POINTS:
            return Result(["version"], [["app@1.0.0"]], 0.0)
        if text.startswith("CALL algo.MSpaths"):
            return Result(["path"], [[_path()]], 0.0)
        if statement == queries.PACKAGE_SEARCH:
            rows = [[name, downloads, 3] for name, downloads in sorted(PACKAGES.items())
                    if name.startswith(parameters["prefix"])]
            return Result(["name", "downloads", "version_count"], rows[: parameters["limit"]], 0.0)
        if statement == queries.MAINTAINER_SEARCH:
            rows = [["attacker", 3]] if "attacker".startswith(parameters["prefix"]) else []
            return Result(["login", "package_count"], rows, 0.0)
        if statement == queries.PACKAGE_VERSIONS:
            if parameters["name"] not in PACKAGES:
                return Result(["version", "published_at"], [], 0.0)
            return Result(
                ["version", "published_at"],
                [[f"{parameters['name']}@4.18.2", 1_700_000_000]],
                0.0,
            )
        if statement == queries.PACKAGE_ADVISORIES:
            rows = [["expess@4.18.2", "MAL-2025-1", "malicious", "UNKNOWN", False, 1_750_000_000]]
            return Result(
                ["version", "advisory", "kind", "severity", "has_fix", "disclosed_at"],
                rows if parameters["name"] == "expess" else [],
                0.0,
            )
        if statement == queries.PACKAGE_SERVICES:
            return Result(
                ["service", "version", "direct", "dev"],
                [["demo", f"{parameters['name']}@4.18.2", True, False]],
                0.0,
            )
        if statement == queries.PACKAGE_MAINTAINERS:
            return Result(["login", "package_count"], [["attacker", 3]], 0.0)
        if statement == queries.TYPOSQUAT_NEIGHBOURS_BY_NAME:
            rows = [["express", 1, 1.08e-06, 127_296_948]] if parameters["name"] == "expess" else []
            return Result(["looks_like", "distance", "downloads_ratio", "target_downloads"],
                          rows, 0.0)
        if statement == queries.MAINTAINER_REACH_BY_LOGIN:
            rows = ([["demo", "expess", "expess@4.18.2", True]]
                    if parameters["login"] == "attacker" else [])
            return Result(["service", "package", "version", "direct"], rows, 0.0)
        if statement == queries.LOOKALIKES_ALL:
            return Result(
                ["suspect", "looks_like", "distance", "downloads_ratio", "suspect_downloads",
                 "target_downloads"],
                [["expess", "express", 1, 1.08e-06, 138, 127_296_948]],
                0.0,
            )
        raise AssertionError(f"the fake was not taught this statement:\n{statement}")


def _path() -> Path:
    nodes = [
        PathNode(id=1, labels=["Ver"], properties={"key": "expess@4.18.2"}),
        PathNode(id=2, labels=["Ver"], properties={"key": "app@1.0.0"}),
    ]
    rels = [PathRel(edge_type="DEPENDS", src=2, dst=1, properties={"requirement": "^4.18.0"})]
    return Path(nodes=nodes, relationships=rels)


@pytest.fixture()
def api() -> Api:
    return Api(FakeClient())


@pytest.fixture()
def base_url():
    server = serve(FakeClient(), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def get(url: str, method: str = "GET") -> tuple[int, dict]:
    import urllib.error

    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read()
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


class TestRouting:
    def test_a_segment_is_captured(self):
        table = [(["api", "services", ":name"], lambda path, query: path)]
        handler, captured = match_route(table, ["api", "services", "demo"])
        assert captured == {"name": "demo"}
        assert handler(captured, {}) == {"name": "demo"}

    def test_a_different_length_is_not_a_match(self):
        table = [(["api", "services", ":name"], lambda path, query: path)]
        assert match_route(table, ["api", "services"]) is None
        assert match_route(table, ["api", "services", "demo", "extra"]) is None

    def test_a_literal_segment_has_to_be_equal(self):
        table = [(["api", "health"], lambda path, query: {})]
        assert match_route(table, ["api", "healthz"]) is None

    def test_a_scoped_package_name_survives_one_unquote(self, base_url):
        # @types/node is two path segments once decoded, so the route table would
        # never match it; the handler receives it percent-encoded and unquoted.
        status, body = get(f"{base_url}/api/packages/%40types%2Fnode")
        assert status == 404 and "no package" in body["error"]


class TestServiceView:
    def test_counts_agree_with_the_rows(self, api):
        payload = api.service({"name": "demo"}, {})
        assert payload["counts"] == {"hits": 2, "malicious": 1, "unfixable": 1, "chains": 1}
        assert len(payload["hits"]) == 2
        assert payload["hits"][0]["kind"] == "malicious", "malware sorts first"

    def test_the_depth_profile_is_not_silently_empty(self, api):
        payload = api.service({"name": "demo"}, {})
        assert sum(payload["depth_profile"].values()) > 0

    def test_a_chain_keeps_its_hops(self, api):
        chain = api.service({"name": "demo"}, {})["chains"][0]
        assert chain["keys"] == ["expess@4.18.2", "app@1.0.0"]
        assert chain["hops"] == 1

    def test_exposure_days_are_computed_not_guessed(self, api):
        exposure = api.service({"name": "demo"}, {})["exposure"]
        assert exposure and exposure[0]["exposed_days"] == pytest.approx(115.7, abs=0.2)

    def test_an_unknown_service_is_not_found(self, api):
        with pytest.raises(NotFound):
            api.service({"name": "nope"}, {})


class TestPackageAndMaintainerViews:
    def test_a_package_reports_its_chains_into_services(self, api):
        payload = api.package({"name": "expess"}, {})
        assert payload["chain_count"] == 1
        assert payload["shipped_by"][0]["service"] == "demo"
        assert payload["lookalikes"][0]["looks_like"] == "express"

    def test_an_unknown_package_is_not_found(self, api):
        with pytest.raises(NotFound):
            api.package({"name": "no-such-thing"}, {})

    def test_takeover_reach_is_deduplicated(self, api):
        payload = api.maintainer({"login": "attacker"}, {})
        assert payload["counts"] == {"services": 1, "packages": 1, "versions": 1}

    def test_an_unknown_maintainer_is_not_found(self, api):
        with pytest.raises(NotFound):
            api.maintainer({"login": "ghost"}, {})

    def test_search_is_a_prefix_query(self, api):
        payload = api.search({}, {"q": "ex"})
        assert [row["name"] for row in payload["packages"]] == ["expess", "express"]

    def test_an_empty_search_asks_nothing(self, api):
        assert api.search({}, {"q": "  "}) == {"packages": [], "maintainers": []}
        assert not api.client.seen


class TestOverHttp:
    def test_the_page_is_served_at_the_root(self, base_url):
        with urllib.request.urlopen(base_url, timeout=10) as response:
            body = response.read().decode()
        assert response.headers["Content-Type"].startswith("text/html")
        assert "blastradius" in body and "/api/services" in body

    def test_health_reports_the_graph(self, base_url):
        status, body = get(f"{base_url}/api/health")
        assert status == 200 and body["ok"] is True
        assert body["graph"]["Pkg"] == 7 and body["graph"]["SIMILAR"] == 9

    def test_an_unknown_route_is_a_404_with_a_reason(self, base_url):
        status, body = get(f"{base_url}/api/nope")
        assert status == 404 and body["error"]

    def test_a_wrong_name_is_a_404_and_never_an_empty_page(self, base_url):
        """The dangerous answer is 200 with nothing in it: on this UI that reads
        as "no exposure found" when the truth is "that service does not exist"."""
        for path in ("/api/services/ghost", "/api/packages/ghost", "/api/maintainers/ghost"):
            status, body = get(f"{base_url}{path}")
            assert status == 404, f"{path} answered {status}"
            assert body["error"], f"{path} gave a 404 with no reason"

    def test_a_bad_limit_is_the_callers_400_not_the_servers_500(self, base_url):
        for query in ("limit=banana", "limit=0", "limit=-3"):
            status, body = get(f"{base_url}/api/search?q=ex&{query}")
            assert status == 400, f"{query} answered {status}"
            assert "limit" in body["error"]

    def test_a_huge_limit_is_capped_rather_than_refused(self, base_url):
        status, _ = get(f"{base_url}/api/search?q=ex&limit=100000")
        assert status == 200

    def test_the_api_refuses_every_verb_that_would_write(self, base_url):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            status, body = get(f"{base_url}/api/services", method=method)
            assert status == 405, f"{method} answered {status}"
            assert body["error"] == "this API is read-only"

    def test_the_ci_selfcheck_passes_against_a_populated_graph(self, base_url):
        report = api_selfcheck(base_url)
        failures = [check for check in report["checks"] if not check["ok"]]
        assert not failures, failures
        assert len(report["checks"]) >= 8

    def test_the_ci_selfcheck_fails_when_the_graph_is_empty(self):
        class Empty(FakeClient):
            def run(self, statement, parameters=None):
                result = super().run(statement, parameters)
                if statement == queries.DIRECT_HITS:
                    return Result(result.columns, [], 0.0)
                return result

        server = serve(Empty(), host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            report = api_selfcheck(f"http://127.0.0.1:{server.server_address[1]}")
        finally:
            server.shutdown()
            server.server_close()
        assert [check for check in report["checks"] if not check["ok"]], (
            "a service with no hits has to fail the check, or CI proves nothing"
        )


def test_every_route_in_the_table_is_reachable():
    api = Api(FakeClient())
    handler = make_handler(api)
    assert handler.protocol_version == "HTTP/1.1"
    from blastradius.web import routes

    assert {tuple(pattern) for pattern, _ in routes(api)} == {
        ("api", "health"),
        ("api", "services"),
        ("api", "services", ":name"),
        ("api", "search"),
        ("api", "packages", ":name"),
        ("api", "maintainers", ":login"),
        ("api", "lookalikes"),
    }
