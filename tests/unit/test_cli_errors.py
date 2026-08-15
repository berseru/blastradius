"""How the tool behaves when the world is not set up yet.

The most common first run of this project is the one where the container is not
up: a judge, a reviewer or a new colleague clones the repo and types a command
before starting anything. What they see then is the product too.

These tests also pin two things that are easy to get wrong in the other
direction: a check that passes when nothing is listening, and help text that
describes behaviour the code does not have.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from blastradius import cli, contract


def free_port() -> int:
    """A port with nothing behind it, so connecting to it is refused."""
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def nowhere(monkeypatch, tmp_path):
    port = free_port()
    monkeypatch.setenv("HYDRA_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("HYDRA_TOKEN", "irrelevant")
    monkeypatch.chdir(tmp_path)
    return f"http://127.0.0.1:{port}"


@pytest.mark.parametrize(
    "argv",
    [
        ["verify"],
        ["ask", "checkout-api"],
        ["selftest"],
        ["contract"],
    ],
)
def test_an_absent_database_is_explained_once(nowhere, capsys, argv):
    """Not a traceback, not twenty-four identical refusals: one sentence."""
    code = cli.main(argv)

    err = capsys.readouterr().err
    assert code == 2
    assert f"cannot reach HydraDB at {nowhere}" in err
    assert "docker ps" in err
    assert "Traceback" not in err
    assert err.count("cannot reach HydraDB") == 1


def test_a_refused_token_is_explained_in_its_own_terms(monkeypatch, capsys, tmp_path):
    """A 401 is a configuration answer, so say which setting to look at."""
    from blastradius.hydra import HydraError

    def explode(_client):
        raise HydraError("unauthenticated", "missing bearer token", 401, "MATCH (n) RETURN n")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "preflight", explode)

    code = cli.main(["selftest"])

    err = capsys.readouterr().err
    assert code == 2
    assert "HydraDB refused the request: unauthenticated" in err
    assert "HYDRA_TOKEN" in err
    assert "Traceback" not in err


def test_the_oversize_check_cannot_pass_against_nothing(nowhere):
    """A transport refusal only means something once the node has answered.

    The first version of this check accepted any ``httpx`` transport error as
    proof that the server enforced its body cap - which an absent server
    produces for free. It passed against a dead port.
    """
    port = int(nowhere.rsplit(":", 1)[1])
    report = contract.run_contract(
        base_url=f"http://127.0.0.1:{port}",
        token="irrelevant",
        graph="default",
        namespace="default",
        cell="cell-0",
    )

    by_name = {check.name: check for check in report.checks}
    assert not by_name["oversized_row_is_reported"].ok, (
        "the body-cap check passed with no server behind the port"
    )
    assert len(report.failures) == len(report.checks), (
        "every check should fail when the node is absent; "
        f"these passed: {[c.name for c in report.checks if c.ok]}"
    )


def test_help_text_matches_measured_behaviour(capsys):
    """The contract run records 403 for a wrong graph, so the help cannot say 404."""
    parser = cli.build_parser()
    subparsers = parser._subparsers._group_actions[0]
    text = next(action.help for action in subparsers._choices_actions
                if action.dest == "contract")

    assert "403 on a wrong graph" in text
    assert "404" not in text


def test_missing_samples_names_the_command_that_makes_them(tmp_path, capsys):
    """An empty crosscheck is a missing prerequisite, not a mystery."""
    code = cli.main(["crosscheck", "--samples", str(tmp_path / "nothing"), "--out", ""])

    err = capsys.readouterr().err
    assert code == 1
    assert "serve --selfcheck --dump-dir" in err


def test_a_stale_archive_says_so(tmp_path, capsys):
    """OSV publishes daily; a month-old snapshot silently under-reports."""
    archive = tmp_path / "osv-npm.zip"
    archive.write_bytes(b"x" * 2_000_000)
    old = time.time() - 30 * 86_400
    import os

    os.utime(archive, (old, old))

    cli.ensure_archive(archive)

    out = capsys.readouterr().out
    assert "30.0 days old" in out
    assert "WARNING" in out
    assert cli.archive_age_days(archive) == pytest.approx(30, abs=0.1)


def test_a_fresh_archive_is_quiet(tmp_path, capsys):
    archive = tmp_path / "osv-npm.zip"
    archive.write_bytes(b"x" * 2_000_000)

    cli.ensure_archive(Path(archive))

    out = capsys.readouterr().out
    assert "0.0 days old" in out
    assert "WARNING" not in out


def test_verify_writes_a_receipt_for_the_work_the_database_did():
    """"HydraDB was used" has to be a number, not a sentence in a README.

    The client counts every statement it sends and the server time each one
    took; without this the only evidence in the artifacts is that some rows
    appeared.
    """
    from blastradius.hydra import Result

    class CountingClient:
        base_url = "http://127.0.0.1:8443"
        graph = "default"
        cell = "cell-0"

        def __init__(self) -> None:
            self.queries_run = 0
            self.total_query_ms = 0.0

        def run(self, statement, parameters=None):
            self.queries_run += 1
            self.total_query_ms += 1.5
            if "RETURN s.id AS id" in statement:
                return Result(["id", "name"], [], 0.0)
            return Result(["total"], [[0]], 0.0)

    client = CountingClient()
    report = cli.verify(client)

    assert report["hydra"]["queries_run"] == client.queries_run > 0
    assert report["hydra"]["endpoint"] == "http://127.0.0.1:8443"
    assert report["hydra"]["graph"] == "default" and report["hydra"]["cell"] == "cell-0"
    assert report["hydra"]["total_query_ms"] == pytest.approx(client.total_query_ms, abs=0.1)
