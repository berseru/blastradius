"""The Quickstart runner reads the README; these tests hold it to that.

If this file passed while the extractor silently found nothing, CI would report
a green "0/0 commands succeeded" run and the documentation could rot untouched -
so the emptiness case is a failure here, and the real README is parsed too.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci"))

from readme_quickstart import (  # noqa: E402
    UI_COMMAND,
    quickstart_commands,
    write_runner,
)

README = Path(__file__).resolve().parents[2] / "README.md"


def test_the_real_readme_still_documents_a_runnable_quickstart():
    commands = quickstart_commands(README.read_text(encoding="utf-8"))
    assert commands, "no commands extracted from the README Quickstart"
    joined = "\n".join(commands)
    for expected in ["docker run", "pip install -e .", "blastradius wait",
                     "blastradius selftest", "blastradius ingest"]:
        assert expected in joined, f"the Quickstart no longer contains {expected!r}"


def test_the_crosscheck_step_comes_after_the_step_that_writes_its_input():
    """The bug a stranger hit: crosscheck reads what serve --selfcheck dumps."""
    commands = quickstart_commands(README.read_text(encoding="utf-8"))
    dumped = next(i for i, cmd in enumerate(commands) if "--dump-dir" in cmd)
    checked = next(i for i, cmd in enumerate(commands) if cmd.startswith("blastradius crosscheck"))
    assert dumped < checked, "crosscheck is documented before its samples exist"


def test_continuation_lines_stay_one_command():
    readme = "## Quickstart\n\n```bash\ndocker run -d \\\n  --name x \\\n  image\necho done\n```\n\n## Next\n"
    assert quickstart_commands(readme) == ["docker run -d \\\n  --name x \\\n  image", "echo done"]


def test_no_quickstart_section_extracts_nothing():
    assert quickstart_commands("# A README with no quickstart\n") == []


def test_the_blocking_ui_command_is_replaced_by_a_probe(tmp_path):
    """`blastradius serve` never returns, so it is started, probed and stopped."""
    readme = (
        f"## Quickstart\n\n```bash\n{UI_COMMAND}"
        "                 # http://127.0.0.1:8080\n```\n\n## Next\n"
    )
    commands = quickstart_commands(readme)
    runner, labels = write_runner(commands, tmp_path)
    step = (tmp_path / ".quickstart-steps" / "00.sh").read_text()
    assert "curl" in step and "kill" in step
    assert "probed over HTTP" in labels[0]
    assert runner.exists()


def test_every_step_is_recorded_even_when_one_fails(tmp_path):
    """One broken line must not hide the state of the rest."""
    readme = "## Quickstart\n\n```bash\ntrue\nfalse\ntrue\n```\n\n## Next\n"
    commands = quickstart_commands(readme)
    runner, _ = write_runner(commands, tmp_path)
    log = tmp_path / "results.tsv"
    import subprocess

    subprocess.run(["bash", str(runner), str(log)], check=False, capture_output=True)
    rows = [line.split("\t") for line in log.read_text().splitlines()]
    assert [row[0] for row in rows] == ["0", "1", "2"], "not every step was attempted"
    assert [row[1] for row in rows] == ["0", "1", "0"], "the failure was not recorded"


def test_quoting_survives_the_round_trip(tmp_path):
    """Commands contain quotes and $(...) - they must arrive unmangled."""
    readme = ("## Quickstart\n\n```bash\nprintf 'a b' > out.txt\n"
              'echo "$(cat out.txt)" >> out.txt\n```\n\n## Next\n')
    commands = quickstart_commands(readme)
    runner, _ = write_runner(commands, tmp_path)
    import subprocess

    subprocess.run(["bash", str(runner), str(tmp_path / "log.tsv")], check=False,
                   capture_output=True)
    assert (tmp_path / "out.txt").read_text() == "a ba b\n"
