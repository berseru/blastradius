"""Run the README's Quickstart, exactly as written, and report what happened.

The commands are *extracted from the README*, not copied into this file. That is
the whole point: if the documentation and the software drift apart, this fails,
which is the failure a stranger meets first and the one no test suite notices.

Two commands need handling that a shell cannot infer:

* the bare ``blastradius serve`` starts the UI and never returns, so it is
  started, probed over HTTP and stopped - which is still a real check of the
  command the README gives for looking at the results;
* anything after a failure is still attempted, so one broken line does not hide
  the state of the rest.

Everything else is executed verbatim, in one shell, so ``export`` lines apply to
the commands that follow them the way a reader would experience it.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

FENCE = re.compile(r"```bash\n(.*?)```", re.DOTALL)
UI_COMMAND = "blastradius serve"

# The README tells a reader to open the UI with a command that blocks. Started,
# probed and stopped here, with the probe naming what it proved.
UI_REPLACEMENT = """
blastradius serve &
QS_UI_PID=$!
sleep 3
curl -fsS http://127.0.0.1:8080/api/health > /dev/null
curl -fsS http://127.0.0.1:8080/ | grep -q "blastradius"
curl -fsS "http://127.0.0.1:8080/api/services" | head -c 200
kill $QS_UI_PID
""".strip()


def quickstart_commands(readme: str) -> list[str]:
    """Every command in the Quickstart section, in order, continuations joined."""
    section = readme.split("## Quickstart", 1)[-1].split("\n## ", 1)[0]
    commands: list[str] = []
    for block in FENCE.findall(section):
        current: list[str] = []
        for line in block.splitlines():
            if not line.strip():
                continue
            current.append(line)
            if not line.rstrip().endswith("\\"):
                commands.append("\n".join(current))
                current = []
        if current:
            commands.append("\n".join(current))
    return commands


def write_runner(commands: list[str], workdir: Path) -> tuple[Path, list[str]]:
    """Write one bash script that runs each command and records its result."""
    steps_dir = workdir / ".quickstart-steps"
    steps_dir.mkdir(parents=True, exist_ok=True)
    labels: list[str] = []
    lines = [
        "#!/usr/bin/env bash",
        "# generated from the README - do not edit",
        "set -uo pipefail",
        f'cd "{workdir}"',
        'QS_LOG="$1"',
        ": > \"$QS_LOG\"",
        "run_step() {",
        '  local index="$1" label="$2" file="$3"',
        '  echo ""',
        '  echo "=== step $index: $label"',
        "  local start=$SECONDS",
        '  eval "$(cat "$file")"',
        "  local rc=$?",
        '  printf \'%s\\t%s\\t%s\\n\' "$index" "$rc" "$((SECONDS-start))" >> "$QS_LOG"',
        '  echo "=== step $index exited $rc after $((SECONDS-start))s"',
        "}",
    ]
    for index, command in enumerate(commands):
        body = UI_REPLACEMENT if command.split("#")[0].strip() == UI_COMMAND else command
        label = command.splitlines()[0].strip()
        if body is UI_REPLACEMENT:
            label += "   (started, probed over HTTP, stopped)"
        step_file = steps_dir / f"{index:02d}.sh"
        step_file.write_text(body + "\n", encoding="utf-8")
        labels.append(label)
        lines.append(f'run_step {index} {json.dumps(label)} "{step_file}"')
    runner = workdir / ".quickstart-run.sh"
    runner.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return runner, labels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="the clone to run the Quickstart in")
    parser.add_argument("--out", required=True, help="where to write the JSON report")
    args = parser.parse_args()

    workdir = Path(args.repo)
    commands = quickstart_commands((workdir / "README.md").read_text(encoding="utf-8"))
    if not commands:
        print("no commands found in the README Quickstart", file=sys.stderr)
        return 1
    runner, labels = write_runner(commands, workdir)
    log = workdir / ".quickstart-results.tsv"

    started = time.time()
    subprocess.run(["bash", str(runner), str(log)], check=False)
    results = {}
    for line in log.read_text(encoding="utf-8").splitlines():
        index, code, seconds = line.split("\t")
        results[int(index)] = {"exit_code": int(code), "seconds": int(seconds)}

    steps = [
        {
            "step": index,
            "command": labels[index],
            "exit_code": results.get(index, {}).get("exit_code"),
            "seconds": results.get(index, {}).get("seconds"),
            "ran": index in results,
        }
        for index in range(len(commands))
    ]
    failed = [step for step in steps if step["exit_code"] not in (0, None) or not step["ran"]]
    report = {
        "readme_commands": len(commands),
        "failed": len(failed),
        "seconds": round(time.time() - started, 1),
        "steps": steps,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\nREADME Quickstart: {len(commands) - len(failed)}/{len(commands)} commands succeeded")
    for step in failed:
        print(f"  FAILED  {step['command']}  (exit {step['exit_code']})", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
