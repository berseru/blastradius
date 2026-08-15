#!/usr/bin/env bash
# Follow the README the way a judge would: clone the public repository into an
# empty directory, install into a fresh virtualenv, and run every command the
# Quickstart lists - with nothing cached, no data directory, and no environment
# left over from this repository's own CI.
#
# It runs before the main integration job and cleans up after itself, so the
# container name and the ports the README uses are free again afterwards.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$PWD"
ARTIFACTS="$REPO_ROOT/artifacts"
WORKDIR="${RUNNER_TEMP:-/tmp}/quickstart"
CLONE_URL="${QUICKSTART_CLONE_URL:-https://github.com/berseru/blastradius}"
mkdir -p "$ARTIFACTS"

cleanup() {
  docker rm -f hydradb > /dev/null 2>&1 || true
  rm -rf /tmp/hydra
}
trap cleanup EXIT

rm -rf "$WORKDIR"
git clone --quiet "$CLONE_URL" "$WORKDIR" || { echo "clone failed"; exit 1; }
if [ -n "${GITHUB_SHA:-}" ]; then
  git -C "$WORKDIR" checkout --quiet "$GITHUB_SHA" 2>/dev/null \
    || echo "note: $GITHUB_SHA not on the remote yet, running the default branch"
fi
echo "quickstart runs $(git -C "$WORKDIR" rev-parse --short HEAD) from $CLONE_URL"

# A virtualenv rather than the job's Python: the point is to prove the documented
# install works from nothing, so nothing already installed here may help it.
python -m venv "$WORKDIR/.venv"
# shellcheck disable=SC1091
source "$WORKDIR/.venv/bin/activate"
python -m pip install --quiet --upgrade pip

python "$REPO_ROOT/ci/readme_quickstart.py" --repo "$WORKDIR" \
  --out "$ARTIFACTS/quickstart.json"
STATUS=$?

# Keep what the documented run produced, so its numbers can be compared with the
# main run's rather than taken on trust.
if [ -d "$WORKDIR/artifacts" ]; then
  mkdir -p "$ARTIFACTS/quickstart-run"
  cp -r "$WORKDIR"/artifacts/* "$ARTIFACTS/quickstart-run/" 2>/dev/null || true
fi
docker logs hydradb > "$ARTIFACTS/quickstart-hydradb.log" 2>&1 || true

exit $STATUS
