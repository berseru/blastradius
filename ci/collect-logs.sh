#!/usr/bin/env bash
# Always-run step: keep the server logs next to the query results.
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=ci/lib.sh
source ci/lib.sh

mkdir -p artifacts
docker logs "$HYDRA_CONTAINER" > artifacts/hydradb.log 2>&1 || true
docker inspect "$HYDRA_CONTAINER" --format '{{.State.Status}} exit={{.State.ExitCode}}' \
  > artifacts/hydradb-state.txt 2>&1 || true
