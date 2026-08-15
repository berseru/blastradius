#!/usr/bin/env bash
# Scale evidence: the same pipeline, four times, on a growing corpus.
#
# A single graph size proves the queries run. It does not say whether they keep
# running when the graph grows, which is the only interesting question about a
# graph database. So this script ingests a ladder of seed counts into a fresh
# store each time and records, per level, how large the graph became, how long
# the ingest took, and how long every query took against it.
#
# Each level is a prefix of the next (see scripts/seed_packages_scale.txt), so
# the levels differ in size and in nothing else.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=ci/lib.sh
source ci/lib.sh

LEVELS="${SCALE_LEVELS:-143 300 600 1200}"
SEEDS_FILE="${SCALE_SEEDS_FILE:-scripts/seed_packages_scale.txt}"

install_project
mkdir -p artifacts/scale data/cache

start_hydra() {
  local data_dir="$1"
  rm -rf "$data_dir"
  mkdir -p "$data_dir/store" "$data_dir/cache"
  printf '%s\n' "$HYDRA_TOKEN" > "$data_dir/auth-token"
  docker run -d --name "$HYDRA_CONTAINER" \
    --user "$(id -u):$(id -g)" \
    -p 7687:7687 -p 8443:8443 -p 9090:9090 \
    -v "$PWD/$data_dir:/data" \
    -e CLOUD_PROVIDER=local \
    -e LOCAL_PATH=/data/store \
    -e GRAPH_NAMESPACE=default \
    -e GRAPH_ID=default \
    -e GRAPH_CELL_ID=cell-0 \
    -e GRAPH_CELLS=cell-0 \
    -e GRAPH_NODE_ID=node-0 \
    -e GRAPH_BOLT_NODE_ADDRESSES=node-0=127.0.0.1:7687 \
    -e GRAPH_ADVERTISED_BOLT_ADDR=127.0.0.1:7687 \
    -e GRAPH_DATA_CACHE_DIR=/data/cache \
    -e GRAPH_AUTH_TOKEN_FILE=/data/auth-token \
    -e GRAPH_ALLOW_PLAINTEXT=true \
    -e RUST_MIN_STACK=33554432 \
    "$HYDRA_IMAGE" > /dev/null
  python -m blastradius.cli wait
}

stop_hydra() {
  docker rm -f "$HYDRA_CONTAINER" > /dev/null 2>&1 || true
}

trap stop_hydra EXIT

for level in $LEVELS; do
  echo "=== scale level: $level seed packages ==="
  stop_hydra
  start_hydra "hydradb-scale-$level"
  # The npm/OSV downloads are cached in one shared directory across levels: the
  # inputs are identical by construction, so re-downloading them would only add
  # network noise to the timings.
  python -m blastradius.cli ingest \
    --seeds "$level" \
    --seeds-file "$SEEDS_FILE" \
    --cache-dir data/cache \
    --out "artifacts/scale/ingest-$level.json"
  python -m blastradius.cli verify --out "artifacts/scale/verify-$level.json"
  stop_hydra
done

python ci/scale_report.py --levels "$LEVELS" --dir artifacts/scale \
  --out artifacts/scale/summary.json --markdown artifacts/scale/SCALE.md
cat artifacts/scale/SCALE.md
