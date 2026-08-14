#!/usr/bin/env bash
# Integration run: start HydraDB, ingest the real corpus, execute every query.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=ci/lib.sh
source ci/lib.sh

install_project

mkdir -p hydradb-data/store hydradb-data/cache artifacts
printf '%s\n' "$HYDRA_TOKEN" > hydradb-data/auth-token

# RUST_MIN_STACK is required: the query planner recurses deeply and the default
# 8 MiB thread stack aborts the server on larger traversals.
docker run -d --name "$HYDRA_CONTAINER" \
  --user "$(id -u):$(id -g)" \
  -p 7687:7687 -p 8443:8443 -p 9090:9090 \
  -v "$PWD/hydradb-data:/data" \
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
  "$HYDRA_IMAGE"

python -m blastradius.cli wait
python -m blastradius.cli ingest --seeds "$SEED_PACKAGES"
python -m blastradius.cli verify --out artifacts/results.json
