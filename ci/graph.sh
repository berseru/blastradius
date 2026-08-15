#!/usr/bin/env bash
# Integration run: start HydraDB, ingest the real corpus, execute every query.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=ci/lib.sh
source ci/lib.sh

# First, and in a clone of its own: the README's Quickstart, run exactly as
# written, in an empty directory with no cache. A judge's first five minutes are
# spent here, and a documented step that cannot be followed is a defect no test
# suite reports. Its result is remembered and applied at the end of this script,
# so one broken line in the docs does not cost the whole run's evidence.
QUICKSTART_STATUS=0
bash ci/quickstart.sh || QUICKSTART_STATUS=$?

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
# The self test is first on purpose: it proves every statement on 11 synthetic
# vertices in seconds, so an unsupported query is reported before the ingest
# spends minutes downloading the advisory corpus.
python -m blastradius.cli selftest --out artifacts/selftest.json
# The contract run is second: it proves the failure paths (a wrong token is
# refused with 401, a wrong graph is refused rather than answered with an empty
# result, and a batch of 2,500 rows is readable back out of the graph after the
# server answers 200) while the graph is still empty and cheap to disturb.
python -m blastradius.cli contract --out artifacts/contract.json
python -m blastradius.cli ingest --seeds "$SEED_PACKAGES"
python -m blastradius.cli verify --out artifacts/results.json
# The API is checked last, against the graph the run just built: every route is
# driven over real HTTP and the assertions are about content, so a page that
# would render empty fails the build instead of surviving until a demo.
python -m blastradius.cli serve --selfcheck --out artifacts/api.json \
  --dump-dir artifacts/api-samples
# Last, and pointed at a different source than everything above it: a sample of
# the answers this run produced is compared against the live OSV API, with a
# semver implementation written separately from the pipeline's. Everything
# before this line agrees with our own parser by construction.
python -m blastradius.cli crosscheck --samples artifacts/api-samples \
  --out artifacts/osv-crosscheck.json

# Every command the README tells a reader to run is run here, including the two
# that only print for humans: a documented command that nothing executes is a
# documented command that quietly rots.
python -m blastradius.cli ask typosquat-incident
python -m blastradius.cli stats --out artifacts/corpus.json
# ...and asking for a service that does not exist must fail, not print nothing.
if python -m blastradius.cli ask no-such-service; then
  echo "ask accepted an unknown service" >&2
  exit 1
fi

# The six questions the track asks, answered from the compromised package
# outwards: once for a malicious package with no fix, once for a plain
# vulnerability that does have one, because those are different answers.
python -m blastradius.cli incident axioss --out artifacts/incident-axioss.json
python -m blastradius.cli incident minimist --out artifacts/incident-minimist.json
# A name the graph has never seen must not answer "you are not affected".
if python -m blastradius.cli incident definitely-not-a-real-package-name; then
  echo "incident answered about a package that is not in the graph" >&2
  exit 1
fi

if [ "$QUICKSTART_STATUS" -ne 0 ]; then
  echo "the README Quickstart failed: see artifacts/quickstart.json" >&2
  exit "$QUICKSTART_STATUS"
fi
