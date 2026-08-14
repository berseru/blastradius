#!/usr/bin/env bash
# Unit tests: no database, no network.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=ci/lib.sh
source ci/lib.sh

install_project
pytest -q tests/unit
