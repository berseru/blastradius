#!/usr/bin/env bash
# Unit tests: no database, no network.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=ci/lib.sh
source ci/lib.sh

install_project
# Lint first: it takes a second and it fails on the kind of thing a reviewer
# would otherwise spend their attention on instead of the answers.
ruff check src tests ci scripts
pytest -q tests/unit
