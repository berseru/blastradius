# Shared settings for the CI scripts. Sourced, not executed.
#
# Everything that decides how HydraDB is started lives here so that the GitHub
# Actions workflow file itself can stay thin and stable.

HYDRA_IMAGE="${HYDRA_IMAGE:-ghcr.io/hydra-db/hydradb:0.1.1}"
HYDRA_TOKEN="${HYDRA_TOKEN:-local-development-token-32-bytes}"
HYDRA_URL="${HYDRA_URL:-http://127.0.0.1:8443}"
HYDRA_ADMIN_URL="${HYDRA_ADMIN_URL:-http://127.0.0.1:9090}"
HYDRA_CONTAINER="${HYDRA_CONTAINER:-hydradb}"
SEED_PACKAGES="${SEED_PACKAGES:-250}"

export HYDRA_IMAGE HYDRA_TOKEN HYDRA_URL HYDRA_ADMIN_URL HYDRA_CONTAINER SEED_PACKAGES

install_project() {
  python -m pip install --upgrade pip
  python -m pip install -e ".[dev]"
}
