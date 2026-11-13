#!/usr/bin/env bash
# The spell check of CI (the typos job of .github/workflows/ci.yml), locally: crate-ci/typos
# (https://github.com/crate-ci/typos) over the whole repository, configured by _typos.toml.
#
#   etc/typos.sh                  check, as CI does
#   etc/typos.sh --write-changes  fix what has one unambiguous correction
#   etc/typos.sh <path>...        check only these files or directories
#
# Runs the version CI pins (keep TYPOS_VERSION and the `uses: crate-ci/typos@v...` line of ci.yml in step): an
# installed `typos` of that version (brew install typos-cli, cargo install typos-cli), else the same version through
# uvx (https://docs.astral.sh/uv/), which downloads it once. A newer release knows more misspellings, so another
# version could pass here and fail in CI.
set -euo pipefail
TYPOS_VERSION=1.52.2
cd "$(dirname "$0")/.."
if command -v typos >/dev/null && [[ "$(typos --version)" == "typos-cli ${TYPOS_VERSION}" ]]; then
  exec typos --format brief "$@"
fi
if command -v uvx >/dev/null; then
  exec uvx "typos==${TYPOS_VERSION}" --format brief "$@"
fi
echo "typos ${TYPOS_VERSION} not found: install uv (brew install uv) or typos-cli ${TYPOS_VERSION}" \
  "(cargo install typos-cli --version ${TYPOS_VERSION})" >&2
exit 1
