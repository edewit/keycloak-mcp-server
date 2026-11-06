#!/usr/bin/env bash
# Moved: one generator writes the run configurations of every example, see examples/gen-run-configs.sh.
exec "$(dirname "$0")/../gen-run-configs.sh" "$@"
