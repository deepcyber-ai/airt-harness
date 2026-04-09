#!/usr/bin/env bash
# Tail container logs. Use -f to follow.
#
# Usage:
#   ./scripts/airt-logs.sh             # last 50 lines
#   ./scripts/airt-logs.sh -f          # follow
#   ./scripts/airt-logs.sh --tail 200  # last 200 lines
set -euo pipefail
CONTAINER_NAME="${CONTAINER_NAME:-airt-harness}"
if [ $# -eq 0 ]; then
  exec docker logs --tail 50 "$CONTAINER_NAME"
fi
exec docker logs "$@" "$CONTAINER_NAME"
