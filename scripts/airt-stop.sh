#!/usr/bin/env bash
# Stop the running AIRT harness container (idempotent).
set -euo pipefail
CONTAINER_NAME="${CONTAINER_NAME:-airt-harness}"
if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  docker stop "$CONTAINER_NAME" >/dev/null
  echo "stopped $CONTAINER_NAME"
else
  echo "$CONTAINER_NAME is not running"
fi
