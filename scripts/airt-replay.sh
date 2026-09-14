#!/usr/bin/env bash
# Replay recorded sessions against the running harness.
#
# Thin wrapper around `python -m harness.replay`.  Automatically locates
# the metabase in ../evidence/ or a profile's intel directory.
#
# Usage:
#   ./scripts/airt-replay.sh evidence/metabase.csv --list-sessions
#   ./scripts/airt-replay.sh evidence/metabase.csv --session abc123
#   ./scripts/airt-replay.sh profiles/default/intel/ --list-sessions
#   ./scripts/airt-replay.sh --help
#
# Env overrides:
#   AIRT_PORT_API   harness API port (default: 8000)
#   HARNESS_URL     full harness URL (overrides port)

set -euo pipefail

AIRT_PORT_API="${AIRT_PORT_API:-8000}"
export HARNESS_URL="${HARNESS_URL:-http://localhost:${AIRT_PORT_API}}"

exec python3 -m harness.replay "$@"
