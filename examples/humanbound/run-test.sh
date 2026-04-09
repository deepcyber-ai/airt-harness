#!/usr/bin/env bash
# Run a HumanBound test against the harness and show failures.
#
# Usage:
#   ./run-test.sh                   # default: --single
#   ./run-test.sh --single          # single-turn OWASP attacks (~5 min)
#   ./run-test.sh --adaptive        # adaptive multi-turn (~20 min)
#   ./run-test.sh --workflow        # full OWASP workflow
#   ./run-test.sh --behavioral      # behavioral QA tests
#
# Prerequisites:
#   - humanbound CLI installed
#   - Harness running on localhost:8000 (airt-launch)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TEST_TYPE="${1:---single}"

# Check harness is running
if ! curl -fs http://localhost:8000/health >/dev/null 2>&1; then
  echo "ERROR: harness not running on localhost:8000"
  echo "Start it with: MOCK_BACKEND=echo airt-launch"
  exit 1
fi

echo "=== HumanBound Test: $TEST_TYPE ==="
echo

# Init if not already registered
if ! humanbound status >/dev/null 2>&1; then
  echo "Registering bot..."
  humanbound init
  echo
fi

# Run the test
echo "Running test $TEST_TYPE ..."
humanbound test "$TEST_TYPE"

# Wait for results
echo
echo "Waiting for results..."
sleep 3

# Show failures
echo
echo "=== Findings ==="
humanbound logs --failed || echo "(no failures found)"

echo
echo "=== Posture Score ==="
humanbound posture || true
