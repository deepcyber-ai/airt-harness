#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# AIRT Harness v1.2.0 — Smoke Test
# ═══════════════════════════════════════════════════════════════════
#
# Tests the replay module end-to-end:
#   1. Starts harness + mock (echo backend, no API key needed)
#   2. Sends a few messages to generate intel logs
#   3. Replays from intel logs
#   4. Replays from an external metabase CSV (if SMOKE_METABASE is set)
#   5. Tears down
#
# Prerequisites:
#   - Docker / Colima running        (colima start)
#   - pip install -e .               (from the airt-harness repo root)
#
# Usage:
#   ./scripts/smoke-test.sh
#
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
API_PORT=8000

pass() { ((PASS++)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { ((FAIL++)); echo -e "  ${RED}FAIL${NC} $1"; }
info() { echo -e "  ${YELLOW}INFO${NC} $1"; }

cleanup() {
  echo
  echo "Tearing down..."
  airt-stop 2>/dev/null || true
}
trap cleanup EXIT

# ── Preflight ──────────────────────────────────────────────────────

echo "═══ AIRT Harness v1.2.0 Smoke Test ═══"
echo

echo "1. Preflight checks"

if ! command -v airt-launch &>/dev/null; then
  fail "airt-launch not on PATH — run: pip install -e ."
  exit 1
fi
pass "airt-launch on PATH"

if ! command -v airt-replay &>/dev/null; then
  fail "airt-replay not on PATH"
  exit 1
fi
pass "airt-replay on PATH"

if ! docker info &>/dev/null; then
  fail "Docker not running — run: colima start"
  exit 1
fi
pass "Docker running"

echo

# ── Launch harness with echo backend ───────────────────────────────

echo "2. Launch harness (echo backend, no API key needed)"

MOCK_BACKEND=echo airt-launch 2>&1 | sed 's/^/   /'

# Verify health
if curl -fs "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then
  pass "Harness healthy"
else
  fail "Harness not healthy"
  exit 1
fi

echo

# ── Send test messages to generate intel ───────────────────────────

echo "3. Send test messages (generating intel logs)"

SESSION_ID="smoke-test-$(date +%s)"

for i in 1 2 3; do
  RESP=$(curl -s -X POST "http://localhost:${API_PORT}/chat" \
    -H "Content-Type: application/json" \
    -H "x-session-id: ${SESSION_ID}" \
    -d "{\"input\": \"Test message ${i} for smoke test\"}")

  if echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('answer')" 2>/dev/null; then
    pass "Turn ${i}: got response"
  else
    fail "Turn ${i}: no answer in response"
    echo "   Response: $RESP"
  fi
done

echo

# ── Replay from intel logs ─────────────────────────────────────────

echo "4. Replay from intel logs"

# List sessions
OUTPUT=$(airt-replay profiles/default/ --list-sessions 2>&1)
if echo "$OUTPUT" | grep -q "$SESSION_ID"; then
  pass "--list-sessions shows our session"
else
  fail "--list-sessions missing our session"
  echo "   Output: $OUTPUT"
fi

# Replay the session
OUTPUT=$(airt-replay profiles/default/ --session "$SESSION_ID" 2>&1)
if echo "$OUTPUT" | grep -q "turns changed"; then
  pass "--session replayed successfully"
else
  fail "--session replay failed"
  echo "   Output: $OUTPUT"
fi

# Replay with report output
REPORT_FILE="/tmp/airt-smoke-intel-report.md"
airt-replay profiles/default/ --session "$SESSION_ID" -o "$REPORT_FILE" 2>&1 >/dev/null
if [ -f "$REPORT_FILE" ] && grep -q "Replay Report" "$REPORT_FILE"; then
  pass "Report generated: $REPORT_FILE"
else
  fail "Report not generated"
fi

echo

# ── Replay from external metabase (if provided) ───────────────────

echo "5. Replay from external metabase"

METABASE="${SMOKE_METABASE:-}"

if [ -z "$METABASE" ] || [ ! -f "$METABASE" ]; then
  info "Skipping — set SMOKE_METABASE=/path/to/metabase.csv to test CSV replay"
else
  # List sessions
  OUTPUT=$(airt-replay "$METABASE" --list-sessions 2>&1)
  if echo "$OUTPUT" | grep -q "sessions"; then
    pass "Metabase: sessions listed"
  else
    fail "Metabase: could not list sessions"
    echo "   Output: $(echo "$OUTPUT" | head -2)"
  fi

  # Replay first session found
  FIRST_SESSION=$(airt-replay "$METABASE" --list-sessions 2>&1 | grep -v "^Source:" | grep -v "^$" | grep -v "^-" | grep -v "Session ID" | head -1 | awk '{print $1}')
  if [ -n "$FIRST_SESSION" ]; then
    OUTPUT=$(airt-replay "$METABASE" --session "$FIRST_SESSION" --delay 0.2 2>&1)
    if echo "$OUTPUT" | grep -q "turns changed"; then
      pass "Metabase: session replayed"
    else
      fail "Metabase: replay failed"
      echo "   Output: $OUTPUT"
    fi

    # Report
    REPORT_FILE="/tmp/airt-smoke-metabase-report.md"
    airt-replay "$METABASE" --session "$FIRST_SESSION" --delay 0.2 -o "$REPORT_FILE" 2>&1 >/dev/null
    if [ -f "$REPORT_FILE" ] && grep -q "Replay Report" "$REPORT_FILE"; then
      pass "Metabase: report generated: $REPORT_FILE"
    else
      fail "Metabase: report not generated"
    fi
  else
    fail "Metabase: could not find a session to replay"
  fi
fi

echo

# ── Summary ────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "═══════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
  echo
  echo "Reports (if generated):"
  ls -la /tmp/airt-smoke-*.md 2>/dev/null | sed 's/^/  /'
  exit 1
fi

echo
echo "All good. Reports:"
ls -la /tmp/airt-smoke-*.md 2>/dev/null | sed 's/^/  /'
echo
echo "Review a report:  cat /tmp/airt-smoke-intel-report.md"
