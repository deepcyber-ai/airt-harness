#!/usr/bin/env bash
# One-command local launch of the investigations demo (no Docker, uses local source).
#
# Starts mock (8091) + harness server (8000) + GUI (7860) from the working tree, so
# the governance-rung code changes are live without rebuilding the Docker image.
# Use this until the harness image is rebuilt; then `airt-launch investigations`
# works one-command like the other profiles.
#
#   ./profiles/investigations/run.sh          # start
#   ./profiles/investigations/run.sh stop     # stop

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

stop() {
  pkill -f "harness.mock --profile profiles/investigations" 2>/dev/null || true
  pkill -f "uvicorn harness.server" 2>/dev/null || true
  pkill -f "harness.gui" 2>/dev/null || true
}

if [[ "${1:-}" == "stop" ]]; then
  stop; echo "investigations demo stopped."; exit 0
fi

if [[ "${1:-}" == "reset" ]]; then
  # Restore the evidence files WITHOUT restarting the stack (between demo takes).
  cp profiles/investigations/docs/_pristine/*.html profiles/investigations/docs/ 2>/dev/null || true
  echo "evidence files restored (EV-1001, EV-2087, EV-3120, EV-4471, from_email)."
  exit 0
fi

stop; sleep 1
# Restore the evidence files — a demo's disposals really delete them.
cp profiles/investigations/docs/_pristine/*.html profiles/investigations/docs/ 2>/dev/null || true
LOG=/tmp/investigations
echo "starting mock + harness + GUI ..."

python3 -m harness.mock --profile profiles/investigations/profile.yaml --port 8091 \
  > "$LOG-mock.log" 2>&1 &

PROFILE=profiles/investigations/profile.yaml BACKEND=mock \
  python3 -m uvicorn harness.server:app --host 127.0.0.1 --port 8000 \
  > "$LOG-server.log" 2>&1 &

# wait for the harness to answer /health
for _ in $(seq 1 30); do
  curl -sf http://localhost:8000/health >/dev/null 2>&1 && break; sleep 1
done

python3 -m harness.gui --url http://localhost:8000 --port 7860 > "$LOG-gui.log" 2>&1 &

for _ in $(seq 1 30); do
  curl -sf http://localhost:7860 >/dev/null 2>&1 && break; sleep 1
done

cat <<EOF

  investigations demo ready
  ─────────────────────────
  GUI:     http://localhost:7860     <- open this
  Harness: http://localhost:8000
  Mock:    http://localhost:8091
  Logs:    $LOG-{mock,server,gui}.log

  Stop with:  ./profiles/investigations/run.sh stop
EOF
