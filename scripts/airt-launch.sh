#!/usr/bin/env bash
# AIRT Harness launcher -- one container, any profile.
#
# Usage:
#   ./scripts/airt-launch.sh                       # default profile (Deep Vault Capital)
#   ./scripts/airt-launch.sh myproject             # profile mounted from profiles/myproject/
#   ./scripts/airt-launch.sh another               # any profile under profiles/<name>/
#
# Env overrides:
#   AIRT_IMAGE        Docker image                 (default: deepcyberx/airt-harness:1.3.0)
#   MOCK_BACKEND      mock LLM backend             (default: gemini)
#   AIRT_ENV_FILE     .env to source for API keys  (default: .env in current directory)
#   AIRT_PORT_GUI     GUI port                     (default: 7860)
#   AIRT_PORT_API     harness API port             (default: 8000)
#   AIRT_PORT_MOCK    mock API port                (default: 8089)
#   CONTAINER_NAME    Docker container name        (default: airt-harness)
#
# The script:
#   1. Stops any running airt-harness container (idempotent)
#   2. Sources API keys from a .env, if present
#   3. Starts a fresh container with the requested profile bind-mounted
#   4. Waits up to 30s for /health and prints the result

set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-airt-harness}"
AIRT_IMAGE="${AIRT_IMAGE:-deepcyberx/airt-harness:1.3.0}"
MOCK_BACKEND="${MOCK_BACKEND:-gemini}"
AIRT_PORT_GUI="${AIRT_PORT_GUI:-7860}"
AIRT_PORT_API="${AIRT_PORT_API:-8000}"
AIRT_PORT_MOCK="${AIRT_PORT_MOCK:-8089}"

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE_NAME="${1:-default}"

# Source .env if present
ENV_FILE="${AIRT_ENV_FILE:-.env}"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

# Stop any previous container with the same name
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

DOCKER_ARGS=(
  --rm -d
  --name "$CONTAINER_NAME"
  -p "${AIRT_PORT_GUI}:7860"
  -p "${AIRT_PORT_API}:8000"
  -p "${AIRT_PORT_MOCK}:8089"
  -e "MOCK_BACKEND=${MOCK_BACKEND}"
)

if [ -n "${GOOGLE_API_KEY:-}" ]; then
  DOCKER_ARGS+=(-e GOOGLE_API_KEY)
fi
if [ -n "${OPENAI_API_KEY:-}" ]; then
  DOCKER_ARGS+=(-e OPENAI_API_KEY)
fi
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  DOCKER_ARGS+=(-e ANTHROPIC_API_KEY)
fi
if [ -n "${DEEPSEEK_API_KEY:-}" ]; then
  DOCKER_ARGS+=(-e DEEPSEEK_API_KEY)
fi

if [ "$PROFILE_NAME" = "default" ]; then
  echo "Launching $CONTAINER_NAME with default profile (Deep Vault Capital, baked in)..."
else
  PROFILE_DIR="$SCRIPT_ROOT/profiles/$PROFILE_NAME"
  if [ ! -d "$PROFILE_DIR" ]; then
    echo "ERROR: profile directory not found: $PROFILE_DIR" >&2
    echo "Available profiles:" >&2
    ls -1 "$SCRIPT_ROOT/profiles/" 2>/dev/null | sed 's/^/  - /' >&2
    exit 1
  fi
  if [ ! -f "$PROFILE_DIR/profile.yaml" ]; then
    echo "ERROR: missing profile.yaml in $PROFILE_DIR" >&2
    exit 1
  fi
  echo "Launching $CONTAINER_NAME with $PROFILE_NAME profile..."
  echo "  Mount: $PROFILE_DIR -> /app/profiles/$PROFILE_NAME"
  DOCKER_ARGS+=(
    -v "$PROFILE_DIR:/app/profiles/$PROFILE_NAME"
    -e "PROFILE=profiles/$PROFILE_NAME/profile.yaml"
  )
fi

DOCKER_ARGS+=("$AIRT_IMAGE")

docker run "${DOCKER_ARGS[@]}" >/dev/null

# Wait for /health
echo -n "Waiting for harness"
for i in $(seq 1 30); do
  if curl -fs "http://localhost:${AIRT_PORT_API}/health" >/dev/null 2>&1; then
    echo " ready."
    echo
    curl -s "http://localhost:${AIRT_PORT_API}/health" | python3 -m json.tool 2>/dev/null \
      || curl -s "http://localhost:${AIRT_PORT_API}/health"
    echo
    echo "GUI:     http://localhost:${AIRT_PORT_GUI}"
    echo "Harness: http://localhost:${AIRT_PORT_API}"
    echo "Mock:    http://localhost:${AIRT_PORT_MOCK}"
    echo
    echo "Stop with:    ./scripts/airt-stop.sh"
    echo "Tail logs:    ./scripts/airt-logs.sh"
    echo "Replay:       ./scripts/airt-replay.sh --list-sessions"
    exit 0
  fi
  sleep 1
  echo -n "."
done

echo
echo "ERROR: harness did not become healthy within 30s" >&2
echo "--- container logs ---" >&2
docker logs --tail 40 "$CONTAINER_NAME" >&2 || true
exit 1
