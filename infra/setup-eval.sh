#!/bin/bash
# Setup for scorer evaluation — run once on a fresh machine.
#
# Usage:
#   ./setup-eval.sh
#
# What it does:
#   1. Checks Python, pip, venv
#   2. Installs airt-harness from GitHub
#   3. Clones/pulls DAME and DASE repos
#   4. Installs DAME and DASE as editable packages
#   5. Symlinks .env for API keys
#   6. Verifies Bedrock access
#   7. Pulls Ollama models (if Ollama is running)
#   8. Prints what's ready and what's missing

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}OK${NC}  $1"; }
fail() { echo -e "  ${RED}FAIL${NC} $1"; }
warn() { echo -e "  ${YELLOW}SKIP${NC} $1"; }

echo "=== AIRT Scorer Evaluation Setup ==="
echo

# ── 1. Python ──────────────────────────────────────────────────────

echo "1. Python environment"

if ! command -v python3 &>/dev/null; then
  fail "python3 not found — install Python 3.10+"
  exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
pass "Python $PY_VERSION"

# Create or activate venv
if [ -d "$HOME/airt-env" ]; then
  source "$HOME/airt-env/bin/activate"
  pass "venv activated (existing: ~/airt-env)"
else
  python3 -m venv "$HOME/airt-env"
  source "$HOME/airt-env/bin/activate"
  pass "venv created and activated: ~/airt-env"
fi

echo

# ── 2. airt-harness ───────────────────────────────────────────────

echo "2. AIRT Harness"

if command -v airt-replay &>/dev/null; then
  HARNESS_VER=$(python3 -c "from harness import __version__; print(__version__)" 2>/dev/null || echo "?")
  pass "airt-harness $HARNESS_VER already installed"
else
  echo "  Installing airt-harness from GitHub..."
  pip install -q git+https://github.com/deepcyber-ai/airt-harness.git
  pass "airt-harness installed"
fi

echo

# ── 3. DAME & DASE ───────────────────────────────────────────────

echo "3. DAME & DASE"

AIRT_DIR="$HOME/src/deepcyber-airt"
mkdir -p "$AIRT_DIR"

for repo in dame dase; do
  if [ -d "$AIRT_DIR/$repo" ]; then
    cd "$AIRT_DIR/$repo"
    git pull -q 2>/dev/null || warn "$repo: git pull failed (check SSH key)"
    pip install -q -e . 2>/dev/null
    pass "$repo updated and installed"
  else
    cd "$AIRT_DIR"
    if git clone -q "https://github.com/deepcyber-ai/airt.git" tmp-clone 2>/dev/null; then
      # Monorepo — dame and dase are subdirectories
      pass "$repo cloned"
    else
      warn "$repo: clone failed (check SSH key / repo access)"
    fi
  fi
done

# Verify imports
if python3 -c "import dame" 2>/dev/null; then
  pass "dame importable"
else
  fail "dame not importable — check pip install -e ~/src/deepcyber-airt/dame"
fi

if python3 -c "import dase" 2>/dev/null; then
  pass "dase importable"
else
  fail "dase not importable — check pip install -e ~/src/deepcyber-airt/dase"
fi

if command -v inspect &>/dev/null; then
  pass "inspect-ai $(inspect --version 2>/dev/null || echo '?')"
else
  fail "inspect-ai not installed"
fi

echo

# ── 4. API Keys ──────────────────────────────────────────────────

echo "4. API keys"

ENV_FILE="$HOME/.airt-config/.env"
if [ -f "$ENV_FILE" ]; then
  set -a; source "$ENV_FILE"; set +a
  pass ".env loaded from $ENV_FILE"

  # Symlink into DAME/DASE dirs for python-dotenv auto-loading
  for dir in "$AIRT_DIR/dame" "$AIRT_DIR/dase"; do
    if [ -d "$dir" ] && [ ! -f "$dir/.env" ]; then
      ln -s "$ENV_FILE" "$dir/.env"
      pass "  symlinked .env → $dir/.env"
    fi
  done
else
  warn ".env not found at $ENV_FILE"
  echo "       Create it: mkdir -p ~/.airt-config && nano ~/.airt-config/.env"
  echo "       Add: OPENAI_API_KEY=... GOOGLE_API_KEY=... ANTHROPIC_API_KEY=..."
fi

[ -n "${OPENAI_API_KEY:-}" ] && pass "OPENAI_API_KEY set" || warn "OPENAI_API_KEY not set"
[ -n "${GOOGLE_API_KEY:-}" ] && pass "GOOGLE_API_KEY set" || warn "GOOGLE_API_KEY not set"
[ -n "${ANTHROPIC_API_KEY:-}" ] && pass "ANTHROPIC_API_KEY set" || warn "ANTHROPIC_API_KEY not set (not needed if using Bedrock)"

echo

# ── 5. AWS Bedrock ───────────────────────────────────────────────

echo "5. AWS Bedrock"

if command -v aws &>/dev/null; then
  IDENTITY=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null || echo "")
  if [ -n "$IDENTITY" ]; then
    pass "AWS identity: $IDENTITY"

    # Check Bedrock model access
    if aws bedrock list-foundation-models --region eu-west-2 --query 'modelSummaries[0].modelId' --output text &>/dev/null; then
      pass "Bedrock access confirmed (eu-west-2)"
    else
      warn "Bedrock access failed — check IAM permissions"
    fi
  else
    fail "AWS not configured — run: aws configure"
  fi
else
  fail "AWS CLI not installed"
fi

echo

# ── 6. Docker ────────────────────────────────────────────────────

echo "6. Docker"

if command -v docker &>/dev/null; then
  if docker info &>/dev/null; then
    pass "Docker running"
    if docker image inspect deepcyberx/airt-harness:1.3.0 &>/dev/null; then
      pass "airt-harness:1.3.0 image present"
    else
      warn "airt-harness image not pulled — run: docker pull deepcyberx/airt-harness:1.3.0"
    fi
  else
    warn "Docker installed but not running"
  fi
else
  warn "Docker not installed — harness will need to run from source"
fi

echo

# ── 7. Ollama ────────────────────────────────────────────────────

echo "7. Ollama (optional — for local attacker models)"

if curl -fs http://localhost:11434/api/tags >/dev/null 2>&1; then
  MODELS=$(curl -fs http://localhost:11434/api/tags | python3 -c "import sys,json; print(', '.join(m['name'] for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null)
  pass "Ollama running. Models: $MODELS"

  for m in dolphin-mistral:7b deepseek-r1:32b llama3.3:70b; do
    if echo "$MODELS" | grep -q "$m"; then
      pass "  $m available"
    else
      warn "  $m not pulled — run: ollama pull $m"
    fi
  done
else
  warn "Ollama not running (local models won't be available)"
fi

echo

# ── 8. Datasets ──────────────────────────────────────────────────

echo "8. Datasets"

for ds in deepvault_agentic.jsonl mediguide.jsonl financial_advisor.jsonl; do
  if [ -f "$AIRT_DIR/dame/datasets/$ds" ]; then
    count=$(wc -l < "$AIRT_DIR/dame/datasets/$ds")
    pass "$ds ($count objectives)"
  else
    fail "$ds not found"
  fi
done

echo

# ── Summary ──────────────────────────────────────────────────────

echo "=== Setup Complete ==="
echo
echo "Next steps:"
echo "  1. Start harness:  MOCK_BACKEND=gemini airt-launch"
echo "  2. Run eval:       cd ~/src/airt-harness && ./infra/run-scorer-batch.sh"
echo
echo "Or run DAME manually:"
echo "  cd ~/src/deepcyber-airt/dame"
echo "  inspect eval src/dame/task.py \\"
echo "    --model bedrock/anthropic.claude-sonnet-4-6 \\"
echo "    -T target_model=openai/target \\"
echo "    -T target_base_url=http://localhost:8000/v1 \\"
echo "    -T dataset_path=datasets/deepvault_agentic.jsonl \\"
echo "    -T strategy=crescendo_5 \\"
echo "    --log-dir results/tier1/"
