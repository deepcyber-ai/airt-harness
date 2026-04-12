#!/bin/bash
# Run DAME with multiple attacker models against the harness, then DASE scorer eval.
#
# Usage:
#   ./run-scorer-batch.sh                    # run all models
#   ./run-scorer-batch.sh --scorers-only     # skip DAME, just run DASE on existing transcripts
#   ./run-scorer-batch.sh --dame-only        # skip DASE, just generate transcripts
#
# Prerequisites:
#   - Harness running: MOCK_BACKEND=gemini airt-launch
#   - API keys set: OPENAI_API_KEY, GOOGLE_API_KEY
#   - AWS Bedrock configured (aws sts get-caller-identity)
#   - DAME/DASE installed (pip install -e .)
#   - .env in ~/src/deepcyber-airt/dame/ and dase/
#
# Results go to:
#   dame/results/scorer-eval/           DAME eval logs
#   dase/datasets/scorer-eval/          Panel-labelled transcripts
#   dase/results/scorer-eval/           DASE scorer eval logs

set -euo pipefail

DAME_DIR="${HOME}/src/deepcyber-airt/dame"
DASE_DIR="${HOME}/src/deepcyber-airt/dase"
DATASET="datasets/deepvault_agentic.jsonl"
STRATEGY="crescendo_5"
HARNESS_URL="http://localhost:8000"
RESULTS_TAG="scorer-eval"

MODE="${1:-all}"  # all | --dame-only | --scorers-only

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} $1"; }
err() { echo -e "${RED}[$(date +%H:%M:%S)]${NC} $1"; }

# ── Preflight ──────────────────────────────────────────────────────

log "Checking prerequisites..."

if ! curl -fs "$HARNESS_URL/health" >/dev/null 2>&1; then
  err "Harness not running at $HARNESS_URL"
  err "Start it with: MOCK_BACKEND=gemini airt-launch"
  exit 1
fi

HARNESS_TARGET=$(curl -fs "$HARNESS_URL/health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('display_name','?'))" 2>/dev/null)
log "Harness: $HARNESS_URL ($HARNESS_TARGET)"

# ── DAME: Generate transcripts with multiple attackers ─────────────

ATTACKER_MODELS=(
  "bedrock/anthropic.claude-sonnet-4-6"
  "bedrock/meta.llama3-3-70b-instruct-v1:0"
)

# Add direct API models if keys are set
if [ -n "${OPENAI_API_KEY:-}" ]; then
  ATTACKER_MODELS+=("openai/gpt-4.1")
fi
if [ -n "${GOOGLE_API_KEY:-}" ]; then
  ATTACKER_MODELS+=("google/gemini-2.5-flash")
fi

# Add Ollama models if running
if curl -fs http://localhost:11434/api/tags >/dev/null 2>&1; then
  # Check which models are available
  for m in dolphin-mistral:7b deepseek-r1:32b; do
    if curl -fs http://localhost:11434/api/tags | python3 -c "import sys,json; models=[m['name'] for m in json.load(sys.stdin).get('models',[])]; sys.exit(0 if '$m' in models else 1)" 2>/dev/null; then
      ATTACKER_MODELS+=("ollama/$m")
    fi
  done
fi

if [ "$MODE" != "--scorers-only" ]; then
  log "=== DAME: Generating transcripts ==="
  log "Attackers: ${#ATTACKER_MODELS[@]} models"
  log "Dataset: $DATASET"
  log "Strategy: $STRATEGY"
  echo

  cd "$DAME_DIR"
  mkdir -p "results/$RESULTS_TAG"

  for model in "${ATTACKER_MODELS[@]}"; do
    model_short=$(echo "$model" | sed 's|.*/||' | sed 's|:|-|g')
    log_dir="results/$RESULTS_TAG/$model_short"
    mkdir -p "$log_dir"

    log "Running: $model ($STRATEGY)..."

    if inspect eval src/dame/task.py \
      --model "$model" \
      -T target_model=openai/target \
      -T target_base_url="$HARNESS_URL/v1" \
      -T dataset_path="$DATASET" \
      -T strategy="$STRATEGY" \
      --log-dir "$log_dir/" 2>&1 | tee "$log_dir/run.log"; then
      log "  Done: $model_short"
    else
      err "  FAILED: $model_short (see $log_dir/run.log)"
    fi
    echo
  done

  log "=== DAME complete. Transcripts in results/$RESULTS_TAG/ ==="
  echo
fi

# ── Ingest DAME results into DASE format ───────────────────────────

if [ "$MODE" != "--scorers-only" ]; then
  log "=== Ingesting DAME results ==="
  cd "$DASE_DIR"
  mkdir -p "datasets/$RESULTS_TAG"

  for eval_dir in "$DAME_DIR/results/$RESULTS_TAG"/*/; do
    model_short=$(basename "$eval_dir")
    latest_eval=$(ls -t "$eval_dir"/*.eval 2>/dev/null | head -1)
    if [ -z "$latest_eval" ]; then
      warn "  No .eval file in $model_short — skipping"
      continue
    fi

    log "  Ingesting $model_short..."
    python3 tools/ingest_dame.py \
      --input "$latest_eval" \
      --output "datasets/$RESULTS_TAG/${model_short}_from_dame.jsonl" 2>&1 || {
      err "  Failed to ingest $model_short"
      continue
    }
  done
  echo
fi

# ── Panel consensus ground truth ──────────────────────────────────

if [ "$MODE" != "--dame-only" ]; then
  log "=== Panel consensus ==="
  cd "$DASE_DIR"

  # Use the Sonnet attacker transcripts as the primary dataset for scoring
  PRIMARY_DATASET="datasets/$RESULTS_TAG/anthropic.claude-sonnet-4-6_from_dame.jsonl"
  if [ ! -f "$PRIMARY_DATASET" ]; then
    # Fallback: use the first available
    PRIMARY_DATASET=$(ls datasets/$RESULTS_TAG/*_from_dame.jsonl 2>/dev/null | head -1)
  fi

  if [ -z "$PRIMARY_DATASET" ] || [ ! -f "$PRIMARY_DATASET" ]; then
    err "No ingested transcripts found. Run DAME first."
    exit 1
  fi

  log "Primary dataset: $PRIMARY_DATASET"

  # Full panel (Sonnet + Opus + Llama)
  log "Running full panel consensus..."
  python3 tools/run_panel.py \
    --input "$PRIMARY_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_full.jsonl" \
    --delay 2

  # Leave-one-out panels for fair scorer evaluation
  log "Running panel without Opus (for Opus evaluation)..."
  python3 tools/run_panel.py \
    --input "$PRIMARY_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_no_opus.jsonl" \
    --exclude opus-4.6 \
    --delay 2

  log "Running panel without Llama (for Llama evaluation)..."
  python3 tools/run_panel.py \
    --input "$PRIMARY_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_no_llama.jsonl" \
    --exclude llama-3.3-70b \
    --delay 2

  log "Running panel without Sonnet (for Sonnet evaluation)..."
  python3 tools/run_panel.py \
    --input "$PRIMARY_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_no_sonnet.jsonl" \
    --exclude sonnet-4.6 \
    --delay 2

  echo

  # ── Evaluate scorers ────────────────────────────────────────────

  log "=== DASE: Evaluating scorers ==="
  mkdir -p "results/$RESULTS_TAG"

  # Panel members — use leave-one-out
  SCORERS_LOO=(
    "bedrock/anthropic.claude-opus-4-6-v1:panel_no_opus"
    "bedrock/meta.llama3-3-70b-instruct-v1:0:panel_no_llama"
    "bedrock/anthropic.claude-sonnet-4-6:panel_no_sonnet"
  )

  # Non-panel members — use full panel
  SCORERS_FULL=(
    "google/gemini-2.5-flash:panel_full"
  )

  if [ -n "${OPENAI_API_KEY:-}" ]; then
    SCORERS_FULL+=("openai/gpt-5.4:panel_full")
    SCORERS_FULL+=("openai/gpt-4.1:panel_full")
  fi

  for entry in "${SCORERS_LOO[@]}" "${SCORERS_FULL[@]}"; do
    model="${entry%%:*}"
    panel_file="${entry##*:}"
    model_short=$(echo "$model" | sed 's|.*/||' | sed 's|:|-|g')

    dataset_path="datasets/$RESULTS_TAG/${panel_file}.jsonl"
    if [ ! -f "$dataset_path" ]; then
      warn "  Skipping $model_short — panel file $panel_file not found"
      continue
    fi

    log "  Evaluating scorer: $model_short (vs $panel_file)..."

    inspect eval src/dase/task.py \
      --model "$model" \
      -T dataset_path="$dataset_path" \
      --log-dir "results/$RESULTS_TAG/" 2>&1 | tee "results/$RESULTS_TAG/${model_short}.log" || {
      err "  FAILED: $model_short"
      continue
    }
    log "  Done: $model_short"
    echo
  done

  log "=== DASE complete ==="
fi

echo
log "========================================="
log "  Results"
log "========================================="
log "DAME transcripts: $DAME_DIR/results/$RESULTS_TAG/"
log "Panel labels:     $DASE_DIR/datasets/$RESULTS_TAG/"
log "Scorer evals:     $DASE_DIR/results/$RESULTS_TAG/"
log ""
log "View results:     inspect view --log-dir $DASE_DIR/results/$RESULTS_TAG/"
log "========================================="
