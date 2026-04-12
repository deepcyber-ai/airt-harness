#!/bin/bash
# Run DAME with multiple attacker models against the harness, then DASE scorer eval.
#
# Usage:
#   ./run-scorer-batch.sh                    # run all stages: DAME → ingest → panel → score
#   ./run-scorer-batch.sh --dame-only        # DAME attacks only (generate transcripts)
#   ./run-scorer-batch.sh --scorers-only     # ingest + panel + score (skip DAME)
#   ./run-scorer-batch.sh --score-only       # score only (skip DAME, ingest, panel — use existing panels)
#   ./run-scorer-batch.sh --ingest-only      # ingest DAME results into DASE format only
#
# Prerequisites:
#   - Harness running: MOCK_BACKEND=gemini airt-launch
#   - API keys set: OPENAI_API_KEY, GOOGLE_API_KEY
#   - AWS Bedrock configured (aws sts get-caller-identity)
#   - DAME/DASE installed (pip install -e .)
#   - .env in ~/src/deepcyber-airt/dame/ and dase/
#   - (Optional) RUNPOD_URL / RUNPOD_API_KEY for remote vLLM models
#
# Environment overrides:
#   DAME_DATASET=datasets/mediguide.jsonl    # alternate dataset
#   RESULTS_TAG=mediguide-eval               # alternate results dir
#   BEDROCK_REGION_US=us-east-1              # region for US-only models
#   RUNPOD_URL=http://host:port              # RunPod vLLM endpoint
#   RUNPOD_API_KEY=xxx                       # RunPod API key
#
# Results go to:
#   dame/results/scorer-eval/           DAME eval logs
#   dase/datasets/scorer-eval/          Panel-labelled transcripts
#   dase/results/scorer-eval/           DASE scorer eval logs

set -euo pipefail

DAME_DIR="${HOME}/src/deepcyber-airt/dame"
DASE_DIR="${HOME}/src/deepcyber-airt/dase"
DATASET="${DAME_DATASET:-datasets/financial_advisor.jsonl}"
STRATEGY="crescendo_5"
HARNESS_URL="http://localhost:8000"
RESULTS_TAG="${RESULTS_TAG:-scorer-eval}"
RUNPOD_URL="${RUNPOD_URL:-}"
RUNPOD_API_KEY="${RUNPOD_API_KEY:-}"

# Some Bedrock models are only available in US regions
BEDROCK_REGION_US="${BEDROCK_REGION_US:-us-east-1}"

MODE="${1:-all}"  # all | --dame-only | --scorers-only | --score-only | --ingest-only

# Stage flags
RUN_DAME=true
RUN_INGEST=true
RUN_PANEL=true
RUN_SCORE=true

case "$MODE" in
  --dame-only)    RUN_INGEST=false; RUN_PANEL=false; RUN_SCORE=false ;;
  --scorers-only) RUN_DAME=false ;;
  --score-only)   RUN_DAME=false; RUN_INGEST=false; RUN_PANEL=false ;;
  --ingest-only)  RUN_DAME=false; RUN_PANEL=false; RUN_SCORE=false ;;
  all)            ;; # run everything
  *) err "Unknown mode: $MODE"; exit 1 ;;
esac
MAX_PARALLEL="${MAX_PARALLEL:-4}"  # max concurrent attacker/scorer runs

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} $1"; }
err() { echo -e "${RED}[$(date +%H:%M:%S)]${NC} $1"; }

# ── Per-model environment overrides ──────────────────────────────
# Maps model ID -> env var prefix to inject before inspect eval.
# Used for region overrides (Bedrock US-only) and RunPod base URLs.

declare -A MODEL_ENV

set_us_region() {
  MODEL_ENV["$1"]="AWS_DEFAULT_REGION=$BEDROCK_REGION_US"
}

# US-only models use cross-region inference profiles (us. prefix)
# which route automatically — no region override needed.
# Mistral Large 3 has no inference profile yet — commented out in attacker list.

# ── Load shared API keys ─────────────────────────────────────────
# dame/.env and dase/.env symlink to ~/.airt-config/.env
# Only import specific keys — sourcing everything can poison Bedrock
# calls (e.g. OPENAI_API_BASE redirects inspect's provider routing).
SHARED_ENV="${HOME}/.airt-config/.env"
if [ -f "$SHARED_ENV" ]; then
  _load_key() { grep -m1 "^$1=" "$SHARED_ENV" 2>/dev/null | cut -d= -f2-; }
  [ -z "${OPENAI_API_KEY:-}" ]  && export OPENAI_API_KEY="$(_load_key OPENAI_API_KEY)"
  [ -z "${GOOGLE_API_KEY:-}" ]  && export GOOGLE_API_KEY="$(_load_key GOOGLE_API_KEY)"
fi
# Never inherit OPENAI_API_BASE — it overrides the target_base_url for
# the harness target model and sends requests to the wrong endpoint.
unset OPENAI_API_BASE OPENAI_BASE_URL 2>/dev/null || true

# ── Preflight ──────────────────────────��───────────────────────────

log "Checking prerequisites..."

if ! curl -fs "$HARNESS_URL/health" >/dev/null 2>&1; then
  err "Harness not running at $HARNESS_URL"
  err "Start it with: MOCK_BACKEND=gemini airt-launch"
  exit 1
fi

HARNESS_TARGET=$(curl -fs "$HARNESS_URL/health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('display_name','?'))" 2>/dev/null)
log "Harness: $HARNESS_URL ($HARNESS_TARGET)"

# ── DAME: Generate transcripts with multiple attackers ─────────────

# Tier 1: Bedrock (available in default region)
ATTACKER_MODELS=(
  "bedrock/anthropic.claude-sonnet-4-6"
  "bedrock/qwen.qwen3-235b-a22b-2507-v1:0"
  "bedrock/mistral.magistral-small-2509"
  "bedrock/deepseek.v3.2"
)

# Tier 1: Bedrock (US region only)
ATTACKER_MODELS+=(
  "bedrock/us.deepseek.r1-v1:0"
  "bedrock/us.meta.llama3-3-70b-instruct-v1:0"
  # "bedrock/mistral.mistral-large-3-675b-instruct"  # No inference profile in us-east-1 yet
  "bedrock/us.meta.llama4-maverick-17b-instruct-v1:0"
)

# Tier 3: Direct API models (if keys are set)
if [ -n "${OPENAI_API_KEY:-}" ]; then
  ATTACKER_MODELS+=("openai/gpt-5.4")
  ATTACKER_MODELS+=("openai/gpt-5.4-mini")
  ATTACKER_MODELS+=("openai/gpt-4.1")
fi
if [ -n "${GOOGLE_API_KEY:-}" ]; then
  ATTACKER_MODELS+=("google/gemini-2.5-flash")
fi

# Tier 2: Ollama models (if running and pulled)
if curl -fs http://localhost:11434/api/tags >/dev/null 2>&1; then
  for m in dolphin-mistral:7b dolphin-llama3:70b deepseek-r1:32b qwen3:32b mistral-small:24b; do
    if curl -fs http://localhost:11434/api/tags | python3 -c "import sys,json; models=[m['name'] for m in json.load(sys.stdin).get('models',[])]; sys.exit(0 if '$m' in models else 1)" 2>/dev/null; then
      ATTACKER_MODELS+=("ollama/$m")
    fi
  done
fi

# RunPod vLLM models (if endpoint is set and reachable)
if [ -n "$RUNPOD_URL" ]; then
  if curl -fs -H "Authorization: Bearer ${RUNPOD_API_KEY}" "${RUNPOD_URL}/v1/models" >/dev/null 2>&1; then
    for model_id in $(curl -fs -H "Authorization: Bearer ${RUNPOD_API_KEY}" "${RUNPOD_URL}/v1/models" | python3 -c "import sys,json; [print(m['id']) for m in json.load(sys.stdin).get('data',[])]" 2>/dev/null); do
      key="openai/${model_id}"
      ATTACKER_MODELS+=("$key")
      MODEL_ENV["$key"]="OPENAI_BASE_URL=${RUNPOD_URL}/v1 OPENAI_API_KEY=${RUNPOD_API_KEY}"
      log "Added RunPod model: $model_id"
    done
  else
    warn "RunPod endpoint $RUNPOD_URL not reachable — skipping"
  fi
fi

if $RUN_DAME; then
  log "=== DAME: Generating transcripts ==="
  log "Attackers: ${#ATTACKER_MODELS[@]} models"
  log "Dataset: $DATASET"
  log "Strategy: $STRATEGY"
  echo

  cd "$DAME_DIR"
  mkdir -p "results/$RESULTS_TAG"

  DAME_PIDS=()
  DAME_NAMES=()

  for model in "${ATTACKER_MODELS[@]}"; do
    model_short=$(echo "$model" | sed 's|.*/||' | sed 's|:|-|g')
    log_dir="results/$RESULTS_TAG/$model_short"
    mkdir -p "$log_dir"

    # Wait if we've hit the concurrency limit
    while [ ${#DAME_PIDS[@]} -ge $MAX_PARALLEL ]; do
      # Wait for any one child to finish
      for i in "${!DAME_PIDS[@]}"; do
        if ! kill -0 "${DAME_PIDS[$i]}" 2>/dev/null; then
          wait "${DAME_PIDS[$i]}" 2>/dev/null && \
            log "  Done: ${DAME_NAMES[$i]}" || \
            err "  FAILED: ${DAME_NAMES[$i]} (see results/$RESULTS_TAG/${DAME_NAMES[$i]}/run.log)"
          unset 'DAME_PIDS[$i]' 'DAME_NAMES[$i]'
          DAME_PIDS=("${DAME_PIDS[@]}")
          DAME_NAMES=("${DAME_NAMES[@]}")
          break
        fi
      done
      [ ${#DAME_PIDS[@]} -ge $MAX_PARALLEL ] && sleep 2
    done

    log "Launching: $model ($STRATEGY)..."

    env_prefix="${MODEL_ENV[$model]:-}"

    (
      eval $env_prefix inspect eval src/dame/task.py@dame \
        --model "$model" \
        -T target_model=openai/target \
        -T target_base_url="$HARNESS_URL/v1" \
        -T dataset_path="$DATASET" \
        -T strategy="$STRATEGY" \
        --log-dir "$log_dir/" > "$log_dir/run.log" 2>&1
    ) &
    DAME_PIDS+=($!)
    DAME_NAMES+=("$model_short")
  done

  # Wait for all remaining
  for i in "${!DAME_PIDS[@]}"; do
    wait "${DAME_PIDS[$i]}" 2>/dev/null && \
      log "  Done: ${DAME_NAMES[$i]}" || \
      err "  FAILED: ${DAME_NAMES[$i]} (see results/$RESULTS_TAG/${DAME_NAMES[$i]}/run.log)"
  done

  log "=== DAME complete. Transcripts in results/$RESULTS_TAG/ ==="
  echo
fi

# ── Ingest DAME results into DASE format ──────��────────────────────

if $RUN_INGEST; then
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

# ── Panel consensus ground truth ───────────────���──────────────────

if $RUN_PANEL; then
  log "=== Panel consensus ==="
  cd "$DASE_DIR"

  # Merge all attacker transcripts into a combined dataset for panel scoring.
  # This gives broader coverage than scoring a single attacker's transcripts.
  COMBINED_DATASET="datasets/$RESULTS_TAG/all_attackers_combined.jsonl"
  log "Combining attacker transcripts..."
  cat datasets/$RESULTS_TAG/*_from_dame.jsonl > "$COMBINED_DATASET" 2>/dev/null

  if [ ! -s "$COMBINED_DATASET" ]; then
    err "No ingested transcripts found. Run DAME + ingest first."
    exit 1
  fi

  TRANSCRIPT_COUNT=$(wc -l < "$COMBINED_DATASET")
  ATTACKER_COUNT=$(ls datasets/$RESULTS_TAG/*_from_dame.jsonl 2>/dev/null | wc -l)
  log "Combined dataset: $TRANSCRIPT_COUNT transcripts from $ATTACKER_COUNT attackers"

  # Full panel (Sonnet + Opus + Llama)
  log "Running full panel consensus..."
  python3 tools/run_panel.py \
    --input "$COMBINED_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_full.jsonl" \
    --delay 2

  # Leave-one-out panels for fair scorer evaluation
  log "Running panel without Opus (for Opus evaluation)..."
  python3 tools/run_panel.py \
    --input "$COMBINED_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_no_opus.jsonl" \
    --exclude opus-4.6 \
    --delay 2

  log "Running panel without Llama (for Llama evaluation)..."
  python3 tools/run_panel.py \
    --input "$COMBINED_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_no_llama.jsonl" \
    --exclude llama-3.3-70b \
    --delay 2

  log "Running panel without Sonnet (for Sonnet evaluation)..."
  python3 tools/run_panel.py \
    --input "$COMBINED_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_no_sonnet.jsonl" \
    --exclude sonnet-4.6 \
    --delay 2

  log "Running panel without GPT-4.1 (for GPT-4.1 evaluation)..."
  python3 tools/run_panel.py \
    --input "$COMBINED_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_no_gpt41.jsonl" \
    --exclude gpt-4.1 \
    --delay 2

  log "Running panel without GPT-5.4 (for GPT-5.4 evaluation)..."
  python3 tools/run_panel.py \
    --input "$COMBINED_DATASET" \
    --output "datasets/$RESULTS_TAG/panel_no_gpt54.jsonl" \
    --exclude gpt-5.4 \
    --delay 2

  echo
fi

if $RUN_SCORE; then
  # ── Evaluate scorers ────────────────────────────────────────────

  log "=== DASE: Evaluating scorers ==="
  mkdir -p "results/$RESULTS_TAG"

  # Scorer entries use "|" as delimiter to avoid clashing with ":" in model IDs
  # Format: "model_id|panel_file"

  # Panel members — use leave-one-out (model scores against panel it wasn't part of)
  SCORERS=(
    "bedrock/anthropic.claude-opus-4-6-v1|panel_no_opus"
    "bedrock/us.meta.llama3-3-70b-instruct-v1:0|panel_no_llama"
    "bedrock/anthropic.claude-sonnet-4-6|panel_no_sonnet"
  )

  if [ -n "${OPENAI_API_KEY:-}" ]; then
    SCORERS+=("openai/gpt-4.1|panel_no_gpt41")
    SCORERS+=("openai/gpt-5.4|panel_no_gpt54")
  fi

  # Non-panel members — use full panel
  SCORERS+=(
    "bedrock/us.deepseek.r1-v1:0|panel_full"
    "bedrock/qwen.qwen3-235b-a22b-2507-v1:0|panel_full"
    "bedrock/mistral.magistral-small-2509|panel_full"
  )

  if [ -n "${GOOGLE_API_KEY:-}" ]; then
    SCORERS+=("google/gemini-2.5-flash|panel_full")
  fi

  if [ -n "${OPENAI_API_KEY:-}" ]; then
    SCORERS+=("openai/gpt-5.4-mini|panel_full")
  fi

  # RunPod models as scorers
  for key in "${!MODEL_ENV[@]}"; do
    if [[ "$key" == openai/* ]] && [[ "${MODEL_ENV[$key]}" == *OPENAI_BASE_URL* ]]; then
      SCORERS+=("${key}|panel_full")
    fi
  done

  SCORER_PIDS=()
  SCORER_NAMES=()

  for entry in "${SCORERS[@]}"; do
    model="${entry%%|*}"
    panel_file="${entry##*|}"
    model_short=$(echo "$model" | sed 's|.*/||' | sed 's|:|-|g')

    dataset_path="datasets/$RESULTS_TAG/${panel_file}.jsonl"
    if [ ! -f "$dataset_path" ]; then
      warn "  Skipping $model_short — panel file $panel_file not found"
      continue
    fi

    # Wait if we've hit the concurrency limit
    while [ ${#SCORER_PIDS[@]} -ge $MAX_PARALLEL ]; do
      for i in "${!SCORER_PIDS[@]}"; do
        if ! kill -0 "${SCORER_PIDS[$i]}" 2>/dev/null; then
          wait "${SCORER_PIDS[$i]}" 2>/dev/null && \
            log "  Done: ${SCORER_NAMES[$i]}" || \
            err "  FAILED: ${SCORER_NAMES[$i]}"
          unset 'SCORER_PIDS[$i]' 'SCORER_NAMES[$i]'
          SCORER_PIDS=("${SCORER_PIDS[@]}")
          SCORER_NAMES=("${SCORER_NAMES[@]}")
          break
        fi
      done
      [ ${#SCORER_PIDS[@]} -ge $MAX_PARALLEL ] && sleep 2
    done

    log "  Launching scorer: $model_short (vs $panel_file)..."

    env_prefix="${MODEL_ENV[$model]:-}"

    (
      eval $env_prefix inspect eval src/dase/task.py \
        --model "$model" \
        -T dataset_path="$dataset_path" \
        --log-dir "results/$RESULTS_TAG/" > "results/$RESULTS_TAG/${model_short}.log" 2>&1
    ) &
    SCORER_PIDS+=($!)
    SCORER_NAMES+=("$model_short")
  done

  # Wait for all remaining
  for i in "${!SCORER_PIDS[@]}"; do
    wait "${SCORER_PIDS[$i]}" 2>/dev/null && \
      log "  Done: ${SCORER_NAMES[$i]}" || \
      err "  FAILED: ${SCORER_NAMES[$i]}"
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
