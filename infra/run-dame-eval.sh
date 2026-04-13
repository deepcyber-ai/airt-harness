#!/bin/bash
# Run DAME attacker evaluation against any harness profile.
#
# Incorporates all lessons from April 12-13 evaluation sessions:
#   - Sequential runs to avoid harness contention
#   - Per-objective execution for GPT-OSS models (batch mode bug)
#   - Gemini spread across waves (API throttling)
#   - Clean env (no OPENAI_API_BASE poisoning)
#   - Cross-region inference profiles for US-only Bedrock models
#   - Automatic run logging
#
# Usage:
#   ./infra/run-dame-eval.sh                              # default: mediguide, all models
#   ./infra/run-dame-eval.sh --profile deepvault-agentic  # different profile
#   ./infra/run-dame-eval.sh --dataset datasets/custom.jsonl
#   ./infra/run-dame-eval.sh --models "sonnet gpt41 dolphin"
#   ./infra/run-dame-eval.sh --tag my-experiment
#
# Prerequisites:
#   - Harness running with target profile (airt-launch <profile> --env-file ~/.airt-config/.env)
#   - API keys in ~/.airt-config/.env
#   - DAME installed (pip install -e . in dame/)

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────

DAME_DIR="${HOME}/src/deepcyber-airt/dame"
DASE_DIR="${HOME}/src/deepcyber-airt/dase"
HARNESS_URL="${HARNESS_URL:-http://localhost:8000}"
STRATEGY="${STRATEGY:-crescendo_5}"

# Defaults
PROFILE="${PROFILE:-mediguide}"
DATASET=""
TAG=""
MODELS=""

# ── Parse arguments ──────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case $1 in
    --profile) PROFILE="$2"; shift 2 ;;
    --dataset) DATASET="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --models) MODELS="$2"; shift 2 ;;
    --strategy) STRATEGY="$2"; shift 2 ;;
    --harness-url) HARNESS_URL="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Default dataset per profile
if [ -z "$DATASET" ]; then
  case "$PROFILE" in
    mediguide)          DATASET="datasets/mediguide.jsonl" ;;
    deepvault-agentic)  DATASET="datasets/deepvault_agentic.jsonl" ;;
    default)            DATASET="datasets/financial_advisor.jsonl" ;;
    baseline)           DATASET="datasets/financial_advisor.jsonl" ;;
    *) echo "Unknown profile: $PROFILE — specify --dataset"; exit 1 ;;
  esac
fi

# Tag for results directory
[ -z "$TAG" ] && TAG="${PROFILE}-$(date +%Y%m%d-%H%M)"
RESULTS_DIR="results/${TAG}"

# ── Load API keys (safe — no OPENAI_API_BASE) ───────────────────────

SHARED_ENV="${HOME}/.airt-config/.env"
if [ -f "$SHARED_ENV" ]; then
  # Extract keys via Python to handle $ and special chars
  export OPENAI_API_KEY=$(python3 -c "
with open('$SHARED_ENV') as f:
    for line in f:
        if line.startswith('OPENAI_API_KEY='):
            print(line.strip().split('=',1)[1])
            break
" 2>/dev/null)
  export GOOGLE_API_KEY=$(grep -m1 "^GOOGLE_API_KEY=" "$SHARED_ENV" 2>/dev/null | cut -d= -f2- || true)
fi
# Never inherit OPENAI_API_BASE — it redirects target model calls
unset OPENAI_API_BASE OPENAI_BASE_URL 2>/dev/null || true

# ── Model definitions ────────────────────────────────────────────────

# Each model: id|short_name|wave|mode
# wave: 1,2,3 (sequential within wave, waves run in order)
# mode: normal|individual (individual = one objective at a time for GPT-OSS)
ALL_MODELS=(
  # Wave 1: Bedrock EU + OpenAI (fast, reliable)
  "bedrock/anthropic.claude-sonnet-4-6|sonnet-4.6|1|normal"
  "bedrock/qwen.qwen3-235b-a22b-2507-v1:0|qwen3-235b|1|normal"
  "openai/gpt-4.1|gpt-4.1|1|normal"
  "bedrock/mistral.magistral-small-2509|magistral-small|1|normal"

  # Wave 2: Bedrock US + local + slower cloud
  "bedrock/us.meta.llama4-maverick-17b-instruct-v1:0|llama4-maverick|2|normal"
  "bedrock/us.meta.llama3-3-70b-instruct-v1:0|llama-3.3-70b|2|normal"
  "bedrock/deepseek.v3.2|deepseek-v3.2|2|normal"
  "ollama/dolphin-mistral:7b|dolphin-7b|2|normal"

  # Wave 3: Slow/problematic models (Gemini throttles, GPT-OSS needs individual mode)
  "google/gemini-2.5-flash|gemini-flash|3|normal"
  "bedrock/openai.gpt-oss-20b-1:0|gpt-oss-20b|3|individual"
  "bedrock/openai.gpt-oss-120b-1:0|gpt-oss-120b|3|individual"
)

# ── Colours ──────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} $1"; }
err() { echo -e "${RED}[$(date +%H:%M:%S)]${NC} $1"; }

# ── Functions ────────────────────────────────────────────────────────

run_normal() {
  local model="$1" dir="$2" dataset="$3"
  local env_prefix=""

  # US-only models need region override
  if [[ "$model" == *"us.meta"* || "$model" == *"us.deepseek"* ]]; then
    env_prefix="AWS_DEFAULT_REGION=us-east-1"
  fi

  log "  Starting: $dir ($model)"
  local start_time=$(date +%s)

  eval $env_prefix inspect eval src/dame/task.py@dame \
    --model "$model" \
    -T target_model=openai/target \
    -T target_base_url="${HARNESS_URL}/v1" \
    -T dataset_path="$dataset" \
    -T strategy="$STRATEGY" \
    --log-dir "${RESULTS_DIR}/$dir/" > "${RESULTS_DIR}/${dir}.log" 2>&1

  local end_time=$(date +%s)
  local duration=$(( end_time - start_time ))

  # Count samples
  local eval_file=$(ls -t "${RESULTS_DIR}/$dir/"*.eval 2>/dev/null | head -1)
  local samples=0
  [ -n "$eval_file" ] && samples=$(python3 -c "import zipfile; print(len([n for n in zipfile.ZipFile('$eval_file').namelist() if n.startswith('samples/')]))" 2>/dev/null || echo 0)

  local total=$(wc -l < "$DAME_DIR/$dataset" 2>/dev/null || echo "?")
  log "  Done: $dir — ${samples}/${total} samples in ${duration}s"

  # Log to run record
  echo "${dir},${model},${samples},${total},${duration},${dataset},${STRATEGY},$(date -Iseconds)" >> "${RESULTS_DIR}/run_record.csv"
}

run_individual() {
  local model="$1" dir="$2" dataset="$3"
  local env_prefix=""

  if [[ "$model" == *"us.meta"* || "$model" == *"us.deepseek"* ]]; then
    env_prefix="AWS_DEFAULT_REGION=us-east-1"
  fi

  log "  Starting: $dir ($model) — INDIVIDUAL MODE"
  local start_time=$(date +%s)
  local completed=0
  local failed=0
  local obj_num=0

  # Run each objective separately
  while IFS= read -r obj_line; do
    obj_num=$((obj_num + 1))
    local obj_file=$(mktemp /tmp/dame_obj_XXXX.jsonl)
    echo "$obj_line" > "$obj_file"

    mkdir -p "${RESULTS_DIR}/${dir}/obj${obj_num}"

    eval $env_prefix inspect eval src/dame/task.py@dame \
      --model "$model" \
      -T target_model=openai/target \
      -T target_base_url="${HARNESS_URL}/v1" \
      -T dataset_path="$obj_file" \
      -T strategy="$STRATEGY" \
      --log-dir "${RESULTS_DIR}/${dir}/obj${obj_num}/" > /dev/null 2>&1

    local eval_file=$(ls -t "${RESULTS_DIR}/${dir}/obj${obj_num}/"*.eval 2>/dev/null | head -1)
    local samples=0
    [ -n "$eval_file" ] && samples=$(python3 -c "import zipfile; print(len([n for n in zipfile.ZipFile('$eval_file').namelist() if n.startswith('samples/')]))" 2>/dev/null || echo 0)

    if [ "$samples" -gt 0 ]; then
      completed=$((completed + 1))
    else
      failed=$((failed + 1))
    fi

    rm -f "$obj_file"
  done < "$DAME_DIR/$dataset"

  local end_time=$(date +%s)
  local duration=$(( end_time - start_time ))
  local total=$((completed + failed))

  log "  Done: $dir — ${completed}/${total} objectives (${failed} failed) in ${duration}s"
  echo "${dir},${model},${completed},${total},${duration},${dataset},${STRATEGY},$(date -Iseconds),individual" >> "${RESULTS_DIR}/run_record.csv"
}

# ── Filter models if --models specified ──────────────────────────────

get_selected_models() {
  if [ -z "$MODELS" ]; then
    printf '%s\n' "${ALL_MODELS[@]}"
    return
  fi

  for entry in "${ALL_MODELS[@]}"; do
    local short=$(echo "$entry" | cut -d'|' -f2)
    for sel in $MODELS; do
      if [[ "$short" == *"$sel"* ]]; then
        echo "$entry"
        break
      fi
    done
  done
}

# ── Preflight ────────────────────────────────────────────────────────

log "=== DAME Attacker Evaluation ==="
log "Profile: $PROFILE"
log "Dataset: $DATASET"
log "Strategy: $STRATEGY"
log "Results: $RESULTS_DIR"
log "Harness: $HARNESS_URL"

# Check harness
if ! curl -fs "${HARNESS_URL}/health" >/dev/null 2>&1; then
  err "Harness not running at $HARNESS_URL"
  err "Start with: MOCK_BACKEND=openai airt-launch $PROFILE --env-file ~/.airt-config/.env"
  exit 1
fi

HARNESS_TARGET=$(curl -fs "${HARNESS_URL}/health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('display_name','?'))" 2>/dev/null)
log "Target: $HARNESS_TARGET"

# Check dataset
if [ ! -f "$DAME_DIR/$DATASET" ]; then
  err "Dataset not found: $DAME_DIR/$DATASET"
  exit 1
fi
OBJ_COUNT=$(wc -l < "$DAME_DIR/$DATASET")
log "Objectives: $OBJ_COUNT"

# Check Ollama (if dolphin in model list)
if echo "${ALL_MODELS[@]}" | grep -q "ollama/" && ! curl -fs http://localhost:11434/api/tags >/dev/null 2>&1; then
  warn "Ollama not running — local models will be skipped"
fi

# ── Setup results directory ──────────────────────────────────────────

cd "$DAME_DIR"
mkdir -p "$RESULTS_DIR"

# Run record header
echo "model_short,model_id,samples,total,duration_s,dataset,strategy,timestamp,mode" > "${RESULTS_DIR}/run_record.csv"

# Save run metadata
cat > "${RESULTS_DIR}/run_metadata.json" << METADATA
{
  "profile": "$PROFILE",
  "dataset": "$DATASET",
  "strategy": "$STRATEGY",
  "harness_url": "$HARNESS_URL",
  "harness_target": "$HARNESS_TARGET",
  "objectives": $OBJ_COUNT,
  "started": "$(date -Iseconds)",
  "tag": "$TAG"
}
METADATA

log ""

# ── Run models by wave ───────────────────────────────────────────────

SELECTED_MODELS=()
while IFS= read -r line; do
  [ -n "$line" ] && SELECTED_MODELS+=("$line")
done < <(get_selected_models)

log "Models: ${#SELECTED_MODELS[@]} selected"

for wave in 1 2 3; do
  WAVE_MODELS=()
  for entry in "${SELECTED_MODELS[@]}"; do
    local_wave=$(echo "$entry" | cut -d'|' -f3)
    [ "$local_wave" = "$wave" ] && WAVE_MODELS+=("$entry")
  done

  [ ${#WAVE_MODELS[@]} -eq 0 ] && continue

  log "=== Wave $wave (${#WAVE_MODELS[@]} models) ==="

  for entry in "${WAVE_MODELS[@]}"; do
    local model_id=$(echo "$entry" | cut -d'|' -f1)
    local short=$(echo "$entry" | cut -d'|' -f2)
    local mode=$(echo "$entry" | cut -d'|' -f4)

    mkdir -p "${RESULTS_DIR}/${short}"

    # Skip Ollama models if not running
    if [[ "$model_id" == ollama/* ]] && ! curl -fs http://localhost:11434/api/tags >/dev/null 2>&1; then
      warn "  Skipping $short — Ollama not running"
      continue
    fi

    if [ "$mode" = "individual" ]; then
      run_individual "$model_id" "$short" "$DATASET"
    else
      run_normal "$model_id" "$short" "$DATASET"
    fi
  done

  log "=== Wave $wave complete ==="
  log ""
done

# ── Summary ──────────────────────────────────────────────────────────

log "========================================="
log "  Evaluation Complete"
log "========================================="
log "Results: $DAME_DIR/$RESULTS_DIR"
log "Run record: $RESULTS_DIR/run_record.csv"
log ""

# Print summary from run record
log "Model Results:"
while IFS=, read -r short model samples total duration dataset strategy ts mode; do
  [ "$short" = "model_short" ] && continue
  local rate=""
  [ "$total" != "0" ] && [ "$total" != "?" ] && rate=" ($(( samples * 100 / total ))%)"
  log "  $short: ${samples}/${total}${rate} in ${duration}s${mode:+ [$mode]}"
done < "${RESULTS_DIR}/run_record.csv"

log ""
log "Next steps:"
log "  1. Ingest:  cd $DASE_DIR && python3 tools/ingest_dame.py --input $DAME_DIR/$RESULTS_DIR/<model>/*.eval --output datasets/<tag>/<model>_from_dame.jsonl"
log "  2. Review:  Check transcripts for breaches"
log "  3. Score:   Run scorer evaluation against transcripts"
log "========================================="
