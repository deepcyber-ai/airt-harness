# DAME/DASE Integration with AIRT Harness

## Architecture

```
DAME (attacker eval)                    DASE (scorer eval)
  |                                       |
  | target_base_url=localhost:8000/v1     | ingests .eval logs from DAME
  v                                       v
AIRT Harness                            DAME .eval files
  |                                       |
  ├── Intel logs (responses.jsonl)        ├── Full conversations + objectives
  ├── Guardrail metadata                  ├── Ground truth labels
  └── Session management                  └── Strategy metadata
  |
  v
Target (mock or real)
```

DAME attacks **through** the harness. DASE evaluates scorers **from** DAME's output.
The harness sits in the DAME→target path, adding intel logging and guardrail data.

## DAME → Harness (works today)

DAME uses Inspect's `get_model()` with a `base_url` override. The harness
serves `/v1/chat/completions` (OpenAI-compatible). No code changes needed.

### Run DAME against the harness

```bash
# Terminal 1: start harness with a profile
airt-launch mediguide                    # or: airt-launch default

# Terminal 2: run DAME through the harness
cd ~/src/deepcyber-airt/dame

inspect eval src/dame/task.py \
  --model openai/gpt-4.1 \
  -T target_model=openai/target \
  -T target_base_url=http://localhost:8000/v1 \
  -T strategy=crescendo_10 \
  --log-dir results/
```

What happens:
1. DAME sends attacker prompts via Inspect's model API
2. Inspect routes to `http://localhost:8000/v1/chat/completions`
3. Harness logs to `responses.jsonl`, applies firewall (if enabled), proxies to mock/real
4. DAME gets responses back through the same path
5. Both DAME `.eval` logs and harness intel capture the full exchange

### Dual logging

Every attacker-target exchange is logged in two places:

| Log | Location | Contains |
|-----|----------|----------|
| DAME eval log | `dame/results/*.eval` | Full conversation, objective, scores, strategy |
| Harness intel | `profiles/<name>/intel/responses.jsonl` | Prompt, answer, raw response, guardrail events |

The DAME log has the **red team context** (what was the attack objective, did it succeed).
The harness intel has the **target context** (what guardrails fired, what pipeline nodes ran).

## DASE ← DAME (works today)

DASE ingests DAME's `.eval` files directly:

```bash
cd ~/src/deepcyber-airt/dase

# Ingest DAME eval logs into unified transcript format
python tools/ingest_dame.py \
  --input ../dame/results/latest.eval \
  --output datasets/from_dame.jsonl

# Convert to Inspect format for scorer evaluation
python tools/pyrit_to_dase.py \
  --input datasets/from_dame.jsonl \
  --output datasets/dame_inspect.jsonl

# Run scorer evaluation
inspect eval src/dase/task.py \
  --model openai/gpt-4.1 \
  -T dataset_path=datasets/dame_inspect.jsonl
```

## Harness Intel as Metadata Enrichment (future)

The harness intel logs contain guardrail metadata that DASE doesn't currently
use. This is valuable for understanding **why** a target responded the way it
did — not just whether the attack succeeded.

### What harness intel adds

| Field | Value for scorer evaluation |
|-------|----------------------------|
| `events[].name` | Which guardrails fired (injection, hallucination, advice) |
| `events[].score` | Guardrail confidence score |
| `events[].triggered` | Whether the guardrail blocked |
| `agent_thoughts` | Pipeline node decisions (classifier, planner, brain, etc.) |
| `raw` | Full target response including internal metadata |

### Future: `ingest_harness.py`

A DASE ingest adapter that enriches unified transcripts with harness metadata:

```bash
python tools/ingest_harness.py \
  --transcripts datasets/from_dame.jsonl \
  --intel ../profiles/mediguide/intel/responses.jsonl \
  --output datasets/enriched.jsonl
```

This would match DAME transcripts to harness intel records by session_id and
timestamp, then attach `events` and `agent_thoughts` as metadata. The enriched
transcripts let DASE evaluate whether scorers correctly account for guardrail
behaviour — for example, a scorer should rate an attack as FAILURE if the
guardrail blocked it, even if the underlying brain response would have been
problematic.

### Why this matters for agentic systems

Agentic targets expose pipeline metadata in their responses (which agent
handled the request, what tools were called, what scores were assigned). This
metadata is:

1. **An attack surface** — information disclosure about the system's
   architecture, guardrail thresholds, and decision logic
2. **Essential for evaluation** — explains why the system behaved a certain
   way, which helps judge whether a scorer's verdict is correct

The enrichment adapter bridges these two perspectives.
