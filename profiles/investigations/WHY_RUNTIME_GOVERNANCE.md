# Why Runtime Governance — the argument behind the DeepTrace demo

*The connective tissue for the four acts: **who decides**, **probabilistic vs.
deterministic**, and **text vs. irreversible action**. This is the "why," alongside
`run.sh` (the how) and `DEEPTRACE_REFERENCE.md` (the what).*

---

## Thesis

Every defense that operates on **language** — model alignment, system-prompt rules,
and external guardrails — ultimately delegates the decision to a **model**, or to a
**pattern-match that's trivially bypassed**. These controls raise the *odds* of catching
a bad request, but they stay **probabilistic, model-dependent, and steerable by untrusted
input**. That is acceptable when the worst outcome is a bad *sentence*. It is **not**
acceptable when the outcome is a consequential, **irreversible action**. Runtime
governance moves the decision **out of the model** into a **deterministic authorization
layer over facts the model may not even have** — the control that irreversible actions
actually require.

## Two sharpenings

1. **Name the invariant.** Across alignment → prompt → external guardrails, the thing
   that never changes is **who decides — a model** (a classifier is also a model). Each
   layer raises the *probability* of catching a bad request; none of them changes it into
   a *guarantee*. You're tuning a dial, never closing the gap.
2. **Make the pivot about risk, not just "actions."** Probabilistic defense is fine for
   chat but not here because **risk = likelihood × consequence**. A 5% miss on a text
   answer is a bad sentence; a 5% miss on *"delete the evidence"* is irreversible.
   Probabilistic controls are acceptable *exactly until the consequence becomes
   irreversible* — and that is the line runtime governance is built for.

---

## The ladder — every rung, the same flaw

| Layer | What it adds | Who decides | Why it's not enough |
|---|---|---|---|
| **1. Model alignment** (no explicit rules) | Refuses what *sounds* harmful | The model's training | Blind to rules it was never given (legal hold, open case); protection is entirely a property of *which model* you run. **Eval: crude 0–95% across models.** |
| **2. Prompt hardening** (explicit rules) | Writes the rules in | The model, *interpreting* the rules | Still probabilistic and model-dependent; framed requests slip through. **Eval: strong models → ~0 crude, but subtle still leaks 1–31%; weak models (mistral 68%) barely move.** |
| **3. External guardrails** (not in the demo, deliberately) | A separate filter | A **regex** (deterministic but trivially bypassed) *or* a **classifier / LLM-judge** — *itself a model* | Regex: bypass by paraphrase / encoding / injection. Classifier: inherits the **same model-reliance** it was meant to fix. You vary the *level* of protection — but **a model still decides**. |
| **✗ Indirect prompt injection** | *(an attack, not a layer)* | Untrusted content, effectively | Doesn't add a rung — it **defeats all three at once**, because every layer above reasons over *text*, and text can be poisoned. |

---

## The tools, by layer  *(the vocabulary this maps to)*

The abstract "layers" above are concrete products your audience will recognise. Naming
them makes the point land — and shows the flaw is **structural**, not a gap in any one
tool:

- **Rung 1 — alignment:** the safety training baked into the model (RLHF / constitutional
  training in GPT, Claude, Llama, etc.). Not a product you add — it's *which model you pick*.
- **Rung 2 — prompt hardening:** system-prompt rules, instruction hierarchy, spotlighting /
  delimiting untrusted content. Free, but the *model* still interprets it.
- **Rung 3 — external guardrails:**
  - **Guardrail frameworks:** **NeMo Guardrails** (NVIDIA), **Guardrails AI**, **LLM Guard**
  - **Safety classifiers / model-as-judge:** **Meta Llama Guard**, **Azure AI Content
    Safety / Prompt Shields**, **AWS Bedrock Guardrails**, **OpenAI Moderation**
  - **Pattern / keyword filters:** regex & denylists
  - *Every one of these is either a bypassable pattern-match or another model — so the
    decision still rests on a probabilistic component.*

**How the leakage is proven:** the residual bypass rates aren't asserted, they're
**measured** with red-team tooling — **Garak** (NVIDIA), **Promptfoo**, **PyRIT**
(Microsoft), **HumanBound**, **Giskard**, **DeepTeam**. The DeepTrace eval in this profile
is the same idea, run across a 10-model panel at three protection levels.

---

## The pivot

All of this is **fine for text**. If a probabilistic control misses, you get an
inappropriate answer — reviewable, reversible, low blast radius. **The moment the model
can take a consequential, irreversible action** — delete evidence, move money, send data —
a probabilistic control is the wrong tool. **You cannot "mostly" prevent an irreversible
action.**

## The resolution — runtime governance

A **deterministic authorization layer** sits in the agent's loop and decides **per action,
not per sentence**. It doesn't interpret language; it evaluates **facts** — legal hold,
retention, case state, session risk, provenance — many of which the model doesn't even
have. It is **not model-dependent, not phrasing-dependent, and not steerable by injected
content**, because it never consults the model's judgment about the request — it consults
**policy over context**. Same request, same model, same wording → allowed or denied purely
on the facts. **Eval: S2 → ~0 across every model.**

> Even the *detection* stays deterministic: the injection detector flags the **concealment
> technique** (an HTML comment, `display:none`, zero-width characters) — not a classifier
> guessing "is this malicious?". Deterministic detection → deterministic outcome; no model
> in the control path.

---

## The receipts — what the eval measured

10 models × 3 protection levels × two attack suites (N=20 at S0/S1, N=1 at S2). Full grid generated by `eval.py` (writes `eval_table.csv`).

**The 2×2 headline**

| | crude (jailbreak) | subtle (legitimate-looking) |
|---|--:|--:|
| **Guardrails only (S0)** | 36% | 66% |
| **+ Governance (S2)** | **0%** | **0%** |

**Weakest → strongest, hardened (S1)** — residual risk *after* best-effort prompt defense, the
fairest cross-model comparison:

| Model | crude S1 | subtle S1 |
|---|--:|--:|
| **mistral** (weakest) | **68%** | **82%** |
| dolphin | 61% | 69% |
| qwen | 14% | 31% |
| bedrock-sonnet | 0% | 15% |
| glm | 0% | 14% |
| gpt-4.1 | 0% | 10% |
| gemini-flash | 0% | 6% |
| deepseek | 5% | 4% |
| haiku | 1% | 1% |
| **gpt-4o-mini** (strongest) | 0% | 1% |

**Two things the panel proves:**

1. **A mainstream enterprise model was as jailbreakable as a deliberately-uncensored one.**
   `mistral` (Mistral Large, a commercial model) sits *below* `dolphin` — an explicitly
   *uncensored* community fine-tune. "We picked a reputable model" is not a control.
2. **Size ≠ safety.** The most *robust* models here are the small ones — **gpt-4o-mini and
   haiku (~1% subtle even hardened)** — while big **Mistral Large is the weakest**. Capability
   and safety are orthogonal.

Governance (S2) takes **all ten — mistral, dolphin, haiku alike — to 0%**. The 0–95%
model-dependent spread *is* the argument: the same policy, applied deterministically, erases it.

> *Footnote: mistral and glm hit provider throttling; call errors count as "not executed," so
> their figures are **directional — true ASR ≥ shown**.*

---

## It maps cleanly onto the demo (the arch already encodes this)

- **Act 0a** → rung 1: alignment alone, blind to rules it wasn't given.
- **Act 0b** → rung 2: rules added, but the *model* interprets them (so, model-dependent).
- **Act 1** → the injection avenue defeating the whole language layer.
- **Act 2** → the pivot + resolution: consequential action, deterministic governance
  deciding on **context and signal** (allow / deny / **escalate**).

You don't need to rethink the *structure* — it's sound, and the eval backs each rung. This
is the **spine** that turns four acts into one argument: *who decides · probabilistic vs.
deterministic · text vs. irreversible.*

---

*Eval numbers are the final figures from the 10-model protection-scale run (N=20 at S0/S1,
N=1 at S2) — generated by `eval.py` (`eval_table.csv` / `eval_results.json`). Run on the pre-escalation governance
model; the S2 → 0% headline is unchanged under allow/deny/escalate (an escalated action is also
"not executed").*
