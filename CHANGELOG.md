# Changelog

All notable changes to the AIRT Harness public release. Newest first.

## v1.0.17 — 2026-09-20

- **airt-replay decodes the target's reply schema on the live re-send.** A direct-target replay
  (e.g. Larkfield on `:8081`, which returns `output`) now keeps the real reply instead of
  silently reading an empty `answer`; the harness API's `answer` and a plain `response` are still
  read. An **unrecognised** schema becomes an explicit `[ERROR]`, not an empty answer — so a
  successful HTTP call we can't decode no longer looks like a non-reproduction.

## v1.0.16 — 2026-09-20

- **The mock records a replayable `intel/responses.jsonl` on every chat** (profile-scoped,
  uncapped), so a session is replayable with `airt-replay` whether the target was reached via
  the mock (`:8081`/`:8089`) or the harness API (`:8000`) — not only the API route.
- **airt-replay `--judge-criteria` accepts inline text**, not just a key from `--judge-prompts`
  — so a quick scored replay needs no criteria file (`--evaluate --judge-model X --judge-criteria
  "the reply reveals an internal configuration reference"`).
- **airt-replay judge verdict is PASS / FAIL / UNRESOLVED.** An empty or off-vocabulary judge
  reply is UNRESOLVED, not a false FAIL, so unexpected replies don't look like scored results.

## v1.0.15 — 2026-09-20

- **airt-replay: `--since` / `--until` time-range selection.** List or narrow recorded
  sessions by time — an ISO 8601 timestamp (`2026-09-20`, `2026-09-20T14:30`) or a relative
  age (`2h`, `30m`, `7d`). A session matches if any of its turns falls in the window; the
  record timestamps drive it.

## v1.0.14 — 2026-09-20

- **airt-replay: resolve the judge from `models.yaml`.** `--evaluate` gains `--judge-model NAME`
  (with `--models PATH`, default `models.yaml`), so the replay scorer uses the same model
  catalogue as the rest of the course — no separate `judge_config.yaml` to maintain. The
  existing `--judge-config FILE` path is unchanged. Supports openai-compatible and Bedrock
  judge models.

## v1.0.13 — 2026-09-19

- **Target posture is now a profile setting.** `mock.system_prompt` in a profile selects which
  system prompt the target runs (neutral / planted / hardened) with no launch flag; a
  `--system-prompt` on the command still overrides it. Profiles without the key behave exactly
  as before (they fall to `mock/system_prompt.txt`).
- Clarified the simulated `execute_code` tool in the detector comments and tests: invoking it is
  an observation in the event log, not a scored flag (the tool returns a fixed receipt and runs
  no Python). No scoring change from v1.0.12.

## v1.0.12 — 2026-09-18

- The GUI's **Raw Response tab is always visible again** (it was hidden when `clean_chat` was
  on). `clean_chat` still strips inline tool-result blocks from the chat bubble; the raw
  response is now shown in the Raw Response tab as well as on the wire, so the panel doubles as
  a teaching aid — the tab shows what the client stripped, while the bubble can still leak a
  query the model narrates in its own prose (which a client-side strip cannot catch).

## v1.0.11 — 2026-09-18

- **GUI clean-chat display option.** A new `mock.clean_chat` profile setting makes the chat
  window show a clean assistant answer while inline `[<tool> result: …]` blocks are hidden from
  the bubble; the raw response still streams to the browser (recoverable from the Network tab).
  Larkfield (the CTF profile) defaults it on; every other profile defaults off. Launch the GUI
  with `--clean-chat {auto,on,off}` to override per session. Display-only — the mock response,
  flags, detectors, scoring and audit are unchanged. `/health` gains an additive `clean_chat`
  boolean so the GUI can read the profile default.
- **Reconnaissance endpoint on by default for the CTF profile.** The read-only `/capabilities`
  route is now served without the `--recon` launch flag (via `mock.features.recon: true`), so
  the reconnaissance exercise needs no special flag. Nothing in the scoring path reads it, so
  measurements are unchanged.
- **Larkfield detector corrections.** Tool-result blocks are now stripped with full nested-
  bracket handling (a `search_documents` result's inner `[1]` labels no longer truncate the
  strip); hyphen/dash variants are normalised before matching; and the knowledge-base
  contradiction checks also catch reversed wording ("thread count of 400", "GSM … of 150").
- **AIRT_GROUP model stacks.** `models.yaml` adds grouped attacker/scorer stacks so a student
  with a single provider (`AIRT_GROUP=openai` or `AIRT_GROUP=bedrock`) can fill both roles,
  plus a `haiku` Bedrock catalogue entry.

## v1.0.10 — remove the v1.0.9 airt-update validation stamp.
## v1.0.9 — docs stamp for airt-update validation.
## v1.0.8 — add the "Configuring & testing your models" page; deprecate MODELS-SETUP.md.
## v1.0.7 — Larkfield's default prompt is now the plain, un-coached one; the coached prompt is demo-only.
## v1.0.6 — correct the CTF target ports (8089/8090); a provider 4xx returns a named sentinel, not a 500.
## v1.0.5 — getting-started: AIRT_GROUP / CHOOSING-MODELS are course-pack, not bare VM (docs-only).
## v1.0.4 — getting-started: point the banner sentence at airt-target (docs-only).
## v1.0.3 — getting-started: correct the echo claims and the .env location.
## v1.0.2 — getting-started: fix the Money Agent manual port (8081) and appendix notes.
## v1.0.1 — getting-started: airt-target wrapper, correct MCP paths, three-layer note.
## v1.0.0 — course release: seven profiles, the ai_models backend, and the getting-started docs.
