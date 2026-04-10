# DeepCyber AI Red Teaming Harness

A generic test harness for AI red teaming engagements. Sits between your red team tools and the target AI system, providing a unified canonical API, protocol translation, mock emulation, intelligence collection, and regression replay.

```
    ____                  ______      __
   / __ \___  ___  ____  / ____/_  __/ /_  ___  _____
  / / / / _ \/ _ \/ __ \/ /   / / / / __ \/ _ \/ ___/
 / /_/ /  __/  __/ /_/ / /___/ /_/ / /_/ /  __/ /
/_____/\___/\___/ .___/\____/\__, /_.___/\___/_/
               /_/          /____/
              AI Red Teaming Harness
```

```bash
pip install airt-harness
```

**One harness, any target, any tool.** Write a mapper once for your target's wire format, then every red team tool — PyRIT, Promptfoo, Garak, Spikee, curl, or your own scripts — talks to the same canonical API. Switch between the real target and a local mock without changing your tools. Replay recorded breach sessions for regression testing after fixes.

### Key capabilities

- **Unified API** — canonical OpenAI-compatible `/v1/chat/completions` endpoint in front of any target, regardless of its native wire format
- **Protocol translation** — bidirectional message mappers handle auth, headers, session management, and response parsing per target
- **Mock emulation** — local mock server with pluggable LLM backends (Ollama, OpenAI, Anthropic, Gemini, DeepSeek, echo) using the target's exact wire format
- **Intel collection** — every request/response logged as JSONL for analysis and replay
- **Regression replay** — replay recorded attack sessions from intel logs or curated metabase CSVs, compare responses, and score with an LLM judge
- **Profile isolation** — per-engagement profiles keep configs, logs, and intel separate

## Architecture

```
Red Team Tool / curl / Promptfoo / Replay
    |
    v
HARNESS (server.py)
    - Canonical /v1/chat/completions endpoint (OpenAI-compatible)
    - Simplified /chat endpoint
    - Auth, retry, token refresh, intel collection
    |
    v
MESSAGE MAPPER (mappers/example.py, your_target.py, ...)
    - Canonical <-> target wire format translation
    - Bidirectional: client side + mock server side
    |
    v
TARGET (real API or mock server)
    - Real: mTLS, bearer, API key -- whatever the target needs
    - Mock: local LLM (ollama, openai, anthropic, gemini, deepseek, echo)
```

## Quick Start

The harness ships with a default profile (**Deep Vault Capital**, a fictional UK finance company) so you can start immediately without any configuration, API keys, or certificates.

```bash
# Install
pip install airt-harness

# Launch the harness container (echo backend, no API key needed)
MOCK_BACKEND=echo airt-launch

# Test
curl http://localhost:8000/health
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"input": "What is an ISA?"}'

# Replay recorded sessions for regression testing
airt-replay profiles/default/intel/ --list-sessions
airt-replay profiles/default/intel/ --session <session-id>

# Stop
airt-stop
```

### From source (without Docker)

```bash
pip install -r requirements.txt

# Start mock server with the default profile
python -m harness.mock --backend echo --port 8089

# Start harness pointing at mock
BACKEND=mock uvicorn harness.server:app --port 8000

# Test
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"input": "What is an ISA?"}'
```

## Docker

```bash
docker build -t deepcyber/airt-harness .
docker run -p 7860:7860 -p 8000:8000 -p 8089:8089 deepcyber/airt-harness

# With a custom profile mounted from outside the image:
docker run -p 8000:8000 \
  -v ./profiles/myproject:/app/profiles/myproject \
  -e PROFILE=profiles/myproject/profile.yaml \
  deepcyber/airt-harness
```

## Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/chat/completions` | POST | Canonical OpenAI-compatible (use with any OpenAI-compatible tool) |
| `/chat` | POST | Simplified: `{"input": "message"}` + optional `x-session-id` header |
| `/auth` | POST | Verify/refresh authentication (mTLS cert check or token refresh) |
| `/firewall` | POST | Toggle HB Firewall on/off (off by default) |
| `/init` | POST | Initialise a session (for targets that require explicit init) |
| `/backend` | POST | Switch between real and mock backend at runtime |
| `/token` | POST | Hot-swap bearer token without restart |
| `/health` | GET | Current configuration and status |
| `/intel/summary` | GET | Summary of recorded API calls |
| `/v1/models` | GET | OpenAI-compatible model list |

## Switching Profiles

### At startup (environment variable)

```bash
# Default (Deep Vault Capital -- no config needed)
uvicorn harness.server:app --port 8000

# Your engagement profile
PROFILE=profiles/myproject/profile.yaml uvicorn harness.server:app --port 8000
```

The mock server uses the same `--profile` flag:

```bash
python -m harness.mock --profile profiles/myproject/profile.yaml --backend echo
```

### At runtime (backend switching)

Switch between real target and mock without restarting:

```bash
# Switch to mock
curl -X POST http://localhost:8000/backend -d '{"backend": "mock"}'

# Switch to real target
curl -X POST http://localhost:8000/backend -d '{"backend": "real"}'

# Toggle (no body)
curl -X POST http://localhost:8000/backend
```

The backend state persists across restarts (saved to `.harness_state.json` in the profile directory).

## Log Isolation

Each profile's data is stored in its own directory -- different profiles never contaminate each other:

```
profiles/
  myproject/
    harness.log               # Harness server log (this profile only)
    mock_server.log           # Mock server log (this profile only)
    mock-audit.jsonl          # Mock audit trail (this profile only)
    intel/
      responses.jsonl         # Intel store (this profile only)
    .harness_state.json       # Backend state (this profile only)
```

You can override log and intel paths in `profile.yaml` if needed:

```yaml
harness:
  intel_dir: /custom/path/intel
  log_file: /custom/path/harness.log
```

But the default (profile directory) is recommended to keep things isolated.

## Project Profiles

Each engagement gets a profile directory:

```
profiles/
  myproject/
    profile.yaml          # Target config (API, auth, TLS, session, mock)
    mock/
      system_prompt.txt   # Optional custom system prompt for the mock server
    certs/                # TLS client certificates (gitignored)
```

### Profile YAML

```yaml
target: example                           # mapper name (built-in or custom)
display_name: "My Target"                 # shown in GUI and health endpoint

# For an engagement-private mapper that lives outside this package:
# target_module: profiles.myproject.mapper

api:
  url: "https://api.example.com"
  path: "/v1/chat"

auth:
  mode: none                              # none | bearer | api_key
  bearer:
    env_var: MY_BEARER_TOKEN
    prefix: "Bearer "
  token_refresh:
    order: ["cli"]                        # ["cli"] | ["endpoint"] | ["cli", "endpoint"]
    cli:
      command: "gcloud auth print-access-token"
    endpoint:
      url: ""                             # remote token server URL
      secret_env: TOKEN_SECRET

tls:
  cert: certs/tls.crt
  key: certs/tls.key
  ca_bundle: null                         # null = no verify; path = custom CA
  verify: false                           # true = system CA store

session:
  header: x-session-id                    # header for session ID
  prefix: "replay-"

mock:
  url: "http://localhost:8089"

harness:
  port: 8000
  # intel_dir and log_file default to the profile directory
```

## Message Mappers

Mappers translate between the harness's canonical format and the target's wire protocol. Each mapper is bidirectional:

| Method | Side | Purpose |
|---|---|---|
| `build_request(message, session_id)` | Client | Canonical -> target request (url, headers, body) |
| `parse_response(data)` | Client | Target response -> canonical format |
| `parse_incoming_request(body, headers)` | Server | Target request -> extract message (for mock) |
| `build_mock_response(answer, session_id)` | Server | LLM answer -> target response format (for mock) |

The harness ships with one built-in mapper as a starting point:

| Mapper | Wire format | Use case |
|---|---|---|
| `example` | Flat JSON `{"input": "..."}` request, `{"output": "...", "session_id": "..."}` response, session ID in `x-session-id` header | Generic baseline; copy and adapt |

### Adding a new mapper

Two ways:

**1. As a built-in (good for mappers you want to publish):**

1. Copy `harness/mappers/example.py` to `harness/mappers/mytarget.py`
2. Subclass `BaseMapper`, implement the four methods, set `name = "mytarget"`
3. Add `"mytarget": "harness.mappers.mytarget"` to `_BUILTIN_MAPPERS` in `mappers/__init__.py`
4. In your profile: `target: mytarget`

**2. As an engagement-private mapper (kept outside this repo):**

1. Create `profiles/myproject/mapper.py` with a `create_mapper(config)` function
2. In your profile YAML, point `target_module:` at either an importable module or a file path:
   ```yaml
   target: myproject                              # display/logging name
   target_module: profiles/myproject/mapper.py    # file path (relative to CWD)
   # or:
   # target_module: my_package.my_target_mapper   # importable module
   ```
3. Run the harness from a directory where the file or module is reachable

This lets you keep customer-specific mappers in private repos while sharing the harness scaffolding from this one.

### Generic mapper (YAML-only, no Python)

For targets with standard REST APIs, use the built-in `generic` mapper instead of writing a custom mapper file. Configure the request body template and response extraction path entirely in profile.yaml:

```yaml
target: generic

api:
  url: "https://api.example.com"
  path: "/v1/chat"

# Request body — {{PROMPT}} is replaced with the user message
request_template:
  model: "gpt-4"
  messages:
    - role: "user"
      content: "{{PROMPT}}"

# Dot-notation path to extract the answer from the JSON response
response_path: "choices.0.message.content"
```

Dot-notation examples:

| Target response shape | `response_path` |
|---|---|
| `{"answer": "..."}` | `answer` |
| `{"responses": [{"value": "..."}]}` | `responses.0.value` |
| `{"choices": [{"message": {"content": "..."}}]}` | `choices.0.message.content` |

For targets with complex wire formats (SSE, double-encoding, custom session init), use a custom mapper instead.

## PyRIT Integration

The harness provides PyRIT-compatible targets for automated red teaming orchestration.

```bash
pip install airt-harness[pyrit]
```

### ProxyTarget — route through the harness

```python
from harness.pyrit import ProxyTarget

target = ProxyTarget(
    harness_url="http://localhost:8000",
    session_id="RedTeam-001",
)

# Use with any PyRIT orchestrator
from pyrit.orchestrator import PromptSendingOrchestrator
orchestrator = PromptSendingOrchestrator(objective_target=target)
```

The `ProxyTarget` sends prompts to the harness `/chat` endpoint. The harness handles protocol translation, auth, session management, and intel collection — PyRIT just sees a simple text-in/text-out target.

### BedrockTarget — direct AWS Bedrock

```python
from harness.pyrit import BedrockTarget

target = BedrockTarget(
    model_id="anthropic.claude-sonnet-4-6",
    region="eu-west-2",
)
```

Requires `pip install airt-harness[bedrock]` and AWS credentials configured.

## HB Firewall

Optional input screening layer using the HumanBound Firewall. **Off by default.** When enabled, every message is evaluated before reaching the target — blocked messages get a standard refusal response.

### Enable at runtime

```bash
# Enable
curl -X POST http://localhost:8000/firewall -d '{"enabled": true}'

# Disable
curl -X POST http://localhost:8000/firewall -d '{"enabled": false}'

# Toggle
curl -X POST http://localhost:8000/firewall

# Check status
curl http://localhost:8000/health | jq .firewall_enabled
```

### Profile config (optional)

```yaml
firewall:
  enabled: false                          # default off
  agent_config: "hb-firewall/agent.yaml"  # HB security policy
  model_path: null                        # optional Tier 2 model
```

### A/B testing workflow

Run the same attack sessions with the firewall off and on to measure its effectiveness:

```bash
# 1. Run tests without firewall
airt-replay evidence/metabase.csv --session abc123 -o results/no-firewall.md

# 2. Enable firewall
curl -X POST http://localhost:8000/firewall -d '{"enabled": true}'

# 3. Run the same tests
airt-replay evidence/metabase.csv --session abc123 -o results/with-firewall.md

# 4. Compare reports
```

Requires `pip install hb-firewall` — the firewall is lazy-loaded only when first enabled.

## Token Refresh

Two independent methods, tried in the order configured in `auth.token_refresh.order`:

| Method | Config Key | Default | Use Case |
|---|---|---|---|
| `cli` | `auth.token_refresh.cli.command` | `gcloud auth print-access-token` | Local development, GCP, Azure, any CLI |
| `endpoint` | `auth.token_refresh.endpoint.url` | (none) | Remote token server via Cloudflare tunnel |

Default order is `["cli"]`. To add a remote endpoint:

```yaml
auth:
  token_refresh:
    order: ["cli", "endpoint"]
    endpoint:
      url: "https://token.example.com/token"
      secret_env: TOKEN_SECRET
```

Token refresh is triggered automatically on 401/403 errors during chat, or manually via `POST /auth`.

## Mock Server

The mock server uses the same mapper as the harness, so it emulates the target's exact wire format. Any tool that works against the real target works identically against the mock.

```bash
# Echo mode (fast, no LLM)
python -m harness.mock --backend echo

# Local Ollama
python -m harness.mock --backend ollama --model llama3.2

# OpenAI
python -m harness.mock --backend openai --model gpt-4o-mini

# Anthropic
python -m harness.mock --backend anthropic

# Gemini
python -m harness.mock --backend gemini

# DeepSeek
python -m harness.mock --backend deepseek
```

API keys are read from environment variables: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY` / `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`.

## Chat GUI

A Gradio-based interactive chat client for manual testing and exploration. The GUI connects to the harness and auto-detects the target name from the profile's `display_name` field.

```bash
# Start the harness first
PROFILE=profiles/default/profile.yaml BACKEND=mock uvicorn harness.server:app --port 8000

# Start the GUI (auto-detects target name)
python -m harness.gui

# Custom port or public link
python -m harness.gui --port 7860 --share
```

Set `display_name` in the profile YAML to customise the GUI title:

```yaml
target: example
display_name: "My Target"    # shown in GUI title and health endpoint
```

Features:
- **Chat panel** with conversation history and session management
- **Raw Response tab** showing the full target response (engagement-specific fields like agent thoughts or guardrail events appear here if the mapper preserves them in `raw`)
- **Auth tab** for verifying/refreshing authentication
- **Backend switching** between real and mock at runtime
- **Intel tab** showing accumulated API call statistics
- **Health tab** showing the harness configuration

## Intel Collection

Every API call through the harness is recorded to `<profile_dir>/intel/responses.jsonl`:

```json
{
  "timestamp": "2026-04-07T14:30:00Z",
  "session_id": "harness-abc123",
  "backend": "real",
  "target": "example",
  "prompt": "What is an ISA?",
  "answer": "An Individual Savings Account is...",
  "raw": { "...": "full target response (engagement-specific fields live here)" },
  "error": null
}
```

The `raw` field holds whatever the target returned -- including any custom metadata, agent thoughts, guardrail events, or other engagement-specific data. The harness itself stays neutral and does not parse those fields.

## Replay

Replay recorded sessions against the running harness for regression testing.  Send the exact attacker prompts from a previous test and compare the new responses with the originals.  Optionally score each turn with an LLM judge.

```bash
# Start the harness first (mock or real)
BACKEND=mock uvicorn harness.server:app --port 8000
```

### Two source types (auto-detected)

| Source | Path | How it works |
|---|---|---|
| **Intel logs** | Directory or `.jsonl` file | Reads `responses.jsonl`, groups by session_id, sorts by timestamp |
| **Metabase CSV** | `.csv` file | Reads CSV with `session_id`, `turn`, `request`/`prompt`, `answer`/`response` columns |

Intel logs are what the harness records automatically (see [Intel Collection](#intel-collection)).  A metabase CSV is a curated subset, typically produced during an engagement, containing selected sessions for regression testing.

### List sessions

```bash
# From intel logs
airt-replay profiles/default/intel/ --list-sessions

# From a metabase CSV
airt-replay evidence/metabase.csv --list-sessions
```

### Replay a session

```bash
airt-replay evidence/metabase.csv --session abc123
```

Partial session-ID matching is supported.  The replay sends each prompt to the harness `/chat` endpoint using a fresh session ID and compares the new response with the original.

### Judge evaluation

Score each replayed turn PASS/FAIL with an LLM judge:

```bash
airt-replay evidence/metabase.csv --session abc123 \
    --evaluate \
    --judge-config replay/judge_config.yaml \
    --judge-prompts replay/judge_prompts.yaml \
    -o results/regression-report.md
```

Judge config and judge prompts are engagement-specific files — the harness provides the multi-provider framework.  Supported judge providers:

| Provider | Config key | Notes |
|---|---|---|
| AWS Bedrock | `bedrock` | Zero data retention; requires `boto3` |
| Ollama (local) | `ollama` | Fully air-gapped; no data leaves your machine |
| Google Gemini | `gemini` | Direct API |
| Anthropic Claude | `claude` | Direct API |
| OpenAI-compatible | (default) | vLLM, RunPod, LiteLLM, or any chat/completions endpoint |

### Metabase format compatibility

The replay works with any CSV that has these four columns:

| Column | Required | Maps to |
|---|---|---|
| `session_id` | Yes | Groups turns into sessions |
| `turn` | Yes | Orders turns within a session |
| `request` or `prompt` | Yes | The attacker prompt (replayed verbatim) |
| `answer` or `response` | Yes | The original response (used for comparison) |

Additional columns (finding_id, scenario_id, guardrail scores, etc.) are ignored by the generic replay engine.  Engagement-specific wrappers can use them for navigation and reporting.

### CLI reference

| Flag | Purpose |
|---|---|
| `source` (positional) | Path to intel dir, `.jsonl`, or `.csv` (default: `.`) |
| `--list-sessions` | List all sessions in the source |
| `--session ID` | Replay a session (partial match supported) |
| `--harness-url URL` | Harness URL (default: `$HARNESS_URL` or `http://localhost:8000`) |
| `--delay SECONDS` | Delay between turns (default: 1) |
| `--evaluate` | Run LLM judge on replayed responses |
| `--judge-config FILE` | Path to judge config YAML |
| `--judge-prompts FILE` | Path to judge prompts YAML |
| `--judge-criteria KEY` | Apply a single criteria key to all turns |
| `-o FILE` | Save comparison report to file |

## License

Copyright (c) 2026 Deep Cyber Ltd.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
