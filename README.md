# DeepCyber AI Red Teaming Harness

A generic test harness for AI red teaming engagements. Sits between your red team tools (PyRIT, Promptfoo, Spikee, curl) and the target AI system, providing a canonical API, protocol translation, mock emulation, and intelligence collection.

```
    ____                  ______      __
   / __ \___  ___  ____  / ____/_  __/ /_  ___  _____
  / / / / _ \/ _ \/ __ \/ /   / / / / __ \/ _ \/ ___/
 / /_/ /  __/  __/ /_/ / /___/ /_/ / /_/ /  __/ /
/_____/\___/\___/ .___/\____/\__, /_.___/\___/_/
               /_/          /____/
              AI Red Teaming Harness
```

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
pip install -r requirements.txt

# Start mock server with the default profile
python -m harness.mock --backend echo --port 8089

# Start harness pointing at mock
BACKEND=mock uvicorn harness.server:app --port 8000

# Test
curl http://localhost:8000/health
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"input": "What is an ISA?"}'
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"What is an ISA?"}]}'
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

## License

Copyright (c) 2026 Deep Cyber Ltd.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
