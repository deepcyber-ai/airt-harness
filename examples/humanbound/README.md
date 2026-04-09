# HumanBound CLI Example

Run OWASP LLM Top 10 adversarial tests against the AIRT Harness using the
HumanBound CLI.

## Prerequisites

- HumanBound CLI installed (`pip install humanbound` or via the DeepCyber toolkit)
- AIRT Harness running on localhost:8000

## Quick Start

### 1. Start the harness

```bash
# Echo backend (no API key needed, instant responses)
MOCK_BACKEND=echo airt-launch

# Or with a real LLM for more realistic responses:
MOCK_BACKEND=gemini airt-launch          # needs GOOGLE_API_KEY
MOCK_BACKEND=openai airt-launch          # needs OPENAI_API_KEY
```

### 2. Register and run

```bash
cd examples/humanbound

# Register the bot with HumanBound cloud
humanbound init

# Run single-turn OWASP attacks (fastest — ~5 min)
humanbound test --single

# Run multi-turn adaptive attacks (~20 min)
humanbound test

# Run all attack types
humanbound test --workflow
```

### 3. View results

```bash
# Check experiment status
humanbound status

# View findings (vulnerabilities found)
humanbound logs --failed

# Security posture score
humanbound posture

# Export guardrail rules
humanbound guardrails --format json -o guardrails.json
```

## How It Works

The `bot.json` file tells HumanBound how to talk to the target:

```
HumanBound Cloud ──> bot.json ──> http://localhost:8000/chat ──> AIRT Harness
                                          │
                                          ├── Mock server (development)
                                          └── Real target API (production)
```

HumanBound replaces `$PROMPT` in the payload with each attack prompt.
The harness handles protocol translation, session management, and intel
collection. All requests are logged to the intel store for replay.

## Customising

### Change the target URL

Edit `bot.json` and change the endpoint URLs. For example, to point at a
remote harness:

```json
"endpoint": "https://my-harness.example.com/chat"
```

### Add authentication

Add auth headers to both `thread_init` and `chat_completion`:

```json
"headers": {
  "Content-Type": "application/json",
  "Authorization": "Bearer <your-token>",
  "x-session-id": "humanbound-run"
}
```

### Change the request body

If your target expects a different field name (e.g. `message` instead of
`input`), update the payload:

```json
"payload": {
  "message": "$PROMPT"
}
```

## Using with dcr (DeepCyber Toolkit)

If you have the full DeepCyber toolkit installed, use `dcr` instead:

```bash
dcr humanbound setup      # auto-generates bot.json from target.yaml
dcr humanbound init
dcr humanbound test --single
dcr humanbound logs --failed
dcr humanbound posture
```

The `dcr humanbound setup` command reads your `target.yaml` and generates
`bot.json` automatically — useful when you have auth, custom headers, or
non-standard payloads.
