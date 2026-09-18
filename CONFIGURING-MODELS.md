# Configuring and testing your models

The targets are driven by a real LLM behind the scenes. Models are defined in
`/opt/airt/src/airt_harness/models.yaml` and can be selected either via the GUI app or
the API. To select a model, you first **enable** it by providing its credentials.

You can either supply an API key for the model or configure AWS Bedrock. We have already
added models to the file; each needs the credential shown below to be enabled:

| Model(s) | Credential |
|---|---|
| `gpt-4.1`, `gpt-4o-mini` | `OPENAI_API_KEY` |
| `gemini-flash` | `GEMINI_API_KEY` |
| `qwen`, `haiku`, `bedrock-sonnet`, `mistral`, `deepseek`, `llama`, `gpt-oss-120b`, `gpt-oss-safeguard-120b`, `gpt-oss-20b`, `qwen3-32b`, `gpt5.6-terra` | AWS Bedrock (region `eu-west-2`) |
| `glm` | `FIREWORKS_API_KEY` |
| `qwen-uncensored` | `RUNPOD_API_KEY` (self-hosted; fill in your own RunPod endpoint first) |

`gpt5.6-terra` is an OpenAI model (`model: global.openai.gpt-5.6-terra`) configured here
**via AWS Bedrock** to test its availability there. You can instead point it at the OpenAI
API (`type: openai-compatible`, `api_key_env: OPENAI_API_KEY`).

You can also add your own models by editing `models.yaml`, as long as the `type` is
supported and you provide the correct details (e.g. base URL, model name, and the name of
the environment variable holding the API key). The supported types are
**`openai-compatible`**, **`fireworks`**, **`anthropic`**, **`aws-bedrock`** and
**`ollama`**. See §5.1 at the end for using an Ollama model on your host from the VM.

You will not need all of these models — we recommend an **OpenAI or Gemini key** and,
ideally, an **AWS account**. You need a credential for **at least one** provider.

---

## 1. Configure credentials

**For API keys**, the harness reads a file called **`.env`** in the directory you launch
from. On the Deep Cyber VM, use the one provided at `/opt/airt/src/.env`.

```bash
#   OPENAI_API_KEY=sk-...
```

`.env` holds your secrets — it is already git-ignored, so it won't be committed. Fill in
only the providers you have; leave the rest blank.

**For AWS Bedrock** there is no key in `.env`. The VM comes with the AWS CLI already
installed; configure AWS credentials the normal way:

```bash
aws configure          # enter your access key, secret, and region (eu-west-2)
```

(Or set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in `.env` — the variable names must
be UPPER CASE.) Bedrock must be **enabled in your account** for the region *and* for the
specific model — AWS console → Bedrock → *Model access*.

---

## 2. Launch the target and check model selection

The VM launches targets with its `airt-target` command, e.g.

```bash
airt-target larkfield
```

This launches with the default model (`gpt-4.1`). You can start on a different model with
`--model`:

```bash
airt-target larkfield --model qwen
```

The model must be in `models.yaml` and active (its credential present).

Once it's up, use the harness's `GET /models` endpoint to verify what your credentials
unlocked:

```bash
# Larkfield (DeepCyber CTF)
curl -s localhost:8089/models | python3 -m json.tool
# Money Agent (Deep Vault Capital)
curl -s localhost:8090/models | python3 -m json.tool
# Investigations (governance)
curl -s localhost:8091/models | python3 -m json.tool
```

It comes back with:

```json
{
  "models":    ["gpt-4.1", "gpt-4o-mini", "qwen", "..."],
  "available": ["gpt-4.1", "gpt-4o-mini"],
  "current":   "gpt-4.1"
}
```

`available` is what your credentials unlocked; `current` is what's answering now. You can
also tail the log to troubleshoot:

```bash
tail -f ~/.airt-target/logs/larkfield-mock.log
tail -f ~/.airt-target/logs/moneyagent-mock.log
```

---

## 3. Test that your model actually answers

**API:**

```bash
curl -s localhost:8089/chat -H 'Content-Type: application/json' -H 'x-session-id: t1' \
  -d '{"input":"hello - who are you?"}' | python3 -m json.tool
```

**UI:** open the web UI (**http://localhost:7860**, adjust the port for other targets),
pick the model, and type `hello`. A normal reply means the model and its credentials are
working end to end. If instead you see:

- `[ERROR] LLM backend unavailable` → the key is wrong, missing, or the provider rejected it.
- `[ERROR] Bedrock unavailable` → AWS credentials, region, or model-access problem (see §6).

---

## 4. Switching the model live — dropdown, API, or target

You can change which model is answering at any time, **no restart**. Three equivalent
ways; pick whichever suits what you're doing.

**A. The GUI dropdown (easiest).** In the web UI (**http://localhost:7860**) the
**Target model** dropdown lists the models your credentials unlocked. Pick one — it
switches immediately and starts a **fresh session**, so a transcript never mixes two
models. Only credentialed models are offered.

**B. The target directly (`:8089`):**

```bash
curl -s http://localhost:8089/models                       # names, available, current
curl -s -X POST http://localhost:8089/model \
  -H 'Content-Type: application/json' -d '{"model": "gpt-4o-mini"}'
```

**C. The canonical API (`:8000`)** — the same control endpoints one layer up (available
when the full stack is running under `airt-target`). Handy for scripting a sweep across
models from the same place your red-team tools point:

```bash
curl -s http://localhost:8000/catalogue                    # proxies the target's /models
curl -s -X POST http://localhost:8000/model \
  -H 'Content-Type: application/json' -d '{"model": "gpt-4o-mini"}'
```

Ports are per target: **Larkfield** API `8000` / target `8089`; **Money Agent** API
`8001` / target `8090`.

Things to know when you script it (the dropdown handles these for you):

- The **API/target endpoints do not pre-filter by credentials** — a `POST /model` to a
  model you have no key for *succeeds*, and the next message then returns
  `[ERROR] LLM backend unavailable … check the API key`. Read `available` from
  `/catalogue` (or `/models`) first to avoid that.
- Switching via the endpoint does **not** auto-start a fresh session — send a new
  `x-session-id` yourself so a transcript doesn't span two models.
- An unknown name returns `400 unknown model`; a target with no catalogue returns
  `400 no models catalogue loaded`.

---

## 5. Adding your own model (optional)

`models.yaml` is the catalogue. To add a model, add an entry under `models:`. Two shapes
cover almost everything:

```yaml
models:
  # Any OpenAI-compatible HTTP endpoint (OpenAI, Gemini, local vLLM, RunPod, …)
  my-model:
    type: openai-compatible
    base_url: https://api.openai.com/v1
    model: gpt-4.1                 # the provider's model id
    api_key_env: OPENAI_API_KEY    # the .env var holding the key

  # An AWS Bedrock model
  my-bedrock-model:
    type: aws-bedrock
    model: qwen.qwen3-235b-a22b-2507-v1:0   # the Bedrock model / inference-profile id
    region: eu-west-2
```

`default_model:` at the top sets which one answers first. If it has no credentials, the
harness falls back to the first model in the file that does — so keep the list ordered
with your most-likely-available model near the top.

### 5.1 Ollama on your host, from the course VM

1. **On the Mac (host), make Ollama listen beyond localhost.** By default it binds
   `127.0.0.1`, which the VM can't reach.

   ```bash
   brew install ollama          # or the app from ollama.com
   ollama pull llama3.2         # ~2 GB, fast enough to be useful
   OLLAMA_HOST=0.0.0.0 ollama serve
   ```

   If you use the menu-bar app rather than `ollama serve`, set the variable where the app
   will see it, then restart it:

   ```bash
   launchctl setenv OLLAMA_HOST 0.0.0.0
   ```

   macOS may prompt to allow incoming connections — say yes.

2. **In the VM, find the host and prove you can reach it.**

   ```bash
   ip route | awk '/default/ {print $3}'        # UTM is usually 192.168.64.1
   curl http://192.168.64.1:11434/api/tags      # should list llama3.2
   ```

   If that `curl` fails, nothing else will work — it's the host binding or the firewall,
   not the harness.

3. **Add a catalogue entry.** Edit `/opt/airt/src/airt_harness/models.yaml` and put this
   under `models:`, matching the two-space indentation of the entries already there:

   ```yaml
     local:
       type: ollama
       model: llama3.2
       base_url: http://192.168.64.1:11434
   ```

   No `api_key_env` — Ollama needs no credential, and the harness treats an `ollama` entry
   as always available. The harness posts to `<base_url>/api/chat`, which is what
   `ollama serve` exposes.

4. **Use it.**

   ```bash
   airt-target stop
   airt-target larkfield --model local
   ```

   The `Model:` line should say `local`. Then:

   ```bash
   curl -s localhost:8089/chat -H 'Content-Type: application/json' -H 'x-session-id: o1' \
     -d '{"input":"hello - who are you?"}' | python3 -m json.tool
   ```

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `available` is empty in `/models` | No credential found | Check `.env` is where you launched from and has a non-blank key; for Bedrock, `aws configure` |
| A model is missing from `available` | That provider's key/creds not set | Set its `api_key_env` in `.env`, or AWS creds for a Bedrock model |
| `[ERROR] LLM backend unavailable` | Wrong/expired key, or provider error | Re-check the key; try it against the provider directly |
| `[ERROR] Bedrock unavailable` | AWS creds, region, or model access | `aws sts get-caller-identity` to confirm creds; enable the model in Bedrock → *Model access*; confirm the region |
| `invalid model identifier` (Bedrock) | Model id / inference-profile / region mismatch | Confirm the exact id in the AWS console and that `region` matches where it's enabled |
| Reply is very slow / times out | Large or slow model | Raise `MOCK_HTTP_TIMEOUT` in `.env`, or pick a faster model |

_Synthetic targets and data throughout; authorised testing only._
