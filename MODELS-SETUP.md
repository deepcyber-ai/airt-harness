# Configuring and testing your models

The targets are driven by a real LLM behind the scenes. You choose which model that is,
and you supply the credentials. This guide gets you from "no keys" to a model answering
in about five minutes.

You need a key for **at least one** provider. Any one of these is enough:

| You have… | Set this | Unlocks |
|---|---|---|
| An **OpenAI** key | `OPENAI_API_KEY` | `gpt-4.1`, `gpt-4o-mini` |
| A **Google Gemini** key | `GEMINI_API_KEY` | `gemini-flash` |
| **AWS** with Bedrock access | `aws configure` (see below) | the Bedrock models (e.g. `qwen`) |

---

## 1. Put your key where the harness reads it

The harness reads a file called **`.env`** in the directory you launch from. A template
is provided:

```bash
cp .env.example .env
# then open .env and paste your key(s) in — e.g.
#   OPENAI_API_KEY=sk-...
```

`.env` holds your secrets — it is already git-ignored, so it won't be committed. Fill in
only the providers you have; leave the rest blank.

**For AWS Bedrock**, there is no key in `.env`. Configure AWS credentials the normal way:

```bash
aws configure          # enter your access key, secret, and region (eu-west-2)
```

(or set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in `.env`). Bedrock must be
**enabled in your account** for the region and for the specific model — Bedrock →
*Model access* in the AWS console.

> **How availability works:** the harness offers only the models whose credential is
> present. If you set just an OpenAI key, only the OpenAI models appear; a Bedrock model
> with no AWS credentials won't be listed. Note this is a **credential/configuration
> filter, not a reachability check** — a model can be listed as available and still fail
> when called (wrong endpoint, no model access, network). Confirm it actually answers with
> the test in step 3.

> **Self-hosted / third-party endpoints (`qwen-uncensored`, `glm`).** The catalogue ships
> `qwen-uncensored` with a placeholder endpoint — `base_url: …/v2/<RUNPOD_ENDPOINT_ID>/…`
> in `models.yaml`. Before selecting that entry, **replace `<RUNPOD_ENDPOINT_ID>` with your
> own endpoint** and set `RUNPOD_API_KEY`; if you are not using it, leave the entry alone
> and pick another model. A present key does not mean the endpoint is configured or
> reachable.

---

## 2. Launch the target

```bash
./scripts/airt-launch.sh deepcyber-ctf        # Larkfield (or another profile name)
```

It prints the URLs when it's up — a web UI (default **http://localhost:7860**) and the
target's API port (default **8089**). Substitute your ports below if the launcher shows
different ones.

---

## 3. Test that your model actually answers

**A. Which models did my credentials unlock?** Ask the target:

```bash
curl -s http://localhost:8089/models | python3 -m json.tool
```

```json
{
  "models":    ["gpt-4.1", "qwen", "gemini-flash", ...],   ← everything in the catalogue
  "available": ["gpt-4.1"],                                ← what YOUR credentials unlock
  "current":   "gpt-4.1"                                   ← what's answering right now
}
```

If `available` is empty, no credential was found — go back to step 1. If the model you
want isn't in `available`, its key/creds aren't set.

**B. Switch to a model** (any name from `available`):

```bash
curl -s -X POST http://localhost:8089/model \
  -H 'Content-Type: application/json' \
  -d '{"model": "gpt-4.1"}'
```

**C. Send it a message.** Open the web UI (**http://localhost:7860**), pick the model,
and type `hello`. A normal reply means the model and its credentials are working end to
end. If instead you see:

- `[ERROR] LLM backend unavailable` → the key is wrong, missing, or the provider rejected it.
- `[ERROR] Bedrock unavailable` → AWS credentials, region, or model-access problem (see §5).

Do this once per model you plan to use. When `hello` gets a real answer, you're ready.

---

## 4. Adding your own model (optional)

`models.yaml` is the catalogue. To add a model, add an entry under `models:`. Two shapes
cover almost everything:

```yaml
models:
  # Any OpenAI-compatible HTTP endpoint (OpenAI, Gemini, local vLLM, …)
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

---

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `available` is empty in `/models` | No credential found | Check `.env` is in the launch directory and has a non-blank key; for Bedrock, `aws configure` |
| A model is missing from `available` | That provider's key/creds not set | Set its `api_key_env` in `.env`, or AWS creds for a Bedrock model |
| `[ERROR] LLM backend unavailable` | Wrong/expired key, or provider error | Re-check the key; try it against the provider directly |
| `[ERROR] Bedrock unavailable` | AWS creds, region, or model access | `aws sts get-caller-identity` to confirm creds; enable the model in Bedrock → *Model access*; confirm the region |
| `invalid model identifier` (Bedrock) | Model id / inference-profile / region mismatch | Confirm the exact id in the AWS console and that `region` matches where it's enabled |
| Reply is very slow / times out | Large or slow model | Raise `MOCK_HTTP_TIMEOUT` in `.env`, or pick a faster model |

Still stuck? Note the exact error from `/models` or the web UI — the message names the
provider and reason, which is enough to fix the key, region, or endpoint.
