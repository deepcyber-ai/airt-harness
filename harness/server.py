"""DeepCyber AI Red Teaming Harness -- server.

Exposes a canonical API (OpenAI-compatible + simplified /chat) in front of
any target. Message mappers handle the translation between canonical
and target-specific wire formats. Configuration is driven by a project
profile YAML.

Run:
    PROFILE=profiles/default/profile.yaml uvicorn harness.server:app --port 8000

    # Mock backend:
    PROFILE=profiles/default/profile.yaml BACKEND=mock uvicorn harness.server:app

Endpoints:
    POST /v1/chat/completions   Canonical OpenAI-compatible
    POST /chat                  Simplified chat interface
    POST /auth                  Verify/refresh authentication
    POST /init                  Initialise a session (if target requires it)
    GET  /health                Config summary
    POST /backend               Switch real/mock
    GET  /intel/summary         Intel store summary
    POST /token                 Hot-swap bearer token
"""

import asyncio
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml
from dotenv import load_dotenv
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

load_dotenv(override=True)

from harness.mappers import CanonicalResponse, load_mapper

# -- Banner ----------------------------------------------------------------

BANNER = r"""
    ____                  ______      __
   / __ \___  ___  ____  / ____/_  __/ /_  ___  _____
  / / / / _ \/ _ \/ __ \/ /   / / / / __ \/ _ \/ ___/
 / /_/ /  __/  __/ /_/ / /___/ /_/ / /_/ /  __/ /
/_____/\___/\___/ .___/\____/\__, /_.___/\___/_/
               /_/          /____/
              AI Red Teaming Harness  v1.1
"""

# -- Profile ---------------------------------------------------------------

PROFILE_PATH = os.environ.get("PROFILE", "profiles/default/profile.yaml")

with open(PROFILE_PATH) as f:
    PROFILE = yaml.safe_load(f)

TARGET_NAME = PROFILE.get("target", "example")
DISPLAY_NAME = PROFILE.get("display_name", TARGET_NAME)
HARNESS_CFG = PROFILE.get("harness", {})

# Profile-scoped defaults: logs and intel go under the profile directory
# so different profiles never contaminate each other's data.
_PROFILE_DIR = str(Path(PROFILE_PATH).parent)
_PROFILE_NAME = Path(_PROFILE_DIR).name

INTEL_DIR = HARNESS_CFG.get("intel_dir", os.path.join(_PROFILE_DIR, "intel"))
LOG_FILE = HARNESS_CFG.get("log_file", os.path.join(_PROFILE_DIR, "harness.log"))

# -- Persistent state (per-profile) ----------------------------------------

_STATE_FILE = os.path.join(_PROFILE_DIR, ".harness_state.json")


def _load_state() -> dict:
    try:
        with open(_STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_state(state: dict):
    current = _load_state()
    current.update(state)
    with open(_STATE_FILE, "w") as f:
        json.dump(current, f)


def _load_backend() -> str:
    saved = _load_state().get("backend")
    if saved in ("mock", "real"):
        return saved
    return os.environ.get("BACKEND", "real")


BACKEND = _load_backend()

# -- Logging ---------------------------------------------------------------

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
log = logging.getLogger("harness")

# -- Intel Store -----------------------------------------------------------

_INTEL_PATH = Path(os.path.join(INTEL_DIR, "responses.jsonl"))
_INTEL_PATH.parent.mkdir(parents=True, exist_ok=True)


def _record_intel(entry: dict):
    with open(_INTEL_PATH, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def _load_intel() -> list:
    if not _INTEL_PATH.exists():
        return []
    return [json.loads(line) for line in open(_INTEL_PATH) if line.strip()]

# -- Mapper & Client -------------------------------------------------------

mapper = load_mapper(TARGET_NAME, PROFILE)

if BACKEND == "mock":
    _client = httpx.Client(timeout=120)
    _api_url = mapper.get_mock_url()
else:
    _client = httpx.Client(**mapper.build_client_kwargs())
    _api_url = mapper.get_api_url()

_initialised_sessions: set[str] = set()

MAX_RETRIES = 2
RETRY_DELAY = 3

# -- Token refresh ---------------------------------------------------------
#
# Two distinct methods, configurable order via auth.token_refresh:
#   "cli"      - local CLI command (default first, e.g. gcloud)
#   "endpoint" - remote HTTP endpoint (optional, e.g. via Cloudflare tunnel)

_token_updated_at: str | None = None
_token_http: httpx.Client | None = None


def _get_token_http() -> httpx.Client:
    global _token_http
    if _token_http is None:
        _token_http = httpx.Client(timeout=30)
    return _token_http


def _get_refresh_config() -> dict:
    return PROFILE.get("auth", {}).get("token_refresh", {})


def _get_refresh_order() -> list[str]:
    return _get_refresh_config().get("order", ["cli"])


async def _refresh_via_cli() -> str | None:
    """Refresh token via local CLI command."""
    cfg = _get_refresh_config().get("cli", {})
    command = cfg.get("command", "gcloud auth print-access-token")
    try:
        import subprocess
        parts = command.split()
        result = await asyncio.to_thread(
            subprocess.run, parts, capture_output=True, text=True, timeout=15,
        )
        token = result.stdout.strip()
        if result.returncode == 0 and token:
            log.info("Token refreshed via CLI: %s", parts[0])
            return token
        log.warning("CLI token refresh failed (rc=%d): %s", result.returncode, result.stderr.strip()[:200])
    except FileNotFoundError:
        log.warning("CLI not found: %s", command.split()[0])
    except Exception as e:
        log.warning("CLI token refresh failed: %s", e)
    return None


async def _refresh_via_endpoint() -> str | None:
    """Refresh token from a remote HTTP endpoint."""
    cfg = _get_refresh_config().get("endpoint", {})
    url = cfg.get("url") or os.environ.get("TOKEN_ENDPOINT", "")
    if not url:
        return None
    secret_env = cfg.get("secret_env", "TOKEN_SECRET")
    secret = os.environ.get(secret_env, "")
    try:
        headers = {"X-Token-Secret": secret} if secret else {}
        resp = await asyncio.to_thread(_get_token_http().get, url, headers=headers)
        if resp.is_success:
            token = resp.json().get("token", "")
            if token:
                log.info("Token refreshed from endpoint: %s", url)
                return token
        log.warning("Token endpoint returned %s: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        log.warning("Token endpoint failed: %s", e)
    return None


async def _refresh_token() -> bool:
    """Refresh bearer token using configured methods in order.

    Default: ["cli"] (local gcloud).
    Add "endpoint" in profile to also try a remote token server.
    """
    global _token_updated_at

    env_var = PROFILE.get("auth", {}).get("bearer", {}).get("env_var", "")
    if not env_var:
        return False

    methods = {"cli": _refresh_via_cli, "endpoint": _refresh_via_endpoint}

    for method_name in _get_refresh_order():
        fn = methods.get(method_name)
        if not fn:
            log.warning("Unknown token refresh method: %s", method_name)
            continue
        token = await fn()
        if token:
            os.environ[env_var] = token
            _token_updated_at = datetime.now(timezone.utc).isoformat()
            return True

    return False


def _is_auth_error(result: CanonicalResponse) -> bool:
    """Check if the result indicates an auth failure (401/403)."""
    if result.error:
        return "[401]" in result.error or "[403]" in result.error
    return False

# -- Core send -------------------------------------------------------------


def _init_if_needed(session_id: str):
    """Auto-init session for targets that require it."""
    if mapper.needs_init() and session_id not in _initialised_sessions:
        init_url = f"{mapper.get_mock_url().rstrip('/')}/chat" if BACKEND == "mock" else None
        api_sid = mapper.init_session(session_id, _client, url_override=init_url)
        if api_sid:
            _initialised_sessions.add(session_id)
            log.info("Session initialised: %s", session_id)


def _send(message: str, session_id: str) -> CanonicalResponse:
    _init_if_needed(session_id)

    if BACKEND == "mock":
        url = f"{mapper.get_mock_url().rstrip('/')}/chat"
        _, headers, body = mapper.build_request(message, session_id)
        headers = {k: v for k, v in headers.items() if not k.lower().startswith("authorization")}
    else:
        url, headers, body = mapper.build_request(message, session_id)

    try:
        resp = _client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        data = resp.json() if "json" in resp.headers.get("content-type", "") else resp.text
        result = mapper.parse_response(data, raw_text=resp.text)
        result.session_id = session_id
    except httpx.HTTPStatusError as e:
        err = f"[{e.response.status_code}] {e.response.text[:300]}"
        result = CanonicalResponse(answer=f"[error] {err}", session_id=session_id, error=err)
    except httpx.RequestError as e:
        result = CanonicalResponse(answer=f"[error] {e}", session_id=session_id, error=str(e))

    _record_intel({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id, "backend": BACKEND, "target": TARGET_NAME,
        "prompt": message, "answer": result.answer,
        "agent_thoughts": result.agent_thoughts, "guardrails": result.guardrails,
        "error": result.error,
    })
    return result


async def _send_with_retry(message: str, session_id: str) -> CanonicalResponse:
    last = None
    for attempt in range(1, MAX_RETRIES + 1):
        last = _send(message, session_id)
        if last.error and attempt < MAX_RETRIES:
            # On auth error, try to auto-refresh token before retrying
            if _is_auth_error(last):
                log.warning("Attempt %d/%d auth error -- refreshing token", attempt, MAX_RETRIES)
                refreshed = await _refresh_token()
                if refreshed:
                    continue
            log.warning("Attempt %d/%d error: %s -- retrying", attempt, MAX_RETRIES, last.error[:120])
            await asyncio.sleep(RETRY_DELAY)
            continue
        break
    return last

# -- App -------------------------------------------------------------------

app = FastAPI(title="DeepCyber AI Red Teaming Harness", version="1.1.0")


@app.on_event("startup")
async def startup():
    tls = PROFILE.get("tls", {})
    cert_info = "n/a"
    if BACKEND == "real":
        cert_path = tls.get("cert", "")
        if cert_path and os.path.exists(cert_path):
            cert_info = f"mTLS ({cert_path})"
        elif cert_path:
            cert_info = f"MISSING ({cert_path})"
        elif tls.get("verify") is False:
            cert_info = "no verification"
        else:
            cert_info = "system CA"

    print(BANNER)
    print(f"  Profile: {DISPLAY_NAME} ({PROFILE_PATH})")
    print(f"  Backend: {BACKEND} ({_api_url})")
    print(f"  TLS:     {cert_info}")
    print(f"  Port:    {HARNESS_CFG.get('port', 8000)}")
    print(f"  Intel:   {INTEL_DIR}")
    print()


@app.post("/v1/chat/completions")
async def completions(request: Request):
    body = await request.json()
    messages = body.get("messages", [])
    model_name = body.get("model", TARGET_NAME)

    message = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            message = msg.get("content", "")
            break

    if not message:
        return JSONResponse({"error": "no user message found"}, status_code=400)

    session_id = body.get("session_id") or request.headers.get("x-session-id") or f"harness-{uuid.uuid4()}"

    log.info("/v1/chat/completions sid=%s prompt=%.60s", session_id, message)
    result = await _send_with_retry(message, session_id)

    response = {
        "id": f"chatcmpl-{uuid.uuid4().hex[:16]}",
        "object": "chat.completion",
        "model": model_name,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": result.answer}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "metadata": {
            "session_id": result.session_id, "conversation_type": result.conversation_type,
            "agent_thoughts": result.agent_thoughts, "guardrails": result.guardrails,
        },
    }
    if result.error:
        response["error"] = result.error
    return response


@app.post("/chat")
async def chat(request: Request, x_session_id: str = Header(default=None)):
    raw_body = await request.body()
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        m = re.search(rb'"input"\s*:\s*"(.*)"', raw_body, re.DOTALL)
        if m:
            body = {"input": m.group(1).decode("utf-8", errors="replace")}
        else:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)

    message = body.get("input", "") or body.get("message", "") or body.get("content", "")
    if not message:
        return JSONResponse({"error": "missing 'input' field"}, status_code=400)

    session_id = x_session_id or body.get("session_id") or f"harness-{uuid.uuid4()}"

    log.info("/chat sid=%s prompt=%.60s", session_id, message)
    result = await _send_with_retry(message, session_id)

    if result.error:
        return JSONResponse({"session_id": session_id, "answer": result.answer, "error": result.error, "agent_thoughts": [], "events": []}, status_code=502)

    return {"session_id": session_id, "answer": result.answer, "message": result.answer, "content": result.answer, "agent_thoughts": result.agent_thoughts, "events": result.guardrails}


@app.get("/v1/models")
async def models():
    return {"object": "list", "data": [{"id": TARGET_NAME, "object": "model", "owned_by": "deepcyber-airt"}]}


@app.post("/auth")
async def auth():
    """Verify or refresh authentication.

    For bearer auth: attempts to refresh the token from a remote endpoint
    or local CLI (e.g. gcloud), then verifies by sending a health-check.

    curl -X POST http://localhost:8000/auth
    """
    auth_mode = PROFILE.get("auth", {}).get("mode", "none")

    if auth_mode == "none":
        # mTLS -- just verify the cert exists
        tls = PROFILE.get("tls", {})
        cert_path = tls.get("cert", "")
        if cert_path and os.path.exists(cert_path):
            return {"status": "ok", "auth_mode": "mTLS", "cert": cert_path}
        elif cert_path:
            return JSONResponse({"status": "error", "auth_mode": "mTLS", "cert": cert_path, "error": "cert file not found"}, status_code=400)
        return {"status": "ok", "auth_mode": "none"}

    # Bearer / API key -- refresh token
    refreshed = await _refresh_token()
    if refreshed:
        return {"status": "ok", "auth_mode": auth_mode, "token_updated_at": _token_updated_at}
    return JSONResponse({"status": "error", "auth_mode": auth_mode, "error": "failed to refresh token"}, status_code=401)


@app.post("/init")
async def init_session(request: Request):
    """Explicitly initialise a session (for targets that require it).

    curl -X POST http://localhost:8000/init -d '{"session_id": "my-session"}'
    """
    body = await request.json()
    session_id = body.get("session_id", f"harness-{uuid.uuid4()}")

    if not mapper.needs_init():
        _initialised_sessions.add(session_id)
        return {"status": "ok", "session_id": session_id, "message": "target does not require explicit init"}

    init_url = f"{mapper.get_mock_url().rstrip('/')}/chat" if BACKEND == "mock" else None
    api_sid = mapper.init_session(session_id, _client, url_override=init_url)
    if api_sid:
        _initialised_sessions.add(session_id)
        log.info("/init session=%s -> api_sid=%s", session_id, api_sid)
        return {"status": "ok", "session_id": api_sid}
    return JSONResponse({"status": "error", "session_id": session_id, "error": "init failed"}, status_code=502)


@app.post("/backend")
async def switch_backend(request: Request):
    global BACKEND, _client, _api_url, _initialised_sessions
    raw = await request.body()
    new_backend = json.loads(raw).get("backend", "mock" if BACKEND == "real" else "real") if raw else ("mock" if BACKEND == "real" else "real")
    if new_backend not in ("mock", "real"):
        return JSONResponse({"error": f"invalid backend: {new_backend}"}, status_code=400)
    BACKEND = new_backend
    _save_state({"backend": BACKEND})
    _initialised_sessions.clear()
    _client = httpx.Client(timeout=120) if BACKEND == "mock" else httpx.Client(**mapper.build_client_kwargs())
    _api_url = mapper.get_mock_url() if BACKEND == "mock" else mapper.get_api_url()
    log.info("/backend -> %s (%s)", BACKEND, _api_url)
    return {"backend": BACKEND, "api_url": _api_url}


@app.post("/token")
async def update_token(request: Request):
    body = await request.json()
    token = body.get("token", "")
    if not token:
        return JSONResponse({"error": "missing 'token' field"}, status_code=400)
    env_var = PROFILE.get("auth", {}).get("bearer", {}).get("env_var", "")
    if env_var:
        os.environ[env_var] = token
        log.info("/token -> updated %s", env_var)
        return {"status": "ok", "env_var": env_var}
    return JSONResponse({"error": "no bearer env_var configured"}, status_code=400)


@app.get("/intel/summary")
async def intel_summary():
    entries = _load_intel()
    return {"total_calls": len(entries), "target": TARGET_NAME, "backend": BACKEND}


@app.get("/health")
async def health():
    tls = PROFILE.get("tls", {})
    cert_path = tls.get("cert", "")
    if BACKEND == "mock":
        cert_status = "n/a (mock)"
    elif cert_path and os.path.exists(cert_path):
        cert_status = f"loaded ({cert_path})"
    elif cert_path:
        cert_status = f"MISSING ({cert_path})"
    else:
        cert_status = "not configured"
    return {"status": "ok", "target": TARGET_NAME, "display_name": DISPLAY_NAME, "mapper": mapper.name, "backend": BACKEND, "api_url": _api_url, "cert_status": cert_status, "profile": PROFILE_PATH, "intel_dir": INTEL_DIR}


@app.on_event("shutdown")
async def shutdown():
    _client.close()
