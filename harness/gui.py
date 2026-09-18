#!/usr/bin/env python3
"""DeepCyber AIRT Harness -- Chat GUI.

Generic Gradio-based interactive client for any target profile.
Talks to the harness server which handles protocol translation,
auth, and intel collection. Title and target name are pulled
from the harness /health endpoint.

Usage:
    python -m harness.gui                              # harness on localhost:8000
    python -m harness.gui --url http://localhost:8000   # explicit
    python -m harness.gui --port 7860                   # custom Gradio port
"""

import argparse
import json
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path

import gradio as gr
import requests

# -- Logging ----------------------------------------------------------------

LOG_DIR = Path("results/gui_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(LOG_FILE)],
)
log = logging.getLogger("airt-gui")

BANNER = r"""
    ____                  ______      __
   / __ \___  ___  ____  / ____/_  __/ /_  ___  _____
  / / / / _ \/ _ \/ __ \/ /   / / / / __ \/ _ \/ ___/
 / /_/ /  __/  __/ /_/ / /___/ /_/ / /_/ /  __/ /
/_____/\___/\___/ .___/\____/\__, /_.___/\___/_/
               /_/          /____/
"""

# -- Harness helpers --------------------------------------------------------


def harness_chat(harness_url, message, session_id):
    """Send a chat message via the harness."""
    url = f"{harness_url.rstrip('/')}/chat"
    payload = {"input": message}
    headers = {"Content-Type": "application/json", "x-session-id": session_id}

    log.info(">>> %s sid=%s msg=%.80s", url, session_id, message)
    resp = requests.post(url, json=payload, headers=headers, timeout=120)
    log.info("<<< %s (%d bytes)", resp.status_code, len(resp.content))
    resp.raise_for_status()
    return resp.json()


def harness_health(harness_url):
    """Get harness health -- includes target name and profile."""
    resp = requests.get(f"{harness_url.rstrip('/')}/health", timeout=10)
    resp.raise_for_status()
    return resp.json()


def harness_switch_backend(harness_url, backend):
    """Switch harness backend."""
    resp = requests.post(
        f"{harness_url.rstrip('/')}/backend", json={"backend": backend}, timeout=10
    )
    resp.raise_for_status()
    return resp.json()


def harness_catalogue(harness_url):
    """Model catalogue from the harness: names, which are usable, and the current one."""
    try:
        resp = requests.get(f"{harness_url.rstrip('/')}/catalogue", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return {"models": [], "available": [], "current": None}


def harness_switch_model(harness_url, model):
    """Switch the target's backing model."""
    resp = requests.post(
        f"{harness_url.rstrip('/')}/model", json={"model": model}, timeout=15
    )
    resp.raise_for_status()
    return resp.json()


def harness_intel_summary(harness_url):
    """Get intel summary."""
    resp = requests.get(f"{harness_url.rstrip('/')}/intel/summary", timeout=10)
    resp.raise_for_status()
    return resp.json()


def harness_auth(harness_url):
    """Verify/refresh auth."""
    resp = requests.post(f"{harness_url.rstrip('/')}/auth", timeout=30)
    resp.raise_for_status()
    return resp.json()


# -- Format helpers ---------------------------------------------------------


_TOOL_BLOCK_START = re.compile(r"\[\w+ result:")


def _strip_tool_result_blocks(text):
    """Remove whole '[<word> result: ...]' blocks, nested brackets included, so the
    chat bubble reads like a real product's answer. The raw payload still streams to
    the browser (the hidden Raw carrier), so it can be recovered from the Network tab.
    Mirrors the profile detector's strip logic."""
    out, i = [], 0
    while True:
        m = _TOOL_BLOCK_START.search(text, i)
        if not m:
            out.append(text[i:])
            break
        out.append(text[i:m.start()])
        depth, j = 0, m.start()
        while j < len(text):
            ch = text[j]
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        else:
            j = len(text)
        i = j
    return "".join(out)


# Shown in the bubble when a reply was nothing but a tool-result block and stripping it
# leaves no assistant text (e.g. audit row 28226). GUI-authored, kept clearly distinct from
# model text; flags and the raw evidence are untouched and the raw still reaches the browser.
_TOOL_ONLY_STATUS = "_Tool output received; no separate assistant answer was returned._"


def format_response(data, clean_chat=False):
    """Format harness response for display -- the assistant answer. With clean_chat on,
    strip inline tool-result blocks so the bubble shows only the answer; if that leaves
    nothing (a tool-only reply), show a GUI status instead of an empty bubble."""
    answer = data.get("answer", "")
    if not clean_chat:
        return answer
    stripped = _strip_tool_result_blocks(answer)
    return stripped if stripped.strip() else _TOOL_ONLY_STATUS


def format_raw(data):
    """Pretty-print the full raw target response for the Raw Response tab."""
    raw = data.get("raw") if data else None
    if not raw:
        return "*No raw response available*"
    try:
        return "```json\n" + json.dumps(raw, indent=2, default=str) + "\n```"
    except Exception as e:
        return f"*Could not serialise raw response: {e}*"


# -- Build GUI --------------------------------------------------------------


def create_app(harness_url, clean_chat_mode="auto"):
    # Get target info from harness
    clean_chat_default = False
    try:
        health = harness_health(harness_url)
        target_name = health.get("display_name", health.get("target", "Unknown Target"))
        backend = health.get("backend", "?")
        profile = health.get("profile", "?")
        mapper = health.get("mapper", "?")
        # The harness reports whether the real/mock switch is meaningful (the
        # two endpoints resolve to different hosts). Default True so an older
        # harness that doesn't send the flag still shows the control.
        backend_switchable = health.get("backend_switchable", True)
        # Whether the profile asks the chat bubble to hide inline tool-result blocks.
        clean_chat_default = bool(health.get("clean_chat", False))
    except Exception:
        target_name = "Unknown Target"
        backend = "?"
        profile = "?"
        mapper = "?"
        backend_switchable = True

    # Precedence: explicit launch override ('on'/'off'), then the profile default, then False.
    clean_chat = {"on": True, "off": False}.get(clean_chat_mode, clean_chat_default)
    log.info("clean_chat effective=%s (mode=%s, profile default=%s)",
             clean_chat, clean_chat_mode, clean_chat_default)
    print(f"  Clean chat: {'ON' if clean_chat else 'OFF'} "
          f"(mode={clean_chat_mode}, profile default={clean_chat_default})")

    # Model catalogue (present only when the target opts in via mock.models_file).
    cat = harness_catalogue(harness_url)
    model_choices = cat.get("available") or cat.get("models") or []
    current_model = cat.get("current")
    has_catalogue = bool(model_choices)

    title = target_name

    state = {
        "session_id": f"gui-{uuid.uuid4().hex[:12]}",
        "last_response": None,
    }

    def respond(message, history):
        if not message.strip():
            return history, ""

        history.append({"role": "user", "content": message})

        try:
            data = harness_chat(harness_url, message, state["session_id"])
            state["last_response"] = data
            reply = format_response(data, clean_chat)
            history.append({"role": "assistant", "content": reply})
        except Exception as e:
            history.append({"role": "assistant", "content": f"**Error:** {e}"})
            state["last_response"] = None

        return history, ""

    def new_session(history):
        state["session_id"] = f"gui-{uuid.uuid4().hex[:12]}"
        state["last_response"] = None
        return [], f"Session: {state['session_id']}"

    def get_raw():
        if state["last_response"]:
            return format_raw(state["last_response"])
        return "*Send a message first*"

    def get_health():
        try:
            return json.dumps(harness_health(harness_url), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def do_auth():
        try:
            return json.dumps(harness_auth(harness_url), indent=2)
        except Exception as e:
            return f"Error: {e}"

    def switch_backend(backend_choice):
        try:
            result = harness_switch_backend(harness_url, backend_choice)
            state["session_id"] = f"gui-{uuid.uuid4().hex[:12]}"
            state["last_response"] = None
            return (
                f"Switched to **{result['backend']}**\n`{result['api_url']}`",
                [],
                f"Session: {state['session_id']}",
            )
        except Exception as e:
            return f"Error: {e}", gr.update(), gr.update()

    def switch_model(model_choice):
        # Switching the backing model starts a fresh session, so a transcript
        # never mixes two models.
        try:
            result = harness_switch_model(harness_url, model_choice)
            state["session_id"] = f"gui-{uuid.uuid4().hex[:12]}"
            state["last_response"] = None
            return (
                f"Model: **{result['model']}**",
                [],
                f"Session: {state['session_id']}",
            )
        except Exception as e:
            return f"Error: {e}", gr.update(), gr.update()

    def get_intel():
        try:
            summary = harness_intel_summary(harness_url)
            return json.dumps(summary, indent=2)
        except Exception as e:
            return f"Error: {e}"

    # -- Layout -------------------------------------------------------------

    with gr.Blocks(title=f"{title} -- AIRT Red Team Chat") as app:
        gr.Markdown(f"# {title} -- Red Team Chat")
        # Only surface the backend when the real/mock switch is meaningful.
        # For a self-contained mock target the label ("real") is both a no-op
        # and misleading, so drop it.
        _meta = f"Profile: `{profile}` | Mapper: `{mapper}` | "
        if backend_switchable:
            _meta += f"Backend: `{backend}` | "
        _meta += f"Harness: `{harness_url}`"
        gr.Markdown(_meta)

        with gr.Row():
            # Main chat
            with gr.Column(scale=3):
                chatbot = gr.Chatbot(height=500)
                with gr.Row():
                    msg = gr.Textbox(
                        placeholder="Type your message...",
                        show_label=False,
                        scale=5,
                        autofocus=True,
                    )
                    send_btn = gr.Button("Send", variant="primary", scale=1)

            # Sidebar
            with gr.Column(scale=2):
                status = gr.Textbox(
                    label="Session",
                    value=f"Session: {state['session_id']}",
                    interactive=False,
                )

                with gr.Row():
                    new_btn = gr.Button("New Session", variant="secondary")
                    backend_dd = gr.Dropdown(
                        choices=["real", "mock"],
                        label="Backend",
                        value=backend,
                        interactive=True,
                        visible=backend_switchable,
                    )
                    switch_btn = gr.Button(
                        "Switch", variant="secondary", visible=backend_switchable
                    )

                # Backing-model selector — present only when the target ships a
                # model catalogue. Picking one switches the model live and starts
                # a fresh session (explore how the same target behaves per model).
                model_dd = gr.Dropdown(
                    choices=model_choices,
                    value=current_model,
                    label="Target model",
                    interactive=True,
                    visible=has_catalogue,
                )

                with gr.Tabs():
                    # With clean_chat on, the Raw Response tab is hidden but raw_md stays in
                    # the callback outputs, so the raw response still streams to the browser
                    # over queue/data (verified) — the Network tab reveals the tool result
                    # while the UI shows only the clean answer.
                    with gr.Tab("Raw Response", visible=not clean_chat):
                        raw_md = gr.Markdown("*Send a message first*")
                        refresh_raw_btn = gr.Button("Refresh", size="sm")

                    with gr.Tab("Intel"):
                        intel_md = gr.Markdown("*Click refresh to load*")
                        refresh_intel_btn = gr.Button("Refresh", size="sm")

                    with gr.Tab("Auth"):
                        auth_md = gr.Markdown("*Click to verify/refresh auth*")
                        auth_btn = gr.Button("Verify Auth", size="sm")

                    with gr.Tab("Health"):
                        health_md = gr.Markdown("*Click refresh to load*")
                        refresh_health_btn = gr.Button("Refresh", size="sm")

        # Events
        def chat_and_update(message, history):
            history, cleared = respond(message, history)
            raw = get_raw()
            return history, cleared, raw

        msg.submit(chat_and_update, [msg, chatbot], [chatbot, msg, raw_md])
        send_btn.click(chat_and_update, [msg, chatbot], [chatbot, msg, raw_md])
        new_btn.click(new_session, [chatbot], [chatbot, status])
        switch_btn.click(switch_backend, [backend_dd], [raw_md, chatbot, status])
        model_dd.change(switch_model, [model_dd], [raw_md, chatbot, status])
        refresh_raw_btn.click(get_raw, [], [raw_md])
        refresh_intel_btn.click(get_intel, [], [intel_md])
        auth_btn.click(do_auth, [], [auth_md])
        refresh_health_btn.click(get_health, [], [health_md])

    return app


def main():
    print(BANNER)
    print("              AI Red Teaming Chat GUI")
    print()

    parser = argparse.ArgumentParser(description="DeepCyber AIRT Chat GUI")
    parser.add_argument("--url", default="http://localhost:8000", help="Harness URL")
    parser.add_argument("--port", type=int, default=7860, help="Gradio port")
    parser.add_argument("--share", action="store_true", help="Create public link")
    parser.add_argument("--clean-chat", choices=["auto", "on", "off"], default="auto",
                        help="Hide inline tool-result blocks from the chat bubble (the raw "
                             "response still streams to the browser, so the Network tab shows "
                             "it). 'auto' follows the profile's mock.clean_chat; use 'off' for "
                             "demonstrations that show the tool result in the window.")
    args = parser.parse_args()

    print(f"  Harness: {args.url}")

    # Get target name for display
    try:
        health = harness_health(args.url)
        target = health.get("target", "?")
        backend = health.get("backend", "?")
        print(f"  Target:  {target}")
        print(f"  Backend: {backend}")
    except Exception:
        print("  Harness: not reachable (will retry on first message)")

    print()

    app = create_app(args.url, args.clean_chat)
    app.launch(server_name="0.0.0.0", server_port=args.port, share=args.share, theme=gr.themes.Soft())


if __name__ == "__main__":
    main()
