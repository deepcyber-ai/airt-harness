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


def harness_set_risk(harness_url, session_id, risk):
    """Set the session risk on the target's governance rung (if the profile has one)."""
    resp = requests.post(
        f"{harness_url.rstrip('/')}/risk",
        json={"session_id": session_id, "risk": int(risk)}, timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def harness_toggle_governance(harness_url, enabled):
    """Turn runtime Cedar enforcement on/off live."""
    resp = requests.post(
        f"{harness_url.rstrip('/')}/governance", json={"enabled": bool(enabled)}, timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def harness_set_prompt(harness_url, name):
    """Switch the target's active system prompt live (neutral <-> hardened)."""
    resp = requests.post(
        f"{harness_url.rstrip('/')}/prompt", json={"prompt": name}, timeout=10,
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


def format_response(data):
    """Format harness response for display -- just the assistant answer."""
    return data.get("answer", "")


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


def create_app(harness_url):
    # Get target info from harness
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
        # Show the governance controls when the profile *has* a governance block;
        # their initial on/off comes from `governance_enabled` (can start off).
        has_governance = bool(health.get("governance_configured", health.get("governance_enabled")))
        governance_on = bool(health.get("governance_enabled"))
        policy_name = health.get("governance_policy") or "policy.cedar"
        # Live system-prompt toggle (neutral <-> hardened) when the profile
        # declares 2+ switchable prompts. Checkbox = "hardened"; default from profile.
        has_prompt_toggle = bool(health.get("prompt_switchable"))
        hardened_on = health.get("prompt_default") == "hardened"
    except Exception:
        target_name = "Unknown Target"
        backend = "?"
        profile = "?"
        mapper = "?"
        backend_switchable = True
        has_governance = False
        governance_on = False
        policy_name = "policy.cedar"
        has_prompt_toggle = False
        hardened_on = False

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
            reply = format_response(data)
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

    def set_risk(risk):
        # Simulate the session's risk for the governance rung. A profile without
        # governance simply ignores it.
        try:
            r = harness_set_risk(harness_url, state["session_id"], risk)
            return f"session_risk = **{r.get('session_risk', int(risk))}**"
        except Exception as e:
            return f"Risk control unavailable: {e}"

    def toggle_gov(enabled):
        try:
            r = harness_toggle_governance(harness_url, enabled)
            return f"Runtime governance: **{'ON' if r.get('governance_enabled') else 'OFF'}**"
        except Exception as e:
            return f"Governance control unavailable: {e}"

    def toggle_prompt(hardened):
        # Binary system-prompt switch: checked = hardened (strict rules),
        # unchecked = neutral (no rules, no mention of disposal).
        name = "hardened" if hardened else "neutral"
        try:
            r = harness_set_prompt(harness_url, name)
            return f"System prompt: **{r.get('active_prompt', name)}**"
        except Exception as e:
            return f"Prompt control unavailable: {e}"

    def toggle_controls():
        # Hide/show the whole control column so the chat takes the full width.
        state["controls_open"] = not state.get("controls_open", True)
        arrow = "▶" if state["controls_open"] else "◀"
        return gr.update(visible=state["controls_open"]), gr.update(value=arrow)

    # -- Layout -------------------------------------------------------------

    with gr.Blocks(title=title) as app:
        with gr.Row():
            gr.Markdown(f"# {title}")
            controls_btn = gr.Button("▶", scale=0, min_width=48)

        with gr.Row():
            # Main chat
            with gr.Column(scale=3):
                chatbot = gr.Chatbot(height=500, show_label=False)
                with gr.Row():
                    msg = gr.Textbox(
                        placeholder="Type your message...",
                        show_label=False,
                        scale=5,
                        autofocus=True,
                    )
                    send_btn = gr.Button("Send", variant="primary", scale=1)

            # Sidebar — collapses as a whole via the ⚙ Controls button
            with gr.Column(scale=2, visible=True) as sidebar_col:
                gr.Markdown("### Control Panel")
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

                # System-prompt hardening — the "before governance" defense layer.
                # Unchecked = neutral (Act 0a: alignment alone doesn't refuse a
                # non-malicious disposal); checked = hardened strict rules (Act 0b/1/2).
                prompt_toggle = gr.Checkbox(
                    value=hardened_on, label="Hardened system prompt (strict rules)",
                    interactive=True, visible=has_prompt_toggle,
                )
                prompt_status = gr.Markdown("", visible=has_prompt_toggle)

                # Runtime governance on/off — flip between Act 1 (off, agent
                # complies) and Act 2 (on, Cedar denies) without restarting.
                gov_toggle = gr.Checkbox(
                    value=governance_on, label="Runtime governance applied (Cedar)",
                    interactive=True, visible=has_governance,
                )
                gr.Markdown(
                    f'Policy file: <a href="{harness_url}/policy" target="_blank">{policy_name}</a>',
                    visible=has_governance,
                )
                gov_status = gr.Markdown("", visible=has_governance)

                # Session-risk simulator for the governance rung. Governed
                # profiles authorize tool calls partly on this value; ungoverned
                # profiles ignore it. Note: reading a document with a hidden
                # injection can also raise risk server-side.
                risk_slider = gr.Slider(
                    0, 100, value=20, step=5, label="Session risk (simulated)",
                    interactive=True, visible=has_governance,
                )
                risk_status = gr.Markdown("", visible=has_governance)

                with gr.Tabs():
                    with gr.Tab("Raw Response"):
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
        risk_slider.release(set_risk, [risk_slider], [risk_status])
        prompt_toggle.change(toggle_prompt, [prompt_toggle], [prompt_status])
        gov_toggle.change(toggle_gov, [gov_toggle], [gov_status])
        controls_btn.click(toggle_controls, None, [sidebar_col, controls_btn])
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

    app = create_app(args.url)
    app.launch(server_name="0.0.0.0", server_port=args.port, share=args.share, theme=gr.themes.Soft())


if __name__ == "__main__":
    main()
