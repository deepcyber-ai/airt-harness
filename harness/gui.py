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
    """Format harness response for display."""
    answer = data.get("answer", "")
    events = data.get("events", [])

    parts = [answer]

    triggered = [e for e in events if e.get("triggered")]
    if triggered:
        parts.append("\n\n---\n*Guardrails triggered:*")
        for e in triggered:
            parts.append(
                f"- **{e['name']}** ({e.get('type', e.get('guardrail_type', '?'))}): "
                f"score {e['score']}/{e['threshold']} -- {e.get('reason', '')[:100]}"
            )

    return "\n".join(parts)


def format_thoughts(data):
    """Format agent_thoughts for sidebar display."""
    thoughts = data.get("agent_thoughts", [])
    if not thoughts:
        return "*No agent thoughts in response*"

    lines = []
    for t in thoughts:
        node = t.get("node_name", "?")
        thought = t.get("agent_thought", "")
        if len(thought) > 200:
            thought = thought[:200] + "..."
        lines.append(f"**{node}**\n{thought}")

    return "\n\n---\n".join(lines)


def format_events(data):
    """Format events/guardrails for sidebar display."""
    events = data.get("events", [])
    if not events:
        return "*No guardrail events in response*"

    lines = []
    for e in events:
        status = "TRIGGERED" if e.get("triggered") else "passed"
        lines.append(
            f"**{e.get('name', '?')}** ({e.get('type', e.get('guardrail_type', '?'))}): "
            f"{status} -- score {e.get('score', '?')}/{e.get('threshold', '?')}\n"
            f"_{e.get('reason', '')[:150]}_"
        )

    return "\n\n---\n".join(lines)


# -- Build GUI --------------------------------------------------------------


def create_app(harness_url):
    # Get target info from harness
    try:
        health = harness_health(harness_url)
        target_name = health.get("display_name", health.get("target", "Unknown Target"))
        backend = health.get("backend", "?")
        profile = health.get("profile", "?")
        mapper = health.get("mapper", "?")
    except Exception:
        target_name = "Unknown Target"
        backend = "?"
        profile = "?"
        mapper = "?"

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

    def get_thoughts():
        if state["last_response"]:
            return format_thoughts(state["last_response"])
        return "*Send a message first*"

    def get_events():
        if state["last_response"]:
            return format_events(state["last_response"])
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

    def get_intel():
        try:
            summary = harness_intel_summary(harness_url)
            return json.dumps(summary, indent=2)
        except Exception as e:
            return f"Error: {e}"

    # -- Layout -------------------------------------------------------------

    with gr.Blocks(title=f"{title} -- AIRT Red Team Chat") as app:
        gr.Markdown(f"# {title} -- Red Team Chat")
        gr.Markdown(
            f"Profile: `{profile}` | Mapper: `{mapper}` | Backend: `{backend}` | "
            f"Harness: `{harness_url}`"
        )

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
                    )
                    switch_btn = gr.Button("Switch", variant="secondary")

                with gr.Tabs():
                    with gr.Tab("Agent Thoughts"):
                        thoughts_md = gr.Markdown("*Send a message first*")
                        refresh_thoughts_btn = gr.Button("Refresh", size="sm")

                    with gr.Tab("Guardrails"):
                        events_md = gr.Markdown("*Send a message first*")
                        refresh_events_btn = gr.Button("Refresh", size="sm")

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
            thoughts = get_thoughts()
            events = get_events()
            return history, cleared, thoughts, events

        msg.submit(chat_and_update, [msg, chatbot], [chatbot, msg, thoughts_md, events_md])
        send_btn.click(chat_and_update, [msg, chatbot], [chatbot, msg, thoughts_md, events_md])
        new_btn.click(new_session, [chatbot], [chatbot, status])
        switch_btn.click(switch_backend, [backend_dd], [thoughts_md, chatbot, status])
        refresh_thoughts_btn.click(get_thoughts, [], [thoughts_md])
        refresh_events_btn.click(get_events, [], [events_md])
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
