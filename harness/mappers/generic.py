"""Generic YAML-driven mapper — no custom Python needed.

For targets with standard REST APIs, you can configure the request body
and response extraction entirely in profile.yaml.  No mapper file required.

Profile example::

    target: generic

    api:
      url: "https://api.example.com"
      path: "/v1/chat"

    request_template:
      model: "gpt-4"
      messages:
        - role: "user"
          content: "{{PROMPT}}"

    response_path: "choices.0.message.content"

The ``{{PROMPT}}`` placeholder is replaced with the user message.
The ``response_path`` uses dot-notation to extract the answer from the
JSON response (e.g. ``choices.0.message.content`` walks into nested
dicts and lists).

For targets with complex wire formats (SSE, double-encoding, custom
session init), use a custom mapper instead — see mappers/example.py.

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from harness.mappers import BaseMapper, CanonicalResponse


def resolve_dot_path(data: Any, path: str) -> Any:
    """Extract a nested value using dot-notation.

    Examples::

        resolve_dot_path(d, "answer")                     → d["answer"]
        resolve_dot_path(d, "choices.0.message.content")  → d["choices"][0]["message"]["content"]
        resolve_dot_path(d, "responses.0.value")          → d["responses"][0]["value"]

    Returns None if the path cannot be resolved.
    """
    if not path:
        return data
    for key in path.split("."):
        if data is None:
            return None
        if isinstance(data, list):
            try:
                data = data[int(key)]
            except (ValueError, IndexError):
                return None
        elif isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def substitute_prompt(template: Any, prompt: str) -> Any:
    """Recursively replace ``{{PROMPT}}`` in a template structure."""
    if isinstance(template, str):
        return template.replace("{{PROMPT}}", prompt)
    if isinstance(template, dict):
        return {k: substitute_prompt(v, prompt) for k, v in template.items()}
    if isinstance(template, list):
        return [substitute_prompt(item, prompt) for item in template]
    return template


def _find_prompt_field(template: Any, path: tuple = ()) -> str | None:
    """Find the dot-notation path to the field containing {{PROMPT}}."""
    if isinstance(template, str) and "{{PROMPT}}" in template:
        return ".".join(str(p) for p in path)
    if isinstance(template, dict):
        for k, v in template.items():
            result = _find_prompt_field(v, path + (k,))
            if result is not None:
                return result
    if isinstance(template, list):
        for i, v in enumerate(template):
            result = _find_prompt_field(v, path + (str(i),))
            if result is not None:
                return result
    return None


class GenericMapper(BaseMapper):
    """YAML-driven mapper using request templates and dot-notation paths."""

    name = "generic"

    def __init__(self, config: dict):
        super().__init__(config)
        self._template = config.get("request_template", {"input": "{{PROMPT}}"})
        self._answer_path = config.get("response_path", "answer")
        self._thoughts_path = config.get("response_thoughts_path")
        self._events_path = config.get("response_events_path")
        self._prompt_field = _find_prompt_field(self._template)

    # -- Client side ---------------------------------------------------------

    def build_request(
        self, message: str, session_id: str
    ) -> tuple[str, dict, dict]:
        url = self.get_api_url()
        session_cfg = self.config.get("session", {}) or {}

        headers = {
            "Content-Type": "application/json",
            session_cfg.get("header", "x-session-id"): session_id,
        }

        for k, v in (self.config.get("headers", {}) or {}).items():
            headers[k] = v

        headers.update(self.build_auth_headers())

        body = substitute_prompt(copy.deepcopy(self._template), message)
        return url, headers, body

    def parse_response(
        self, data: Any, raw_text: str = ""
    ) -> CanonicalResponse:
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                return CanonicalResponse(answer=data, raw={"raw_text": raw_text})

        if not isinstance(data, dict):
            return CanonicalResponse(
                answer=str(data), raw={"raw_text": raw_text}
            )

        answer = resolve_dot_path(data, self._answer_path) or ""
        return CanonicalResponse(answer=str(answer), raw=data)

    # -- Server side (mock) --------------------------------------------------

    def parse_incoming_request(
        self, body: dict, headers: dict
    ) -> tuple[str, str]:
        # Walk the template to find the prompt field and extract it.
        message = ""
        if self._prompt_field:
            message = resolve_dot_path(body, self._prompt_field) or ""
        if not message:
            message = (
                body.get("input", "")
                or body.get("message", "")
                or body.get("content", "")
            )

        session_cfg = self.config.get("session", {}) or {}
        header_name = session_cfg.get("header", "x-session-id")
        session_id = headers.get(
            header_name.lower(), headers.get("x-session-id", "")
        )
        return str(message), session_id

    def build_mock_response(
        self, answer: str, session_id: str, **kwargs
    ) -> dict:
        # Build a response that matches the configured response_path.
        # For "choices.0.message.content" → {"choices": [{"message": {"content": answer}}]}
        parts = self._answer_path.split(".")
        result: Any = answer
        for key in reversed(parts):
            try:
                idx = int(key)
                wrapper = [None] * (idx + 1)
                wrapper[idx] = result
                result = wrapper
            except ValueError:
                result = {key: result}
        if isinstance(result, dict):
            result["session_id"] = session_id
        return result


def create_mapper(config: dict) -> GenericMapper:
    return GenericMapper(config)
