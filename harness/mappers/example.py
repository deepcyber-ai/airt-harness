"""Example message mapper.

A minimal, neutral mapper demonstrating the bidirectional pattern. Use this
as a starting point when adding a new target.

Wire format (kept deliberately simple):
  Request:  POST {"input": "<user message>"}
            Header: x-session-id: <session id>
  Response: {"output": "<assistant reply>", "session_id": "<session id>"}

Session: client supplies the session ID in a header (no explicit init).
Auth: whatever is configured in profile.yaml (bearer, api_key, mTLS, none).

To add your own target:

  1. Copy this file to harness/mappers/<your_target>.py
  2. Subclass BaseMapper and implement the four methods below
  3. Register it in harness/mappers/__init__.py:_BUILTIN_MAPPERS
     OR set target_module: in your profile YAML to point to it directly

The four methods to implement are:

  Client side (harness sends real requests):
    build_request(message, session_id) -> (url, headers, body)
    parse_response(data, raw_text)     -> CanonicalResponse

  Server side (mock emulates the target):
    parse_incoming_request(body, headers) -> (message, session_id)
    build_mock_response(answer, session_id, **kwargs) -> dict
"""

from __future__ import annotations

from typing import Any

from harness.mappers import BaseMapper, CanonicalResponse


class ExampleMapper(BaseMapper):
    name = "example"

    # -- Client side -------------------------------------------------------

    def build_request(
        self, message: str, session_id: str
    ) -> tuple[str, dict, dict]:
        url = self.get_api_url()
        session_cfg = self.config.get("session", {}) or {}

        headers = {
            "Content-Type": "application/json",
            session_cfg.get("header", "x-session-id"): session_id,
        }

        # Pass through any extra headers from the profile
        for k, v in (self.config.get("headers", {}) or {}).items():
            headers[k] = v

        # Auth headers (bearer / api_key) come from BaseMapper
        headers.update(self.build_auth_headers())

        body = {"input": message}
        return url, headers, body

    def parse_response(self, data: Any, raw_text: str = "") -> CanonicalResponse:
        if isinstance(data, str):
            import json
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                return CanonicalResponse(answer=data, raw={"raw_text": raw_text})

        if not isinstance(data, dict):
            return CanonicalResponse(answer=str(data), raw={"raw_text": raw_text})

        # Accept "output", "answer", "message", or "content" as the reply field
        answer = (
            data.get("output")
            or data.get("answer")
            or data.get("message")
            or data.get("content")
            or ""
        )

        return CanonicalResponse(
            answer=answer,
            session_id=data.get("session_id", ""),
            raw=data,
        )

    def needs_init(self) -> bool:
        return False

    # -- Server side (mock) ------------------------------------------------

    def parse_incoming_request(
        self, body: dict, headers: dict
    ) -> tuple[str, str]:
        message = (
            body.get("input", "")
            or body.get("message", "")
            or body.get("content", "")
        )
        session_cfg = self.config.get("session", {}) or {}
        header_name = session_cfg.get("header", "x-session-id")
        # HTTP headers are case-insensitive; FastAPI lowercases them
        session_id = headers.get(header_name.lower(), headers.get("x-session-id", ""))
        return message, session_id

    def build_mock_response(
        self, answer: str, session_id: str, **kwargs
    ) -> dict:
        return {
            "output": answer,
            "session_id": session_id,
        }


def create_mapper(config: dict) -> ExampleMapper:
    return ExampleMapper(config)
