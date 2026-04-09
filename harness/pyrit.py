"""PyRIT integration targets for the AIRT Harness.

Provides two PyRIT-compatible targets:

  ProxyTarget  — routes prompts through the running harness (any mapper)
  BedrockTarget — calls AWS Bedrock Converse API directly

Usage::

    from harness.pyrit import ProxyTarget

    target = ProxyTarget(
        harness_url="http://localhost:8000",
        session_id="RedTeam-001",
    )

    # Use with any PyRIT orchestrator
    orchestrator = PromptSendingOrchestrator(objective_target=target)

Requires: ``pip install airt-harness[pyrit]``

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

import os
import uuid
from typing import Optional

try:
    from pyrit.models import PromptRequestResponse, construct_response_from_request
    from pyrit.prompt_target import PromptTarget
except ImportError:
    raise ImportError(
        "PyRIT is required for harness.pyrit. "
        "Install it with: pip install airt-harness[pyrit]"
    )

import requests


class ProxyTarget(PromptTarget):
    """PyRIT target that sends prompts through the AIRT Harness.

    The harness handles protocol translation, auth, session management,
    and intel collection.  This target just talks to the harness ``/chat``
    endpoint.
    """

    def __init__(
        self,
        harness_url: str = "http://localhost:8000",
        session_id: Optional[str] = None,
        max_requests_per_minute: Optional[int] = None,
    ):
        super().__init__(max_requests_per_minute=max_requests_per_minute)
        self._harness_url = harness_url.rstrip("/")
        self._session_id = session_id or f"pyrit-{uuid.uuid4().hex[:8]}"

        # Detect target name from health endpoint.
        try:
            health = requests.get(f"{self._harness_url}/health", timeout=5)
            info = health.json()
            self._target_name = info.get("display_name") or info.get("target", "harness")
        except Exception:
            self._target_name = "harness"

    async def send_prompt_async(
        self, *, prompt_request
    ) -> PromptRequestResponse:
        request = prompt_request
        prompt_text = request.request_pieces[0].original_value

        try:
            resp = requests.post(
                f"{self._harness_url}/chat",
                json={"input": prompt_text},
                headers={
                    "Content-Type": "application/json",
                    "x-session-id": self._session_id,
                },
                timeout=120,
            )
            data = resp.json()
            answer = (
                data.get("answer")
                or data.get("message")
                or data.get("content", "")
            )
        except Exception as e:
            answer = f"[ERROR] {e}"

        return construct_response_from_request(
            request=request,
            response_text_pieces=[str(answer)],
        )

    def _validate_request(self, *, prompt_request) -> None:
        if len(prompt_request.request_pieces) != 1:
            raise ValueError("ProxyTarget only supports single-piece prompts")
        if prompt_request.request_pieces[0].converted_value_data_type != "text":
            raise ValueError("ProxyTarget only supports text prompts")


class BedrockTarget(PromptTarget):
    """PyRIT target that calls AWS Bedrock Converse API directly.

    Supports any model available through Bedrock (Claude, Llama, Mistral,
    etc.) using the unified Converse API.

    Requires: ``pip install airt-harness[bedrock]``
    """

    def __init__(
        self,
        model_id: str,
        region: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.6,
        max_requests_per_minute: Optional[int] = None,
    ):
        super().__init__(max_requests_per_minute=max_requests_per_minute)
        self._model_id = model_id
        self._region = region or os.environ.get("AWS_DEFAULT_REGION", "eu-west-2")
        self._max_tokens = max_tokens
        self._temperature = temperature

        try:
            import boto3
        except ImportError:
            raise ImportError(
                "boto3 is required for BedrockTarget. "
                "Install it with: pip install airt-harness[bedrock]"
            )
        self._client = boto3.client(
            "bedrock-runtime", region_name=self._region
        )

    async def send_prompt_async(
        self, *, prompt_request
    ) -> PromptRequestResponse:
        request = prompt_request
        prompt_text = request.request_pieces[0].original_value

        try:
            response = self._client.converse(
                modelId=self._model_id,
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": prompt_text}],
                    }
                ],
                inferenceConfig={
                    "maxTokens": self._max_tokens,
                    "temperature": self._temperature,
                },
            )
            content = (
                response.get("output", {})
                .get("message", {})
                .get("content", [])
            )
            answer = content[0].get("text", "") if content else ""
        except Exception as e:
            answer = f"[ERROR] {e}"

        return construct_response_from_request(
            request=request,
            response_text_pieces=[str(answer)],
        )

    def _validate_request(self, *, prompt_request) -> None:
        if len(prompt_request.request_pieces) != 1:
            raise ValueError("BedrockTarget only supports single-piece prompts")
        if prompt_request.request_pieces[0].converted_value_data_type != "text":
            raise ValueError("BedrockTarget only supports text prompts")
