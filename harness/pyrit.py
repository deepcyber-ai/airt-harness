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

    # Use with any PyRIT attack strategy
    attack = PromptSendingAttack(objective_target=target)

Requires PyRIT >= 1.0 (``pip install airt-harness[pyrit]``).

PyRIT 1.0 renamed ``PromptRequestResponse`` to ``Message``, made
``send_prompt_async`` concrete, and moved the abstract work into
``_send_prompt_to_target_async``.  Subclass ``__init__`` must be
keyword-only or the base class raises ``TypeError``.

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

import os
import uuid
from typing import Optional

try:
    from pyrit.models import Message, construct_response_from_request
    from pyrit.prompt_target import PromptTarget
except ImportError:
    raise ImportError(
        "PyRIT >= 1.0 is required for harness.pyrit. "
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
        *,
        harness_url: str = "http://localhost:8000",
        session_id: Optional[str] = None,
        max_requests_per_minute: Optional[int] = None,
    ):
        self._harness_url = harness_url.rstrip("/")
        self._session_id = session_id or f"pyrit-{uuid.uuid4().hex[:8]}"
        # Every user turn actually delivered to the harness, in order. This is
        # what lets _resync notice that PyRIT has rewound underneath us.
        self._sent: list[str] = []

        # Every /chat response's TRUSTED tool events, captured in send order as
        # {prompt, response, events}. The harness returns the events it actually
        # executed in the response body; capturing them here lets the run driver
        # attach authenticated provenance to the saved row DIRECTLY, in-run and
        # full-text, instead of joining a shared historical audit log after the
        # fact. Replayed turns (see _resync) append too; the driver keys on
        # (prompt, response) so the selected transcript still resolves.
        self._events_log: list[dict] = []

        # Set to a reason string the moment this run cannot continue safely — an
        # unconfirmed backtrack reset, or a target left in a dirty state. It is a
        # STRUCTURED signal the run driver reads after the attack (never parsed
        # from model-visible prose), so a fatally-aborted run is recorded as an
        # error and excluded from valid scoring rather than counted as a clean 0
        #. Once set, no further turn touches the target.
        self._fatal: str | None = None

        # Detect target name from health endpoint.
        try:
            health = requests.get(f"{self._harness_url}/health", timeout=5)
            info = health.json()
            self._target_name = info.get("display_name") or info.get("target", "harness")
        except Exception:
            self._target_name = "harness"

        super().__init__(
            max_requests_per_minute=max_requests_per_minute,
            endpoint=self._harness_url,
            model_name=self._target_name,
        )

        # Declared, not assumed. PyRIT 1.0 validates an attack's requirements
        # against these before it sends anything, and the default for a custom
        # target is False everywhere — which is why CrescendoAttack raised
        # "Target must natively support 'supports_multi_turn'" and had never
        # run against this harness at all. RedTeamingAttack and TAPAttack
        # declare no requirements, so they worked and hid the gap.
        #
        #  multi_turn       true: the harness keeps conversation state per
        #                   x-session-id, so consecutive sends continue one
        #                   conversation.
        #  editable_history true ONLY because _resync implements it, by
        #                   clearing the session and replaying. Without that
        #                   machinery this would be a lie that silently
        #                   desynchronises every backtracking attack.
        try:
            from pyrit.models import TargetCapabilities
            self.apply_capabilities(capabilities=TargetCapabilities(
                supports_multi_turn=True,
                supports_editable_history=True,
            ))
        except ImportError:      # older PyRIT with no capability model
            pass

    def _user_turns(self, conversation: list[Message]) -> list[str]:
        """Every user prompt in PyRIT's view of the conversation, in order."""
        turns = []
        for message in conversation:
            for piece in message.message_pieces:
                if getattr(piece, "role", None) == "user":
                    turns.append(piece.converted_value or "")
        return turns

    def _resync(self, wanted: list[str]) -> list[str]:
        """Make the harness's session match PyRIT's conversation, and return
        whatever still needs sending.

        The harness keeps conversation state server-side against the session
        id, and PyRIT keeps its own copy. Ordinarily the two agree and each
        call just appends one turn. They stop agreeing when an attack
        BACKTRACKS: CrescendoAttack, on a refusal, drops the last exchange from
        its memory and tries a different line. The harness never hears about
        that, so it is still holding the refused turn — and every subsequent
        turn is then reasoned about against a conversation the target is not
        in. Nothing errors. The attack simply argues with a history only one
        side can see, which is unfalsifiable from the transcript afterwards.

        So PyRIT's conversation is treated as the source of truth. While it
        extends what we have sent, we append. When it diverges, we clear the
        session and replay the prompts it now believes in.
        """
        if wanted[:len(self._sent)] == self._sent:
            return wanted[len(self._sent):]          # ordinary case: append

        try:
            r = requests.post(
                f"{self._harness_url}/session/reset",
                json={"session_id": self._session_id, "reseed": True},
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            status = r.json() if getattr(r, "content", True) else {}
        except Exception:
            # A target with no /session/reset cannot be rewound. Say so rather
            # than carrying on against a history we know to be wrong.
            self._fatal = (f"{self._harness_url} has no /session/reset, so this "
                           "attack's backtracking cannot be applied to the target")
            raise RuntimeError(
                self._fatal + ". Use an attack that does not rewind "
                "(RedTeamingAttack, TAPAttack), or point at a harness that "
                "supports session reset.")
        # CONFIRM the backtrack reset the same way the per-run baseline does
        #. A rewind reseeds the database and replays the new branch's
        # prompts from clean, which RECONSTRUCTS the correct state — but only if
        # the reseed actually happened. A database-backed target that did NOT
        # reseed would replay onto the abandoned branch's writes and silently
        # corrupt the run, so abort instead of scoring dirty state. (The measured
        # flags are event-based, captured per turn, so a confirmed reseed+replay
        # loses no real effect; per-branch identical-text separation stays with
        # #5's campaign identity.)
        if isinstance(status, dict) and (status.get("error")
                or (status.get("mcp_db") and not status.get("reseeded"))):
            self._fatal = ("backtracking reset not confirmed clean: "
                           f"{status.get('error') or 'database not reseeded'}")
            raise RuntimeError(
                self._fatal + "; aborting the run rather than replaying onto "
                "dirty state")
        self._sent = []
        return wanted                                 # replay from the start

    def _post(self, prompt_text: str) -> str:
        # Once a run has fatally aborted, do NOT touch the target again — an
        # ordinary extension of the old, un-reset conversation would otherwise
        # send another chat against dirty state.
        if self._fatal:
            raise RuntimeError(f"target in fatal state: {self._fatal}")
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
        # ``output`` is what harness/server.py actually returns; the others
        # are fallbacks for custom mappers.  Without ``output`` first this
        # silently yields "" for every reply, which reads as a target that
        # refuses everything rather than as an integration bug.
        answer = (
            data.get("output")
            or data.get("answer")
            or data.get("message")
            or data.get("content", "")
        )
        # Capture the trusted tool events the harness reports for this turn.
        # ``events`` is the mock's authenticated list; a turn that ran but called
        # no tool records []. Absent field (a custom mapper that does not emit
        # events) is left as None so the driver can tell "none ran" from "not
        # captured" — the same distinction the resolver and judge draw.
        self._events_log.append({
            "prompt": prompt_text, "response": answer,
            "events": data.get("events"),
        })
        return answer

    @property
    def captured_events(self) -> list[dict]:
        """The per-turn {prompt, response, events} log for this run, in order."""
        return self._events_log

    async def _send_prompt_to_target_async(
        self, *, normalized_conversation: list[Message]
    ) -> list[Message]:
        piece = normalized_conversation[-1].message_pieces[0]

        # A run already in a fatal state must not be resumed.
        if self._fatal:
            return [self._error_response(piece, self._fatal)]

        try:
            pending = self._resync(self._user_turns(normalized_conversation))
            answer = ""
            for turn in pending:                      # replay, then the new turn
                answer = self._post(turn)
                self._sent.append(turn)
        except Exception as e:
            # Carry the failure across the callback boundary as a STRUCTURED
            # error, not as prose the driver would have to grep for.
            self._fatal = self._fatal or f"{type(e).__name__}: {e}"
            return [self._error_response(piece, self._fatal)]

        return [
            construct_response_from_request(
                request=piece,
                response_text_pieces=[str(answer)],
            )
        ]

    def _error_response(self, piece, reason: str):
        """A response marked as a real ERROR (not ordinary text), so the attack
        engine stops and the run is not scored as a clean turn. Best-effort across
        PyRIT versions: set the error type where the constructor accepts it, and
        always leave `self._fatal` as the driver-side structured signal."""
        try:
            return construct_response_from_request(
                request=piece, response_text_pieces=[f"[ABORTED] {reason}"],
                response_type="error")
        except TypeError:
            msg = construct_response_from_request(
                request=piece, response_text_pieces=[f"[ABORTED] {reason}"])
            for p in getattr(msg, "message_pieces", []):
                try:
                    p.response_error = "unknown"
                except Exception:  # noqa: BLE001
                    pass
            return msg

    def _validate_request(self, *, normalized_conversation: list[Message]) -> None:
        pieces = normalized_conversation[-1].message_pieces
        if len(pieces) != 1:
            raise ValueError("ProxyTarget only supports single-piece prompts")
        if pieces[0].converted_value_data_type != "text":
            raise ValueError("ProxyTarget only supports text prompts")


class BedrockTarget(PromptTarget):
    """PyRIT target that calls AWS Bedrock Converse API directly.

    Supports any model available through Bedrock (Claude, Llama, Mistral,
    etc.) using the unified Converse API.

    Requires: ``pip install airt-harness[bedrock]``
    """

    def __init__(
        self,
        *,
        model_id: str,
        region: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.6,
        max_requests_per_minute: Optional[int] = None,
    ):
        super().__init__(
            max_requests_per_minute=max_requests_per_minute,
            model_name=model_id,
        )
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

    async def _send_prompt_to_target_async(
        self, *, normalized_conversation: list[Message]
    ) -> list[Message]:
        piece = normalized_conversation[-1].message_pieces[0]
        prompt_text = piece.converted_value

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

        return [
            construct_response_from_request(
                request=piece,
                response_text_pieces=[str(answer)],
            )
        ]

    def _validate_request(self, *, normalized_conversation: list[Message]) -> None:
        pieces = normalized_conversation[-1].message_pieces
        if len(pieces) != 1:
            raise ValueError("BedrockTarget only supports single-piece prompts")
        if pieces[0].converted_value_data_type != "text":
            raise ValueError("BedrockTarget only supports text prompts")
