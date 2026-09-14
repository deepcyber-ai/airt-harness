"""HumanBound Firewall integration for the AIRT Harness.

Optional input screening layer that evaluates messages before they reach
the target.  Disabled by default — enable at runtime via the ``/firewall``
endpoint or in profile.yaml.

The firewall module is lazy-loaded: ``hb-firewall`` is only imported when
the firewall is first enabled.

Profile config (all fields optional)::

    firewall:
      enabled: false                          # default off
      agent_config: "hb-firewall/agent.yaml"  # HB security policy
      model_path: null                        # Tier 2 model (optional)

Runtime toggle::

    curl -X POST http://localhost:8000/firewall -d '{"enabled": true}'
    curl -X POST http://localhost:8000/firewall -d '{"enabled": false}'
    curl -X POST http://localhost:8000/firewall   # toggle

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

from typing import Any, Optional


DEFAULT_DETECTOR = "protectai/deberta-v3-base-prompt-injection-v2"


def load_firewall(
    agent_config: str = "hb-firewall/agent.yaml",
    model_path: Optional[str] = None,
    judge_model: Optional[str] = None,
) -> Any:
    """Load an HB Firewall instance from config.

    Args:
        agent_config: Path to the HB Firewall agent YAML policy.
        model_path:   Path to an optional Tier 2 model file (.hbfw).
        judge_model:  OpenAI model for the Tier 3 judge, e.g. ``gpt-4o-mini``.
                      Without one, Tier 3 cannot run: anything Tier 1 and 2
                      do not settle comes back ``REVIEW`` / "No LLM judge
                      configured" with ``blocked=False``. That is *unadjudicated*
                      rather than allowed, and reading it as allowed understates
                      the firewall — Tier 1 alone can miss probes that Tier 3 blocks.

    Returns:
        An HB Firewall instance.

    Raises:
        ImportError: if hb-firewall is not installed.
    """
    try:
        from hb_firewall import Firewall
    except ImportError:
        raise ImportError(
            "hb-firewall is required for firewall integration. "
            "Install it with: pip install hb-firewall"
        )

    import os

    # hb-firewall 0.1.0 takes ``attack_detectors``, a LIST. This was
    # ``attack_detector`` singular, which raises TypeError before the firewall
    # is ever built — so /firewall had never successfully enabled.
    fw_kwargs: dict[str, Any] = {
        "attack_detectors": [{"model": DEFAULT_DETECTOR}],
    }

    if model_path and os.path.exists(model_path):
        fw_kwargs["model_path"] = model_path

    if judge_model:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "judge_model was requested but OPENAI_API_KEY is unset, so "
                "Tier 3 would silently return REVIEW for everything it saw. "
                "Set the key or drop judge_model.")
        from hb_firewall import Provider, ProviderName, ProviderIntegration
        fw_kwargs["provider"] = Provider(
            name=ProviderName.OPENAI,
            integration=ProviderIntegration(api_key=api_key, model=judge_model),
        )

    return Firewall.from_config(agent_config, **fw_kwargs)


def evaluate_message(firewall: Any, message: str) -> dict[str, Any]:
    """Evaluate a single message against the firewall.

    Returns:
        Dict with keys: blocked, tier, verdict, explanation, attack_probability
    """
    result = firewall.evaluate([{"role": "user", "content": message}])

    return {
        "blocked": bool(result.blocked),
        "tier": getattr(result, "tier", "unknown"),
        "verdict": getattr(result, "verdict", "unknown"),
        "explanation": str(getattr(result, "explanation", ""))[:500],
        "attack_probability": getattr(result, "attack_probability", None),
    }


def build_blocked_response(
    session_id: str, fw_result: dict[str, Any]
) -> dict:
    """Build a standard harness response for a firewall-blocked request.

    The response shape matches the canonical /chat response so clients
    see a consistent format regardless of whether the firewall blocked
    or the target responded.
    """
    explanation = fw_result.get("explanation", "Request blocked by firewall.")
    answer = (
        "I'm sorry, I can't help with that request. "
        "Please rephrase your question."
    )

    return {
        "session_id": session_id,
        "answer": answer,
        "message": answer,
        "content": answer,
        "raw": {
            "firewall": {
                "blocked": True,
                "tier": fw_result.get("tier", "unknown"),
                "verdict": fw_result.get("verdict", "unknown"),
                "explanation": explanation,
                "attack_probability": fw_result.get("attack_probability"),
            },
            "events": [
                {
                    "guardrail_type": "inbound",
                    "name": "hb_firewall",
                    "triggered": True,
                    "tier": fw_result.get("tier", "unknown"),
                    "verdict": fw_result.get("verdict", "unknown"),
                    "reason": explanation,
                    "type": "FirewallEvent",
                },
            ],
        },
    }
