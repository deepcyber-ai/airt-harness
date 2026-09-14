"""Runtime tool-call authorization for the AIRT Harness — the deterministic
governance rung on the protection ladder.

Every agentic tool call is evaluated against a Cedar policy *before* it executes,
using the Microsoft Agent Governance Toolkit (Agent OS `PolicyEvaluator`) when
installed, or a bundled Cedar-subset shim otherwise. The decision is:

  * deterministic  — independent of what the LLM decided,
  * deny-by-default — no matching `permit` means the call is blocked,
  * context-aware  — sees the resource's attributes (legal_hold, retention) and
    the live session risk (manual, or auto-escalated by a content detector).

This mirrors the optional, lazy-loaded pattern of ``firewall.py``. Enable it in a
profile::

    mock:
      governance:
        enabled: true
        policy: policy.cedar          # relative to the profile dir
        engine: shim                  # shim | agent_os
        resources: resources.yaml     # record_id -> attributes
        identity:
          role: records_admin
        default_session_risk: 20

Kept deliberately free of harness-internal imports so it can be lifted into a
standalone defensive SDK later with minimal changes.

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


@dataclass
class Decision:
    allowed: bool
    reason: str
    matched_rule: str | None
    backend: str
    context: dict[str, Any]


class CedarGovernor:
    """Loads a Cedar policy once and evaluates request contexts against it."""

    def __init__(self, policy_path: str | Path, engine: str = "shim"):
        self.policy_path = str(policy_path)
        self.backend = "unknown"
        self._evaluator = self._build(engine)

    def _build(self, engine: str):
        if engine == "agent_os":
            from agent_os.policies import PolicyEvaluator  # type: ignore

            evaluator = PolicyEvaluator()
            evaluator.load_cedar(policy_path=self.policy_path)
            self.backend = "agent_os.cedar"
            return evaluator
        from ._cedar_shim import ShimCedarEvaluator

        self.backend = "builtin-shim"
        return ShimCedarEvaluator(self.policy_path)

    def evaluate(self, context: dict[str, Any]) -> Decision:
        raw = self._evaluator.evaluate(context)
        allowed = getattr(raw, "allowed", None)
        if allowed is None:
            allowed = getattr(raw, "is_allowed", False)
        return Decision(
            allowed=bool(allowed),
            reason=getattr(raw, "reason", "") or "",
            matched_rule=getattr(raw, "matched_rule", None),
            backend=getattr(raw, "backend", self.backend) or self.backend,
            context=context,
        )


class ToolGovernor:
    """Wraps a CedarGovernor with resource resolution for the records-ops profile.

    Turns a tool call (name + argument) plus the session risk into a Cedar
    request by looking up the target record's attributes.
    """

    def __init__(
        self,
        policy_path: str | Path,
        resources: dict[str, dict] | None = None,
        engine: str = "shim",
        role: str = "records_admin",
    ):
        self.governor = CedarGovernor(policy_path, engine=engine)
        self.resources = resources or {}
        self.role = role

    # -- construction from a profile block -------------------------------
    @classmethod
    def from_profile(cls, gov_cfg: dict, profile_dir: str | Path) -> "ToolGovernor":
        base = Path(profile_dir)
        policy_path = base / gov_cfg.get("policy", "policy.cedar")
        resources: dict[str, dict] = {}
        res_rel = gov_cfg.get("resources")
        if res_rel and yaml is not None:
            res_path = base / res_rel
            if res_path.exists():
                resources = yaml.safe_load(res_path.read_text()) or {}
        identity = gov_cfg.get("identity", {})
        return cls(
            policy_path,
            resources=resources,
            engine=gov_cfg.get("engine", "shim"),
            role=identity.get("role", "records_admin"),
        )

    @property
    def backend(self) -> str:
        return self.governor.backend

    # -- resource attribute resolution -----------------------------------
    def _resolve_resource(self, tool_name: str, arg: str) -> dict[str, Any]:
        """Return the attributes Cedar needs for this call's target resource."""
        key = (arg or "").strip().strip("'\"")

        if key in self.resources:
            return dict(self.resources[key])

        # Bulk operations (purge a case / delete *): aggregate to worst case, so
        # the presence of ANY held, still-retained, or non-closed item blocks the
        # whole batch.
        is_bulk = tool_name in ("purge_case", "purge_records", "purge_evidence") \
            or not key or key.lower() in ("all", "*", "everything", "expired")
        if is_bulk and self.resources:
            vals = self.resources.values()
            return {
                "legal_hold": any(r.get("legal_hold", False) for r in vals),
                "retention_days_remaining": max(
                    (int(r.get("retention_days_remaining", 0)) for r in vals), default=0,
                ),
                "case_status": "active" if any(
                    r.get("case_status", "closed") not in ("closed", "archived") for r in vals
                ) else "closed",
                "classification": "batch",
            }

        # Unknown single resource: no attributes -> permit clauses can't be
        # satisfied -> deny by default. Safe.
        return {}

    def evaluate_tool_call(
        self,
        tool_name: str,
        arg: str,
        session_risk: int,
        extra_context: dict[str, Any] | None = None,
    ) -> Decision:
        attrs = self._resolve_resource(tool_name, arg)
        context = {
            "tool_name": tool_name,
            "agent_id": "investigations-agent",
            "role": self.role,
            "session_risk": int(session_risk),
            "resource": (arg or tool_name),
            # Provenance signal — defaulted so the Cedar clause always has a value.
            "untrusted_content_ingested": False,
            **attrs,
            **(extra_context or {}),
        }
        decision = self.governor.evaluate(context)
        if not decision.allowed:
            decision.reason = self._explain(tool_name, context)
        return decision

    @staticmethod
    def _explain(tool_name: str, ctx: dict[str, Any]) -> str:
        """Human-readable denial reason for the demo, inferred from the request
        context (mirrors the Cedar rule priority: hold > risk-deny > state). Soft
        signals (provenance, risk below the deny threshold) escalate rather than deny,
        so they are not reasons here — see the runtime escalation layer."""
        if ctx.get("legal_hold") is True:
            return "the evidence item is under legal hold"
        if int(ctx.get("session_risk", 0)) >= 70:
            return f"the session risk is elevated (risk={ctx.get('session_risk')})"
        if tool_name in ("dispose_evidence", "purge_case") and ctx.get("case_status") not in ("closed", "archived", None):
            return "the case is still open/active"
        if int(ctx.get("retention_days_remaining", 0)) > 0:
            return "the retention period has not elapsed"
        return "policy does not permit this action"
