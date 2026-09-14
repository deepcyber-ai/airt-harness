"""Tiny dependency-free Cedar-subset evaluator (teaching stand-in).

Used when the Microsoft Agent Governance Toolkit (`agent_os`) is not installed,
so the governance rung runs offline. Understands just enough Cedar for the
records-ops policy: `permit`/`forbid`, `action == Action::"Name"` (or
unconstrained), and one `when { ... }` block of `context.<field> <op> <value>`
clauses joined by `&&`, ops `== != <= >= < >`.

Install `agent-governance-toolkit` and use engine="agent_os" for the real engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ACTION_RE = re.compile(r'action\s*==\s*Action::"([^"]+)"')
_WHEN_RE = re.compile(r"when\s*\{(.+?)\}", re.DOTALL)
_CLAUSE_RE = re.compile(r"context\.(\w+)\s*(==|!=|<=|>=|<|>)\s*(.+)")


@dataclass
class ShimDecision:
    allowed: bool
    reason: str
    matched_rule: str | None
    backend: str = "builtin-shim"


def _pascal_case(tool_name: str) -> str:
    return "".join(part.capitalize() for part in tool_name.split("_"))


def _parse_value(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw in ("true", "false"):
        return raw == "true"
    try:
        return int(raw)
    except ValueError:
        try:
            return float(raw)
        except ValueError:
            return raw


def _check(op: str, left: Any, right: Any) -> bool:
    try:
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op == "<=":
            return left <= right
        if op == ">=":
            return left >= right
        if op == "<":
            return left < right
        if op == ">":
            return left > right
    except TypeError:
        return False
    return False


@dataclass
class _Statement:
    effect: str
    action: str | None
    clauses: list[tuple[str, str, Any]]
    source: str


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def _parse_policies(text: str) -> list[_Statement]:
    text = _strip_comments(text)
    statements: list[_Statement] = []
    for chunk in text.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        low = chunk.lstrip()
        if low.startswith("permit"):
            effect = "permit"
        elif low.startswith("forbid"):
            effect = "forbid"
        else:
            continue

        action_match = _ACTION_RE.search(chunk)
        action = action_match.group(1) if action_match else None

        clauses: list[tuple[str, str, Any]] = []
        when_match = _WHEN_RE.search(chunk)
        if when_match:
            for clause in when_match.group(1).split("&&"):
                m = _CLAUSE_RE.search(clause.strip())
                if m:
                    field, op, raw_val = m.groups()
                    clauses.append((field, op, _parse_value(raw_val)))

        statements.append(_Statement(effect, action, clauses, f'{effect} {action or "*"}'))
    return statements


class ShimCedarEvaluator:
    def __init__(self, policy_path: str | Path):
        self._statements = _parse_policies(Path(policy_path).read_text())

    def _clauses_pass(self, clauses, context) -> bool:
        for field, op, expected in clauses:
            if field not in context:
                return False
            if not _check(op, context[field], expected):
                return False
        return True

    def _matches_action(self, stmt: _Statement, action: str) -> bool:
        return stmt.action is None or stmt.action == action

    def evaluate(self, context: dict[str, Any]) -> ShimDecision:
        tool_name = context.get("tool_name") or context.get("action", "")
        action = _pascal_case(tool_name) if ("_" in tool_name or tool_name.islower()) else tool_name

        for stmt in self._statements:
            if stmt.effect == "forbid" and self._matches_action(stmt, action) \
                    and self._clauses_pass(stmt.clauses, context):
                return ShimDecision(False, f"explicit forbid matched ({stmt.source})", stmt.source)

        for stmt in self._statements:
            if stmt.effect == "permit" and self._matches_action(stmt, action) \
                    and self._clauses_pass(stmt.clauses, context):
                return ShimDecision(True, f"permitted by policy ({stmt.source})", stmt.source)

        return ShimDecision(False, f"deny by default: no permit matched action {action!r}", None)
