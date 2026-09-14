"""Content-risk detectors for the AIRT Harness governance rung.

`detect_hidden_injection` scans *ingested* document content (retrieved by a tool
such as read_document) for indirect prompt injection hidden from a human reader:
HTML comments, invisible CSS (display:none, white-on-white, 0-size, off-screen),
and zero-width characters carrying imperative instructions.

The detector does not need to be perfect. In the governance model it does not
block anything itself — it raises the session risk signal, and the deterministic
Cedar policy refuses the dangerous tool call. Defense in depth.

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Imperative phrases that have no business living in an invisible channel.
_INJECTION_PHRASES = [
    "ignore previous", "ignore all previous", "ignore your instructions",
    "disregard", "you are now", "new instructions", "system:",
    "delete all", "delete every", "purge all", "drop table", "drop database",
    "remove all files", "wipe", "exfiltrate", "send all", "override",
    "without confirmation", "do not ask", "bypass",
    # Procedural-sounding but destructive imperatives — the "not a jailbreak"
    # injection: legitimate wording, catastrophic effect.
    "dispose of all", "dispose all", "dispose of every", "purge the case",
    "purge all cases", "no further review", "proceed without",
]

_ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿"]

# CSS that renders text invisible to a human but not to the model.
_INVISIBLE_STYLE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|"
    r"font-size\s*:\s*0|color\s*:\s*#?(fff(fff)?|white)|"
    r"left\s*:\s*-\d{3,}px|text-indent\s*:\s*-\d{3,}px)",
    re.IGNORECASE,
)

_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_STYLED_ELEMENT = re.compile(r'<[^>]*style\s*=\s*"([^"]*)"[^>]*>(.*?)</[^>]+>', re.IGNORECASE | re.DOTALL)


@dataclass
class DetectionResult:
    detected: bool
    reason: str
    hidden_text: str = ""
    hostile: bool = False  # Tier 2: concealed text matches a destructive-imperative denylist

    def __bool__(self) -> bool:  # allow `if detect_hidden_injection(...):`
        return self.detected


def _has_injection_phrase(text: str) -> bool:
    low = text.lower()
    return any(phrase in low for phrase in _INJECTION_PHRASES)


def _is_substantive(text: str) -> bool:
    """Enough natural-language words to be prose/instructions, not markup noise
    (so ordinary comments like `<!-- nav -->` don't fire)."""
    return len(re.findall(r"[A-Za-z]{2,}", text)) >= 5


def detect_hidden_injection(content: str) -> DetectionResult:
    """Deterministic, two-tier detection of concealed content in an ingested document.

    Tier 1 (detected, hostile=False): a concealment technique wraps substantive text.
    Tier 2 (detected, hostile=True):  that concealed text also matches a destructive-
                                      imperative denylist.
    The tier drives the upstream outcome (benign -> escalate, hostile -> deny). No model
    or classifier is in the path — only deterministic parsing and a fixed denylist.
    """
    if not content:
        return DetectionResult(False, "empty content")

    blocks: list[tuple[str, str]] = []  # (technique, concealed_text)

    # 1) Zero-width characters embedded in the text.
    if any(zw in content for zw in _ZERO_WIDTH):
        blocks.append(("zero-width characters", ""))

    # 2) Substantive text hidden inside HTML comments.
    for comment in _HTML_COMMENT.findall(content):
        if _is_substantive(comment):
            blocks.append(("HTML comment", comment.strip()))

    # 3) Substantive text inside invisible / off-screen styled elements.
    for style, inner in _STYLED_ELEMENT.findall(content):
        if _INVISIBLE_STYLE.search(style):
            text = re.sub(r"<[^>]+>", "", inner).strip()
            if _is_substantive(text):
                blocks.append((f"invisible CSS ({style.strip()[:32]})", text))

    if not blocks:
        return DetectionResult(False, "no concealed content found")

    hostile = any(_has_injection_phrase(text) for _, text in blocks)
    technique, sample = blocks[0]
    tag = ("matches a destructive-imperative denylist"
           if hostile else "no known-destructive payload")
    return DetectionResult(True, f"concealed content via {technique} — {tag}",
                           sample[:200], hostile=hostile)
