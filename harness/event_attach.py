"""Contract-aware trusted-event attachment .

The mock returns, in every /chat response, the tool events it actually executed.
ProxyTarget captures that `events` field per turn (see harness/pyrit.py); this
module joins the captured log to a run's SELECTED transcript so the authenticated
events travel ON the saved row — same-run, full-text, no historical audit join.

Pure and dependency-free on purpose (no PyRIT import), so both the run driver and
the tests use exactly the same join.

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""
from __future__ import annotations


def attach_trusted_events(transcript, events_log):
    """Attach a run's trusted tool events to its selected transcript.

    `events_log` is ProxyTarget.captured_events — every /chat turn's
    {prompt, response, events} in send order. It is keyed on (prompt, response),
    last-write-wins so a rewound-then-replayed turn resolves to its final
    execution, then the selected transcript is walked pairing each target reply
    with its preceding user turn.

    Returns (tool_events, companion). `tool_events` is None when NOT ONE turn
    could be matched (e.g. an errored run): the row then honestly carries no
    provenance rather than a fabricated empty one — the same "none ran" vs "not
    captured" distinction the resolver and judge draw.

    Capture is only what the producer genuinely delivered. A turn contributes to
    the pooled events ONLY when its `events` value is a real list — including an
    explicit [] (the model ran and called no tool: a complete, empty capture). A
    matched turn whose `events` is None (the formatter dropped it, or the turn
    short-circuited before tool capture) is treated as UNCAPTURED and must NOT be
    coerced to [] — coercing it turned a real VERIFIED_EFFECT into
    VERIFIED_NO_EFFECT at the resolver.
    """
    idx = {}
    for c in events_log or []:
        idx[(c.get("prompt") or "", c.get("response") or "")] = c.get("events")
    pooled, turn_map, captured, uncaptured = [], [], 0, 0
    pending_user = None
    for m in transcript:
        if m.get("role") == "user":
            pending_user = m.get("text", "")
        elif m.get("role") == "assistant":
            key = (pending_user or "", m.get("text", ""))
            evs = idx.get(key)
            if key in idx and isinstance(evs, list):   # genuinely delivered (incl. [])
                captured += 1
                pooled.extend(evs)
                turn_map.append({"n_events": len(evs)})
            else:                                       # absent turn, or events=None
                uncaptured += 1
                turn_map.append({"n_events": None})
            pending_user = None
    companion = {"captured_turns": captured, "uncaptured_turns": uncaptured,
                 "turn_map": turn_map, "source": "in-run capture"}
    return (pooled if captured else None), companion
