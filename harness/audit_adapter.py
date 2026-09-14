"""Historical audit source-adapter for the shared evidence resolver.

The resolver (harness/evidence.py) is source-agnostic: a source adapter must
ESTABLISH coverage and association and hand it a TurnEvidence. This adapter does
that for historical rescoring, joining a saved result-row's turns to their
authenticated events in mock-audit.jsonl.

Scope, stated exactly (review S1/S5): a saved transcript is the objective-target
conversation only — a SELECTED SUBSET of the physical session. So this produces a
PROVISIONAL occurrence summary of the selected transcript, NOT whole-run coverage
and NOT E3 objective scoring. Coverage is declared PARTIAL: a real effect in the
selected transcript is a confirmed VERIFIED_EFFECT, but its ABSENCE is UNVERIFIED,
never a whole-run negative.

Join (review S2/V2-1): result rows carry no session id, so the join is by
CONTENT over the producer's captured text (2000 chars/field), compared EXACTLY —
no whitespace canonicalisation (that is a semantic guess) and no prefix. Only
records with PRESENT STRING prompt AND response are keyed; a missing/null/
wrong-type field is quarantined, not treated as authenticated empty text.

Completeness (review V2-2/S6): a REQUIRED source that has any undecodable byte,
malformed JSON line, or record lacking string prompt/response FAILS TO LOAD — a
discarded competitor could otherwise manufacture a false unique match. An optional
source that is ABSENT, partly quarantined, or otherwise incomplete is permitted
and reported, but it QUALIFIES uniqueness: a would-be-unique lone hit is then
demoted to AMBIGUOUS (a discarded competitor could exist), so its positive
resolves UNVERIFIED. This is NOT outcome-neutral — an absent optional source can
change a positive to UNVERIFIED.

Diagnostics (review V2-3): `occurrence_summary` returns a companion envelope with
the source manifest (per-source record counts + SHA-256), load/quarantine notes,
capture policy, and a per-turn candidate mapping — so an exported result carries
the evidence needed to distinguish otherwise-identical UNVERIFIED rows.

No prose is parsed; nothing unmatched/ambiguous is promoted; events carry whatever
the tool actually recorded (including old mis-parses).

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

import collections
import hashlib
from pathlib import Path

from evidence import (TurnEvidence, EventEvidence, Coverage, Assoc,
                      resolve_named, Evidence)

CAPTURE_CHARS = 2000        # the producer stores 2000 chars/field (harness/mock.py)
CAPTURE_POLICY = "exact-2000-char captured text; no whitespace canonicalisation"


class SourceError(Exception):
    """A required association source is corrupt/incomplete — fail closed."""


def _cap(s):
    """Exact captured text, truncated to the producer's capture limit. Returns
    None for a non-string value (a missing/invalid field, not empty text)."""
    if not isinstance(s, str):
        return None
    return s[:CAPTURE_CHARS]


class AuditIndex:
    def __init__(self, required_paths, optional_paths=()):
        self._idx = collections.defaultdict(list)
        self._n = 0
        self.sources = {}                 # path -> {records, sha256, quarantined}
        self.load_errors = []
        self.uniqueness_qualified = False  # True if an optional source was incomplete
        for p in required_paths:
            self._load(p, required=True)
        for p in optional_paths:
            self._load(p, required=False)

    def _load(self, path, required):
        p = Path(path)
        if not p.exists():
            if required:
                raise SourceError(f"required audit source missing: {p}")
            self.load_errors.append(f"optional missing: {p}")
            self.uniqueness_qualified = True
            return
        raw = p.read_bytes()
        rec = {"records": 0, "sha256": hashlib.sha256(raw).hexdigest(),
               "quarantined": 0, "quarantine_notes": []}
        self.sources[str(p)] = rec

        def _quarantine(lineno, cause):
            # An optional record we could not authenticate. Record its cause AND
            # location (review V3-2), and qualify uniqueness: a discarded
            # competitor could otherwise manufacture a false unique match.
            note = f"{p}:{lineno}: {cause}"
            rec["quarantined"] += 1
            rec["quarantine_notes"].append(note)
            self.load_errors.append(f"optional quarantine: {note}")
            self.uniqueness_qualified = True

        for lineno, bline in enumerate(raw.split(b"\n"), 1):
            if not bline.strip():
                continue
            try:
                line = bline.decode("utf-8")            # STRICT: no replacement
            except UnicodeDecodeError:
                if required:
                    raise SourceError(f"{p}:{lineno}: undecodable bytes in required source")
                _quarantine(lineno, "undecodable bytes"); continue
            import json as _json
            try:
                r = _json.loads(line)
            except ValueError:
                if required:
                    raise SourceError(f"{p}:{lineno}: malformed JSON in required source")
                _quarantine(lineno, "malformed JSON"); continue
            kp, kr = (_cap(r.get("prompt")), _cap(r.get("response"))) if isinstance(r, dict) else (None, None)
            if kp is None or kr is None:
                if required:
                    raise SourceError(f"{p}:{lineno}: record lacks string prompt/response")
                _quarantine(lineno, "record lacks string prompt/response"); continue
            self._idx[(kp, kr)].append(r)
            rec["records"] += 1
            self._n += 1

    def __len__(self):
        return self._n

    def matches(self, user_text, assistant_text):
        ku, ka = _cap(user_text), _cap(assistant_text)
        if ku is None or ka is None:
            return []
        return self._idx.get((ku, ka), [])

    def manifest(self):
        return {"sources": self.sources, "load_errors": self.load_errors,
                "capture_policy": CAPTURE_POLICY,
                "uniqueness_qualified": self.uniqueness_qualified,
                "total_records": self._n}


def _run_events(index, transcript):
    """Pool the run's authenticated events across its selected-transcript turns,
    plus a per-turn candidate mapping and the coverage reasons."""
    events, reasons, turn_map = [], set(), []
    idx = 0
    for i, m in enumerate(transcript or []):
        role = m.get("role")
        text = m.get("text") or ""
        if role == "note":
            # TRUSTED producer structure: a capture/extraction note is not a
            # transcript turn to match (review V3-1). Record it as a coverage
            # reason only.
            reasons.add("capture_note")
            turn_map.append({"turn": i, "kind": "capture_note", "text": text[:80]})
            continue
        if role != "assistant":
            continue
        # An assistant turn is ALWAYS matched, even if its PROSE quotes a capture
        # marker (review V3-1): that string is delivered content, not trusted
        # evidence of an exporter failure, and it must not erase independently
        # associated tool evidence. Label it DISTINCTLY from a genuine producer
        # note (review v4 qualification): a quoted marker is not a capture
        # failure, so it never gets `capture_note` — only role=="note" does.
        if "[transcript unavailable" in text:
            reasons.add("prose_capture_marker")
        user = transcript[i - 1]["text"] if i > 0 and transcript[i - 1].get("role") == "user" else ""
        hits = index.matches(user, text)
        tm = {"turn": i, "n_matches": len(hits),
              "refs": [f"{h.get('session_id','?')}@{h.get('timestamp','?')}#turn{h.get('turn','?')}" for h in hits]}
        turn_map.append(tm)
        if not hits:
            reasons.add("unmatched_turn"); continue
        # Association (review V3-2): a lone hit is ASSOCIATED only when the
        # candidate universe is COMPLETE. If an optional competitor was
        # quarantined (uniqueness_qualified), a discarded record could have been
        # a second candidate — so a single hit cannot be certified unique and is
        # AMBIGUOUS, preserving uncertainty (a positive from it -> UNVERIFIED).
        if len(hits) > 1:
            assoc = Assoc.AMBIGUOUS
            reasons.add("ambiguous_turn")
        elif index.uniqueness_qualified:
            assoc = Assoc.AMBIGUOUS
            reasons.add("uniqueness_qualified")
        else:
            assoc = Assoc.ASSOCIATED
        for h in hits:
            ref = f"{h.get('session_id','?')}@{h.get('timestamp','?')}#turn{h.get('turn','?')}"
            te = h.get("tool_events")
            if not isinstance(te, list):
                reasons.add("malformed_event_container")
                events.append(EventEvidence({"name": "?", "result": None}, idx, assoc, ref)); idx += 1
                continue
            for ev in te:
                events.append(EventEvidence(ev, idx, assoc, ref)); idx += 1
    return events, reasons, turn_map


def occurrence_summary(index, transcript, effect):
    """PROVISIONAL occurrence of `effect` across a run's SELECTED transcript.
    NOT E3 objective scoring, NOT whole-run coverage. Returns (Resolution,
    companion) where companion carries the source manifest and per-turn mapping."""
    # The association DOWNGRADE for a qualified source is enforced per-turn in
    # _run_events (review V3-2). This blanket reason only ensures the qualifier
    # is reported even for a run with no matched turns.
    reasons_extra = {"uniqueness_qualified"} if index.uniqueness_qualified else set()
    events, reasons, turn_map = _run_events(index, transcript)
    reasons |= reasons_extra
    reason = "selected_transcript_partial"
    if reasons:
        reason += "+" + "+".join(sorted(reasons))
    turn = TurnEvidence(events, Coverage.PARTIAL, reason, {"turn_reasons": sorted(reasons)})
    res = resolve_named(effect, turn)
    companion = {"source_manifest": index.manifest(), "turn_map": turn_map,
                 "coverage": "PARTIAL", "capture_policy": CAPTURE_POLICY}
    return res, companion
