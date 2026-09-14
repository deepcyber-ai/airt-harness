"""contract-aware trusted-event attachment.

No network. The mock already returns the trusted tool events it executed in each
/chat response; these assert the two halves that carry them onto the saved row:
ProxyTarget captures the `events` field per turn, and bakeoff.attach_trusted_events
joins them to the SELECTED transcript in-run and full-text — no historical audit
join — preserving the "none ran" vs "not captured" distinction the resolver and
judge depend on.
"""
import os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))      # the harness/ dir
ROOT = os.path.dirname(_HERE)
# Running this file directly puts harness/ on sys.path, which would make
# `import pyrit` inside harness/pyrit.py resolve to harness/pyrit.py itself (a
# shadow) and its guard would raise. Drop the script dir; keep only ROOT.
sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != _HERE]
sys.path.insert(0, ROOT)
# the pure join (no PyRIT) — the same function the run driver uses
from harness.event_attach import attach_trusted_events as _attach
from harness.mappers.example import create_mapper
import harness.evidence as EV                       # the signed resolver (§1)
import json as _json
# the capture side lives in harness.pyrit; import it while only ROOT is on the
# path, so `import pyrit` inside it resolves to the real package, not a shadow.
try:
    import harness.pyrit as PY
    _HAVE_PYRIT = True
except Exception as _e:                      # pragma: no cover - env without PyRIT
    PY, _HAVE_PYRIT = None, False
    print(f"  NOTE ProxyTarget capture checks skipped: {type(_e).__name__}")

class _B:
    attach_trusted_events = staticmethod(_attach)
B = _B()

R = []
def ck(label, cond): R.append((bool(cond), label))

DELETE_EV = {"type": "ToolCallEvent", "name": "delete_account", "arg": "id=LF-1",
             "result": "Account LF-1 deleted.", "restricted": True, "authorised": False}
QUERY_EV = {"type": "ToolCallEvent", "name": "query", "arg": "SELECT 1", "result": "{\"rows\":[[1]]}"}

# ── attach_trusted_events ────────────────────────────────────────────────
def turn(u, a): return [{"role": "user", "text": u}, {"role": "assistant", "text": a}]

# one captured turn with a real event
tr = turn("delete it", "Done.")
log = [{"prompt": "delete it", "response": "Done.", "events": [DELETE_EV]}]
ev, comp = B.attach_trusted_events(tr, log)
ck("captured turn attaches its trusted event", ev == [DELETE_EV])
ck("companion counts the captured turn", comp["captured_turns"] == 1 and comp["uncaptured_turns"] == 0)
ck("attached event keeps name+result (resolver-compatible)", ev[0]["name"] == "delete_account" and "result" in ev[0])

# a turn that ran but called no tool → captured, empty (NOT 'not captured')
tr = turn("hello", "Hi there.")
ev, comp = B.attach_trusted_events(tr, [{"prompt": "hello", "response": "Hi there.", "events": []}])
ck("turn with no tool → captured with zero events (not None)", ev == [] and comp["captured_turns"] == 1)
ck("companion turn_map records n_events 0 for a captured no-tool turn", comp["turn_map"][0]["n_events"] == 0)

# a reply that was never captured → uncaptured; whole row has no provenance
tr = turn("delete it", "Done.")
ev, comp = B.attach_trusted_events(tr, [])
ck("no capture at all → tool_events is None (not [])", ev is None)
ck("companion marks the reply uncaptured", comp["uncaptured_turns"] == 1 and comp["turn_map"][0]["n_events"] is None)

# multi-turn: order preserved, mixed captured/uncaptured
tr = turn("a", "A") + turn("b", "B") + turn("c", "C")
log = [{"prompt": "a", "response": "A", "events": [QUERY_EV]},
       {"prompt": "c", "response": "C", "events": [DELETE_EV]}]   # 'b' never captured
ev, comp = B.attach_trusted_events(tr, log)
ck("pooled events are in transcript order", ev == [QUERY_EV, DELETE_EV])
ck("mixed run: 2 captured, 1 uncaptured", comp["captured_turns"] == 2 and comp["uncaptured_turns"] == 1)

# rewound-then-replayed turn: last write wins on (prompt, response)
tr = turn("trade", "Placed.")
log = [{"prompt": "trade", "response": "Placed.", "events": []},                 # first (rewound)
       {"prompt": "trade", "response": "Placed.", "events": [DELETE_EV]}]        # replayed, final
ev, comp = B.attach_trusted_events(tr, log)
ck("last capture for a (prompt,response) wins (replayed turn)", ev == [DELETE_EV])

# B2: a MATCHED turn whose events value is None is NOT captured-empty — it is
# uncaptured, and must not be coerced to [] (that flipped the resolver's verdict).
tr = turn("delete it", "Done.")
ev, comp = B.attach_trusted_events(tr, [{"prompt": "delete it", "response": "Done.", "events": None}])
ck("events=None on a matched turn → uncaptured (not captured [])", ev is None)
ck("companion marks that turn uncaptured, not n_events 0", comp["uncaptured_turns"] == 1
   and comp["turn_map"][0]["n_events"] is None)

# ── B1: the ExampleMapper formatter PRESERVES the events field ────────────
mp = create_mapper({})
TRADE_EV = {"type": "ToolCallEvent", "name": "place_trade", "arg": "amount=5000",
            "result": _json.dumps({"rows_affected": 1, "amount": 5000.0})}
resp = mp.build_mock_response("Placed.", "s1", events=[TRADE_EV])
ck("mapper preserves a delivered events list", resp.get("events") == [TRADE_EV])
resp0 = mp.build_mock_response("Hi.", "s1", events=[])
ck("mapper preserves an explicit empty capture []", resp0.get("events") == [])
resp_none = mp.build_mock_response("Hi.", "s1")             # no events kwarg (short-circuit)
ck("mapper omits events when the turn was not captured", "events" not in resp_none)

# ── the reviewer's end-to-end chain: formatter → capture → attach → resolver ─
def _resolve(tool_events, present):
    return EV.resolve_named("trade_executed", EV.from_live(tool_events, present)).state.value
# a real trade delivered through the formatter must stay VERIFIED_EFFECT
pooled, _c = B.attach_trusted_events(turn("trade", "Placed."),
    [{"prompt": "trade", "response": "Placed.", "events": mp.build_mock_response("Placed.", "s", events=[TRADE_EV])["events"]}])
ck("delivered trade survives formatter→attach as a real event", pooled == [TRADE_EV])
ck("resolver sees VERIFIED_EFFECT for the delivered trade", _resolve(pooled, present=True) == "VERIFIED_EFFECT")
# the SAME turn with the events field dropped must NOT become VERIFIED_NO_EFFECT
dropped, _c = B.attach_trusted_events(turn("trade", "Placed."),
    [{"prompt": "trade", "response": "Placed.", "events": None}])
ck("dropped capture → tool_events None (no provenance on the row)", dropped is None)
ck("resolver returns UNVERIFIED for missing provenance (NOT VERIFIED_NO_EFFECT)",
   _resolve(dropped, present=(dropped is not None)) == "UNVERIFIED")

# ── ProxyTarget captures the response's events field (stubbed HTTP) ───────
class _Resp:
    def __init__(self, payload): self._p = payload
    def json(self): return self._p

if _HAVE_PYRIT:

    def _make_target(monkeypatched_post):
        # Bypass PyRIT's __init__ (it needs a CentralMemory instance we don't set
        # up for a unit test); _post only touches these three attributes.
        t = PY.ProxyTarget.__new__(PY.ProxyTarget)
        t._harness_url = "http://localhost:1"
        t._session_id = "s1"
        t._events_log = []
        t._fatal = None
        PY.requests.post = monkeypatched_post
        return t

    captured_args = {}
    def fake_post(url, json=None, headers=None, timeout=None):
        captured_args["events"] = [DELETE_EV]
        return _Resp({"output": "Done.", "session_id": "s1", "events": [DELETE_EV]})
    t = _make_target(fake_post)
    ans = t._post("delete it")
    ck("_post returns the reply text", ans == "Done.")
    ck("_post records the turn in captured_events", len(t.captured_events) == 1)
    ck("_post captured the trusted events field", t.captured_events[0]["events"] == [DELETE_EV])
    ck("_post recorded the sent prompt + response for keying",
       t.captured_events[0]["prompt"] == "delete it" and t.captured_events[0]["response"] == "Done.")

    # a mapper that emits NO events field → recorded as None (not captured), not []
    t2 = _make_target(lambda *a, **k: _Resp({"output": "Hi"}))
    t2._post("hello")
    ck("absent events field is recorded as None (distinct from [])", t2.captured_events[0]["events"] is None)

    # end to end: ProxyTarget capture feeds attach_trusted_events correctly
    t3 = _make_target(fake_post)
    t3._post("delete it")
    ev, comp = B.attach_trusted_events(turn("delete it", "Done."), t3.captured_events)
    ck("capture → attach delivers the trusted event onto the transcript", ev == [DELETE_EV])

passed = sum(1 for x in R if x[0])
for okk, l in R:
    if not okk: print(f"  FAIL {l}")
print(f"\nevent attachment (#1): {passed}/{len(R)} passed")
sys.exit(0 if passed == len(R) else 1)
