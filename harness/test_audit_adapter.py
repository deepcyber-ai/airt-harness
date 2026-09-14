"""Adapter tests vs Step-1 review S1-S6 + V2-1..V2-3, with mutation-resistant
assertions (must fail if prefix matching, all-associated, or dropped reasons return)."""
import json, tempfile, os, sys
from audit_adapter import AuditIndex, occurrence_summary, SourceError
from evidence import Evidence as E

def af(entries):
    fd,p=tempfile.mkstemp(suffix=".jsonl"); os.close(fd)
    open(p,"w").write("\n".join(json.dumps(e) for e in entries)+"\n"); return p
def entry(prompt,response,events,sid="s1",ts="2026-09-05T00:00:00",turn=1):
    return {"prompt":prompt,"response":response,"tool_events":events,"session_id":sid,"timestamp":ts,"turn":turn}
def ev(name,**r): return {"name":name,"result":json.dumps({"tool":name,**r})}
def tr(u,a): return [{"role":"user","text":u},{"role":"assistant","text":a}]
def occ(idx,tx,eff): return occurrence_summary(idx,tx,eff)   # (res, companion)

R=[]
def ck(label,cond): R.append((bool(cond),label))

# real trade -> VERIFIED_EFFECT
i=AuditIndex([af([entry("do it","ok",[ev("place_trade",amount=5000,rows_affected=1)])])])
res,_=occ(i,tr("do it","ok"),"trade_executed"); ck("real trade -> EFFECT", res.state is E.VERIFIED_EFFECT)
# S1 £0-only -> UNVERIFIED
i=AuditIndex([af([entry("do it","ok",[ev("place_trade",amount=0,rows_affected=1)])])])
res,_=occ(i,tr("do it","ok"),"trade_executed"); ck("S1 £0-only -> UNVERIFIED", res.state is E.UNVERIFIED)

# STRONGER V2/S2 #1: unique-positive disambiguation. Two entries share a 400-char
# prefix but differ in full captured text; the query full-matches ONLY the
# positive one. matches()==1 (fails if prefix matching restored) AND EFFECT.
pre="P"*410
i=AuditIndex([af([
  entry(pre+"AAA","R"+"y"*210+"AAA",[ev("place_trade",amount=5000,rows_affected=1)]),
  entry(pre+"BBB","R"+"y"*210+"BBB",[ev("place_trade",amount=0,rows_affected=1)]),
])])
ck("S2 full-text unique match count==1", len(i.matches(pre+"AAA","R"+"y"*210+"AAA"))==1)
res,_=occ(i,tr(pre+"AAA","R"+"y"*210+"AAA"),"trade_executed")
ck("S2 unique positive -> EFFECT", res.state is E.VERIFIED_EFFECT)

# STRONGER S4 #2: ambiguous positive rejection. Two entries with IDENTICAL full
# content, one positive -> matches()==2, AMBIGUOUS, positive NOT accepted ->
# UNVERIFIED (fails if candidates wrongly marked ASSOCIATED).
i=AuditIndex([af([
  entry("hi","g",[ev("place_trade",amount=5000,rows_affected=1)],sid="a"),
  entry("hi","g",[ev("place_trade",amount=0,rows_affected=1)],sid="b",ts="2026-09-06T00:00:00"),
])])
ck("S4 identical-content match count==2", len(i.matches("hi","g"))==2)
res,_=occ(i,tr("hi","g"),"trade_executed")
ck("S4 ambiguous positive -> UNVERIFIED", res.state is E.UNVERIFIED)

# STRONGER S3/V3-3 #3: cause preservation with a REAL malformed second turn.
# Turn 1 matches a unique positive; turn 2 matches a record whose tool_events is
# NOT a list. Pooled: positive is preserved (VERIFIED_EFFECT) AND the
# malformed_event_container diagnostic survives (fails if the reason is dropped),
# and BOTH matched turns appear in the companion turn_map with the right source
# hash/count (fails if the companion manifest/turn_map is emptied).
pos_e=entry("q1","a1",[ev("place_trade",amount=5000,rows_affected=1)])
mal_e={"prompt":"q2","response":"a2","tool_events":"NOTALIST","session_id":"m","timestamp":"t","turn":2}
i2=AuditIndex([af([pos_e,mal_e])])
tx4=[{"role":"user","text":"q1"},{"role":"assistant","text":"a1"},
     {"role":"user","text":"q2"},{"role":"assistant","text":"a2"}]
res,comp=occ(i2,tx4,"trade_executed")
ck("V3-3 positive preserved beside malformed turn -> EFFECT", res.state is E.VERIFIED_EFFECT)
ck("V3-3 malformed_event_container diagnostic survives", "malformed_event_container" in res.context.get("turn_reasons",[]))
ck("V3-3 companion carries turn_map + source manifest, PARTIAL",
   "turn_map" in comp and "source_manifest" in comp and comp["coverage"]=="PARTIAL")
_matched=[t for t in comp["turn_map"] if t.get("n_matches")==1]
ck("V3-3 both matched turns mapped (fails if turn_map emptied)", len(_matched)==2)
_srcs=comp["source_manifest"]["sources"]
ck("V3-3 source manifest non-empty with sha+count (fails if emptied)",
   len(_srcs)==1 and all(len(s["sha256"])==64 and s["records"]==2 for s in _srcs.values()))

# V3-1: an assistant turn whose PROSE quotes the capture marker must STILL match
# its uniquely authenticated trade -> VERIFIED_EFFECT (fails if prose skips match).
_a='trade complete. (log said "[transcript unavailable]" earlier)'
i=AuditIndex([af([entry("do it",_a,[ev("place_trade",amount=5000,rows_affected=1)])])])
res,_=occ(i,tr("do it",_a),"trade_executed")
ck("V3-1 prose quoting marker still -> EFFECT", res.state is E.VERIFIED_EFFECT)
# v4 qualification: a quoted marker is labelled distinctly, NOT as a genuine
# producer capture_note (fails if the two are conflated again).
_tr=res.context.get("turn_reasons",[])
ck("V4 prose marker -> prose_capture_marker not capture_note",
   "prose_capture_marker" in _tr and "capture_note" not in _tr)
# a genuine producer role=note entry IS a capture note (skipped), positive from a
# real adjacent turn is still preserved.
i=AuditIndex([af([entry("do it","ok",[ev("place_trade",amount=5000,rows_affected=1)])])])
tx_note=[{"role":"note","text":"[transcript unavailable: exporter error]"},
         {"role":"user","text":"do it"},{"role":"assistant","text":"ok"}]
res,comp=occ(i,tx_note,"trade_executed")
ck("V3-1 role=note preserves adjacent positive -> EFFECT", res.state is E.VERIFIED_EFFECT)
ck("V3-1 role=note recorded as capture_note", "capture_note" in res.context.get("turn_reasons",[]))

# V3-2: an optional competitor sharing the same captured pair.
_reqf=af([entry("hi","g",[ev("place_trade",amount=5000,rows_affected=1)])])
_optvalid=af([entry("hi","g",[ev("place_trade",amount=0,rows_affected=1)])])
i=AuditIndex([_reqf],[_optvalid])
res,_=occ(i,tr("hi","g"),"trade_executed")
ck("V3-2 both valid competitors -> UNVERIFIED (ambiguous)", res.state is E.UNVERIFIED)
# corrupt the optional competitor: it is quarantined, uniqueness is qualified,
# and the SURVIVING single hit must NOT be certified a verified positive.
fd,_optbad=tempfile.mkstemp(suffix=".jsonl"); os.close(fd)
open(_optbad,"w").write("{ not json corrupt competitor\n")
i=AuditIndex([_reqf],[_optbad])
ck("V3-2 corrupted optional -> uniqueness_qualified", i.uniqueness_qualified)
res,comp=occ(i,tr("hi","g"),"trade_executed")
ck("V3-2 corrupted optional does NOT manufacture EFFECT", res.state is E.UNVERIFIED)
ck("V3-2 uniqueness_qualified surfaced in reason", "uniqueness_qualified" in res.context.get("turn_reasons",[]))
ck("V3-2 quarantine cause+location recorded",
   any("malformed JSON" in n for s in comp["source_manifest"]["sources"].values()
       for n in s.get("quarantine_notes",[])))

# V2-1: missing/null/wrong-type prompt is NOT authenticated empty text.
# A required source containing such a record fails to load (fail-closed).
try:
    AuditIndex([af([{"response":"ok","tool_events":[ev("place_trade",amount=5000,rows_affected=1)]}])]); ok=False
except SourceError: ok=True
ck("V2-1 required record missing string prompt -> SourceError", ok)
# and an empty-string user query does not borrow a positive from such a record
i=AuditIndex([af([entry("real prompt","ok",[ev("place_trade",amount=5000,rows_affected=1)])])])
ck("V2-1 empty query does not match a real record", i.matches("","")==[])

# V2-1 exact matching: whitespace-differing query does NOT match
i=AuditIndex([af([entry('client "A  B"',"ok",[ev("place_trade",amount=5000,rows_affected=1)])])])
ck("V2-1 whitespace-differing query -> no match", i.matches('client "A B"',"ok")==[])

# V2-2: malformed JSON line in a REQUIRED source -> raises
fd,p=tempfile.mkstemp(suffix=".jsonl"); os.close(fd)
open(p,"w").write(json.dumps(entry("do it","ok",[]))+"\n{ not json\n")
try:
    AuditIndex([p]); ok=False
except SourceError: ok=True
ck("V2-2 malformed required line -> SourceError", ok)

passed=sum(1 for x in R if x[0])
for ok,l in R:
    if not ok: print(f"  FAIL {l}")
print(f"\naudit adapter v3: {passed}/{len(R)} passed")
sys.exit(0 if passed==len(R) else 1)
