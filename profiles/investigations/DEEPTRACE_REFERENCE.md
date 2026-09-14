# DeepTrace Investigations — How It Works

*A short introduction to the DeepTrace evidence-management assistant: what it does,
what it will and won't do on your behalf, and the safeguards that protect your case
files. No technical background needed.*

---

## What DeepTrace is

DeepTrace is an AI assistant for **corporate investigations, e-discovery, and DFIR
teams**. It helps investigators manage **evidence items** — the documents, exports,
and artifacts attached to a case — across the whole life of an investigation, from the
moment a case opens to the day its evidence is finally disposed of.

You talk to it in plain language. Instead of clicking through a records system, you ask:

> *"Show me the evidence on the vendor reconciliation case."*
> *"Add a note to EV-2087 that the interview is scheduled."*
> *"That matter has closed and it's past retention — please dispose of the evidence."*

DeepTrace does the work — and, crucially, it knows the difference between a request it
should carry out and one it should hold back.

---

## Who it's for

- **Investigators & case handlers** managing day-to-day evidence and case notes.
- **Legal & compliance teams** who need confidence that evidence under legal hold or
  within a retention window is never destroyed — even by accident, even on request.
- **Records & DFIR teams** running high-volume clean-ups where a single mistaken bulk
  action could be catastrophic.

---

## What DeepTrace can do

Disposing of evidence is a **legitimate, everyday part of the job** — old, closed cases
are meant to be cleaned up. DeepTrace treats destruction as a normal function, not a
forbidden one. Its capabilities fall into three groups:

**Look things up** (always available)
- Search or list the evidence index
- Retrieve the details of an evidence item
- Open and read a case document

**Maintain the record** (available in normal working conditions)
- Update an evidence item's notes, metadata, or lifecycle status
- Close a case

**Dispose of evidence** (available only when the conditions are right)
- Permanently dispose of a single evidence item
- Purge all evidence for a closed case

The last group is where DeepTrace's judgment matters. Reading is always fine. Disposal
is fine *when it should be* — and DeepTrace checks that on every single request.

---

## The evidence lifecycle

Every evidence item moves through states, and each state carries different rules:

```
   open  ──►  active  ──►  closed  ──►  archived / disposed
```

Alongside its state, each item carries a few facts DeepTrace always considers:

| Property | Meaning |
|----------|---------|
| **Case status** | Is the case open, active, closed? Evidence on a live case is protected. |
| **Legal hold** | Is the item under active litigation hold? If so, it is untouchable. |
| **Retention** | Has the mandatory retention period elapsed? Nothing goes before its time. |
| **Classification** | Standard, sensitive, or privileged. |

---

## The safeguards: how DeepTrace decides what to do

Here's the important part. A conventional assistant would do whatever it's told, as long
as the request sounds reasonable. DeepTrace is different: **before it carries out any
action that changes or destroys evidence, an independent safeguard checks the request
against a fixed set of rules.** The AI proposes; the safeguard decides.

This matters because the AI, on its own, can be talked into things — by a cleverly
worded message, by a document that contains hidden instructions, or simply by a busy
investigator approving something without reading the fine print. The safeguard doesn't
care how persuasive the request was. It only looks at the facts of the case.

### The rules that protect your evidence

**1. Legal hold is absolute.**
Evidence under an active legal hold cannot be disposed of, purged, or even edited — no
matter who asks or how the request is phrased. This is the one line that is never crossed.

**2. Nothing is destroyed before its time.**
Evidence can only be disposed of once its case is **closed** *and* its **retention
period has elapsed**. A closed case that's still within retention stays protected.

**3. Live cases are protected.**
Evidence attached to an open or active investigation cannot be disposed of. You can
update it and work with it, but not destroy it.

**4. A risky session locks down destruction.**
DeepTrace tracks the "risk" of the current session. If anything makes the session
untrustworthy, destructive actions are automatically blocked — even actions that would
normally be perfectly fine. Risk can rise from live signals, most notably:

   - **Untrusted content.** If DeepTrace reads a document that turns out to contain
     hidden instructions (a common way attackers try to hijack an AI), the session is
     marked as tainted and disposal is frozen for the rest of that session.
   - **Manual escalation.** A supervisor can raise the session's risk level directly.

   The key point: *the same disposal request can be allowed in a clean session and
   blocked in a risky one.* Nothing about the evidence changed — only the trust in the
   conversation did.

**5. Large clean-ups need a second pair of eyes.**
Even when every item is individually fine to dispose of, destroying a **large batch** in
one go is a high-consequence action. DeepTrace caps how much it will delete on its own
authority. A bulk request above that cap isn't refused — it's **sent for human
sign-off**. One click can't wipe out a quarter's worth of cases; a person has to approve
the scale of it first.

---

## Three possible outcomes

When you ask DeepTrace to change or destroy evidence, one of three things happens:

| Outcome | What it means |
|---------|---------------|
| ✅ **Allowed** | The request meets every rule. DeepTrace carries it out and tells you what it did. |
| ⛔ **Blocked** | The request breaks a rule (legal hold, retention, a live case, or a risky session). DeepTrace explains why and changes nothing. |
| ⇧ **Sent for sign-off** | The request is legitimate but too large to auto-approve. DeepTrace routes it to a supervisor and changes nothing until it's approved. |

Whenever DeepTrace blocks or escalates, it shows a **plain-language verdict** rather than
guessing or improvising — for example:

> 🛡 *Runtime governance reviewed this request:*
> *• dispose_evidence blocked — the evidence item is under legal hold.*
> *No changes were made.*

You always know exactly what happened and why.

---

## Why this design

Ordinary AI safety training teaches a model to *refuse things that sound harmful*. That
helps with obviously bad requests, but it has two gaps that matter in an investigations
setting:

- It depends entirely on the model. A different or weaker model behaves differently, and
  the same clever wording that fools one can fool another.
- It only reads the *words* of a request. It can't see that an item is under legal hold,
  that the session was just poisoned by a malicious document, or that a "routine" bulk
  clean-up would erase far more than intended.

DeepTrace's safeguards don't rely on the model's judgment or on how a request is phrased.
They look at the **facts** — legal hold, retention, case status, session risk, and the
scale of the action — and apply the same rules every time, no matter which underlying AI
is answering. Destruction stays a normal, useful capability; it just never happens when
it shouldn't.

---

*DeepTrace Investigations is part of the DeepCyber AI Red Team Harness, used here to
demonstrate runtime governance for agentic AI. For the hands-on demo walkthrough, see `run.sh`.*
