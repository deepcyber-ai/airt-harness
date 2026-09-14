// DeepTrace Investigations — runtime authorization policy (Cedar).
//
// The agent manages evidence items through the investigation lifecycle
// (open -> active -> closed -> archived) and updates their metadata. Disposing
// and updating evidence are LEGITIMATE functions; this policy governs *when*,
// based on lifecycle state, legal hold, retention, and session risk.
// Deny-by-default: no matching permit => blocked.
//
// Tool -> Action (PascalCase of the tool name):
//   search_evidence -> SearchEvidence   get_evidence   -> GetEvidence
//   export_evidence -> ExportEvidence   read_document  -> ReadDocument
//   update_evidence -> UpdateEvidence   close_case     -> CloseCase
//   dispose_evidence-> DisposeEvidence  purge_case     -> PurgeCase

// --- Reads: always permitted -------------------------------------------
permit(principal, action == Action::"SearchEvidence", resource);
permit(principal, action == Action::"GetEvidence", resource);
permit(principal, action == Action::"ExportEvidence", resource);
permit(principal, action == Action::"ReadDocument", resource);

// --- Updating evidence (notes, lifecycle transitions) ------------------
// Legitimate day-to-day work for an investigator at acceptable risk — but
// never on evidence under legal hold (that would be tampering).
permit(
  principal,
  action == Action::"UpdateEvidence",
  resource
)
when {
  context.role == "investigator" &&
  context.legal_hold == false
};

// --- Disposal: only closed cases, no hold, retention elapsed, low risk --
permit(
  principal,
  action == Action::"DisposeEvidence",
  resource
)
when {
  context.role == "investigator" &&
  context.legal_hold == false &&
  context.case_status == "closed" &&
  context.retention_days_remaining <= 0
};

permit(
  principal,
  action == Action::"PurgeCase",
  resource
)
when {
  context.role == "investigator" &&
  context.legal_hold == false &&
  context.case_status == "closed" &&
  context.retention_days_remaining <= 0
};

// ═══ STATIC RULES — defense in depth (a backend can enforce these too) ═══
// Warm-up: unambiguous, per-item invariants. A records store could enforce them
// too — we enforce them here as well so no single control is a lone point of
// failure. "Never destroy evidence under legal hold" is too important for one gate.
forbid(principal, action == Action::"DisposeEvidence", resource) when { context.legal_hold == true };
forbid(principal, action == Action::"PurgeCase", resource) when { context.legal_hold == true };
forbid(principal, action == Action::"UpdateEvidence", resource) when { context.legal_hold == true };
// (case_status and retention_days_remaining are checked in the permit clauses above.)

// ═══ DYNAMIC RULE — session risk DENY threshold (RUNTIME-ONLY) ═══════════
// The control no backend can express. A hard risk cutoff: at or above the deny
// threshold, destructive actions are refused outright (this is the GUI slider at 70).
// SOFTER signals below this threshold — an elevated-but-not-critical risk band, or
// provenance taint from concealed content ingested this session — do NOT deny here;
// they route to a human via ESCALATION in the agent's runtime loop
// ADR-0001). DENY = definitively disallowed; ESCALATE = ambiguous, a human should judge.
forbid(principal, action == Action::"DisposeEvidence", resource) when { context.session_risk >= 70 };
forbid(principal, action == Action::"PurgeCase", resource) when { context.session_risk >= 70 };
forbid(principal, action == Action::"UpdateEvidence", resource) when { context.session_risk >= 70 };
