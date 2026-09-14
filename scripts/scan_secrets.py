#!/usr/bin/env python3
"""Shared secret / sensitive-content scanner for airt-harness.

ONE engine, TWO policies (reviewer correction #4 — share the code, not the policy):

  credentials  universal.  Credential-shaped patterns only. Safe to run over the
               WIP checkout (a pre-push credential gate) because it does NOT forbid
               the research catalogue, review evidence or course notes that WIP
               legitimately retains.
  export       the public-output policy.  credentials + deployment identifiers +
               forbidden research/course content.  Run over the CLEAN EXPORT
               CANDIDATE bytes, never over WIP history.

Diagnostics are value-free (reviewer correction #2): a hit reports rule id,
category, file and line — never the matched text — so scan logs never carry a
secret.

Rules are credential-SHAPED, not bare prefixes (reviewer correction #2): a literal
`fw_` rejected 15 ordinary firewall lines (`fw_kwargs`, `fw_result`), so the
credential rules require realistic length/charset with token boundaries. The
RunPod rule matches a resolved route id but NOT the `<RUNPOD_ENDPOINT_ID>`
placeholder.

  python3 scripts/scan_secrets.py --policy export PATH [PATH ...]
  python3 scripts/scan_secrets.py --policy credentials PATH ...    # WIP push gate
  # exit 0 = clean, 1 = hits, 2 = usage error. Importable: scan_paths(paths, policy).

The scanner is exercised against its own shipped source (reviewer: "exercise the
scanner against its own shipped source so its definitions do not reject the entire
tool"). Its rule-definition file necessarily contains the forbidden CONTENT tokens
as pattern text, so that ONE file is exempt from the `content` category only —
a narrow, documented exception. It is NOT exempt from credential/deployment rules
(those patterns do not self-match), so a real key pasted here is still caught.
"""
from __future__ import annotations
import argparse, os, re, sys
from dataclasses import dataclass

VERSION = "scan_secrets/1.0.0"


@dataclass(frozen=True)
class Rule:
    id: str
    category: str          # credential | deployment | content
    pattern: re.Pattern
    description: str


def _r(id, category, pat, desc, flags=0):
    return Rule(id, category, re.compile(pat, flags), desc)


# --- credential-shaped rules (universal) ---------------------------------------
# Length/charset + boundaries chosen so ordinary identifiers do not match.
CREDENTIAL_RULES = [
    _r("openai_key",     "credential", r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b",
       "OpenAI-style secret key"),
    _r("anthropic_key",  "credential", r"\bsk-ant-[A-Za-z0-9-]{20,}\b",
       "Anthropic API key"),
    _r("aws_access_key", "credential", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
       "AWS access key id"),
    _r("google_key",     "credential", r"\bAIza[0-9A-Za-z_-]{30,}\b",
       "Google API key"),
    _r("fireworks_key",  "credential", r"\bfw_[A-Za-z0-9]{20,}\b",
       "Fireworks API key (shaped; excludes fw_kwargs / fw_result)"),
    _r("jwt",            "credential", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b",
       "JWT"),
    _r("private_key",    "credential", r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----",
       "PEM private key block"),
]

# --- deployment identifiers (export policy) ------------------------------------
# The resolved RunPod route id; the <RUNPOD_ENDPOINT_ID> placeholder is NOT matched.
DEPLOYMENT_RULES = [
    _r("runpod_route",   "deployment", r"runpod\.ai/v2/[a-z0-9]{8,}/",
       "resolved RunPod endpoint route (private deployment id)"),
]

# --- forbidden research / course content (export policy) -----------------------
# The private-repo name is assembled from fragments so this shipped source does NOT
# carry the sensitive literal itself (it still matches the literal in scanned files).
_PRIVATE_REPO = "-".join(["airt", "eval", "private"])
CONTENT_RULES = [
    _r("private_repo",   "content", re.escape(_PRIVATE_REPO),
       "private research repository name"),
    _r("research_acronym", "content", r"\bDA(?:ME|SE)\b",
       "internal research-programme acronym (not a secret)"),
    _r("model_rankings", "content", r"\b\d{1,3}/70\b|best-first|CTF reliability|ordered best",
       "model ranking / results content"),
    _r("local_path",     "content", r"/Users/[A-Za-z0-9._-]+/",
       "developer local filesystem path"),
    # Research/course residue that is NOT credential- or ranking-shaped but must not
    # ship in the public export (reviewer E1). Targeted markers, not a general
    # fraction/term matcher — synthetic seed values and generic learner terms stay.
    _r("campaign_label", "content", r"\bPilot[- ]B\b",
       "internal campaign label"),
    _r("review_label",   "content", r"\bindependent review\b",
       "internal review-process label"),
    _r("course_module",  "content", r"\bModules? \d",
       "course module number"),
    _r("private_review_path", "content", r"reviews/review2|evals-to-review|remaining_detector_findings",
       "private review/corpus path"),
    _r("course_label",   "content", r"course-run|Opening on L\d|dropping to L\d",
       "course-run / teaching-sequence label"),
    _r("result_phrase",  "content",
       r"scored HIGHER|coaching is worth|across six models|excluded from the panel|"
       r"measured here|four-flags-for-one|\b\d{2,3}/\d{2,3} (?:on|against)\b|~\d{1,3}% of",
       "embedded evaluation result or interpretation"),
]

POLICIES = {
    "credentials": CREDENTIAL_RULES,
    "export": CREDENTIAL_RULES + DEPLOYMENT_RULES + CONTENT_RULES,
}

# Narrow, documented CONTENT-only exemptions:
#  - the scanner's own rule-definition file holds the forbidden tokens as pattern text;
#  - .dockerignore/.gitignore are exclusion-pattern LISTS that legitimately name the
#    excluded private dirs/files (reviews/, evals-to-review/, FINDINGS.md, ...).
# All three still get the credential/deployment rules (those patterns do not self-match).
_SELF = os.path.basename(__file__)
_CONTENT_EXEMPT = {_SELF, ".dockerignore", ".gitignore"}


def _exempt(rel_path: str, category: str) -> bool:
    return category == "content" and os.path.basename(rel_path) in _CONTENT_EXEMPT


TEXT_EXT = {".py", ".yaml", ".yml", ".md", ".txt", ".json", ".sh", ".cfg", ".ini",
            ".toml", ".sql", ".env", ".example", ".js", ".ts", ".html", ".css", ""}


def _is_texty(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in TEXT_EXT


def scan_text(text: str, policy: str, rel_path: str = ""):
    """Yield (rule_id, category, description, lineno) — never the matched value."""
    rules = POLICIES[policy]
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule in rules:
            if _exempt(rel_path, rule.category):
                continue
            if rule.pattern.search(line):
                yield (rule.id, rule.category, rule.description, lineno)


def _iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".venv")]
                for fn in files:
                    yield os.path.join(root, fn)
        else:
            yield p


def scan_paths(paths, policy, root: str | None = None):
    """Scan files/dirs. Returns list of dicts (value-free). Skips binary/unreadable."""
    hits = []
    for fp in _iter_files(paths):
        if not _is_texty(fp):
            continue
        rel = os.path.relpath(fp, root) if root else fp
        try:
            text = open(fp, "r", errors="strict").read()
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable — not a text secret carrier
        for rid, cat, desc, ln in scan_text(text, policy, rel):
            hits.append({"rule": rid, "category": cat, "file": rel, "line": ln,
                         "description": desc})
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="airt-harness secret/content scanner")
    ap.add_argument("--policy", choices=sorted(POLICIES), default="export")
    ap.add_argument("--root", default=None, help="report paths relative to this root")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()
    hits = scan_paths(a.paths, a.policy, a.root)
    print(f"{VERSION}  policy={a.policy}  scanned={len(list(_iter_files(a.paths)))} paths")
    if not hits:
        print("CLEAN — no matches for the listed patterns in the scanned set.")
        return 0
    print(f"{len(hits)} HIT(S) (rule/file/line only; matched values not shown):")
    for h in sorted(hits, key=lambda h: (h["file"], h["line"])):
        print(f"  {h['category']:10} {h['rule']:16} {h['file']}:{h['line']}  — {h['description']}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
