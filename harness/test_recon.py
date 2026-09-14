#!/usr/bin/env python3
"""Module-2 reconnaissance /capabilities endpoint — unit checks.

Read-only metadata, gated on the `recon` feature, tools sourced from the ACTIVE
profile (no profile-specific names in the harness), MCP accounted separately,
the LIVE model alias (not the legacy backend field). Run directly:

    python3 harness/test_recon.py
"""
import asyncio, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import mock

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  PASS {name}")
    else:
        failed += 1; print(f"  FAIL {name}")

def setup(features, current="gpt-4.1", mcp_client=None, mcp_configured=True,
          mcp_tools=None, profile="deepcyber-ctf"):
    mock._features = features
    mock._current_model = current
    mock._mcp_client = mcp_client
    mock._mcp_configured = mcp_configured
    mock._mcp_tools = mcp_tools or []
    mock.app_config["profile_name"] = profile

def run():
    return asyncio.run(mock.capabilities())

# 1. recon OFF -> 404 (disabled by default; a features dict WITHOUT recon must not serve it)
setup({"tools": {"available": [{"name": "search_documents"}]}})
r = run()
check("recon off -> 404", getattr(r, "status_code", 200) == 404)

# 2. recon ON -> tools sourced from the profile; live alias; MCP unconfirmed when not connected
setup({"recon": True, "tools": {"available": [
    {"name": "delete_account"}, {"name": "execute_code"},
    {"name": "search_documents"}, {"name": "issue_refund"}]}})
r = run()
check("recon on -> dict", isinstance(r, dict) and r.get("recon") is True)
check("tools from profile, sorted",
      r["tools"]["profile_declared"] == ["delete_account", "execute_code", "issue_refund", "search_documents"])
# teaching-list verification done here (test-side), against the profile-sourced list
TEACHING = {"search_documents", "issue_refund", "delete_account", "execute_code"}
check("teaching list matches profile source", set(r["tools"]["profile_declared"]) == TEACHING)
check("configured_model = live alias (not legacy backend)", r["configured_model"] == "gpt-4.1")
check("mcp unconfirmed when not connected",
      r["tools"]["mcp_supplied"] == [] and r["tools"]["mcp_status"].startswith("configured"))
check("read-only note present", "no tool was executed" in r["source"])

# 3. genericness: a DIFFERENT profile yields ITS tools; no Larkfield names hardcoded
setup({"recon": True, "tools": {"available": [{"name": "trade"}, {"name": "send_email"}]}},
      profile="deepvault-capital")
r = run()
check("generic: other profile's tools", r["tools"]["profile_declared"] == ["send_email", "trade"])
check("generic: no larkfield leak",
      "delete_account" not in r["tools"]["profile_declared"] and r["profile"] == "deepvault-capital")

# 4. MCP connected -> its tools listed as connected
setup({"recon": True, "tools": {"available": []}}, mcp_client=object(),
      mcp_tools=[{"name": "query"}, {"name": "reseed_database"}])
r = run()
check("mcp connected lists tools",
      r["tools"]["mcp_supplied"] == ["query", "reseed_database"] and r["tools"]["mcp_status"] == "connected")

# 5. no MCP configured at all -> not configured
setup({"recon": True, "tools": {"available": []}}, mcp_configured=False)
r = run()
check("mcp not configured", r["tools"]["mcp_status"] == "not configured")

print(f"\n{passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
