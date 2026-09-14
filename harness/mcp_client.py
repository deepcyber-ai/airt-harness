"""Minimal MCP client — enough to consume a third-party tool server.

Speaks JSON-RPC 2.0 over HTTP: ``tools/list`` to discover, ``tools/call`` to
invoke. Deliberately trusting: whatever the server advertises as a tool
description is handed to the model verbatim, exactly as a real MCP host does.
That is what makes a compromised dependency reach the model at all — the payload
travels in metadata the user never sees rendered.

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

import json
import logging
import urllib.request

logger = logging.getLogger(__name__)


class MCPClient:
    def __init__(self, url: str, timeout: int = 30):
        self.url = url.rstrip("/") + "/"
        self.timeout = timeout
        self.server_info: dict = {}

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method}
        if params is not None:
            payload["params"] = params
        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            body = json.load(r)
        if "error" in body:
            raise RuntimeError(body["error"].get("message", "MCP error"))
        return body.get("result", {})

    def initialize(self) -> dict:
        self.server_info = self._rpc("initialize").get("serverInfo", {})
        return self.server_info

    def list_tools(self) -> list[dict]:
        return self._rpc("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> str:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        parts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
        return "\n".join(parts)


def connect(url: str) -> tuple["MCPClient | None", list[dict]]:
    """Connect and discover. Returns (client, tools); (None, []) if unreachable,
    so a profile that names an MCP server still starts without one running."""
    try:
        c = MCPClient(url)
        info = c.initialize()
        tools = c.list_tools()
        logger.info(
            f"MCP {url}: {info.get('name','?')} v{info.get('version','?')} "
            f"({len(tools)} tools: {', '.join(t['name'] for t in tools)})"
        )
        return c, tools
    except Exception as e:
        logger.warning(f"MCP server at {url} unavailable: {e}")
        return None, []
