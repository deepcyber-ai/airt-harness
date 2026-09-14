#!/usr/bin/env python3
"""larkfield-render — the intranet preview pane that renders assistant replies.

In the story this is the component that displays a support reply inside the
Larkfield intranet. It is where model output stops being text and becomes
something an interpreter acts on, which is what LLM05 Improper Output Handling
is actually about: not that a model produced dangerous-looking content, but that
a downstream component handled it without validation.

Two builds, identical from the model's point of view:

  --auto-fetch   resources referenced in the reply are fetched as the page is
                 rendered, which is what an image tag means in an HTML client
  (default)      references are recorded and NOT fetched

The model's output is byte-identical between them. Only the renderer differs, so
the demonstration measures the renderer rather than the model — and it reproduces
on every model, including ones that have not shipped yet.

**Preconditions.** Exfiltration by this route needs three things TOGETHER: data
placed in a URL, a client that fetches it without asking, and an egress policy
that permits the destination. A clickable link on its own produces no request.
Say all three in the brief; the technique is not unconditional.

Run:
    python3 server.py --port 8300 --collector http://localhost:8301 --auto-fetch
    python3 server.py --port 8302 --collector http://localhost:8301

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed. Synthetic data only.
"""

from __future__ import annotations

import argparse
import re
import urllib.parse
import urllib.request

from fastapi import FastAPI, Request

app = FastAPI()
_cfg: dict = {}

# Resource references a browser resolves on its own, without the reader doing
# anything. An anchor is deliberately excluded: a link is only followed when
# somebody clicks it, and conflating the two is how this technique gets
# overstated.
AUTO_RESOURCE = re.compile(
    r"""<(?:img|script|iframe|source|video|audio|embed|link)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']""",
    re.I,
)
MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*([^)\s]+)")


def _references(html: str) -> list[str]:
    """URLs a rendering client would resolve without being asked."""
    found = AUTO_RESOURCE.findall(html) + MARKDOWN_IMAGE.findall(html)
    return [u for u in found if u.lower().startswith(("http://", "https://"))]


@app.post("/render")
async def render(request: Request):
    """Render a reply. Reports every reference found, and which were fetched."""
    body = await request.json()
    html = body.get("html", "")
    refs = _references(html)
    fetched: list[str] = []

    if _cfg["auto_fetch"]:
        for url in refs:
            try:
                # Only loopback is reachable — the collector stands in for the
                # attacker's server. Nothing leaves the machine.
                host = urllib.parse.urlparse(url).hostname or ""
                if host not in ("localhost", "127.0.0.1"):
                    continue
                urllib.request.urlopen(url, timeout=3).read()
                fetched.append(url)
            except Exception:
                # A failed fetch still means the request was attempted, which is
                # the behaviour under test.
                fetched.append(url)

    return {"references": refs, "fetched": fetched, "auto_fetch": _cfg["auto_fetch"]}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "larkfield-render",
            "auto_fetch": _cfg["auto_fetch"]}


def main() -> None:
    ap = argparse.ArgumentParser(description="larkfield-render")
    ap.add_argument("--port", type=int, default=8300)
    ap.add_argument("--auto-fetch", action="store_true",
                    help="Fetch referenced resources while rendering (the vulnerable build)")
    args = ap.parse_args()
    _cfg.update({"auto_fetch": args.auto_fetch})

    import uvicorn
    mode = "AUTO-FETCH (vulnerable)" if args.auto_fetch else "no fetch (fixed)"
    print(f"larkfield-render on :{args.port}  [{mode}]")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
