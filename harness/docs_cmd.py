"""Open AIRT Harness documentation in the browser.

After ``pip install airt-harness``, run::

    airt-docs                   # README and quick start
    airt-docs replay            # Replay module docs
    airt-docs pyrit             # PyRIT integration
    airt-docs firewall          # HB Firewall docs
    airt-docs contributing      # Dev setup, smoke test, PyPI publishing
    airt-docs examples          # Example scripts
    airt-docs dame              # DAME/DASE integration guide

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

from __future__ import annotations

import sys
import webbrowser

REPO = "https://github.com/deepcyber-ai/airt-harness"

PAGES = {
    "":             REPO,
    "readme":       REPO,
    "replay":       f"{REPO}#replay",
    "pyrit":        f"{REPO}#pyrit-integration",
    "firewall":     f"{REPO}#hb-firewall",
    "mapper":       f"{REPO}#generic-mapper-yaml-only-no-python",
    "mappers":      f"{REPO}#message-mappers",
    "mock":         f"{REPO}#mock-server",
    "profiles":     f"{REPO}#project-profiles",
    "contributing": f"{REPO}/blob/main/CONTRIBUTING.md",
    "examples":     f"{REPO}/tree/main/examples",
    "dame":         f"{REPO}/blob/main/docs/DAME-DASE-integration.md",
    "dase":         f"{REPO}/blob/main/docs/DAME-DASE-integration.md",
    "mediguide":    f"{REPO}/tree/main/profiles/mediguide",
    "mocks":        f"{REPO}/blob/main/docs/TODO-mock-types.md",
}


def main():
    topic = sys.argv[1].lower().strip("-") if len(sys.argv) > 1 else ""

    if topic in ("help", "h", "?", "list"):
        print("Usage: airt-docs [topic]\n")
        print("Topics:")
        for key in sorted(PAGES):
            if key:
                print(f"  {key:<16s} {PAGES[key]}")
        return

    url = PAGES.get(topic)
    if not url:
        print(f"Unknown topic: {topic}")
        print(f"Available: {', '.join(k for k in sorted(PAGES) if k)}")
        print(f"\nOpening main docs instead...")
        url = REPO

    print(f"Opening {url}")
    webbrowser.open(url)


if __name__ == "__main__":
    main()
