"""DeepCyber AI Red Teaming Harness.

A generic test harness for AI red teaming engagements. Provides:
- Canonical OpenAI-compatible API in front of any target
- Message mappers for target-specific wire format translation
- Generic mock server with pluggable LLM backends
- Project profiles for per-engagement configuration

Usage:
    # Start harness with the default profile (Deep Vault Capital)
    uvicorn harness.server:app --port 8000

    # Start mock server
    python -m harness.mock --backend echo

(c) 2026 Deep Cyber Ltd. Apache 2.0 licensed.
"""

__version__ = "1.2.0"
