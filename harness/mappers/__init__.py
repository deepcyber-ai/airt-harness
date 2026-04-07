"""DeepCyber AIRT Harness -- Message Mapper Registry.

Each target API gets a mapper that translates between the harness's
canonical format and the target's wire format. Mappers are bidirectional:

  Client side (harness -> real target):
    build_request()   -- canonical message -> target request
    parse_response()  -- target response -> canonical format

  Server side (mock emulating the target):
    parse_incoming_request()  -- target request -> extract message
    build_mock_response()     -- LLM answer -> target response format

Built-in mappers are listed in `_BUILTIN_MAPPERS`. To use a custom mapper
that lives outside this package (for example, an engagement-private mapper
in your profile directory), set `target_module:` in your profile YAML to
either:

  - an importable Python module path:
        target: my_target
        target_module: my_package.my_target_mapper

  - or a file path (relative to CWD or absolute):
        target: my_target
        target_module: profiles/my_target/mapper.py

The module must expose a `create_mapper(config) -> BaseMapper` function.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CanonicalResponse:
    """Normalised response from any target."""

    answer: str = ""
    session_id: str = ""
    conversation_type: str = "ai"
    agent_thoughts: list[dict] = field(default_factory=list)
    guardrails: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    error: str | None = None


class BaseMapper:
    """Base class for target mappers."""

    name: str = "base"

    def __init__(self, config: dict):
        self.config = config

    # -- Client side (harness -> real target) -----------------------------

    def build_client_kwargs(self) -> dict:
        """Return kwargs for httpx.Client (cert, verify, timeout)."""
        import os

        tls = self.config.get("tls", {}) or {}
        kwargs: dict[str, Any] = {"timeout": 120}

        cert_path = tls.get("cert")
        key_path = tls.get("key")
        if cert_path and key_path:
            if os.path.exists(cert_path) and os.path.exists(key_path):
                kwargs["cert"] = (cert_path, key_path)

        ca_bundle = tls.get("ca_bundle")
        if ca_bundle:
            kwargs["verify"] = ca_bundle
        elif tls.get("verify") is False:
            kwargs["verify"] = False

        return kwargs

    def build_auth_headers(self) -> dict:
        """Return auth headers from config."""
        import os

        auth = self.config.get("auth", {})
        mode = auth.get("mode", "none")

        if mode == "bearer":
            bearer = auth.get("bearer", {})
            token = os.environ.get(bearer.get("env_var", ""), "")
            if token:
                prefix = bearer.get("prefix", "Bearer ")
                return {"Authorization": f"{prefix}{token}"}
        elif mode == "api_key":
            ak = auth.get("api_key", {})
            token = os.environ.get(ak.get("env_var", ""), "")
            if token:
                prefix = ak.get("prefix", "Bearer ")
                header = ak.get("header", "Authorization")
                return {header: f"{prefix}{token}"}
        return {}

    def get_api_url(self) -> str:
        """Return the full API URL from config."""
        api = self.config.get("api", {})
        return f"{api['url'].rstrip('/')}{api.get('path', '')}"

    def get_mock_url(self) -> str:
        """Return the mock server URL."""
        mock = self.config.get("mock", {})
        return mock.get("url", "http://localhost:8089")

    def build_request(
        self, message: str, session_id: str
    ) -> tuple[str, dict, dict]:
        """Translate canonical message into (url, headers, body)."""
        raise NotImplementedError

    def parse_response(self, data: Any, raw_text: str = "") -> CanonicalResponse:
        """Translate target response into canonical format."""
        raise NotImplementedError

    def needs_init(self) -> bool:
        """Whether this target requires explicit session initialisation."""
        return False

    def init_session(self, session_id: str, client, url_override: str = None) -> str | None:
        """Initialise a session. Returns API session ID or None.

        url_override: use this URL instead of the configured API URL (e.g. for mock mode).
        """
        return None

    # -- Server side (mock emulating the target) --------------------------

    def parse_incoming_request(
        self, body: dict, headers: dict
    ) -> tuple[str, str]:
        """Extract (message, session_id) from an incoming target-format request."""
        raise NotImplementedError

    def build_mock_response(
        self, answer: str, session_id: str, **kwargs
    ) -> dict:
        """Build a target-format response from an LLM answer."""
        raise NotImplementedError


# -- Registry --------------------------------------------------------------

_BUILTIN_MAPPERS = {
    "example": "harness.mappers.example",
}


def load_mapper(target_name: str, config: dict) -> BaseMapper:
    """Load a mapper for the given target.

    Resolution order:
      1. If profile has `target_module:`, import it directly. This is the
         escape hatch for engagement-private mappers that live outside
         this package.
      2. Otherwise, look up `target_name` in the built-in registry.

    The resolved module must expose `create_mapper(config) -> BaseMapper`.
    """
    custom_module = config.get("target_module")
    if custom_module:
        if custom_module.endswith(".py") or "/" in custom_module:
            # File path (relative to CWD or absolute)
            import importlib.util
            from pathlib import Path

            file_path = Path(custom_module).resolve()
            if not file_path.exists():
                raise ValueError(
                    f"target_module file not found: {file_path}"
                )
            spec = importlib.util.spec_from_file_location(
                f"_airt_custom_mapper_{file_path.stem}", file_path
            )
            if spec is None or spec.loader is None:
                raise ValueError(
                    f"Cannot load mapper from file: {file_path}"
                )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        else:
            # Importable module path
            try:
                mod = importlib.import_module(custom_module)
            except ImportError as e:
                raise ValueError(
                    f"Failed to import target_module '{custom_module}': {e}. "
                    f"Make sure it is on PYTHONPATH and exposes create_mapper(config)."
                ) from e
        if not hasattr(mod, "create_mapper"):
            raise ValueError(
                f"target_module '{custom_module}' does not expose create_mapper(config)."
            )
        return mod.create_mapper(config)

    module_path = _BUILTIN_MAPPERS.get(target_name)
    if not module_path:
        raise ValueError(
            f"Unknown target '{target_name}'. Built-in mappers: "
            f"{', '.join(_BUILTIN_MAPPERS)}. For a custom mapper, set "
            f"'target_module:' in profile.yaml to an importable module path."
        )
    mod = importlib.import_module(module_path)
    return mod.create_mapper(config)
