"""Load a catalogue YAML and resolve a model name to connection parameters.

Resolution reads API keys from the environment (by the entry's ``api_key_env``)
and reports availability, so a consumer can offer only the models it can actually
reach. Nothing here makes a network call — the consumer's own client layer does.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from .schema import Config


@dataclass(frozen=True)
class Resolved:
    """A catalogue entry resolved against the environment, ready to hand to a
    caller. ``api_key`` is filled from ``api_key_env``; ``available`` says whether
    the credential needed to use this model is actually present."""

    name: str
    type: str
    model: str
    base_url: str | None = None
    api_key: str | None = None
    api_key_env: str | None = None
    region: str | None = None
    aws_profile: str | None = None
    available: bool = True


def load(path: str | Path) -> Config:
    """Read and validate a catalogue YAML file."""
    data = yaml.safe_load(Path(path).read_text()) or {}
    return Config.model_validate(data)


def resolve(cfg: Config, name: str) -> Resolved:
    """Resolve one model name to its connection parameters + availability."""
    if name not in cfg.models:
        raise KeyError(f"model {name!r} not in catalogue")
    m = cfg.models[name]

    if m.type == "aws-bedrock":
        return Resolved(
            name=name, type=m.type, model=m.model,
            region=m.region, aws_profile=m.aws_profile,
            available=bool(m.region) and _aws_creds_present(),
        )

    if m.type == "ollama":
        # Can't confirm the daemon is up without a call; treat as available and
        # let the caller surface a connection error if it isn't.
        return Resolved(name=name, type=m.type, model=m.model, base_url=m.base_url)

    # openai-compatible / fireworks / anthropic: key comes from the environment.
    key = os.environ.get(m.api_key_env)
    return Resolved(
        name=name, type=m.type, model=m.model, base_url=m.base_url,
        api_key=key, api_key_env=m.api_key_env, available=bool(key),
    )


def available(cfg: Config) -> list[str]:
    """Names of models whose credential is present — the set safe to offer."""
    return [name for name in cfg.models if resolve(cfg, name).available]


def _aws_creds_present() -> bool:
    """Cheap check for usable AWS credentials without touching the network."""
    if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"):
        return True
    aws = Path.home() / ".aws"
    return (aws / "credentials").exists() or (aws / "config").exists()
