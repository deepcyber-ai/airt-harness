"""Model catalogue schema — declarative provider/model profiles.

A discriminated union on ``type``. Provider defaults (base URLs, key env vars)
live here so a catalogue entry can be as short as ``{type: fireworks, model: ...}``.
This module describes models and how to connect to them; it never calls anything.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field


class OpenAICompatibleModel(BaseModel):
    """Any OpenAI-compatible endpoint (OpenAI, Gemini's compat endpoint, vLLM, …)."""

    type: Literal["openai-compatible"]
    base_url: str
    model: str
    api_key_env: str


class FireworksModel(BaseModel):
    """Fireworks-hosted models (e.g. GLM). Thin wrapper over openai-compatible."""

    type: Literal["fireworks"]
    model: str
    base_url: str = "https://api.fireworks.ai/inference/v1"
    api_key_env: str = "FIREWORKS_API_KEY"


class AnthropicModel(BaseModel):
    type: Literal["anthropic"]
    model: str
    base_url: str = "https://api.anthropic.com"
    api_key_env: str = "ANTHROPIC_API_KEY"


class BedrockModel(BaseModel):
    """AWS Bedrock. Auth comes from the AWS credential chain, not an api_key_env."""

    type: Literal["aws-bedrock"]
    region: str
    model: str
    aws_profile: str | None = None


class OllamaModel(BaseModel):
    type: Literal["ollama"]
    model: str
    base_url: str = "http://localhost:11434"


ModelConfig = Annotated[
    Union[
        OpenAICompatibleModel,
        FireworksModel,
        AnthropicModel,
        BedrockModel,
        OllamaModel,
    ],
    Field(discriminator="type"),
]


class Config(BaseModel):
    """A catalogue: a set of named model profiles, optionally with a default."""

    default_model: str | None = None
    models: dict[str, ModelConfig] = Field(default_factory=dict)
