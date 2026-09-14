"""ai-models — a shared, declarative catalogue of LLM provider/model profiles.

The catalogue describes *what models exist and how to connect to them*; each
consuming project brings its own ``models.yaml`` and uses its own client layer to
make calls. This package only parses and resolves — it never calls a provider.

    from ai_models import load, resolve, available
    cfg = load("models.yaml")
    r = resolve(cfg, "glm")        # -> Resolved(type="fireworks", base_url=..., api_key=...)
    names = available(cfg)         # models whose credentials are present
"""

from .catalogue import Resolved, available, load, resolve
from .schema import Config, ModelConfig

__all__ = ["Config", "ModelConfig", "Resolved", "load", "resolve", "available"]
