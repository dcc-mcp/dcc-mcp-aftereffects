"""Runtime configuration for the After Effects adapter."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AfterEffectsConfig:
    broker_url: str | None = None
    token: str | None = None
    target: str = "default"
    timeout: float = 5.0
    poll_interval: float = 2.0

    @classmethod
    def from_env(cls) -> "AfterEffectsConfig":
        return cls(
            broker_url=os.getenv("ADOBEPY_BROKER_URL"),
            token=os.getenv("ADOBEPY_TOKEN"),
            target=os.getenv("ADOBEPY_TARGET", "default"),
            timeout=float(os.getenv("DCC_MCP_AFTEREFFECTS_BROKER_TIMEOUT_SECS", "5")),
            poll_interval=float(os.getenv("DCC_MCP_AFTEREFFECTS_BRIDGE_POLL_SECS", "2")),
        )


__all__ = ["AfterEffectsConfig"]
