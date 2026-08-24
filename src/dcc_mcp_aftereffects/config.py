"""Runtime configuration for the After Effects adapter."""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse


def _bounded_seconds(name: str, default: str, *, maximum: float) -> float:
    raw = os.getenv(name, default)
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} timeout must be a finite positive number") from exc
    if not math.isfinite(value) or value <= 0 or value > maximum:
        raise ValueError(f"{name} timeout must be finite and within (0, {maximum}]")
    return value


@dataclass(frozen=True)
class AfterEffectsConfig:
    broker_url: str | None = None
    token: str | None = None
    target: str = "default"
    timeout: float = 5.0
    poll_interval: float = 2.0

    @classmethod
    def from_env(cls) -> "AfterEffectsConfig":
        broker_url = os.getenv("ADOBEPY_BROKER_URL")
        if broker_url:
            parsed = urlparse(broker_url)
            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError("broker URL must contain a valid loopback port") from exc
            if (
                parsed.scheme != "http"
                or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                or port is None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("broker URL must be an uncredentialed loopback HTTP origin")
        target = os.getenv("ADOBEPY_TARGET", "default")
        if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", target) is None:
            raise ValueError("target must be a bounded canonical identifier")
        token = os.getenv("ADOBEPY_TOKEN")
        if token is not None and (not token or len(token) > 4_096 or "\0" in token):
            raise ValueError("token must be a bounded non-empty environment value")
        return cls(
            broker_url=broker_url,
            token=token,
            target=target,
            timeout=_bounded_seconds(
                "DCC_MCP_AFTEREFFECTS_BROKER_TIMEOUT_SECS", "5", maximum=300.0
            ),
            poll_interval=_bounded_seconds(
                "DCC_MCP_AFTEREFFECTS_BRIDGE_POLL_SECS", "2", maximum=60.0
            ),
        )


__all__ = ["AfterEffectsConfig"]
