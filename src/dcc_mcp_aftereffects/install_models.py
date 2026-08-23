"""Pure models for the After Effects install lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class InstallRequest:
    command: str
    as_json: bool = False
    yes: bool = False
    dry_run: bool = False
    dcc_path: str | None = None
    python: str | None = None


@dataclass(frozen=True)
class ResolvedInstall:
    host_path: Path
    host_version: str
    python_path: Path
    python_version: str
    core_version: str
    extension_path: Path
    receipt_path: Path
    bootstrap_error_path: Path
    adobepy_cli: Path | None
    token: str | None = field(repr=False)
    broker_url: str | None = None
    target: str = "default"


__all__ = ["InstallRequest", "ResolvedInstall"]
