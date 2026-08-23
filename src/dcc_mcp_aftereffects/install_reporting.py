"""Install SOP v1 report and recovery-command construction."""

from __future__ import annotations

import sys
from typing import Any

from .__version__ import __version__
from .install_contract import SCHEMA_VERSION, runtime_core_version
from .install_discovery import PreflightError
from .install_models import InstallRequest, ResolvedInstall


def next_step(command: list[str], why: str, step_id: str = "retry") -> dict[str, Any]:
    return {
        "id": step_id,
        "description": "Run the reported lifecycle command after resolving the failure",
        "command": command,
        "why": why,
    }


def retry_command(request: InstallRequest) -> list[str]:
    command = ["dcc-mcp-aftereffects", request.command, "--json"]
    if request.dcc_path:
        command.extend(["--dcc-path", request.dcc_path])
    if request.python:
        command.extend(["--python", request.python])
    if request.yes:
        command.append("--yes")
    return command


def launch_host_command(resolved: ResolvedInstall) -> list[str]:
    if sys.platform == "darwin" and resolved.host_path.suffix.lower() == ".app":
        return ["open", "-a", str(resolved.host_path)]
    return [str(resolved.host_path)]


def build_report(
    resolved: ResolvedInstall,
    *,
    status: str,
    state: str,
    steps: list[dict[str, Any]],
    directly_usable: bool = False,
    failure_stage: str | None = None,
    failure_reason: str | None = None,
    next_steps: list[dict[str, Any]] | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "dcc_type": "aftereffects",
        "adapter_version": __version__,
        "core_version": resolved.core_version,
        "installation_state": state,
        "plan": {
            "mode": mode or state,
            "host": str(resolved.host_path),
            "host_version": resolved.host_version,
            "python": str(resolved.python_path),
            "python_version": resolved.python_version,
            "extension_path": str(resolved.extension_path),
        },
        "steps": steps,
        "next_steps": list(next_steps or ()),
        "receipt_path": str(resolved.receipt_path),
        "verify": {
            "directly_usable": directly_usable,
            "failure_stage": failure_stage,
            "failure_reason": failure_reason,
        },
    }


def build_preflight_report(request: InstallRequest, error: PreflightError) -> dict[str, Any]:
    reason = str(error)
    recovery = ["adobepy", "--version"] if error.stage == "acquire" else retry_command(request)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "failed",
        "dcc_type": "aftereffects",
        "adapter_version": __version__,
        "core_version": runtime_core_version(),
        "installation_state": "unknown",
        "plan": {
            "mode": request.command,
            "host": request.dcc_path,
            "python": request.python or sys.executable,
        },
        "steps": [{"id": "preflight", "status": "failed", "message": reason}],
        "next_steps": [next_step(recovery, reason, "retry-preflight")],
        "receipt_path": None,
        "verify": {
            "directly_usable": False,
            "failure_stage": error.stage,
            "failure_reason": reason,
        },
    }


__all__ = [
    "build_preflight_report",
    "build_report",
    "launch_host_command",
    "next_step",
    "retry_command",
]
