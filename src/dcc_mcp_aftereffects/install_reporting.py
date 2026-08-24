"""Install SOP v1 report and recovery-command construction."""

from __future__ import annotations

import sys
from typing import Any
from urllib.parse import urlparse

from .__version__ import __version__
from .install_contract import SCHEMA_VERSION, runtime_core_version
from .install_discovery import PreflightError
from .install_models import InstallRequest, ResolvedInstall


def _public_broker_origin(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or not port
    ):
        return None
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme}://{host}:{port}"


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


def verify_command(request: InstallRequest) -> list[str]:
    command = ["dcc-mcp-aftereffects", "verify", "--json"]
    if request.dcc_path:
        command.extend(["--dcc-path", request.dcc_path])
    if request.python:
        command.extend(["--python", request.python])
    return command


def launch_host_command(resolved: ResolvedInstall) -> list[str]:
    if sys.platform == "darwin" and resolved.host_path.suffix.lower() == ".app":
        return ["open", "-a", str(resolved.host_path)]
    return [str(resolved.host_path)]


def _acquire_adobepy_steps(request: InstallRequest, reason: str) -> list[dict[str, Any]]:
    if sys.platform != "win32":
        return [
            next_step(
                ["gh", "issue", "view", "65", "--repo", "dcc-mcp/adobepy"],
                reason,
                "inspect-supported-cli-dependency",
            )
        ]
    script = (
        "$ErrorActionPreference='Stop';"
        "$root=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) "
        "'dcc-mcp\\adobepy\\0.6.2';"
        "$bundle=Join-Path $root 'adobepy-0.6.2-windows-x64';"
        "$cli=Join-Path $bundle 'bin\\adobepy.exe';"
        "if(Test-Path -LiteralPath $root){"
        "$item=Get-Item -LiteralPath $root -Force;"
        "if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){"
        "throw 'Existing adobepy root is a reparse point'}};"
        "if(-not(Test-Path -LiteralPath $cli -PathType Leaf)){"
        "if(Test-Path -LiteralPath $root){throw 'Existing adobepy root is incomplete'};"
        "$parent=Split-Path -Parent $root;"
        "New-Item -ItemType Directory -Path $parent -Force|Out-Null;"
        "$archive=Join-Path $parent ('.adobepy-'+[Guid]::NewGuid().ToString('N')+'.zip');"
        "try{Invoke-WebRequest -UseBasicParsing -Uri "
        "'https://github.com/dcc-mcp/adobepy/releases/download/adobepy-v0.6.2/"
        "adobepy-0.6.2-windows-x64.zip' -OutFile $archive;"
        "if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()"
        "-ne '9ef9abb5e034359f12e9ce248b0030e38d34c76df343eb2713f18036068719a7')"
        "{throw 'adobepy archive checksum mismatch'};"
        "New-Item -ItemType Directory -Path $root|Out-Null;"
        "Expand-Archive -LiteralPath $archive -DestinationPath $root}"
        "finally{Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue}};"
        "if((Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant()"
        "-ne 'c02f28f07705b69a4f97f9f6639f0f80d1f5292115446801fbd92423336301aa')"
        "{throw 'adobepy executable checksum mismatch'};"
        "[Environment]::SetEnvironmentVariable('ADOBEPY_CLI',$cli,'User');"
        "Write-Output $cli"
    )
    return [
        next_step(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            reason,
            "acquire-pinned-adobepy-cli",
        ),
        next_step(retry_command(request), reason, "retry-after-acquire"),
    ]


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
            "python_modules": dict(resolved.python_modules),
            "extension_path": str(resolved.extension_path),
            "bridge": dict(resolved.bridge_identity),
            "broker_url": _public_broker_origin(resolved.broker_url),
            "target": resolved.target,
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
    recovery = (
        _acquire_adobepy_steps(request, reason)
        if error.stage == "acquire"
        else [next_step(retry_command(request), reason, "retry-preflight")]
    )
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
        "next_steps": recovery,
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
    "verify_command",
]
