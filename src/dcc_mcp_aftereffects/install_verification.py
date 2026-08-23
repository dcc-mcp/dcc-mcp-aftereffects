"""Receipt state and verify-to-usable ownership."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .install_contract import EXIT_OK, EXIT_VERIFY, SCHEMA_VERSION
from .install_io import file_manifest, read_receipt, write_bootstrap_error, write_receipt
from .install_models import InstallRequest, ResolvedInstall
from .install_reporting import build_report, next_step, retry_command
from .runtime import AfterEffectsStatus, probe_aftereffects


def _default_import_probe(python_path: Path) -> tuple[bool, str]:
    environment = dict(os.environ)
    environment.pop("ADOBEPY_TOKEN", None)
    try:
        completed = subprocess.run(
            [
                str(python_path),
                "-c",
                "import adobe,dcc_mcp_aftereffects; print('adapter imports passed')",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "Target Python import probe could not run"
    if completed.returncode != 0:
        return False, "Target Python could not import adobepy and dcc-mcp-aftereffects"
    return True, "adapter imports passed"


def _default_readiness_probe(resolved: ResolvedInstall) -> AfterEffectsStatus:
    return probe_aftereffects(
        broker_url=resolved.broker_url,
        token=resolved.token,
        target=resolved.target,
    )


@dataclass
class LifecycleDependencies:
    bridge_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run
    import_probe: Callable[[Path], tuple[bool, str]] = _default_import_probe
    readiness_probe: Callable[[ResolvedInstall], AfterEffectsStatus] = _default_readiness_probe
    receipt_writer: Callable[[Path, Mapping[str, Any]], None] = write_receipt


def installation_state(resolved: ResolvedInstall) -> tuple[str, dict[str, Any] | None]:
    receipt = read_receipt(resolved.receipt_path)
    exists = resolved.extension_path.is_dir()
    if receipt is None:
        return ("partial" if exists else "fresh"), None
    if not exists:
        return "partial", receipt
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("dcc_type") != "aftereffects"
        or receipt.get("extension_path") != str(resolved.extension_path)
    ):
        return "partial", receipt
    expected = receipt.get("files")
    if not isinstance(expected, list) or expected != file_manifest(resolved.extension_path):
        return "partial", receipt
    return "installed", receipt


def verify_install(
    request: InstallRequest,
    resolved: ResolvedInstall,
    dependencies: LifecycleDependencies,
) -> tuple[dict[str, Any], int]:
    state, _receipt = installation_state(resolved)
    steps = [{"id": "receipt", "status": "ok" if state == "installed" else "failed"}]
    if state != "installed":
        reason = "A complete matching install receipt is required before verification"
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                failure_stage="receipt",
                failure_reason=reason,
                next_steps=[next_step(retry_command(request), reason, "repair-install")],
            ),
            EXIT_VERIFY,
        )
    import_ok, import_reason = dependencies.import_probe(resolved.python_path)
    steps.append(
        {
            "id": "target-import",
            "status": "ok" if import_ok else "failed",
            "message": import_reason,
        }
    )
    if not import_ok:
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                failure_stage="import",
                failure_reason=import_reason,
                next_steps=[next_step(retry_command(request), import_reason, "retry-import")],
            ),
            EXIT_VERIFY,
        )
    status = dependencies.readiness_probe(resolved)
    steps.append(
        {
            "id": "typed-readiness",
            "status": "ok" if status.ready else "failed",
            "message": status.reason,
        }
    )
    if not status.ready:
        reason = status.reason or "After Effects did not answer the typed host version probe"
        write_bootstrap_error(resolved.bootstrap_error_path, "readiness", reason, resolved.token)
        wait_ready = ["dcc-mcp-cli", "wait-ready", "--dcc-type", "aftereffects"]
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                failure_stage="readiness",
                failure_reason=reason,
                next_steps=[next_step(wait_ready, reason, "wait-ready")],
            ),
            EXIT_VERIFY,
        )
    return (
        build_report(
            resolved,
            status="ok",
            state=state,
            steps=steps,
            directly_usable=True,
        ),
        EXIT_OK,
    )


__all__ = ["LifecycleDependencies", "installation_state", "verify_install"]
