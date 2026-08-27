"""Application service for After Effects host-integrated lifecycle verbs."""

from __future__ import annotations

import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from .__version__ import __version__
from .install_contract import (
    EXIT_INSTALL,
    EXIT_OK,
    EXIT_PREFLIGHT,
    EXIT_REQUIRES_RESTART,
    SCHEMA_VERSION,
    runtime_core_version,
)
from .install_discovery import PreflightError, recapture_python_modules, resolve_install
from .install_io import (
    InstallIoError,
    RestartRequired,
    RollbackError,
    commit_staged_install,
    create_staging_dir,
    file_manifest,
    remove_receipted_install,
    remove_staging,
    run_adobepy_install_bridge,
    write_bootstrap_error,
)
from .install_models import InstallRequest, ResolvedInstall
from .install_reporting import (
    build_preflight_report,
    build_report,
    launch_host_command,
    next_step,
    retry_command,
    verify_command,
)
from .install_verification import (
    LifecycleDependencies,
    installation_state,
    recapture_resolved_host,
    verify_install,
)


def _install_or_upgrade(
    request: InstallRequest,
    resolved: ResolvedInstall,
    dependencies: LifecycleDependencies,
) -> tuple[dict[str, Any], int]:
    state, receipt = installation_state(resolved)
    mode = (
        "upgrade" if request.command == "upgrade" else ("repair" if state == "partial" else state)
    )
    steps = [
        {"id": "preflight", "status": "ok"},
        {"id": "stage-bridge", "status": "planned"},
        {"id": "commit-extension", "status": "planned"},
        {"id": "write-receipt", "status": "planned"},
        {"id": "verify", "status": "planned"},
    ]
    if request.command == "upgrade" and receipt is None:
        reason = (
            "Upgrade requires an existing adapter-owned receipt; use install for a fresh profile"
        )
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                mode=mode,
                failure_stage="receipt",
                failure_reason=reason,
                next_steps=[next_step(["dcc-mcp-aftereffects", "install", "--json"], reason)],
            ),
            EXIT_PREFLIGHT,
        )
    if state == "partial":
        reason = (
            "The existing CEP directory or receipt is not a complete adapter-owned install; "
            "all existing content was preserved"
        )
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                mode=mode,
                failure_stage="receipt",
                failure_reason=reason,
                next_steps=[
                    next_step(
                        ["dcc-mcp-aftereffects", "status", "--json"],
                        reason,
                        "inspect-partial-install",
                    )
                ],
            ),
            EXIT_PREFLIGHT,
        )
    if state == "installed" and request.command == "install":
        return verify_install(request, resolved, dependencies)
    if request.dry_run or not request.yes:
        return build_report(
            resolved, status="planned", state=state, steps=steps, mode=mode
        ), EXIT_OK
    if resolved.adobepy_cli is None or not resolved.token:
        reason = (
            "The supported adobepy CLI and ADOBEPY_TOKEN are required to install the CEP bridge"
        )
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                mode=mode,
                failure_stage="preflight",
                failure_reason=reason,
                next_steps=[next_step(retry_command(request), reason, "retry-preflight")],
            ),
            EXIT_PREFLIGHT,
        )

    host_identity = recapture_resolved_host(resolved, dependencies)
    if host_identity is None:
        reason = (
            "The signed After Effects host identity could not be recaptured exactly "
            "before installation"
        )
        steps[0] = {"id": "preflight", "status": "failed", "message": reason}
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                mode=mode,
                failure_stage="host_attestation",
                failure_reason=reason,
                next_steps=[],
            ),
            EXIT_PREFLIGHT,
        )
    resolved = replace(resolved, host_identity=host_identity)

    python_modules = recapture_python_modules(resolved.python_modules)
    if python_modules is None:
        reason = "The target Python package identities could not be recaptured exactly"
        steps[0] = {"id": "preflight", "status": "failed", "message": reason}
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                mode=mode,
                failure_stage="python_attestation",
                failure_reason=reason,
                next_steps=[],
            ),
            EXIT_PREFLIGHT,
        )
    resolved = replace(resolved, python_modules=python_modules)

    staged = create_staging_dir(resolved.extension_path)
    try:
        run_adobepy_install_bridge(
            cli=resolved.adobepy_cli,
            expected_identity=resolved.bridge_identity,
            destination=staged,
            token=resolved.token,
            broker_url=resolved.broker_url,
            target=resolved.target,
            runner=dependencies.bridge_runner,
        )
        steps[1]["status"] = "ok"
        receipt_payload = {
            "schema_version": SCHEMA_VERSION,
            "dcc_type": "aftereffects",
            "adapter_version": __version__,
            "core_version": resolved.core_version,
            "host_path": str(resolved.host_path),
            "host_version": resolved.host_version,
            "host_identity": dict(resolved.host_identity),
            "python": str(resolved.python_path),
            "python_version": resolved.python_version,
            "extension_path": str(resolved.extension_path),
            "files": file_manifest(staged),
            "python_modules": dict(resolved.python_modules),
            "bridge": dict(resolved.bridge_identity),
            "broker_url": resolved.broker_url,
            "target": resolved.target,
            "installed_at": datetime.now(timezone.utc).isoformat(),
        }
        transaction = commit_staged_install(
            staged=staged,
            destination=resolved.extension_path,
            receipt=receipt_payload,
            receipt_path=resolved.receipt_path,
            receipt_writer=dependencies.receipt_writer,
        )
        steps[2]["status"] = "ok"
        steps[3]["status"] = "ok"
    except RestartRequired as exc:
        reason = str(exc)
        return (
            build_report(
                resolved,
                status="requires_restart",
                state=state,
                steps=steps,
                mode=mode,
                failure_stage="install",
                failure_reason=reason,
                next_steps=[next_step(retry_command(request), reason, "retry-after-restart")],
            ),
            EXIT_REQUIRES_RESTART,
        )
    except RollbackError as exc:
        reason = str(exc)
        write_bootstrap_error(resolved.bootstrap_error_path, "rollback", reason, resolved.token)
        return (
            build_report(
                resolved,
                status="failed",
                state=installation_state(resolved)[0],
                steps=steps,
                mode=mode,
                failure_stage="rollback",
                failure_reason=reason,
                next_steps=[next_step(retry_command(request), reason, "retry-rollback")],
            ),
            EXIT_INSTALL,
        )
    except InstallIoError as exc:
        reason = str(exc)
        write_bootstrap_error(resolved.bootstrap_error_path, "install", reason, resolved.token)
        return (
            build_report(
                resolved,
                status="failed",
                state=installation_state(resolved)[0],
                steps=steps,
                mode=mode,
                failure_stage="install",
                failure_reason=reason,
                next_steps=[next_step(retry_command(request), reason, "retry-install")],
            ),
            EXIT_INSTALL,
        )
    finally:
        remove_staging(staged)

    verify_report, verify_exit = verify_install(request, resolved, dependencies)
    steps[4]["status"] = "ok" if verify_exit == EXIT_OK else "failed"
    combined_steps = steps + verify_report["steps"]
    if verify_exit == EXIT_OK:
        try:
            transaction.finalize()
        except RestartRequired as exc:
            reason = str(exc)
            return (
                build_report(
                    resolved,
                    status="requires_restart",
                    state="installed",
                    steps=combined_steps,
                    mode=mode,
                    failure_stage="cleanup",
                    failure_reason=reason,
                    next_steps=[next_step(retry_command(request), reason, "retry-cleanup")],
                ),
                EXIT_REQUIRES_RESTART,
            )
        return (
            build_report(
                resolved,
                status="ok",
                state="installed",
                steps=combined_steps,
                mode=mode,
                directly_usable=True,
            ),
            verify_exit,
        )
    reason = verify_report["verify"]["failure_reason"] or "After Effects must load the CEP bridge"
    if request.command == "upgrade" and transaction.moved_existing:
        try:
            transaction.rollback()
        except OSError:
            rollback_reason = "The previous After Effects extension could not be restored"
            return (
                build_report(
                    resolved,
                    status="failed",
                    state="partial",
                    steps=combined_steps,
                    mode=mode,
                    failure_stage="rollback",
                    failure_reason=rollback_reason,
                    next_steps=[],
                ),
                EXIT_INSTALL,
            )
        report = build_report(
            resolved,
            status="failed",
            state=installation_state(resolved)[0],
            steps=combined_steps,
            mode=mode,
            failure_stage=verify_report["verify"].get("failure_stage") or "readiness",
            failure_reason=reason,
            next_steps=verify_report.get("next_steps", []),
        )
        report["previous_install_restored"] = True
        return report, verify_exit
    failure_stage = verify_report["verify"].get("failure_stage")
    if failure_stage != "readiness":
        try:
            transaction.rollback()
        except OSError:
            rollback_reason = "The failed install could not be rolled back safely"
            return (
                build_report(
                    resolved,
                    status="failed",
                    state="partial",
                    steps=combined_steps,
                    mode=mode,
                    failure_stage="rollback",
                    failure_reason=rollback_reason,
                    next_steps=[],
                ),
                EXIT_INSTALL,
            )
        return verify_report, verify_exit
    try:
        transaction.finalize()
    except RestartRequired as exc:
        reason = str(exc)
    return (
        build_report(
            resolved,
            status="requires_restart",
            state="installed",
            steps=combined_steps,
            mode=mode,
            failure_stage="bootstrap",
            failure_reason=reason,
            next_steps=[
                next_step(launch_host_command(resolved), reason, "start-host"),
                next_step(verify_command(request), reason, "verify-after-start"),
            ],
        ),
        EXIT_REQUIRES_RESTART,
    )


def _uninstall(
    request: InstallRequest,
    resolved: ResolvedInstall,
) -> tuple[dict[str, Any], int]:
    state, receipt = installation_state(resolved)
    steps = [
        {"id": "read-receipt", "status": "ok" if receipt is not None else "failed"},
        {"id": "remove-receipted-extension", "status": "planned"},
        {"id": "remove-receipt", "status": "planned"},
    ]
    if receipt is None:
        if state == "fresh":
            steps[0]["status"] = "ok"
            steps[1]["status"] = "skipped"
            steps[2]["status"] = "skipped"
            return (
                build_report(
                    resolved,
                    status="planned" if request.dry_run or not request.yes else "ok",
                    state="fresh",
                    steps=steps,
                    failure_stage="not_installed",
                    failure_reason="No receipt-owned After Effects extension is installed",
                ),
                EXIT_OK,
            )
        reason = "Uninstall is receipt-only; unreceipted files were preserved"
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                failure_stage="receipt",
                failure_reason=reason,
                next_steps=[next_step(["dcc-mcp-aftereffects", "status", "--json"], reason)],
            ),
            EXIT_PREFLIGHT,
        )
    if receipt.get("dcc_type") != "aftereffects" or receipt.get("extension_path") != str(
        resolved.extension_path
    ):
        reason = "Receipt ownership does not match the selected After Effects CEP profile"
        return (
            build_report(
                resolved,
                status="failed",
                state="partial",
                steps=steps,
                failure_stage="receipt",
                failure_reason=reason,
                next_steps=[next_step(["dcc-mcp-aftereffects", "status", "--json"], reason)],
            ),
            EXIT_PREFLIGHT,
        )
    if request.dry_run or not request.yes:
        return build_report(resolved, status="planned", state=state, steps=steps), EXIT_OK
    try:
        remove_receipted_install(resolved.extension_path, resolved.receipt_path)
    except RestartRequired as exc:
        reason = str(exc)
        return (
            build_report(
                resolved,
                status="requires_restart",
                state=state,
                steps=steps,
                failure_stage="uninstall",
                failure_reason=reason,
                next_steps=[next_step(retry_command(request), reason, "retry-after-restart")],
            ),
            EXIT_REQUIRES_RESTART,
        )
    except InstallIoError as exc:
        reason = str(exc)
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                failure_stage="uninstall",
                failure_reason=reason,
                next_steps=[next_step(retry_command(request), reason, "retry-uninstall")],
            ),
            EXIT_INSTALL,
        )
    steps[1]["status"] = "ok"
    steps[2]["status"] = "ok"
    return build_report(resolved, status="ok", state="fresh", steps=steps), EXIT_OK


def _run_lifecycle(
    request: InstallRequest,
    *,
    resolved: ResolvedInstall | None = None,
    dependencies: LifecycleDependencies | None = None,
) -> tuple[dict[str, Any], int]:
    active_dependencies = dependencies or LifecycleDependencies()
    if resolved is None:
        try:
            resolved = resolve_install(request)
        except PreflightError as exc:
            return build_preflight_report(request, exc), exc.exit_code
    if request.command == "status":
        state, _receipt = installation_state(resolved)
        return (
            build_report(
                resolved,
                status="partial" if state == "partial" else "ok",
                state=state,
                steps=[{"id": "inspect", "status": "ok"}],
            ),
            EXIT_OK,
        )
    if request.command == "verify":
        return verify_install(request, resolved, active_dependencies)
    if request.command in {"install", "upgrade"}:
        return _install_or_upgrade(request, resolved, active_dependencies)
    if request.command == "uninstall":
        return _uninstall(request, resolved)
    raise ValueError(f"Unsupported lifecycle command: {request.command}")


def run_lifecycle(
    request: InstallRequest,
    *,
    resolved: ResolvedInstall | None = None,
    dependencies: LifecycleDependencies | None = None,
) -> tuple[dict[str, Any], int]:
    try:
        return _run_lifecycle(request, resolved=resolved, dependencies=dependencies)
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        if isinstance(exc, FileNotFoundError):
            error_type = "invalid_executable"
        elif isinstance(exc, OSError):
            error_type = "os_error"
        elif isinstance(exc, KeyError):
            error_type = "missing_field"
        elif isinstance(exc, TypeError):
            error_type = "invalid_type"
        elif isinstance(exc, subprocess.SubprocessError):
            error_type = "subprocess_error"
        elif isinstance(exc, RuntimeError):
            error_type = "runtime_error"
        else:
            error_type = "invalid_value"
        report = {
            "schema_version": SCHEMA_VERSION,
            "status": "failed",
            "dcc_type": "aftereffects",
            "adapter_version": __version__,
            "core_version": resolved.core_version if resolved else runtime_core_version(),
            "steps": [{"id": "lifecycle", "status": "failed"}],
            "next_steps": [],
            "receipt_path": str(resolved.receipt_path) if resolved else None,
            "verify": {
                "directly_usable": False,
                "failure_stage": "internal_error",
                "failure_reason": "The After Effects lifecycle could not complete safely",
                "error_type": error_type,
            },
        }
        return report, EXIT_INSTALL


__all__ = ["LifecycleDependencies", "run_lifecycle"]
