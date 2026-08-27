"""Application service for After Effects host-integrated lifecycle verbs."""

from __future__ import annotations

import os
import subprocess
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
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
from .install_discovery import (
    PreflightError,
    capture_mutation_roots,
    recapture_python_modules,
    resolve_install,
)
from .install_io import (
    IdentityAttestationError,
    InstallIoError,
    RestartRequired,
    RollbackError,
    commit_staged_install,
    create_staging_dir,
    file_manifest,
    prepare_install_directories,
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


def _identity_attestation_failure(
    resolved: ResolvedInstall,
    *,
    state: str,
    steps: list[dict[str, Any]],
    mode: str,
    failure_stage: str,
    reason: str,
    transaction: Any | None = None,
) -> tuple[dict[str, Any], int]:
    rollback_failed = False
    if transaction is not None:
        try:
            transaction.rollback()
        except BaseException:
            rollback_failed = True
    report = build_report(
        resolved,
        status="failed",
        state=installation_state(resolved)[0] if transaction is not None else state,
        steps=steps,
        mode=mode,
        failure_stage=failure_stage,
        failure_reason=reason,
        next_steps=[],
    )
    if rollback_failed:
        report["rollback_failed"] = True
    return report, EXIT_PREFLIGHT


def _transaction_failure(
    resolved: ResolvedInstall,
    *,
    steps: list[dict[str, Any]],
    mode: str,
    failure_stage: str,
    reason: str,
    transaction: Any,
) -> tuple[dict[str, Any], int]:
    rollback_failed = False
    try:
        transaction.rollback()
    except BaseException:
        rollback_failed = True
    report = build_report(
        resolved,
        status="failed",
        state=installation_state(resolved)[0],
        steps=steps,
        mode=mode,
        failure_stage=failure_stage,
        failure_reason=reason,
        next_steps=[],
    )
    if rollback_failed:
        report["rollback_failed"] = True
    else:
        report["previous_install_restored"] = True
    return report, EXIT_INSTALL


def _recapture_resolved_python(
    resolved: ResolvedInstall, dependencies: LifecycleDependencies
) -> dict[str, Any] | None:
    try:
        expected = deepcopy(dict(resolved.python_modules))
        observed = dependencies.python_distribution_probe(resolved.python_path, deepcopy(expected))
        return recapture_python_modules(expected, observed)
    except BaseException:
        return None


def _recapture_resolved_mutation_roots(resolved: ResolvedInstall) -> dict[str, Any] | None:
    try:
        expected = deepcopy(dict(resolved.mutation_roots))
        if not expected:
            return None
        current = capture_mutation_roots(resolved.extension_path, resolved.receipt_path)
    except BaseException:
        return None

    def compatible(expected_root: Any, current_root: Any) -> bool:
        if not isinstance(expected_root, dict) or not isinstance(current_root, dict):
            return False
        if expected_root.get("target") != current_root.get("target"):
            return False
        expected_ancestors = expected_root.get("ancestors")
        current_ancestors = current_root.get("ancestors")
        if not isinstance(expected_ancestors, list) or not isinstance(current_ancestors, list):
            return False
        if len(expected_ancestors) != len(current_ancestors):
            return False
        for prior, observed in zip(expected_ancestors, current_ancestors):
            if not isinstance(prior, dict) or not isinstance(observed, dict):
                return False
            if prior.get("path") != observed.get("path"):
                return False
            if prior.get("state") == "missing":
                if observed.get("state") not in {"missing", "directory"}:
                    return False
            elif observed != prior:
                return False
        return True

    if set(expected) != {"extension", "receipt"} or set(current) != set(expected):
        return None
    return current if all(compatible(expected[key], current[key]) for key in expected) else None


def _physical_identity_paths(*values: Any) -> tuple[Path, ...]:
    paths: dict[str, Path] = {}

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            path = value.get("path")
            if isinstance(path, str) and isinstance(value.get("physical"), dict):
                candidate = Path(path)
                if candidate.exists():
                    paths[os.path.normcase(str(candidate.absolute()))] = candidate
            for nested in value.values():
                collect(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                collect(nested)

    for value in values:
        collect(value)
    return tuple(paths[key] for key in sorted(paths))


def _attested_identity_paths(resolved: ResolvedInstall) -> tuple[Path, ...]:
    return _physical_identity_paths(
        dict(resolved.host_identity),
        dict(resolved.python_modules),
        dict(resolved.mutation_roots),
    )


def _attested_mutation_root_paths(resolved: ResolvedInstall) -> tuple[Path, ...]:
    return _physical_identity_paths(dict(resolved.mutation_roots))


def _require_exact_install_attestations(
    resolved: ResolvedInstall, dependencies: LifecycleDependencies
) -> ResolvedInstall:
    mutation_roots = _recapture_resolved_mutation_roots(resolved)
    if mutation_roots is None:
        raise IdentityAttestationError(
            "The extension or receipt mutation roots could not be recaptured exactly",
            stage="mutation_roots",
        )
    try:
        host_identity = recapture_resolved_host(resolved, dependencies)
    except BaseException:
        host_identity = None
    if host_identity is None:
        raise IdentityAttestationError(
            "The signed After Effects host identity could not be recaptured exactly",
            stage="host_attestation",
        )
    python_modules = _recapture_resolved_python(resolved, dependencies)
    if python_modules is None:
        raise IdentityAttestationError(
            "The target Python package identities could not be recaptured exactly",
            stage="python_attestation",
        )
    return replace(
        resolved,
        host_identity=host_identity,
        python_modules=python_modules,
        mutation_roots=mutation_roots,
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

    mutation_roots = _recapture_resolved_mutation_roots(resolved)
    if mutation_roots is None:
        reason = "The extension or receipt mutation roots could not be recaptured exactly"
        steps[0] = {"id": "preflight", "status": "failed", "message": reason}
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                mode=mode,
                failure_stage="mutation_roots",
                failure_reason=reason,
                next_steps=[],
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

    python_modules = _recapture_resolved_python(resolved, dependencies)
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

    try:
        mutation_roots = prepare_install_directories(
            (resolved.extension_path, resolved.receipt_path),
            before_mutation=lambda: _require_exact_install_attestations(resolved, dependencies),
            identity_paths=_attested_identity_paths(resolved),
            capture_after=lambda: capture_mutation_roots(
                resolved.extension_path, resolved.receipt_path
            ),
        )
        resolved = replace(resolved, mutation_roots=mutation_roots)
        staged = create_staging_dir(
            resolved.extension_path,
            before_mutation=lambda: _require_exact_install_attestations(resolved, dependencies),
            identity_paths=_attested_identity_paths(resolved),
        )
    except IdentityAttestationError as exc:
        reason = str(exc)
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                mode=mode,
                failure_stage=exc.stage,
                failure_reason=reason,
                next_steps=[],
            ),
            EXIT_PREFLIGHT,
        )
    except BaseException:
        reason = "The extension or receipt mutation roots could not be prepared safely"
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                mode=mode,
                failure_stage="mutation_roots",
                failure_reason=reason,
                next_steps=[],
            ),
            EXIT_PREFLIGHT,
        )
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
        try:
            resolved = _require_exact_install_attestations(resolved, dependencies)
        except IdentityAttestationError as exc:
            reason = str(exc)
            steps[2] = {"id": "commit-extension", "status": "failed", "message": reason}
            return (
                build_report(
                    resolved,
                    status="failed",
                    state=state,
                    steps=steps,
                    mode=mode,
                    failure_stage=exc.stage,
                    failure_reason=reason,
                    next_steps=[],
                ),
                EXIT_PREFLIGHT,
            )
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
            identity_attestor=lambda: bool(
                _require_exact_install_attestations(resolved, dependencies)
            ),
            identity_paths=_attested_identity_paths(resolved),
            mutation_root_attestor=lambda: _recapture_resolved_mutation_roots(resolved) is not None,
            mutation_root_paths=_attested_mutation_root_paths(resolved),
        )
        steps[2]["status"] = "ok"
        steps[3]["status"] = "ok"
    except IdentityAttestationError as exc:
        reason = str(exc)
        report = build_report(
            resolved,
            status="failed",
            state=installation_state(resolved)[0],
            steps=steps,
            mode=mode,
            failure_stage=exc.stage,
            failure_reason=reason,
            next_steps=[],
        )
        if exc.rollback_failed:
            report["rollback_failed"] = True
        return (
            report,
            EXIT_PREFLIGHT,
        )
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
        report = build_report(
            resolved,
            status="failed",
            state=installation_state(resolved)[0],
            steps=steps,
            mode=mode,
            failure_stage="install",
            failure_reason=reason,
            next_steps=[next_step(retry_command(request), reason, "retry-install")],
        )
        if getattr(exc, "rollback_failed", False):
            report["rollback_failed"] = True
        return report, EXIT_INSTALL
    finally:
        remove_staging(staged)

    verify_report, verify_exit = verify_install(
        request,
        resolved,
        dependencies,
        receipt_override=transaction.committed_receipt(),
    )
    steps[4]["status"] = "ok" if verify_exit == EXIT_OK else "failed"
    combined_steps = steps + verify_report["steps"]
    if verify_exit == EXIT_OK:
        try:
            resolved = _require_exact_install_attestations(resolved, dependencies)
        except IdentityAttestationError as exc:
            return _identity_attestation_failure(
                resolved,
                state=state,
                steps=combined_steps,
                mode=mode,
                failure_stage=exc.stage,
                reason=str(exc),
                transaction=transaction,
            )
        try:
            transaction.finalize()
        except IdentityAttestationError as exc:
            return _identity_attestation_failure(
                resolved,
                state=state,
                steps=combined_steps,
                mode=mode,
                failure_stage=exc.stage,
                reason=str(exc),
                transaction=transaction,
            )
        except RestartRequired as exc:
            return _transaction_failure(
                resolved,
                steps=combined_steps,
                mode=mode,
                failure_stage="cleanup",
                reason=str(exc),
                transaction=transaction,
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
        rollback_failed = False
        try:
            transaction.rollback()
        except BaseException:
            rollback_failed = True
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
        if rollback_failed:
            report["rollback_failed"] = True
        else:
            report["previous_install_restored"] = True
        return report, verify_exit
    failure_stage = verify_report["verify"].get("failure_stage")
    if failure_stage != "readiness":
        rollback_failed = False
        try:
            transaction.rollback()
        except BaseException:
            rollback_failed = True
        if rollback_failed:
            verify_report["rollback_failed"] = True
        return verify_report, verify_exit
    try:
        resolved = _require_exact_install_attestations(resolved, dependencies)
    except IdentityAttestationError as exc:
        return _identity_attestation_failure(
            resolved,
            state=state,
            steps=combined_steps,
            mode=mode,
            failure_stage=exc.stage,
            reason=str(exc),
            transaction=transaction,
        )
    try:
        transaction.finalize()
    except IdentityAttestationError as exc:
        return _identity_attestation_failure(
            resolved,
            state=state,
            steps=combined_steps,
            mode=mode,
            failure_stage=exc.stage,
            reason=str(exc),
            transaction=transaction,
        )
    except RestartRequired as exc:
        return _transaction_failure(
            resolved,
            steps=combined_steps,
            mode=mode,
            failure_stage="cleanup",
            reason=str(exc),
            transaction=transaction,
        )
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
    mutation_roots = _recapture_resolved_mutation_roots(resolved)
    if mutation_roots is None:
        reason = "The extension or receipt mutation roots could not be recaptured exactly"
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                failure_stage="mutation_roots",
                failure_reason=reason,
                next_steps=[],
            ),
            EXIT_PREFLIGHT,
        )
    resolved = replace(resolved, mutation_roots=mutation_roots)

    def require_mutation_roots() -> None:
        if _recapture_resolved_mutation_roots(resolved) is None:
            raise IdentityAttestationError(
                "The extension or receipt mutation roots could not be recaptured exactly",
                stage="mutation_roots",
            )

    try:
        remove_receipted_install(
            resolved.extension_path,
            resolved.receipt_path,
            before_mutation=require_mutation_roots,
            identity_paths=_attested_identity_paths(resolved),
        )
    except IdentityAttestationError as exc:
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                failure_stage=exc.stage,
                failure_reason=str(exc),
                next_steps=[],
            ),
            EXIT_PREFLIGHT,
        )
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
