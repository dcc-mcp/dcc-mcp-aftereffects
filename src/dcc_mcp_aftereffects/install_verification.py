"""Receipt state and verify-to-usable ownership."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .install_contract import EXIT_OK, EXIT_VERIFY, SCHEMA_VERSION
from .install_discovery import (
    PreflightError,
    _version_key,
    host_process_executable,
    recapture_host_attestation,
)
from .install_io import (
    read_receipt,
    receipt_files_match,
    write_bootstrap_error,
    write_receipt,
)
from .install_models import InstallRequest, ResolvedInstall
from .install_reporting import build_report, next_step, retry_command
from .runtime import AfterEffectsStatus, probe_aftereffects


def _same_path(left: Any, right: Any) -> bool:
    try:
        return os.path.normcase(str(Path(left).resolve())) == os.path.normcase(
            str(Path(right).resolve())
        )
    except (OSError, TypeError, ValueError):
        return False


def _bounded_text(value: Any, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and "\0" not in value


def _process_executable_path(pid: int) -> Path | None:
    if pid <= 0 or pid > 2_147_483_647:
        return None
    if sys.platform == "win32":
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            buffer = ctypes.create_unicode_buffer(32_768)
            size = wintypes.DWORD(len(buffer))
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return None
            return Path(buffer.value).resolve()
        finally:
            kernel32.CloseHandle(handle)
    if sys.platform == "darwin":
        buffer = ctypes.create_string_buffer(4096)
        try:
            libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
            length = int(libproc.proc_pidpath(int(pid), buffer, len(buffer)))
        except (OSError, AttributeError):
            return None
        return Path(buffer.value.decode("utf-8")).resolve() if length > 0 else None
    try:
        return Path(f"/proc/{pid}/exe").resolve(strict=True)
    except OSError:
        return None


def _process_start_identity(pid: int) -> str | None:
    if pid <= 0 or pid > 2_147_483_647:
        return None
    if sys.platform == "win32":
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            creation = wintypes.FILETIME()
            exit_time = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return None
            value = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
            return f"windows-filetime:{value}"
        finally:
            kernel32.CloseHandle(handle)
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "lstart="],
                capture_output=True,
                text=True,
                timeout=3,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        value = result.stdout.strip()
        return f"darwin-lstart:{value}" if result.returncode == 0 and value else None
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        closing = stat.rfind(") ")
        start_ticks = stat[closing + 2 :].split()[19]
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except (IndexError, OSError, ValueError):
        return None
    return f"linux:{boot_id}:{start_ticks}"


def observe_process_identity(pid: int) -> dict[str, Any]:
    path = _process_executable_path(pid)
    start = _process_start_identity(pid)
    if path is None or start is None:
        return {"ok": False}
    return {"ok": True, "executable": str(path), "process_start_identity": start}


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
    process_probe: Callable[[int], dict[str, Any]] = observe_process_identity
    receipt_writer: Callable[[Path, Mapping[str, Any]], None] = write_receipt
    host_attestation_probe: Callable[[Path, Mapping[str, Any]], dict[str, Any] | None] = (
        recapture_host_attestation
    )


def recapture_resolved_host(
    resolved: ResolvedInstall, dependencies: LifecycleDependencies
) -> dict[str, Any] | None:
    """Recapture the exact resolved identity through the injected trust boundary."""
    try:
        expected = dict(resolved.host_identity)
        if not expected:
            return None
        observed = dependencies.host_attestation_probe(resolved.host_path, expected)
        current = dict(observed) if observed is not None else None
    except (KeyError, OSError, TypeError, ValueError):
        return None
    return current if current == expected else None


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
    if (
        receipt.get("receipt_version") != 1
        or receipt.get("host_path") != str(resolved.host_path)
        or receipt.get("host_version") != resolved.host_version
        or not resolved.host_identity
        or receipt.get("host_identity") != dict(resolved.host_identity)
        or receipt.get("python") != str(resolved.python_path)
        or receipt.get("python_version") != resolved.python_version
        or receipt.get("target") != resolved.target
        or receipt.get("broker_url") != resolved.broker_url
        or (
            bool(resolved.python_modules)
            and receipt.get("python_modules") != dict(resolved.python_modules)
        )
        or (
            bool(resolved.bridge_identity)
            and receipt.get("bridge") != dict(resolved.bridge_identity)
        )
        or not receipt_files_match(receipt, resolved.extension_path)
    ):
        return "partial", receipt
    return "installed", receipt


def _runtime_identity_failure(
    stage: str, reason: str, error_type: str
) -> tuple[bool, str, str, str]:
    return False, stage, reason, error_type


def _validate_runtime_identity(
    status: AfterEffectsStatus,
    resolved: ResolvedInstall,
    process_probe: Callable[[int], dict[str, Any]],
) -> tuple[bool, str | None, str | None, str | None]:
    if not status.ready:
        return _runtime_identity_failure(
            "readiness",
            status.reason or "After Effects did not answer the typed readiness probe",
            status.error_type or "host_not_ready",
        )
    identity = status.identity
    if not isinstance(identity, Mapping):
        return _runtime_identity_failure(
            "readiness_identity",
            "The typed After Effects probe omitted exact runtime identity attestation",
            "runtime_identity_unavailable",
        )
    try:
        host_pid = int(identity["host_pid"])
        broker = identity["broker"]
        broker_pid = int(broker["pid"])
        connected_at = identity["connected_at_epoch_ms"]
    except (KeyError, TypeError, ValueError):
        return _runtime_identity_failure(
            "readiness_identity",
            "The typed After Effects probe omitted bounded process identity fields",
            "invalid_identity",
        )
    if not isinstance(broker, Mapping):
        return _runtime_identity_failure(
            "readiness_identity",
            "The typed After Effects probe omitted broker identity attestation",
            "invalid_identity",
        )
    expected_host_executable = host_process_executable(resolved.host_path)
    string_fields = (
        "process_start_identity",
        "process_executable",
        "instance_id",
        "profile_id",
        "plugin_root",
        "plugin_module_origin",
        "bridge_version",
    )
    broker_fields = ("process_start_identity", "executable", "version", "instance_id")
    if (
        host_pid <= 0
        or host_pid > 2_147_483_647
        or broker_pid <= 0
        or broker_pid > 2_147_483_647
        or isinstance(connected_at, bool)
        or not isinstance(connected_at, int)
        or connected_at <= 0
        or connected_at > 9_223_372_036_854_775_807
        or any(not _bounded_text(identity.get(key), 4_096) for key in string_fields)
        or any(not _bounded_text(broker.get(key), 4_096) for key in broker_fields)
    ):
        return _runtime_identity_failure(
            "readiness_identity",
            "The typed After Effects probe returned noncanonical identity fields",
            "invalid_identity",
        )
    try:
        _version_key(identity["host_version"])
        _version_key(identity["bridge_version"])
        _version_key(broker["version"])
    except (KeyError, PreflightError):
        return _runtime_identity_failure(
            "readiness_identity",
            "The typed After Effects probe returned a noncanonical version",
            "invalid_version",
        )
    if (
        identity.get("host") != "after-effects"
        or identity.get("bridge_kind") != "cep"
        or identity.get("target") != resolved.target
        or identity.get("host_version") != resolved.host_version
        or status.version != resolved.host_version
        or status.target != resolved.target
        or not _same_path(identity.get("process_executable"), expected_host_executable)
        or not _same_path(identity.get("plugin_root"), resolved.extension_path)
    ):
        return _runtime_identity_failure(
            "readiness_identity",
            "The ready CEP session does not match the selected After Effects instance",
            "identity_mismatch",
        )
    expected_broker = resolved.adobepy_cli or broker.get("executable")
    expected_broker_version = (
        resolved.bridge_identity.get("version")
        if resolved.bridge_identity
        else broker.get("version")
    )
    if (
        not _same_path(broker.get("executable"), expected_broker)
        or broker.get("version") != expected_broker_version
    ):
        return _runtime_identity_failure(
            "readiness_identity",
            "The ready broker differs from the audited adobepy runtime",
            "identity_mismatch",
        )
    try:
        module_origin = Path(identity["plugin_module_origin"]).resolve()
        module_origin.relative_to(resolved.extension_path.resolve())
    except (OSError, TypeError, ValueError):
        return _runtime_identity_failure(
            "readiness_identity",
            "The ready CEP module origin is outside the receipted extension",
            "wrong_plugin_origin",
        )
    if not module_origin.is_file():
        return _runtime_identity_failure(
            "readiness_identity",
            "The ready CEP module origin is missing from the receipted extension",
            "wrong_plugin_origin",
        )
    try:
        host_before = process_probe(host_pid)
        host_after = process_probe(host_pid)
        broker_before = process_probe(broker_pid)
        broker_after = process_probe(broker_pid)
    except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
        return _runtime_identity_failure(
            "readiness_identity",
            "The reported PID/start/path identity is stale or foreign",
            "process_identity_mismatch",
        )
    if (
        not all(
            isinstance(observed, Mapping)
            for observed in (host_before, host_after, broker_before, broker_after)
        )
        or host_before.get("ok") is not True
        or host_before != host_after
        or not _same_path(host_before.get("executable"), expected_host_executable)
        or host_before.get("process_start_identity") != identity["process_start_identity"]
        or broker_before.get("ok") is not True
        or broker_before != broker_after
        or not _same_path(broker_before.get("executable"), expected_broker)
        or broker_before.get("process_start_identity") != broker["process_start_identity"]
    ):
        return _runtime_identity_failure(
            "readiness_identity",
            "The reported PID/start/path identity is stale or foreign",
            "process_identity_mismatch",
        )
    return True, None, None, None


def verify_install(
    request: InstallRequest,
    resolved: ResolvedInstall,
    dependencies: LifecycleDependencies,
) -> tuple[dict[str, Any], int]:
    host_identity = recapture_resolved_host(resolved, dependencies)
    state, _receipt = installation_state(resolved)
    steps = [{"id": "receipt", "status": "ok" if state == "installed" else "failed"}]
    if host_identity is None:
        reason = "The signed After Effects host identity could not be recaptured exactly"
        steps.append({"id": "host-attestation", "status": "failed", "message": reason})
        return (
            build_report(
                resolved,
                status="failed",
                state=state,
                steps=steps,
                failure_stage="host_attestation",
                failure_reason=reason,
                next_steps=[],
            ),
            EXIT_VERIFY,
        )
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
    steps.append({"id": "host-attestation", "status": "ok"})
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
    identity_ok, failure_stage, failure_reason, error_type = _validate_runtime_identity(
        status, resolved, dependencies.process_probe
    )
    steps.append(
        {
            "id": "typed-readiness",
            "status": "ok" if identity_ok else "failed",
            "message": status.reason or failure_reason or "exact runtime identity verified",
        }
    )
    if not identity_ok:
        reason = failure_reason or "After Effects exact runtime identity could not be verified"
        write_bootstrap_error(
            resolved.bootstrap_error_path,
            failure_stage or "readiness",
            reason,
            resolved.token,
        )
        report = build_report(
            resolved,
            status="failed",
            state=state,
            steps=steps,
            failure_stage=failure_stage or "readiness",
            failure_reason=reason,
            next_steps=[next_step(retry_command(request), reason, "retry-verify")],
        )
        report["verify"]["error_type"] = error_type or "host_not_ready"
        return (
            report,
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


__all__ = [
    "LifecycleDependencies",
    "installation_state",
    "recapture_resolved_host",
    "verify_install",
]
