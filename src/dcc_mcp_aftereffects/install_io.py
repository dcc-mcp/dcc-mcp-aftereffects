"""Adapter-owned filesystem and external bridge installation I/O."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urlparse
from uuid import uuid4

from dcc_mcp_core.install_lifecycle import inspect_install_root, safe_remove_tree


class InstallIoError(RuntimeError):
    pass


class RestartRequired(InstallIoError):
    pass


class RollbackError(InstallIoError):
    pass


def _redact(value: str, secret: str | None) -> str:
    if secret:
        return value.replace(secret, "<redacted>")
    return value


def file_manifest(root: Path) -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == "adobepy.config.js":
            manifest.append({"path": relative, "sensitive": True})
        else:
            manifest.append(
                {"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            )
    return manifest


def write_receipt(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(dict(payload), indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_receipt(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def write_bootstrap_error(
    path: Path, stage: str, error: BaseException | str, secret: str | None
) -> None:
    message = _redact(str(error), secret)
    payload = {
        "schema_version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "error_type": error.__class__.__name__
        if isinstance(error, BaseException)
        else "RuntimeError",
        "message": message,
    }
    write_receipt(path, payload)


@contextmanager
def capture_bootstrap_errors(path: Path, stage: str, secret: str | None = None) -> Iterator[None]:
    try:
        yield
    except Exception as exc:
        try:
            write_bootstrap_error(path, stage, exc, secret)
        except Exception:
            pass
        raise


def run_adobepy_install_bridge(
    *,
    cli: Path,
    destination: Path,
    token: str,
    broker_url: str | None,
    target: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    if broker_url:
        parsed_broker = urlparse(broker_url)
        if (
            parsed_broker.scheme not in {"http", "https"}
            or not parsed_broker.hostname
            or parsed_broker.username is not None
            or parsed_broker.password is not None
        ):
            raise InstallIoError(
                "ADOBEPY_BROKER_URL must be an absolute HTTP URL without embedded credentials"
            )
    command = [
        str(cli),
        "install-bridge",
        "after-effects",
        "--dest",
        str(destination),
        "--kind",
        "cep",
        "--target",
        target,
        "--json",
    ]
    if broker_url:
        command.extend(["--broker-url", broker_url])
    environment = dict(os.environ)
    environment["ADOBEPY_TOKEN"] = token
    try:
        completed = runner(
            command,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallIoError("The supported adobepy install-bridge process could not run") from exc
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if token in stdout or token in stderr:
        raise InstallIoError("The external installer exposed a configured secret and was rejected")
    if completed.returncode != 0:
        raise InstallIoError(
            "adobepy install-bridge failed without returning a usable bridge payload"
        )
    try:
        metadata = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise InstallIoError("adobepy install-bridge returned invalid JSON") from exc
    expected_config = destination / "adobepy.config.js"
    if (
        not isinstance(metadata, dict)
        or metadata.get("host") != "after-effects"
        or metadata.get("kind") != "cep"
        or metadata.get("token_configured") is not True
        or Path(str(metadata.get("destination", ""))).resolve() != destination.resolve()
        or not expected_config.is_file()
    ):
        raise InstallIoError("adobepy install-bridge returned an incomplete or mismatched payload")
    return {
        "host": "after-effects",
        "kind": "cep",
        "destination": str(destination),
        "config": str(expected_config),
        "token_configured": True,
    }


def create_staging_dir(destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f".{destination.name}.stage-", dir=destination.parent))


def _locked_error(exc: OSError) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in {5, 32, 33}


def commit_staged_install(
    *,
    staged: Path,
    destination: Path,
    receipt: Mapping[str, Any],
    receipt_path: Path,
    receipt_writer: Callable[[Path, Mapping[str, Any]], None] = write_receipt,
) -> None:
    inspection = inspect_install_root(destination)
    if inspection.get("requires_restart"):
        raise RestartRequired(
            "The existing extension is loaded and must be released by After Effects"
        )
    backup = destination.with_name(f".{destination.name}.backup-{uuid4().hex}")
    moved_existing = False
    committed_new = False
    try:
        if destination.exists():
            os.replace(destination, backup)
            moved_existing = True
        os.replace(staged, destination)
        committed_new = True
        receipt_writer(receipt_path, receipt)
    except OSError as exc:
        rollback_failed = False
        try:
            if committed_new and destination.exists():
                removed = safe_remove_tree(destination)
                rollback_failed = not bool(removed.get("success"))
            if moved_existing and backup.exists() and not rollback_failed:
                os.replace(backup, destination)
        except OSError:
            rollback_failed = True
        if rollback_failed:
            raise RollbackError(
                "Install commit failed and the previous extension could not be restored"
            ) from exc
        if _locked_error(exc):
            raise RestartRequired(
                "After Effects holds a file lock on the extension directory"
            ) from exc
        raise RollbackError("Install commit failed; the previous extension was restored") from exc
    finally:
        if staged.exists():
            safe_remove_tree(staged)
    if backup.exists():
        cleanup = safe_remove_tree(backup)
        if not cleanup.get("success"):
            raise RestartRequired(
                "The previous extension backup is locked until After Effects restarts"
            )


def remove_receipted_install(destination: Path, receipt_path: Path) -> None:
    removed = safe_remove_tree(destination)
    if removed.get("requires_restart"):
        raise RestartRequired("After Effects holds the receipted extension open")
    if not removed.get("success"):
        raise InstallIoError(
            str(removed.get("message") or "Could not remove the receipted extension")
        )
    try:
        receipt_path.unlink(missing_ok=True)
    except OSError as exc:
        raise InstallIoError(
            "The extension was removed but its receipt could not be deleted"
        ) from exc


def remove_staging(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


__all__ = [
    "InstallIoError",
    "RestartRequired",
    "RollbackError",
    "capture_bootstrap_errors",
    "commit_staged_install",
    "create_staging_dir",
    "file_manifest",
    "read_receipt",
    "remove_receipted_install",
    "remove_staging",
    "run_adobepy_install_bridge",
    "write_bootstrap_error",
    "write_receipt",
]
