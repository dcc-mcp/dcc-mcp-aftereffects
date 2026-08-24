"""Adapter-owned filesystem and external bridge installation I/O."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
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


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_relative(value: Any) -> Path | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        return None
    return Path(*pure.parts)


def _safe_symlink_target(link_path: str, target: Any) -> bool:
    if not isinstance(target, str) or not target or len(target) > 4_096 or "\0" in target:
        return False
    normalized = target.replace("\\", "/")
    if PurePosixPath(normalized).is_absolute() or PureWindowsPath(target).is_absolute():
        return False
    stack = list(PurePosixPath(link_path).parent.parts)
    for part in PurePosixPath(normalized).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                return False
            stack.pop()
        else:
            stack.append(part)
    return bool(stack)


def file_manifest(root: Path) -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if len(manifest) >= 4_096:
            raise OSError("Bridge contains too many owned entries")
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            if not _safe_symlink_target(relative, target):
                raise OSError(f"Unsafe bridge symlink target: {relative}")
            contents = os.fsencode(target)
            manifest.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "target": target,
                    "bytes": len(contents),
                    "sha256": _sha256(contents),
                }
            )
        elif path.is_dir():
            manifest.append(
                {
                    "path": relative,
                    "type": "directory",
                    "bytes": 0,
                    "sha256": _sha256(("directory\0" + relative).encode("utf-8")),
                }
            )
        elif path.is_file():
            size = path.stat().st_size
            if size < 0 or size > 64 * 1024 * 1024 or total_bytes + size > 256 * 1024 * 1024:
                raise OSError(f"Bridge file exceeds bounded receipt limits: {relative}")
            contents = path.read_bytes()
            total_bytes += len(contents)
            entry = {
                "path": relative,
                "type": "file",
                "bytes": len(contents),
                "sha256": _sha256(contents),
            }
            if relative == "adobepy.config.js":
                entry["sensitive"] = True
            manifest.append(entry)
        else:
            raise OSError(f"Unsupported bridge entry type: {relative}")
    return manifest


def _manifest_digest(entries: list[dict[str, Any]]) -> str:
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256(payload)


def receipt_files_match(receipt: Mapping[str, Any], root: Path) -> bool:
    expected = receipt.get("files")
    if not isinstance(expected, list) or not expected:
        return False
    paths: set[Path] = set()
    for entry in expected:
        if not isinstance(entry, dict):
            return False
        relative = _safe_relative(entry.get("path"))
        if relative is None or relative in paths:
            return False
        paths.add(relative)
        if entry.get("type") not in {"file", "directory", "symlink"}:
            return False
        if not isinstance(entry.get("bytes"), int) or isinstance(entry.get("bytes"), bool):
            return False
        digest = entry.get("sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            return False
    try:
        actual = file_manifest(root)
    except OSError:
        return False
    return actual == expected and receipt.get("manifest_sha256") == _manifest_digest(expected)


def write_receipt(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        encoded = (json.dumps(dict(payload), indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > 1_048_576:
            raise OSError("Install receipt exceeds the bounded size limit")
        temporary.write_bytes(encoded)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_receipt(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > 1_048_576:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def write_bootstrap_error(
    path: Path, stage: str, error: BaseException | str, secret: str | None
) -> None:
    message = _redact(str(error), secret)[:2_048]
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
        try:
            broker_port = parsed_broker.port
        except ValueError as exc:
            raise InstallIoError("ADOBEPY_BROKER_URL has an invalid port") from exc
        if (
            parsed_broker.scheme != "http"
            or parsed_broker.hostname not in {"127.0.0.1", "localhost", "::1"}
            or broker_port is None
            or parsed_broker.username is not None
            or parsed_broker.password is not None
            or parsed_broker.path not in {"", "/"}
            or parsed_broker.query
            or parsed_broker.fragment
        ):
            raise InstallIoError(
                "ADOBEPY_BROKER_URL must be an uncredentialed loopback HTTP origin"
            )
    if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", target) is None:
        raise InstallIoError("ADOBEPY_TARGET must be a bounded canonical identifier")
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
    if (
        len(stdout.encode("utf-8", errors="replace")) > 65_536
        or len(stderr.encode("utf-8", errors="replace")) > 65_536
    ):
        raise InstallIoError("adobepy install-bridge returned unbounded output")
    if token in stdout or token in stderr:
        raise InstallIoError("The external installer exposed a configured secret and was rejected")
    if completed.returncode != 0:
        raise InstallIoError(
            "adobepy install-bridge failed without returning a usable bridge payload"
        )
    try:
        metadata = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise InstallIoError("adobepy install-bridge returned invalid JSON") from exc
    expected_config = destination / "adobepy.config.js"
    expected_manifest = destination / "manifest.xml"
    if (
        not isinstance(metadata, dict)
        or metadata.get("success") is not True
        or metadata.get("host") != "after-effects"
        or metadata.get("kind") != "cep"
        or metadata.get("token_configured") is not True
        or Path(str(metadata.get("destination", ""))).resolve() != destination.resolve()
        or not expected_config.is_file()
        or expected_config.is_symlink()
        or not expected_manifest.is_file()
        or expected_manifest.is_symlink()
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


def _replace_with_retry(source: Path, destination: Path) -> None:
    for attempt in range(3):
        try:
            os.replace(source, destination)
            return
        except OSError:
            if attempt == 2:
                raise
            time.sleep(0.05 * (attempt + 1))


def _write_receipt_bytes(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_bytes(contents)
        _replace_with_retry(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass
class InstallTransaction:
    destination: Path
    backup: Path
    receipt_path: Path
    old_receipt: bytes | None
    old_receipt_valid: bool
    moved_existing: bool = False
    committed_new: bool = False
    closed: bool = False

    def rollback(self) -> None:
        if self.closed:
            return
        failed = self.destination.with_name(f".{self.destination.name}.failed-{uuid4().hex}")
        try:
            if self.committed_new and self.destination.exists():
                _replace_with_retry(self.destination, failed)
            if self.moved_existing:
                if not self.backup.exists():
                    raise OSError("previous After Effects extension backup is missing")
                _replace_with_retry(self.backup, self.destination)
            if self.old_receipt is None:
                self.receipt_path.unlink(missing_ok=True)
            else:
                _write_receipt_bytes(self.receipt_path, self.old_receipt)
            if self.old_receipt_valid:
                restored = read_receipt(self.receipt_path)
                if restored is None or not receipt_files_match(restored, self.destination):
                    raise OSError("previous After Effects extension rollback did not validate")
            self.closed = True
        finally:
            if failed.exists():
                safe_remove_tree(failed)
            if self.closed and self.backup.exists():
                safe_remove_tree(self.backup)

    def finalize(self) -> None:
        if self.closed:
            return
        if self.backup.exists():
            cleanup = safe_remove_tree(self.backup)
            if not cleanup.get("success"):
                raise RestartRequired(
                    "The verified previous extension backup is locked until After Effects restarts"
                )
        self.closed = True


def commit_staged_install(
    *,
    staged: Path,
    destination: Path,
    receipt: dict[str, Any],
    receipt_path: Path,
    receipt_writer: Callable[[Path, Mapping[str, Any]], None] = write_receipt,
) -> InstallTransaction:
    inspection = inspect_install_root(destination)
    if inspection.get("requires_restart"):
        raise RestartRequired(
            "The existing extension is loaded and must be released by After Effects"
        )
    backup = destination.with_name(f".{destination.name}.backup-{uuid4().hex}")
    if receipt_path.is_file() and receipt_path.stat().st_size <= 1_048_576:
        old_receipt = receipt_path.read_bytes()
    else:
        old_receipt = None
    old_payload = read_receipt(receipt_path)
    transaction = InstallTransaction(
        destination=destination,
        backup=backup,
        receipt_path=receipt_path,
        old_receipt=old_receipt,
        old_receipt_valid=bool(
            old_payload is not None
            and destination.exists()
            and receipt_files_match(old_payload, destination)
        ),
    )
    try:
        if destination.exists():
            _replace_with_retry(destination, backup)
            transaction.moved_existing = True
        _replace_with_retry(staged, destination)
        transaction.committed_new = True
        receipt["receipt_version"] = 1
        receipt["files"] = file_manifest(destination)
        receipt["manifest_sha256"] = _manifest_digest(receipt["files"])
        receipt_writer(receipt_path, receipt)
        committed = read_receipt(receipt_path)
        if committed is None or not receipt_files_match(committed, destination):
            raise OSError("After Effects extension receipt did not validate after commit")
    except (OSError, TypeError, ValueError) as exc:
        try:
            transaction.rollback()
        except OSError:
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
    return transaction


def remove_receipted_install(destination: Path, receipt_path: Path) -> None:
    receipt = read_receipt(receipt_path)
    if receipt is None or not destination.is_dir() or not receipt_files_match(receipt, destination):
        raise InstallIoError("A complete matching After Effects receipt is required for uninstall")
    inspection = inspect_install_root(destination)
    if inspection.get("requires_restart"):
        raise RestartRequired("After Effects holds the receipted extension open")
    recovery = destination.with_name(f".{destination.name}.recovery-{uuid4().hex}")
    quarantine = destination.with_name(f".{destination.name}.uninstall-{uuid4().hex}")
    receipt_bytes = receipt_path.read_bytes()

    def cleanup(path: Path) -> bool:
        if not path.exists() and not path.is_symlink():
            return True
        result = safe_remove_tree(path)
        return bool(result.get("success")) and not path.exists()

    def restore() -> bool:
        try:
            cleanup(destination)
            shutil.copytree(recovery, destination, symlinks=True, copy_function=shutil.copy2)
            _write_receipt_bytes(receipt_path, receipt_bytes)
            restored = read_receipt(receipt_path)
            if restored is None or not receipt_files_match(restored, destination):
                raise OSError("After Effects uninstall recovery did not validate")
        except OSError:
            return False
        cleanup(quarantine)
        cleanup(recovery)
        return True

    moved = False
    try:
        shutil.copytree(destination, recovery, symlinks=True, copy_function=shutil.copy2)
        if not receipt_files_match(receipt, recovery):
            raise OSError("After Effects uninstall recovery snapshot did not validate")
        _replace_with_retry(destination, quarantine)
        moved = True
        if not cleanup(quarantine):
            raise PermissionError("After Effects extension cleanup is locked")
        receipt_path.unlink()
    except OSError as exc:
        if not moved:
            cleanup(recovery)
            if _locked_error(exc):
                raise RestartRequired("After Effects holds the receipted extension open") from exc
            raise InstallIoError(
                "Uninstall staging failed; no extension files were removed"
            ) from exc
        if not restore():
            raise RollbackError(
                "Uninstall failed and the receipted extension requires operator recovery"
            ) from exc
        if _locked_error(exc):
            raise RestartRequired("Uninstall was rolled back because files remain locked") from exc
        raise InstallIoError("Uninstall failed; the receipted extension was restored") from exc
    if not cleanup(recovery):
        if restore():
            raise RestartRequired("Uninstall cleanup failed; the extension was restored")
        raise RollbackError("Uninstall cleanup failed and recovery requires operator action")


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
