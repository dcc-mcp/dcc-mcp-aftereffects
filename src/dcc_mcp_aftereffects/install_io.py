"""Adapter-owned filesystem and external bridge installation I/O."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urlparse
from uuid import uuid4

from dcc_mcp_core.install_lifecycle import inspect_install_root, safe_remove_tree

from .install_discovery import reattest_bridge_cli

if os.name == "nt":
    from ctypes import wintypes as _wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", _wintypes.DWORD),
            ("creation_time", _wintypes.FILETIME),
            ("access_time", _wintypes.FILETIME),
            ("write_time", _wintypes.FILETIME),
            ("volume_serial", _wintypes.DWORD),
            ("size_high", _wintypes.DWORD),
            ("size_low", _wintypes.DWORD),
            ("links", _wintypes.DWORD),
            ("file_index_high", _wintypes.DWORD),
            ("file_index_low", _wintypes.DWORD),
        ]

    class _FileRenameInformation(ctypes.Structure):
        _fields_ = [
            ("replace_if_exists", ctypes.c_ubyte),
            ("root_directory", _wintypes.HANDLE),
            ("file_name_length", _wintypes.DWORD),
            ("file_name", _wintypes.WCHAR * 1),
        ]

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _KERNEL32.CreateFileW.argtypes = [
        _wintypes.LPCWSTR,
        _wintypes.DWORD,
        _wintypes.DWORD,
        _wintypes.LPVOID,
        _wintypes.DWORD,
        _wintypes.DWORD,
        _wintypes.HANDLE,
    ]
    _KERNEL32.CreateFileW.restype = _wintypes.HANDLE
    _KERNEL32.GetFileInformationByHandle.argtypes = [
        _wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    _KERNEL32.GetFileInformationByHandle.restype = _wintypes.BOOL
    _KERNEL32.SetFilePointerEx.argtypes = [
        _wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        _wintypes.DWORD,
    ]
    _KERNEL32.SetFilePointerEx.restype = _wintypes.BOOL
    _KERNEL32.ReadFile.argtypes = [
        _wintypes.HANDLE,
        _wintypes.LPVOID,
        _wintypes.DWORD,
        ctypes.POINTER(_wintypes.DWORD),
        _wintypes.LPVOID,
    ]
    _KERNEL32.ReadFile.restype = _wintypes.BOOL
    _KERNEL32.SetFileInformationByHandle.argtypes = [
        _wintypes.HANDLE,
        ctypes.c_int,
        _wintypes.LPVOID,
        _wintypes.DWORD,
    ]
    _KERNEL32.SetFileInformationByHandle.restype = _wintypes.BOOL
    _KERNEL32.CloseHandle.argtypes = [_wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = _wintypes.BOOL


class InstallIoError(RuntimeError):
    pass


class RestartRequired(InstallIoError):
    pass


class RollbackError(InstallIoError):
    pass


class IdentityAttestationError(InstallIoError):
    def __init__(self, message: str, *, stage: str = "python_attestation"):
        super().__init__(message)
        self.stage = stage
        self.rollback_failed = False


class ReceiptCallbackError(InstallIoError):
    def __init__(self, message: str):
        super().__init__(message)
        self.rollback_failed = False


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

    def visit(directory: Path) -> Iterator[Path]:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise OSError("Bridge directory could not be inspected safely") from exc
        for entry in entries:
            path = Path(entry.path)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise OSError("Bridge entry could not be inspected safely") from exc
            is_link = stat.S_ISLNK(metadata.st_mode)
            is_reparse = bool(
                getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
            if is_reparse and not is_link:
                raise OSError("Bridge contains an unsupported directory reparse point")
            yield path
            if stat.S_ISDIR(metadata.st_mode):
                yield from visit(path)

    for path in visit(root):
        if len(manifest) >= 4_096:
            raise OSError("Bridge contains too many owned entries")
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
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
        elif stat.S_ISDIR(metadata.st_mode):
            manifest.append(
                {
                    "path": relative,
                    "type": "directory",
                    "bytes": 0,
                    "sha256": _sha256(("directory\0" + relative).encode("utf-8")),
                }
            )
        elif stat.S_ISREG(metadata.st_mode):
            size = metadata.st_size
            if size < 0 or size > 64 * 1024 * 1024 or total_bytes + size > 256 * 1024 * 1024:
                raise OSError(f"Bridge file exceeds bounded receipt limits: {relative}")
            contents = path.read_bytes()
            after = path.lstat()
            if (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            ):
                raise OSError(f"Bridge file changed during receipt capture: {relative}")
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


def _receipt_from_bytes(contents: bytes) -> dict[str, Any] | None:
    if len(contents) > 1_048_576:
        return None
    try:
        value = json.loads(contents.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
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
    expected_identity: Mapping[str, Any],
    destination: Path,
    token: str,
    broker_url: str | None,
    target: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    if not reattest_bridge_cli(cli, expected_identity):
        raise InstallIoError("The audited adobepy CLI identity changed before execution")
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


def prepare_install_directories(
    paths: tuple[Path, ...],
    *,
    before_mutation: Callable[[], None],
    identity_paths: tuple[Path, ...],
    capture_after: Callable[[], Any],
) -> Any:
    """Create missing mutation ancestors one level at a time under the identity lease."""
    created: dict[str, dict[str, int]] = {}

    def directory_identity(path: Path) -> dict[str, int]:
        details = path.lstat()
        if stat.S_ISLNK(details.st_mode) or bool(
            getattr(details, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise IdentityAttestationError(
                "A mutation-root ancestor crossed a link or reparse boundary",
                stage="mutation_roots",
            )
        if not stat.S_ISDIR(details.st_mode):
            raise IdentityAttestationError(
                "A mutation-root ancestor is not a directory",
                stage="mutation_roots",
            )
        return {
            "device": int(details.st_dev),
            "inode": int(details.st_ino),
            "mode": int(details.st_mode),
        }

    def require_created_identities() -> None:
        if any(directory_identity(Path(path)) != expected for path, expected in created.items()):
            raise IdentityAttestationError(
                "A newly created mutation-root ancestor changed identity",
                stage="mutation_roots",
            )

    with ExitStack() as leases:
        leases.enter_context(_hold_identity_paths(identity_paths))
        before_mutation()
        for target in paths:
            parent = Path(os.path.abspath(target)).parent
            current = Path(parent.anchor)
            for part in parent.parts[1:]:
                current /= part
                if current.exists() or current.is_symlink():
                    require_created_identities()
                    before_mutation()
                    continue
                if os.name == "nt":
                    provisional = Path(
                        tempfile.mkdtemp(prefix=f".{current.name}.create-", dir=current.parent)
                    )
                    expected = directory_identity(provisional)
                    try:
                        require_created_identities()
                        before_mutation()
                        os.rename(provisional, current)
                    except OSError:
                        require_created_identities()
                        before_mutation()
                        raise IdentityAttestationError(
                            "A mutation-root ancestor appeared inside the creation boundary",
                            stage="mutation_roots",
                        ) from None
                    finally:
                        if provisional.exists():
                            safe_remove_tree(provisional)
                else:
                    try:
                        current.mkdir()
                    except FileExistsError:
                        before_mutation()
                        raise IdentityAttestationError(
                            "A mutation-root ancestor appeared inside the creation boundary",
                            stage="mutation_roots",
                        ) from None
                    expected = directory_identity(current)
                leases.enter_context(_hold_identity_paths((current,)))
                if directory_identity(current) != expected:
                    raise IdentityAttestationError(
                        "A newly created mutation-root ancestor changed identity",
                        stage="mutation_roots",
                    )
                created[os.path.normcase(str(current.absolute()))] = expected
                require_created_identities()
                before_mutation()
        require_created_identities()
        before_mutation()
        captured = capture_after()
        require_created_identities()
        return captured


def create_staging_dir(
    destination: Path,
    *,
    before_mutation: Callable[[], None] | None = None,
    identity_paths: tuple[Path, ...] = (),
) -> Path:
    with _hold_identity_paths(identity_paths):
        if before_mutation is not None:
            before_mutation()
        return Path(tempfile.mkdtemp(prefix=f".{destination.name}.stage-", dir=destination.parent))


def _locked_error(exc: OSError) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in {5, 32, 33}


@contextmanager
def _hold_identity_paths(paths: tuple[Path, ...]) -> Iterator[None]:
    """Keep exact attested Windows objects non-replaceable through one mutation."""
    handles: list[Any] = []
    locked = {os.path.normcase(str(Path(path).absolute())) for path in paths}
    try:
        if os.name == "nt":
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            kernel32.CreateFileW.restype = wintypes.HANDLE
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            invalid = wintypes.HANDLE(-1).value
            for path in paths:
                flags = 0x02000000 if path.is_dir() else 0
                handle = kernel32.CreateFileW(
                    str(path),
                    0x80,
                    0x3 if path.is_dir() else 0x1,
                    None,
                    3,
                    flags,
                    None,
                )
                if handle == invalid:
                    raise ctypes.WinError(ctypes.get_last_error())
                handles.append((kernel32, handle))
        else:
            for path in paths:
                handles.append(os.open(path, os.O_RDONLY))
        yield
    except OSError as exc:
        error_paths = {
            os.path.normcase(str(Path(value).absolute()))
            for value in (getattr(exc, "filename", None), getattr(exc, "filename2", None))
            if value
        }
        if error_paths & locked:
            raise IdentityAttestationError(
                "An attested install identity changed inside the mutation boundary",
                stage="identity_attestation",
            ) from exc
        raise
    finally:
        for handle in reversed(handles):
            if os.name == "nt":
                kernel32, native = handle
                kernel32.CloseHandle(native)
            else:
                os.close(handle)


@dataclass
class _ExactObjectLease:
    """Bind one checked filesystem object to its native handle for a transaction."""

    path: Path
    physical: Mapping[str, int]
    is_directory: bool
    native_handle: Any | None = None
    file_descriptor: int | None = None
    closed: bool = False

    @classmethod
    def acquire(cls, path: Path) -> _ExactObjectLease:
        path = Path(os.path.abspath(path))
        if os.name != "nt":
            descriptor = os.open(path, os.O_RDONLY)
            details = os.fstat(descriptor)
            return cls(
                path=path,
                physical={
                    "device": int(details.st_dev),
                    "inode": int(details.st_ino),
                    "mode": int(details.st_mode),
                },
                is_directory=stat.S_ISDIR(details.st_mode),
                file_descriptor=descriptor,
            )

        invalid = _wintypes.HANDLE(-1).value
        desired_access = 0x00010000 | 0x00000080
        if not path.is_dir():
            desired_access |= 0x80000000
        handle = _KERNEL32.CreateFileW(
            str(path),
            desired_access,
            0x1 | 0x2,
            None,
            3,
            0x02000000 | 0x00200000,
            None,
        )
        if handle == invalid:
            raise ctypes.WinError(ctypes.get_last_error())
        information = _ByHandleFileInformation()
        if not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information)):
            error = ctypes.WinError(ctypes.get_last_error())
            _KERNEL32.CloseHandle(handle)
            raise error
        if information.attributes & 0x400:
            _KERNEL32.CloseHandle(handle)
            raise IdentityAttestationError(
                "A checked extension or receipt object crossed a link or reparse boundary",
                stage="identity_attestation",
            )
        is_directory = bool(information.attributes & 0x10)
        return cls(
            path=path,
            physical={
                "volume_serial": int(information.volume_serial),
                "file_index_high": int(information.file_index_high),
                "file_index_low": int(information.file_index_low),
                "attributes": int(information.attributes),
                "links": int(information.links),
                "size": (int(information.size_high) << 32) | int(information.size_low),
            },
            is_directory=is_directory,
            native_handle=handle,
        )

    def read_bytes(self, *, maximum: int = 1_048_576) -> bytes:
        self._require_open()
        if self.is_directory:
            raise IsADirectoryError(str(self.path))
        if os.name != "nt":
            if self.file_descriptor is None:
                raise OSError("exact-object descriptor is unavailable")
            os.lseek(self.file_descriptor, 0, os.SEEK_SET)
            contents = os.read(self.file_descriptor, maximum + 1)
        else:
            size = int(self.physical.get("size", maximum + 1))
            if size > maximum:
                raise OSError("checked receipt exceeds the bounded size limit")
            if not _KERNEL32.SetFilePointerEx(self.native_handle, 0, None, 0):
                raise ctypes.WinError(ctypes.get_last_error())
            buffer = ctypes.create_string_buffer(size)
            read = _wintypes.DWORD()
            if not _KERNEL32.ReadFile(
                self.native_handle,
                buffer,
                size,
                ctypes.byref(read),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            contents = buffer.raw[: read.value]
        if len(contents) > maximum:
            raise OSError("checked receipt exceeds the bounded size limit")
        return contents

    def _require_open(self) -> None:
        if self.closed:
            raise OSError("exact-object lease is already closed")

    def rename(self, destination: Path, *, replace: bool = False) -> None:
        self._require_open()
        destination = Path(os.path.abspath(destination))
        if os.name != "nt":
            current = self.path.stat()
            expected = (
                self.physical["device"],
                self.physical["inode"],
                self.physical["mode"],
            )
            if (int(current.st_dev), int(current.st_ino), int(current.st_mode)) != expected:
                raise IdentityAttestationError(
                    "A checked extension or receipt object changed inside the transaction",
                    stage="identity_attestation",
                )
            if replace:
                os.replace(self.path, destination)
            else:
                os.rename(self.path, destination)
            self.path = destination
            return

        encoded = str(destination).encode("utf-16-le")
        offset = _FileRenameInformation.file_name.offset
        buffer = ctypes.create_string_buffer(offset + len(encoded) + ctypes.sizeof(_wintypes.WCHAR))
        information = ctypes.cast(buffer, ctypes.POINTER(_FileRenameInformation)).contents
        information.replace_if_exists = int(replace)
        information.root_directory = None
        information.file_name_length = len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + offset, encoded, len(encoded))
        if not _KERNEL32.SetFileInformationByHandle(
            self.native_handle,
            3,
            buffer,
            offset + len(encoded),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        self.path = destination

    def delete(self) -> None:
        self._require_open()
        if os.name != "nt":
            if self.is_directory:
                self.path.rmdir()
            else:
                self.path.unlink()
            self.close()
            return

        delete_file = _wintypes.BOOLEAN(1)
        if not _KERNEL32.SetFileInformationByHandle(
            self.native_handle,
            4,
            ctypes.byref(delete_file),
            ctypes.sizeof(delete_file),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        self.close()

    def close(self) -> None:
        if self.closed:
            return
        if os.name == "nt":
            _KERNEL32.CloseHandle(self.native_handle)
        elif self.file_descriptor is not None:
            os.close(self.file_descriptor)
        self.closed = True


def _delete_leased_tree(lease: _ExactObjectLease) -> dict[str, Any]:
    cleanup = safe_remove_tree(lease.path)
    if lease.path.exists():
        try:
            if not lease.path.is_dir() or any(lease.path.iterdir()):
                return cleanup
            lease.delete()
        except OSError as exc:
            errors = list(cleanup.get("errors", [])) if isinstance(cleanup, dict) else []
            errors.append(str(exc))
            return {"success": False, "errors": errors}
    return {"success": not lease.path.exists(), "errors": []}


def _replace_with_retry(
    source: Path,
    destination: Path,
    *,
    before_mutation: Callable[[], None] | None = None,
    identity_paths: tuple[Path, ...] = (),
) -> None:
    for attempt in range(3):
        try:
            with _hold_identity_paths(identity_paths):
                if before_mutation is not None:
                    before_mutation()
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
    receipt_backup: Path | None = None
    moved_existing: bool = False
    moved_receipt: bool = False
    committed_new: bool = False
    closed: bool = False
    recovery_archive: Path | None = None
    identity_attestor: Callable[[], bool] | None = None
    identity_paths: tuple[Path, ...] = ()
    mutation_root_attestor: Callable[[], bool] | None = None
    mutation_root_paths: tuple[Path, ...] = ()
    previous_extension_lease: _ExactObjectLease | None = None
    previous_receipt_lease: _ExactObjectLease | None = None

    @staticmethod
    def _require_attestation(
        attestor: Callable[[], bool] | None,
        *,
        stage: str,
        message: str,
    ) -> None:
        if attestor is None:
            return
        try:
            verified = attestor()
        except IdentityAttestationError:
            raise
        except BaseException as exc:
            raise IdentityAttestationError(message, stage=stage) from exc
        if verified is not True:
            raise IdentityAttestationError(message, stage=stage)

    def _require_identity(self) -> None:
        self._require_attestation(
            self.identity_attestor,
            stage="identity_attestation",
            message="The install identities could not be recaptured exactly",
        )

    def _require_mutation_roots(self) -> None:
        self._require_attestation(
            self.mutation_root_attestor,
            stage="mutation_roots",
            message="The extension or receipt mutation roots could not be recaptured exactly",
        )

    def _prior_receipt(self) -> dict[str, Any] | None:
        if self.old_receipt is None or not self.old_receipt_valid:
            return None
        try:
            payload = json.loads(self.old_receipt.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def _require_previous_receipt_object(self) -> None:
        if (
            self.old_receipt is None
            or self.previous_receipt_lease is None
            or self.previous_receipt_lease.read_bytes() != self.old_receipt
        ):
            raise IdentityAttestationError(
                "The checked receipt object changed inside the transaction",
                stage="identity_attestation",
            )

    def _release_exact_object_leases(self) -> None:
        if self.previous_extension_lease is not None:
            self.previous_extension_lease.close()
            self.previous_extension_lease = None
        if self.previous_receipt_lease is not None:
            self.previous_receipt_lease.close()
            self.previous_receipt_lease = None

    def rollback(self) -> None:
        if self.closed:
            return
        failed = self.destination.with_name(f".{self.destination.name}.failed-{uuid4().hex}")
        try:
            with _hold_identity_paths(self.mutation_root_paths):
                self._require_mutation_roots()
                if self.committed_new and self.destination.exists():
                    self._require_mutation_roots()
                    _replace_with_retry(self.destination, failed)
                if self.moved_existing:
                    prior_receipt = self._prior_receipt()
                    self._require_mutation_roots()
                    if prior_receipt is not None and receipt_files_match(
                        prior_receipt, self.backup
                    ):
                        if self.previous_extension_lease is None:
                            raise OSError("previous extension object lease is unavailable")
                        self.previous_extension_lease.rename(self.destination)
                    elif self.recovery_archive is not None and prior_receipt is not None:
                        if self.previous_extension_lease is not None:
                            cleanup = _delete_leased_tree(self.previous_extension_lease)
                            if not cleanup.get("success"):
                                raise OSError("previous extension backup could not be retired")
                            self.previous_extension_lease = None
                        _restore_recovery_archive(
                            self.recovery_archive,
                            self.destination,
                            prior_receipt,
                        )
                    else:
                        raise OSError("previous After Effects extension backup is unavailable")
                if self.moved_receipt:
                    self._require_mutation_roots()
                    if (
                        self.receipt_backup is not None
                        and self.receipt_backup.exists()
                        and self.previous_receipt_lease is not None
                    ):
                        self._require_previous_receipt_object()
                        self.previous_receipt_lease.rename(self.receipt_path, replace=True)
                    elif self.old_receipt is not None:
                        _write_receipt_bytes(self.receipt_path, self.old_receipt)
                    else:
                        raise OSError("previous After Effects receipt backup is unavailable")
                elif self.old_receipt is None:
                    self._require_mutation_roots()
                    self.receipt_path.unlink(missing_ok=True)
                if self.old_receipt_valid:
                    if self.previous_receipt_lease is not None:
                        restored = _receipt_from_bytes(self.previous_receipt_lease.read_bytes())
                    else:
                        restored = read_receipt(self.receipt_path)
                    if restored is None or not receipt_files_match(restored, self.destination):
                        raise OSError("previous After Effects extension rollback did not validate")
                self.closed = True
        finally:
            if failed.exists():
                self._require_mutation_roots()
                safe_remove_tree(failed)
            if self.closed and self.backup.exists():
                self._require_mutation_roots()
                if self.previous_extension_lease is not None:
                    _delete_leased_tree(self.previous_extension_lease)
                    self.previous_extension_lease = None
                else:
                    safe_remove_tree(self.backup)
            if self.closed and self.recovery_archive is not None:
                try:
                    self._require_mutation_roots()
                    self.recovery_archive.unlink(missing_ok=True)
                except OSError:
                    pass
            if self.closed and self.receipt_backup is not None and self.receipt_backup.exists():
                self._require_mutation_roots()
                if self.previous_receipt_lease is not None:
                    self.previous_receipt_lease.delete()
                    self.previous_receipt_lease = None
                else:
                    self.receipt_backup.unlink(missing_ok=True)
            self._release_exact_object_leases()

    def finalize(self) -> None:
        if self.closed:
            return
        with _hold_identity_paths(self.identity_paths):
            self._require_identity()
            if self.backup.exists():
                prior_receipt = self._prior_receipt()
                if prior_receipt is None or not receipt_files_match(prior_receipt, self.backup):
                    raise RestartRequired(
                        "The previous extension backup could not be captured for safe cleanup"
                    )
                recovery_archive = self.backup.with_name(
                    f".{self.backup.name}.recovery-{uuid4().hex}.zip"
                )
                try:
                    self._require_identity()
                    _write_recovery_archive(self.backup, prior_receipt, recovery_archive)
                    _validate_recovery_archive(recovery_archive, self.backup, prior_receipt)
                except BaseException as exc:
                    try:
                        recovery_archive.unlink(missing_ok=True)
                    except BaseException:
                        pass
                    if isinstance(exc, IdentityAttestationError):
                        raise
                    raise RestartRequired(
                        "The previous extension backup could not be captured for safe cleanup"
                    ) from exc
                self.recovery_archive = recovery_archive
                try:
                    self._require_identity()
                    if self.previous_extension_lease is None:
                        raise IdentityAttestationError(
                            "The checked extension object lease was lost before cleanup",
                            stage="identity_attestation",
                        )
                    cleanup = _delete_leased_tree(self.previous_extension_lease)
                except IdentityAttestationError:
                    raise
                except BaseException as exc:
                    raise RestartRequired(
                        "The verified previous extension backup could not be cleaned safely"
                    ) from exc
                if not cleanup.get("success"):
                    raise RestartRequired(
                        "The verified previous extension backup is locked until After Effects "
                        "restarts"
                    )
                self.previous_extension_lease = None
            if self.receipt_backup is not None and self.receipt_backup.exists():
                try:
                    self._require_identity()
                    if self.previous_receipt_lease is None:
                        raise IdentityAttestationError(
                            "The checked receipt object lease was lost before cleanup",
                            stage="identity_attestation",
                        )
                    self._require_previous_receipt_object()
                    self.previous_receipt_lease.delete()
                except IdentityAttestationError:
                    raise
                except BaseException as exc:
                    raise RestartRequired(
                        "The previous receipt transaction snapshot could not be cleaned safely"
                    ) from exc
                self.previous_receipt_lease = None
            if self.recovery_archive is not None and self.recovery_archive.exists():
                try:
                    self._require_identity()
                    self.recovery_archive.unlink()
                except IdentityAttestationError:
                    raise
                except BaseException as exc:
                    raise RestartRequired(
                        "The previous extension recovery snapshot could not be cleaned safely"
                    ) from exc
            self.receipt_backup = None
            self.recovery_archive = None
            self.closed = True
            self._release_exact_object_leases()


def commit_staged_install(
    *,
    staged: Path,
    destination: Path,
    receipt: dict[str, Any],
    receipt_path: Path,
    receipt_writer: Callable[[Path, Mapping[str, Any]], None] = write_receipt,
    identity_attestor: Callable[[], bool] | None = None,
    identity_paths: tuple[Path, ...] = (),
    mutation_root_attestor: Callable[[], bool] | None = None,
    mutation_root_paths: tuple[Path, ...] = (),
) -> InstallTransaction:
    previous_extension_lease = (
        _ExactObjectLease.acquire(destination)
        if destination.exists() or destination.is_symlink()
        else None
    )
    try:
        previous_receipt_lease = (
            _ExactObjectLease.acquire(receipt_path)
            if receipt_path.exists() or receipt_path.is_symlink()
            else None
        )
    except BaseException:
        if previous_extension_lease is not None:
            previous_extension_lease.close()
        raise
    try:
        inspection = inspect_install_root(destination)
        if inspection.get("requires_restart"):
            raise RestartRequired(
                "The existing extension is loaded and must be released by After Effects"
            )
        backup = destination.with_name(f".{destination.name}.backup-{uuid4().hex}")
        receipt_backup = receipt_path.with_name(f".{receipt_path.name}.backup-{uuid4().hex}")
        if previous_receipt_lease is not None and not previous_receipt_lease.is_directory:
            try:
                old_receipt = previous_receipt_lease.read_bytes()
            except OSError:
                old_receipt = None
        else:
            old_receipt = None
        old_payload = _receipt_from_bytes(old_receipt) if old_receipt is not None else None
    except BaseException:
        if previous_extension_lease is not None:
            previous_extension_lease.close()
        if previous_receipt_lease is not None:
            previous_receipt_lease.close()
        raise
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
        receipt_backup=receipt_backup if old_receipt is not None else None,
        identity_attestor=identity_attestor,
        identity_paths=identity_paths,
        mutation_root_attestor=mutation_root_attestor,
        mutation_root_paths=mutation_root_paths,
        previous_extension_lease=previous_extension_lease,
        previous_receipt_lease=previous_receipt_lease,
    )

    def require_identity() -> None:
        if identity_attestor is None:
            return
        try:
            verified = identity_attestor()
        except IdentityAttestationError:
            raise
        except BaseException as exc:
            raise IdentityAttestationError(
                "The install identities could not be recaptured exactly",
                stage="identity_attestation",
            ) from exc
        if verified is not True:
            raise IdentityAttestationError(
                "The target Python package identities could not be recaptured exactly"
            )

    def rename_checked_object(lease: _ExactObjectLease, target: Path) -> None:
        with _hold_identity_paths(identity_paths):
            require_identity()
            lease.rename(target)

    try:
        require_identity()
        if destination.exists():
            if transaction.previous_extension_lease is None:
                raise IdentityAttestationError(
                    "The checked extension object lease was unavailable before backup",
                    stage="identity_attestation",
                )
            rename_checked_object(transaction.previous_extension_lease, backup)
            transaction.moved_existing = True
        if transaction.receipt_backup is not None:
            if transaction.previous_receipt_lease is None:
                raise IdentityAttestationError(
                    "The checked receipt object lease was unavailable before backup",
                    stage="identity_attestation",
                )
            transaction._require_previous_receipt_object()
            rename_checked_object(transaction.previous_receipt_lease, transaction.receipt_backup)
            transaction.moved_receipt = True
        _replace_with_retry(
            staged,
            destination,
            before_mutation=require_identity,
            identity_paths=identity_paths,
        )
        transaction.committed_new = True
        receipt["receipt_version"] = 1
        receipt["files"] = file_manifest(destination)
        receipt["manifest_sha256"] = _manifest_digest(receipt["files"])
        try:
            with _hold_identity_paths(identity_paths):
                require_identity()
                receipt_writer(receipt_path, receipt)
        except IdentityAttestationError:
            raise
        except BaseException as exc:
            callback_error = ReceiptCallbackError(
                "The receipt callback failed after install mutation"
            )
            try:
                transaction.rollback()
            except BaseException:
                callback_error.rollback_failed = True
            raise callback_error from exc
        committed = read_receipt(receipt_path)
        if committed is None or not receipt_files_match(committed, destination):
            raise OSError("After Effects extension receipt did not validate after commit")
    except IdentityAttestationError as exc:
        try:
            transaction.rollback()
        except BaseException:
            exc.rollback_failed = True
        raise
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


def _write_recovery_archive(
    source: Path,
    receipt: Mapping[str, Any],
    archive_path: Path,
) -> None:
    entries = receipt.get("files")
    if not isinstance(entries, list) or not receipt_files_match(receipt, source):
        raise OSError("After Effects recovery source does not match its receipt")
    temporary = archive_path.with_name(f".{archive_path.name}.{uuid4().hex}.tmp")
    try:
        with zipfile.ZipFile(temporary, mode="x", compression=zipfile.ZIP_STORED) as archive:
            for entry in entries:
                relative = _safe_relative(entry.get("path")) if isinstance(entry, dict) else None
                if relative is None:
                    raise OSError("After Effects recovery receipt contains an unsafe path")
                source_path = source / relative
                entry_type = entry.get("type")
                if entry_type == "directory":
                    contents = b""
                elif entry_type == "symlink":
                    contents = os.fsencode(os.readlink(source_path))
                elif entry_type == "file":
                    contents = source_path.read_bytes()
                else:
                    raise OSError("After Effects recovery receipt contains an unsupported entry")
                if len(contents) != entry.get("bytes") or _sha256(contents) != entry.get("sha256"):
                    raise OSError("After Effects recovery source changed during snapshot")
                archive.writestr(relative.as_posix(), contents)
        _replace_with_retry(temporary, archive_path)
    finally:
        temporary.unlink(missing_ok=True)


def _restore_recovery_archive(
    archive_path: Path,
    destination: Path,
    receipt: Mapping[str, Any],
) -> None:
    entries = receipt.get("files")
    if not isinstance(entries, list):
        raise OSError("After Effects recovery receipt is invalid")
    expected = {
        entry.get("path"): entry
        for entry in entries
        if isinstance(entry, dict) and _safe_relative(entry.get("path")) is not None
    }
    if len(expected) != len(entries):
        raise OSError("After Effects recovery receipt contains duplicate or unsafe paths")
    staging = destination.with_name(f".{destination.name}.restore-{uuid4().hex}")
    try:
        with zipfile.ZipFile(archive_path, mode="r") as archive:
            members = archive.infolist()
            if len(members) != len(expected) or {member.filename for member in members} != set(
                expected
            ):
                raise OSError("After Effects recovery archive does not match its receipt")
            for member in sorted(
                members, key=lambda item: (len(PurePosixPath(item.filename).parts), item.filename)
            ):
                entry = expected[member.filename]
                relative = _safe_relative(member.filename)
                if relative is None or member.file_size != entry.get("bytes"):
                    raise OSError("After Effects recovery archive contains an invalid entry")
                contents = archive.read(member)
                if len(contents) != entry.get("bytes") or _sha256(contents) != entry.get("sha256"):
                    raise OSError("After Effects recovery archive entry failed validation")
                output = staging / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                if entry.get("type") == "directory":
                    if contents:
                        raise OSError("After Effects recovery directory entry is not empty")
                    output.mkdir(exist_ok=True)
                elif entry.get("type") == "symlink":
                    target = os.fsdecode(contents)
                    if not _safe_symlink_target(member.filename, target):
                        raise OSError("After Effects recovery symlink target is unsafe")
                    os.symlink(target, output)
                elif entry.get("type") == "file":
                    output.write_bytes(contents)
                else:
                    raise OSError("After Effects recovery archive contains an unsupported entry")
        if not receipt_files_match(receipt, staging):
            raise OSError(
                "After Effects recovery archive did not restore the exact receipt closure"
            )
        _replace_with_retry(staging, destination)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        if staging.exists() or staging.is_symlink():
            safe_remove_tree(staging)
        raise OSError("After Effects recovery archive could not be restored") from exc


def _validate_recovery_archive(
    archive_path: Path,
    destination: Path,
    receipt: Mapping[str, Any],
) -> None:
    validation = destination.with_name(f".{destination.name}.recovery-check-{uuid4().hex}")
    _restore_recovery_archive(archive_path, validation, receipt)
    cleanup = safe_remove_tree(validation)
    if not cleanup.get("success") or validation.exists():
        raise OSError("After Effects recovery validation cleanup failed")


def remove_receipted_install(
    destination: Path,
    receipt_path: Path,
    *,
    before_mutation: Callable[[], None] | None = None,
    identity_paths: tuple[Path, ...] = (),
) -> None:
    with _hold_identity_paths(identity_paths):
        if before_mutation is not None:
            before_mutation()
        _remove_receipted_install(
            destination,
            receipt_path,
            before_mutation=before_mutation,
        )


def _remove_receipted_install(
    destination: Path,
    receipt_path: Path,
    *,
    before_mutation: Callable[[], None] | None = None,
) -> None:
    extension_lease = _ExactObjectLease.acquire(destination)
    try:
        receipt_lease = _ExactObjectLease.acquire(receipt_path)
    except BaseException:
        extension_lease.close()
        raise
    recovery = destination.with_name(f".{destination.name}.recovery-{uuid4().hex}.zip")
    quarantine = destination.with_name(f".{destination.name}.uninstall-{uuid4().hex}")
    receipt: dict[str, Any] | None = None
    receipt_bytes = b""
    moved = False

    def cleanup(path: Path) -> bool:
        if not path.exists() and not path.is_symlink():
            return True
        result = safe_remove_tree(path)
        return bool(result.get("success")) and not path.exists()

    def restore() -> bool:
        nonlocal extension_lease, receipt_lease
        try:
            if extension_lease is not None:
                cleanup_result = _delete_leased_tree(extension_lease)
                if not cleanup_result.get("success"):
                    raise OSError("After Effects failed destination could not be quarantined")
                extension_lease = None
            elif not cleanup(destination):
                raise OSError("After Effects failed destination could not be quarantined")
            if receipt is None:
                raise OSError("After Effects uninstall recovery receipt is unavailable")
            _restore_recovery_archive(recovery, destination, receipt)
            if receipt_lease is None:
                _write_receipt_bytes(receipt_path, receipt_bytes)
            restored = (
                _receipt_from_bytes(receipt_lease.read_bytes())
                if receipt_lease is not None
                else read_receipt(receipt_path)
            )
            if restored is None or not receipt_files_match(restored, destination):
                raise OSError("After Effects uninstall recovery did not validate")
        except OSError:
            return False
        cleanup(quarantine)
        return True

    try:
        receipt_bytes = receipt_lease.read_bytes()
        receipt = _receipt_from_bytes(receipt_bytes)
        if (
            receipt is None
            or not destination.is_dir()
            or not receipt_files_match(receipt, destination)
        ):
            raise InstallIoError(
                "A complete matching After Effects receipt is required for uninstall"
            )
        inspection = inspect_install_root(destination)
        if inspection.get("requires_restart"):
            raise RestartRequired("After Effects holds the receipted extension open")
        if before_mutation is not None:
            before_mutation()
        _write_recovery_archive(destination, receipt, recovery)
        _validate_recovery_archive(recovery, destination, receipt)
        if before_mutation is not None:
            before_mutation()
        extension_lease.rename(quarantine)
        moved = True
        cleanup_result = _delete_leased_tree(extension_lease)
        if not cleanup_result.get("success"):
            raise PermissionError("After Effects extension cleanup is locked")
        extension_lease = None
        if before_mutation is not None:
            before_mutation()
        receipt_lease.delete()
        receipt_lease = None
    except IdentityAttestationError as exc:
        if not moved:
            cleanup(recovery)
        elif not restore():
            exc.rollback_failed = True
        raise
    except (InstallIoError, RestartRequired):
        raise
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
    finally:
        if extension_lease is not None:
            extension_lease.close()
        if receipt_lease is not None:
            receipt_lease.close()
    try:
        recovery.unlink()
    except OSError as exc:
        if restore():
            raise RestartRequired("Uninstall cleanup failed; the extension was restored") from exc
        raise RollbackError(
            "Uninstall cleanup failed and recovery requires operator action"
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
    "prepare_install_directories",
    "remove_receipted_install",
    "remove_staging",
    "run_adobepy_install_bridge",
    "write_bootstrap_error",
    "write_receipt",
]
