"""Host, interpreter, profile, and external-bridge discovery."""

from __future__ import annotations

import base64
import csv
import ctypes
import hashlib
import io
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from urllib.parse import urlparse

from packaging.version import InvalidVersion, Version

from .install_contract import (
    EXIT_ACQUIRE,
    EXIT_PREFLIGHT,
    INSTALL_SOP_SCHEMA_ID,
    INSTALL_SOP_SCHEMA_SHA256,
    INSTALL_SOP_SCHEMA_SIZE,
)
from .install_models import InstallRequest, ResolvedInstall

MIN_HOST_VERSION = Version("24.0")
MIN_PYTHON_VERSION = Version("3.9")
MIN_CORE_VERSION = Version("0.20.14")
MIN_ADOBEPY_VERSION = Version("0.6.2")
_MAX_VERSION_LENGTH = 39
_FINAL_VERSION = re.compile(
    r"(0|[1-9][0-9]{0,8})(?:\.(0|[1-9][0-9]{0,8}))?"
    r"(?:\.(0|[1-9][0-9]{0,8}))?(?:\.(0|[1-9][0-9]{0,8}))?"
)
_TARGET = re.compile(r"[A-Za-z0-9._-]{1,128}")
_PYTHON_MODULES = {
    "adapter": ("dcc-mcp-aftereffects", "dcc_mcp_aftereffects"),
    "core": ("dcc-mcp-core", "dcc_mcp_core"),
    "adobepy": ("adobepy", "adobe.after_effects"),
}
_MAX_PYTHON_MODULE_BYTES = 32 * 1024 * 1024
_MAX_DISTRIBUTION_METADATA_BYTES = 16 * 1024 * 1024
_MAX_DISTRIBUTION_METADATA_FILES = 256
_PUBLISHED_ADOBEPY_RELEASES: dict[tuple[str, str], dict[str, str]] = {
    ("0.6.2", "windows-x64"): {
        "cli_sha256": "c02f28f07705b69a4f97f9f6639f0f80d1f5292115446801fbd92423336301aa",
        "cli_bytes": "2974720",
        "manifest_sha256": "3f0cf14b44b1d4c7d98b0175152e7ea58fc3edb92bd61e84983b3ad39de6b554",
        "manifest_bytes": "663",
        "archive_sha256": "9ef9abb5e034359f12e9ce248b0030e38d34c76df343eb2713f18036068719a7",
        "release_tag": "adobepy-v0.6.2",
        "asset": "adobepy-0.6.2-windows-x64.zip",
    }
}


class PreflightError(RuntimeError):
    def __init__(self, stage: str, message: str, exit_code: int = EXIT_PREFLIGHT):
        super().__init__(message)
        self.stage = stage
        self.exit_code = exit_code


def _path_uses_link(path: Path) -> bool:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError:
            return True
        if stat.S_ISLNK(metadata.st_mode) or bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            return True
    return False


def _stable_file_bytes(path: Path, maximum: int) -> bytes | None:
    try:
        if _path_uses_link(path):
            return None
        before = path.stat()
        if before.st_size <= 0 or before.st_size > maximum:
            return None
        contents = path.read_bytes()
        after = path.stat()
    except OSError:
        return None
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        return None
    return contents


def _stable_file_identity(path: Path, maximum: int) -> dict[str, Any] | None:
    try:
        if _path_uses_link(path):
            return None
        before = path.stat()
        if before.st_size <= 0 or before.st_size > maximum:
            return None
        digest = hashlib.sha256()
        observed = 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                observed += len(chunk)
                if observed > maximum:
                    return None
                digest.update(chunk)
        after = path.stat()
    except OSError:
        return None
    if observed != before.st_size or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        return None
    return {
        "path": str(path.resolve()),
        "bytes": observed,
        "sha256": digest.hexdigest(),
    }


def _signature_helper(
    platform: str, environ: Mapping[str, str]
) -> tuple[Path, dict[str, Any]] | None:
    if platform == "win32":
        del environ
        system_root = _windows_directory()
        if system_root is None:
            return None
        helper = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    elif platform == "darwin":
        helper = Path("/usr/bin/codesign")
    else:
        return None
    identity = _stable_file_identity(helper, 128 * 1024 * 1024)
    if platform == "win32" and (identity is None or not _win_verify_trust(helper)):
        return None
    return (helper.resolve(), identity) if identity is not None else None


def _windows_directory() -> Path | None:
    """Resolve the Windows directory from the kernel, never caller-controlled env."""
    if os.name != "nt":
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32_768)
        length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    except (AttributeError, OSError):
        return None
    if not length or length >= len(buffer):
        return None
    return Path(buffer.value)


def _win_verify_trust(path: Path) -> bool:
    """Verify an embedded or Windows catalog signature without executing the file."""
    if os.name != "nt":
        return False

    import msvcrt

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pcwszFilePath", ctypes.c_wchar_p),
            ("hFile", ctypes.c_void_p),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.c_ulong),
            ("fdwRevocationChecks", ctypes.c_ulong),
            ("dwUnionChoice", ctypes.c_ulong),
            ("pInfo", ctypes.c_void_p),
            ("dwStateAction", ctypes.c_ulong),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.c_ulong),
            ("dwUIContext", ctypes.c_ulong),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    class WINTRUST_CATALOG_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("dwCatalogVersion", ctypes.c_ulong),
            ("pcwszCatalogFilePath", ctypes.c_wchar_p),
            ("pcwszMemberTag", ctypes.c_wchar_p),
            ("pcwszMemberFilePath", ctypes.c_wchar_p),
            ("hMemberFile", ctypes.c_void_p),
            ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
            ("cbCalculatedFileHash", ctypes.c_ulong),
            ("pcCatalogContext", ctypes.c_void_p),
            ("hCatAdmin", ctypes.c_void_p),
        ]

    class CATALOG_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("wszCatalogFile", ctypes.c_wchar * 260),
        ]

    action = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    wintrust = ctypes.windll.wintrust
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.WinVerifyTrust.argtypes = [ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.c_void_p]

    def verify(choice: int, info: ctypes.c_void_p) -> bool:
        trust_data = WINTRUST_DATA(
            ctypes.sizeof(WINTRUST_DATA),
            None,
            None,
            2,
            0,
            choice,
            info,
            0,
            None,
            None,
            0x00001000,
            0,
            None,
        )
        return wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust_data)) == 0

    try:
        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None)
        if verify(1, ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)):
            return True

        catalog_api = ctypes.windll.wintrust
        catalog_api.CryptCATAdminAcquireContext2.restype = ctypes.c_bool
        catalog_api.CryptCATAdminAcquireContext2.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]
        catalog_api.CryptCATAdminCalcHashFromFileHandle2.restype = ctypes.c_bool
        catalog_api.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_ulong,
        ]
        catalog_api.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
        catalog_api.CryptCATAdminEnumCatalogFromHash.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        catalog_api.CryptCATCatalogInfoFromContext.restype = ctypes.c_bool
        catalog_api.CryptCATCatalogInfoFromContext.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(CATALOG_INFO),
            ctypes.c_ulong,
        ]
        catalog_api.CryptCATAdminReleaseCatalogContext.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]
        catalog_api.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        catalog_admin = ctypes.c_void_p()
        if not catalog_api.CryptCATAdminAcquireContext2(
            ctypes.byref(catalog_admin), None, "SHA256", None, 0
        ):
            return False
        try:
            with path.open("rb") as stream:
                native_handle = ctypes.c_void_p(msvcrt.get_osfhandle(stream.fileno()))
                hash_size = ctypes.c_ulong()
                if not catalog_api.CryptCATAdminCalcHashFromFileHandle2(
                    catalog_admin, native_handle, ctypes.byref(hash_size), None, 0
                ):
                    return False
                file_hash = (ctypes.c_ubyte * hash_size.value)()
                if not catalog_api.CryptCATAdminCalcHashFromFileHandle2(
                    catalog_admin,
                    native_handle,
                    ctypes.byref(hash_size),
                    file_hash,
                    0,
                ):
                    return False
                catalog_context = catalog_api.CryptCATAdminEnumCatalogFromHash(
                    catalog_admin, file_hash, hash_size.value, 0, None
                )
                if not catalog_context:
                    return False
                try:
                    catalog = CATALOG_INFO(ctypes.sizeof(CATALOG_INFO))
                    if not catalog_api.CryptCATCatalogInfoFromContext(
                        catalog_context, ctypes.byref(catalog), 0
                    ):
                        return False
                    member_tag = bytes(file_hash).hex().upper()
                    catalog_info = WINTRUST_CATALOG_INFO(
                        ctypes.sizeof(WINTRUST_CATALOG_INFO),
                        0,
                        catalog.wszCatalogFile,
                        member_tag,
                        str(path),
                        native_handle,
                        file_hash,
                        hash_size.value,
                        None,
                        catalog_admin,
                    )
                    return verify(2, ctypes.cast(ctypes.pointer(catalog_info), ctypes.c_void_p))
                finally:
                    catalog_api.CryptCATAdminReleaseCatalogContext(
                        catalog_admin, catalog_context, 0
                    )
        finally:
            catalog_api.CryptCATAdminReleaseContext(catalog_admin, 0)
    except (AttributeError, OSError):
        return False


def _host_binary(path: Path, platform: str) -> Path:
    if platform == "darwin":
        return path / "Contents" / "MacOS" / "After Effects"
    return path


def _verified_host_evidence(
    path: Path, platform: str, helper: Path
) -> tuple[str, dict[str, str]] | None:
    if platform == "win32":
        script = (
            "$self=Get-AuthenticodeSignature -LiteralPath $PSHOME\\powershell.exe;"
            "$selfv=(Get-Item -LiteralPath $PSHOME\\powershell.exe).VersionInfo;"
            "$sig=Get-AuthenticodeSignature -LiteralPath $args[0];"
            "$v=(Get-Item -LiteralPath $args[0]).VersionInfo;"
            "[pscustomobject]@{helperStatus=[string]$self.Status;"
            "helperSubject=[string]$self.SignerCertificate.Subject;"
            "helperProduct=[string]$selfv.ProductName;"
            "helperOriginal=[string]$selfv.OriginalFilename;"
            "helperVersion=[string]$selfv.ProductVersion;status=[string]$sig.Status;"
            "subject=[string]$sig.SignerCertificate.Subject;"
            "product=[string]$v.ProductName;original=[string]$v.OriginalFilename;"
            "version=[string]$v.ProductVersion}|ConvertTo-Json -Compress"
        )
        try:
            result = subprocess.run(
                [str(helper), "-NoProfile", "-NonInteractive", "-Command", script, str(path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            payload = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, UnicodeError):
            return None
        if (
            result.returncode != 0
            or not isinstance(payload, dict)
            or payload.get("helperStatus") != "Valid"
            or re.search(
                r"(?:^|,)\s*CN=Microsoft (?:Windows|Corporation)(?:,|$)",
                str(payload.get("helperSubject", "")),
                flags=re.IGNORECASE,
            )
            is None
            or re.fullmatch(
                r"(?:Windows PowerShell|Microsoft(?:®|\(R\))? Windows(?:®|\(R\))? Operating System)",
                str(payload.get("helperProduct", "")),
                re.IGNORECASE,
            )
            is None
            or str(payload.get("helperOriginal", "")).casefold()
            not in {"powershell.exe", "powershell.exe.mui"}
            or payload.get("status") != "Valid"
            or re.search(
                r"(?:^|,)\s*CN=Adobe (?:Inc\.?|Systems Incorporated)(?:,|$)",
                str(payload.get("subject", "")),
                flags=re.IGNORECASE,
            )
            is None
            or re.search(r"After Effects", str(payload.get("product", "")), re.IGNORECASE) is None
            or str(payload.get("original", "")).casefold() != "afterfx.exe"
        ):
            return None
        try:
            _version_key(str(payload.get("helperVersion", "")))
        except PreflightError:
            return None
        return str(payload.get("version", "")), {
            "authenticode": "valid",
            "subject": str(payload.get("helperSubject", "")),
            "product": str(payload.get("helperProduct", "")),
            "original": str(payload.get("helperOriginal", "")),
            "version": str(payload.get("helperVersion", "")),
        }
    if platform == "darwin":
        try:
            verified = subprocess.run(
                [str(helper), "--verify", "--deep", "--strict", str(path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            details = subprocess.run(
                [str(helper), "-dv", "--verbose=4", str(path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            with (path / "Contents" / "Info.plist").open("rb") as handle:
                plist = plistlib.load(handle)
        except (OSError, subprocess.SubprocessError, plistlib.InvalidFileException):
            return None
        signature = (details.stdout or "") + (details.stderr or "")
        if (
            verified.returncode != 0
            or details.returncode != 0
            or "TeamIdentifier=JQ525L2MZD" not in signature
            or "Identifier=com.adobe.AfterEffects" not in signature
            or plist.get("CFBundleIdentifier") != "com.adobe.AfterEffects"
        ):
            return None
        return str(plist.get("CFBundleShortVersionString", "")), {
            "authenticode": "not_applicable",
            "subject": "Apple system codesign",
            "product": "codesign",
            "original": "codesign",
            "version": "system",
        }
    return None


def trusted_host_attestation(
    path: Path,
    platform: str,
    *,
    environ: Mapping[str, str] | None = None,
    helper_path: Path | None = None,
) -> dict[str, Any] | None:
    """Bind Adobe signature evidence to exact OS helper and host bytes."""
    active_env = os.environ if environ is None else environ
    if helper_path is None:
        selected = _signature_helper(platform, active_env)
        if selected is None:
            return None
        helper, helper_identity = selected
    else:
        helper = helper_path
        helper_identity = _stable_file_identity(helper, 128 * 1024 * 1024)
        if helper_identity is None or (platform == "win32" and not _win_verify_trust(helper)):
            return None
    host_identity = _stable_file_identity(_host_binary(path, platform), 2_147_483_647)
    if host_identity is None:
        return None
    if platform == "win32" and not _win_verify_trust(helper):
        return None
    execution_helper_identity = _stable_file_identity(helper, 128 * 1024 * 1024)
    execution_host_identity = _stable_file_identity(_host_binary(path, platform), 2_147_483_647)
    if execution_helper_identity != helper_identity or execution_host_identity != host_identity:
        return None
    evidence = _verified_host_evidence(path, platform, helper)
    if evidence is None:
        return None
    version, helper_metadata = evidence
    final_helper_identity = _stable_file_identity(helper, 128 * 1024 * 1024)
    final_host_identity = _stable_file_identity(_host_binary(path, platform), 2_147_483_647)
    if (
        final_helper_identity != helper_identity
        or final_host_identity != host_identity
        or (platform == "win32" and not _win_verify_trust(helper))
    ):
        return None
    try:
        _version_key(version)
    except PreflightError:
        return None
    return {
        "platform": platform,
        "version": version,
        "host": final_host_identity,
        "signature_helper": {**final_helper_identity, **helper_metadata},
    }


def recapture_host_attestation(path: Path, expected: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return the exact current host attestation or fail closed on any drift."""
    if not expected:
        return None
    try:
        expected_identity = dict(expected)
        platform = expected["platform"]
        expected_host = Path(expected["host"]["path"]).resolve()
        helper = Path(expected["signature_helper"]["path"])
    except (KeyError, OSError, TypeError, ValueError):
        return None
    if not isinstance(platform, str):
        return None
    try:
        current_host = _host_binary(path, platform).resolve()
    except (OSError, TypeError, ValueError):
        return None
    if os.path.normcase(str(current_host)) != os.path.normcase(str(expected_host)):
        return None
    try:
        current = trusted_host_attestation(path, platform, helper_path=helper)
    except (OSError, TypeError, ValueError):
        return None
    return current if current is not None and current == expected_identity else None


def reattest_host(path: Path, expected: Mapping[str, Any]) -> bool:
    """Re-run signature verification and byte binding immediately before readiness."""
    return recapture_host_attestation(path, expected) is not None


def default_extension_path(
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    active_platform = platform or sys.platform
    active_env = os.environ if environ is None else environ
    active_home = home or Path.home()
    if active_platform == "win32":
        appdata = active_env.get("APPDATA")
        if not appdata:
            raise PreflightError("profile", "APPDATA is required to resolve the user CEP profile")
        root = Path(appdata) / "Adobe" / "CEP" / "extensions"
    elif active_platform == "darwin":
        root = active_home / "Library" / "Application Support" / "Adobe" / "CEP" / "extensions"
    else:
        raise PreflightError(
            "platform",
            "After Effects Authoring and its CEP profile are supported only on Windows and macOS",
        )
    return root / "dcc-mcp-aftereffects"


def default_state_dir(
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    active_platform = platform or sys.platform
    active_env = os.environ if environ is None else environ
    override = active_env.get("DCC_MCP_AFTEREFFECTS_STATE_DIR")
    if override:
        return Path(override).expanduser()
    active_home = home or Path.home()
    if active_platform == "win32":
        local = active_env.get("LOCALAPPDATA")
        if not local:
            raise PreflightError("profile", "LOCALAPPDATA is required to resolve adapter state")
        return Path(local) / "dcc-mcp" / "aftereffects"
    if active_platform == "darwin":
        return active_home / "Library" / "Application Support" / "dcc-mcp" / "aftereffects"
    return active_home / ".local" / "state" / "dcc-mcp" / "aftereffects"


def _host_candidates(platform: str, environ: Mapping[str, str]) -> list[Path]:
    if platform == "win32":
        roots = [
            Path(value) / "Adobe"
            for key in ("ProgramFiles", "ProgramW6432")
            if (value := environ.get(key))
        ]
        return [
            path
            for root in roots
            for path in root.glob("Adobe After Effects */Support Files/AfterFX.exe")
        ]
    if platform == "darwin":
        return list(Path("/Applications").glob("Adobe After Effects */Adobe After Effects *.app"))
    return []


def _trusted_host_version(path: Path, platform: str) -> str | None:
    """Return product-derived version only for a platform-verified Adobe binary."""
    identity = trusted_host_attestation(path, platform)
    return str(identity["version"]) if identity is not None else None


def _host_version(path: Path) -> str:
    if path.suffix.lower() == ".app":
        plist_path = path / "Contents" / "Info.plist"
        if plist_path.is_file():
            with plist_path.open("rb") as handle:
                value = plistlib.load(handle).get("CFBundleShortVersionString")
            if value:
                _version_key(str(value))
                return str(value)
    text = str(path)
    explicit = re.search(r"After Effects\s+(20\d{2})", text, flags=re.IGNORECASE)
    if explicit:
        return f"{int(explicit.group(1)) - 2000}.0"
    release = re.search(r"(?:^|[^\d])(\d{2}(?:\.\d+){1,3})(?:[^\d]|$)", text)
    if release:
        value = release.group(1)
        _version_key(value)
        return value
    raise PreflightError(
        "host_version",
        "Could not determine the After Effects version from the selected installation",
    )


def _resolve_host(
    request: InstallRequest, platform: str, environ: Mapping[str, str]
) -> tuple[Path, str, dict[str, Any]]:
    if request.dcc_path:
        host_path = Path(request.dcc_path).expanduser()
    else:
        candidates = _host_candidates(platform, environ)
        if not candidates:
            raise PreflightError(
                "host",
                "After Effects was not found; pass the exact executable or application with --dcc-path",
            )
        host_path = sorted(candidates, key=lambda item: _version_key(_host_version(item)))[-1]
    if not host_path.exists() or host_path.is_symlink():
        raise PreflightError("host", f"After Effects path does not exist: {host_path}")
    resolved_host = host_path.resolve()
    if platform == "win32":
        try:
            native_host = resolved_host.read_bytes()[:2] == b"MZ"
        except OSError:
            native_host = False
        canonical = bool(
            resolved_host.is_file()
            and resolved_host.name.casefold() == "afterfx.exe"
            and resolved_host.parent.name.casefold() == "support files"
            and native_host
            and re.fullmatch(
                r"Adobe After Effects 20\d{2}",
                resolved_host.parent.parent.name,
                flags=re.IGNORECASE,
            )
        )
    elif platform == "darwin":
        executable = resolved_host / "Contents" / "MacOS" / "After Effects"
        try:
            magic = executable.read_bytes()[:4]
        except OSError:
            magic = b""
        canonical = bool(
            resolved_host.is_dir()
            and re.fullmatch(
                r"Adobe After Effects 20\d{2}\.app",
                resolved_host.name,
                flags=re.IGNORECASE,
            )
            and (resolved_host / "Contents" / "Info.plist").is_file()
            and executable.is_file()
            and magic
            in {
                b"\xfe\xed\xfa\xce",
                b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf",
                b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe",
            }
        )
    else:
        canonical = False
    if not canonical:
        raise PreflightError(
            "host",
            "--dcc-path must select a canonical After Effects AfterFX.exe or application bundle",
        )
    host_identity = trusted_host_attestation(resolved_host, platform, environ=environ)
    if not host_identity:
        raise PreflightError(
            "host",
            "After Effects product metadata or platform signature could not be verified",
        )
    try:
        version = host_identity["version"]
    except KeyError as exc:
        raise PreflightError(
            "host", "After Effects signed product metadata omitted its version"
        ) from exc
    if _version_key(version) < MIN_HOST_VERSION:
        raise PreflightError(
            "host_version",
            f"After Effects {version} is unsupported; version {MIN_HOST_VERSION} or newer is required",
        )
    return resolved_host, version, host_identity


def host_process_executable(host_path: Path) -> Path:
    """Map a signed macOS application bundle to its exact native process binary."""
    if host_path.suffix.lower() == ".app":
        return host_path / "Contents" / "MacOS" / "After Effects"
    return host_path


def _version_key(value: str) -> Version:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_VERSION_LENGTH
        or _FINAL_VERSION.fullmatch(value) is None
    ):
        raise PreflightError("version", "Version value is not a bounded canonical final release")
    try:
        return Version(value)
    except InvalidVersion as exc:
        raise PreflightError("version", f"Invalid version value: {value}") from exc


def _normalized_distribution_name(value: Any) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= 256 or "\0" in value:
        return ""
    return re.sub(r"[-_.]+", "-", value).lower()


def _absolute_path(value: Any) -> Path:
    if not isinstance(value, str) or not 0 < len(value) <= 4_096 or "\0" in value:
        raise ValueError("invalid bounded path")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("path is not absolute")
    return Path(os.path.abspath(path))


def _physical_identity(details: os.stat_result) -> dict[str, int]:
    return {
        "device": int(details.st_dev),
        "inode": int(details.st_ino),
        "mode": int(details.st_mode),
        "links": int(details.st_nlink),
        "modified_ns": int(details.st_mtime_ns),
        "changed_ns": int(details.st_ctime_ns),
    }


def _plain_directory_identity(path: Path) -> dict[str, Any]:
    path = Path(os.path.abspath(path))
    if _path_uses_link(path):
        raise ValueError("directory crosses a link or reparse boundary")
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError("directory identity is unavailable")
    return {"path": str(path), "physical": _physical_identity(details)}


def _plain_file_identity(path: Path, maximum: int, *, allow_empty: bool = False) -> dict[str, Any]:
    path = Path(os.path.abspath(path))
    if _path_uses_link(path):
        raise ValueError("file crosses a link or reparse boundary")
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size < 0
        or (before.st_size == 0 and not allow_empty)
        or before.st_size > maximum
    ):
        raise ValueError("file physical identity is unsupported")
    digest = hashlib.sha256()
    observed = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            observed += len(chunk)
            if observed > maximum:
                raise ValueError("file exceeds bounded identity size")
            digest.update(chunk)
    after = path.lstat()
    if observed != before.st_size or _physical_identity(before) != _physical_identity(after):
        raise ValueError("file changed while its identity was captured")
    return {
        "path": str(path),
        "bytes": observed,
        "sha256": digest.hexdigest(),
        "physical": _physical_identity(after),
    }


def _owned_directory_chain(path: Path, root: Path) -> list[dict[str, Any]]:
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("path is outside its ownership root") from exc
    chain = [_plain_directory_identity(root)]
    current = root
    for part in relative.parts:
        current /= part
        chain.append(_plain_directory_identity(current))
    return chain


def _module_identity(path: Path, ownership_root: Path) -> dict[str, Any]:
    return {
        "ownership_chain": _owned_directory_chain(path.parent, ownership_root),
        "file": _plain_file_identity(path, _MAX_PYTHON_MODULE_BYTES),
    }


def _metadata_identity(metadata_path: Path, distribution_root: Path) -> dict[str, Any]:
    metadata_path = Path(os.path.abspath(metadata_path))
    distribution_root = Path(os.path.abspath(distribution_root))
    chain = _owned_directory_chain(metadata_path, distribution_root)
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for current, directories, files in os.walk(metadata_path, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in directories:
            directory = current_path / name
            entries.append(
                {
                    "path": directory.relative_to(metadata_path).as_posix(),
                    "type": "directory",
                    "identity": _plain_directory_identity(directory),
                }
            )
        for name in files:
            file_path = current_path / name
            identity = _plain_file_identity(
                file_path, _MAX_DISTRIBUTION_METADATA_BYTES, allow_empty=True
            )
            total_bytes += int(identity["bytes"])
            if total_bytes > _MAX_DISTRIBUTION_METADATA_BYTES:
                raise ValueError("distribution metadata exceeds bounded identity size")
            entries.append(
                {
                    "path": file_path.relative_to(metadata_path).as_posix(),
                    "type": "file",
                    "identity": identity,
                }
            )
        if len(entries) > _MAX_DISTRIBUTION_METADATA_FILES:
            raise ValueError("distribution metadata has too many entries")
    files_by_name = {
        entry["path"]: entry["identity"] for entry in entries if entry["type"] == "file"
    }
    if any(
        not isinstance(files_by_name.get(name), Mapping) or files_by_name[name].get("bytes", 0) <= 0
        for name in ("METADATA", "RECORD")
    ):
        raise ValueError("distribution metadata is incomplete")
    return {
        "root": str(metadata_path),
        "ownership_chain": chain,
        "entries": sorted(entries, key=lambda item: (item["path"], item["type"])),
    }


def _captured_metadata_bytes(
    metadata_path: Path,
    snapshot: Mapping[str, Any],
    name: str,
    *,
    required: bool,
) -> bytes | None:
    entry = next(
        (
            item
            for item in snapshot.get("entries", ())
            if isinstance(item, Mapping) and item.get("path") == name and item.get("type") == "file"
        ),
        None,
    )
    if entry is None:
        if required:
            raise ValueError("required distribution metadata is missing")
        return None
    expected = entry.get("identity")
    if not isinstance(expected, Mapping):
        raise ValueError("distribution metadata identity is invalid")
    path = metadata_path / name
    before = _plain_file_identity(path, _MAX_DISTRIBUTION_METADATA_BYTES, allow_empty=not required)
    contents = path.read_bytes()
    after = _plain_file_identity(path, _MAX_DISTRIBUTION_METADATA_BYTES, allow_empty=not required)
    if (
        before != dict(expected)
        or before != after
        or len(contents) != before["bytes"]
        or hashlib.sha256(contents).hexdigest() != before["sha256"]
    ):
        raise ValueError("distribution metadata changed while it was captured")
    return contents


def _record_identity(contents: bytes, package_path: Path) -> dict[str, Any]:
    target = package_path.as_posix()
    try:
        rows = list(csv.reader(io.StringIO(contents.decode("utf-8"), newline="")))
        matches = [row for row in rows if len(row) == 3 and row[0] == target]
        if len(matches) != 1 or not matches[0][1] or not matches[0][2]:
            raise ValueError("module lacks one exact RECORD owner")
        path, digest, size = matches[0]
        parsed_size = int(size)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("distribution RECORD identity is invalid") from exc
    return {"path": path, "hash": digest, "size": parsed_size}


def _local_editable_root(value: Any) -> Path | None:
    if not isinstance(value, dict) or set(value) != {"url", "dir_info"}:
        return None
    info = value.get("dir_info")
    url = value.get("url")
    if not isinstance(info, dict) or info.get("editable") is not True or not isinstance(url, str):
        return None
    parsed = urlparse(url)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return None
    from urllib.parse import unquote
    from urllib.request import url2pathname

    raw_path = url2pathname(unquote(parsed.path))
    if re.fullmatch(r"/[A-Za-z]:/.*", raw_path):
        raw_path = raw_path[1:]
    try:
        root = Path(os.path.abspath(raw_path))
        _plain_directory_identity(root)
    except (OSError, TypeError, ValueError):
        return None
    return root


def _record_hash_matches(digest: str, record_hash: Any) -> bool:
    if not isinstance(record_hash, str) or not record_hash.startswith("sha256="):
        return False
    expected = record_hash.removeprefix("sha256=").rstrip("=")
    actual = base64.urlsafe_b64encode(bytes.fromhex(digest)).decode("ascii").rstrip("=")
    return actual == expected


def _capture_python_module(
    raw: Mapping[str, Any], distribution: str, package: str
) -> dict[str, Any]:
    if raw.get("distribution") != distribution or (
        _normalized_distribution_name(raw.get("name"))
        != _normalized_distribution_name(distribution)
    ):
        raise ValueError("distribution identity does not match the requested product")
    version = raw.get("version")
    _version_key(version)
    module_path = _absolute_path(raw.get("module_path"))
    distribution_root = _absolute_path(raw.get("distribution_root"))
    metadata_path = _absolute_path(raw.get("metadata_path"))
    metadata_snapshot = _metadata_identity(metadata_path, distribution_root)
    package_path = Path(*package.split(".")) / "__init__.py"
    metadata_contents = _captured_metadata_bytes(
        metadata_path, metadata_snapshot, "METADATA", required=True
    )
    headers = BytesParser().parsebytes(metadata_contents, headersonly=True)
    if (
        _normalized_distribution_name(headers.get("Name"))
        != _normalized_distribution_name(distribution)
        or headers.get("Version") != version
    ):
        raise ValueError("distribution metadata does not match its selected identity")
    direct_url_contents = _captured_metadata_bytes(
        metadata_path, metadata_snapshot, "direct_url.json", required=False
    )
    direct_url = json.loads(direct_url_contents) if direct_url_contents is not None else None
    if direct_url != raw.get("direct_url"):
        raise ValueError("editable source does not match distribution metadata")
    editable_root = _local_editable_root(direct_url)
    record: Mapping[str, Any] | None = None
    if editable_root is not None:
        candidates = (editable_root / "src" / package_path, editable_root / package_path)
        if module_path not in {Path(os.path.abspath(candidate)) for candidate in candidates}:
            raise ValueError("editable module is outside its source ownership")
        ownership = {"kind": "editable", "root": str(editable_root)}
        ownership_root = editable_root
    else:
        expected_path = Path(os.path.abspath(distribution_root / package_path))
        if module_path != expected_path:
            raise ValueError("installed module requires one exact RECORD owner")
        record_contents = _captured_metadata_bytes(
            metadata_path, metadata_snapshot, "RECORD", required=True
        )
        record = _record_identity(record_contents, package_path)
        record_path = Path(str(record.get("path") or ""))
        if (
            record_path.is_absolute()
            or ".." in record_path.parts
            or Path(os.path.abspath(distribution_root / record_path)) != module_path
        ):
            raise ValueError("installed module RECORD path is outside distribution ownership")
        ownership = {"kind": "installed", "root": str(distribution_root)}
        ownership_root = distribution_root
    module_snapshot = _module_identity(module_path, ownership_root)
    if record is not None and (
        not isinstance(record.get("size"), int)
        or isinstance(record.get("size"), bool)
        or record.get("size") != module_snapshot["file"]["bytes"]
        or not _record_hash_matches(module_snapshot["file"]["sha256"], record.get("hash"))
    ):
        raise ValueError("installed module does not match distribution RECORD metadata")
    return {
        "distribution": distribution,
        "metadata_name": raw.get("name"),
        "version": version,
        "module_path": str(module_path),
        "distribution_root": str(distribution_root),
        "metadata_path": str(metadata_path),
        "owned": True,
        "ownership": ownership,
        "record": dict(record) if record is not None else None,
        "module_identity": module_snapshot,
        "metadata_identity": metadata_snapshot,
    }


def capture_python_modules(raw_modules: Mapping[str, Any]) -> dict[str, Any]:
    """Bind target distributions to exact metadata, paths, bytes, and physical files."""
    if not isinstance(raw_modules, Mapping) or set(raw_modules) != set(_PYTHON_MODULES):
        raise PreflightError("python", "Target Python returned incomplete distribution identities")
    try:
        return {
            key: _capture_python_module(raw_modules[key], distribution, package)
            for key, (distribution, package) in _PYTHON_MODULES.items()
        }
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise PreflightError(
            "python", "Target Python imports are not owned by their selected distributions"
        ) from exc


def recapture_python_modules(expected: Mapping[str, Any]) -> dict[str, Any] | None:
    """Recapture exact Python distribution state without importing changed modules."""
    if not isinstance(expected, Mapping) or set(expected) != set(_PYTHON_MODULES):
        return None
    current: dict[str, Any] = {}
    required = {
        "distribution",
        "metadata_name",
        "version",
        "module_path",
        "distribution_root",
        "metadata_path",
        "owned",
        "ownership",
        "record",
        "module_identity",
        "metadata_identity",
    }
    try:
        for key, (distribution, package) in _PYTHON_MODULES.items():
            identity = expected[key]
            if not isinstance(identity, Mapping) or set(identity) != required:
                return None
            if (
                identity.get("distribution") != distribution
                or identity.get("owned") is not True
                or _normalized_distribution_name(identity.get("metadata_name"))
                != _normalized_distribution_name(distribution)
            ):
                return None
            _version_key(identity.get("version"))
            module_path = _absolute_path(identity.get("module_path"))
            distribution_root = _absolute_path(identity.get("distribution_root"))
            metadata_path = _absolute_path(identity.get("metadata_path"))
            ownership = identity.get("ownership")
            if not isinstance(ownership, Mapping) or set(ownership) != {"kind", "root"}:
                return None
            ownership_root = _absolute_path(ownership.get("root"))
            package_path = Path(*package.split(".")) / "__init__.py"
            if ownership.get("kind") == "editable":
                candidates = (
                    ownership_root / "src" / package_path,
                    ownership_root / package_path,
                )
                if module_path not in {Path(os.path.abspath(item)) for item in candidates}:
                    return None
            elif ownership.get("kind") == "installed":
                if module_path != Path(os.path.abspath(distribution_root / package_path)):
                    return None
            else:
                return None
            module_snapshot = _module_identity(module_path, ownership_root)
            metadata_snapshot = _metadata_identity(metadata_path, distribution_root)
            record = identity.get("record")
            if ownership.get("kind") == "installed" and (
                not isinstance(record, Mapping)
                or record.get("size") != module_snapshot["file"]["bytes"]
                or not _record_hash_matches(module_snapshot["file"]["sha256"], record.get("hash"))
            ):
                return None
            current[key] = {
                **dict(identity),
                "record": dict(record) if isinstance(record, Mapping) else None,
                "module_identity": module_snapshot,
                "metadata_identity": metadata_snapshot,
            }
    except (KeyError, OSError, TypeError, ValueError):
        return None
    return current if current == dict(expected) else None


def _python_metadata(python_path: Path) -> dict[str, Any]:
    script = r"""
import hashlib
import importlib.metadata as metadata
import importlib.resources as resources
import json
import os
import pathlib
import sys

import adobe.after_effects
import dcc_mcp_aftereffects
import dcc_mcp_core


def describe(distribution_name, module):
    distribution = metadata.distribution(distribution_name)
    module_path = pathlib.Path(os.path.abspath(module.__file__))
    raw_direct_url = distribution.read_text("direct_url.json")
    return {
        "name": distribution.metadata.get("Name"),
        "distribution": distribution_name,
        "version": distribution.version,
        "module_path": str(module_path),
        "distribution_root": str(
            pathlib.Path(os.path.abspath(distribution.locate_file("")))
        ),
        "metadata_path": str(pathlib.Path(os.path.abspath(distribution._path))),
        "direct_url": json.loads(raw_direct_url) if raw_direct_url else None,
    }


filename = "adapter-install-sop-v1.schema.json"
schema_bytes = resources.read_binary("dcc_mcp_core.schemas", filename)
schema = json.loads(schema_bytes.decode("utf-8"))
core_distribution = metadata.distribution("dcc-mcp-core")
record_path = "dcc_mcp_core/schemas/" + filename
print(json.dumps({
    "python": ".".join(map(str, sys.version_info[:3])),
    "python_executable": sys.executable,
    "modules": {
        "adapter": describe(
            "dcc-mcp-aftereffects", dcc_mcp_aftereffects
        ),
        "core": describe("dcc-mcp-core", dcc_mcp_core),
        "adobepy": describe("adobepy", adobe.after_effects),
    },
    "core_schema": {
        "id": schema.get("$id"),
        "size": len(schema_bytes),
        "sha256": hashlib.sha256(schema_bytes).hexdigest(),
        "record_owned": any(
            str(item).replace("\\", "/") == record_path
            for item in tuple(core_distribution.files or ())
        ),
    },
}))
""".strip()
    environment = dict(os.environ)
    environment.pop("ADOBEPY_TOKEN", None)
    try:
        completed = subprocess.run(
            [str(python_path), "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError("python", "Target Python could not be inspected safely") from exc
    if completed.returncode != 0:
        raise PreflightError(
            "python",
            "Target Python must import adobepy and dcc-mcp-core before host installation",
        )
    try:
        if len((completed.stdout or "").encode("utf-8", errors="replace")) > 262_144:
            raise ValueError("unbounded output")
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError, UnicodeError, ValueError) as exc:
        raise PreflightError("python", "Target Python returned invalid preflight metadata") from exc
    if not isinstance(payload, dict):
        raise PreflightError("python", "Target Python returned invalid preflight metadata")
    return payload


def _bridge_cli_identity(environ: Mapping[str, str]) -> dict[str, Any] | None:
    configured = environ.get("ADOBEPY_CLI")
    selected = configured or shutil.which("adobepy")
    if not selected:
        return None
    try:
        selected_path = Path(selected).expanduser()
        if _path_uses_link(selected_path):
            return None
        path = selected_path.resolve(strict=True)
        contents = _stable_file_bytes(path, 2_147_483_647)
        bundle = path.parent.parent
        manifest_path = bundle / "package-manifest.json"
        manifest_contents = _stable_file_bytes(manifest_path, 65_536)
        if contents is None or manifest_contents is None:
            return None
        manifest = json.loads(manifest_contents.decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    includes = manifest.get("includes") if isinstance(manifest, dict) else None
    relative_cli = f"bin/{path.name}"
    safe_includes = bool(
        isinstance(includes, list)
        and includes
        and all(
            isinstance(item, str)
            and 0 < len(item) <= 256
            and "\\" not in item
            and not PurePosixPath(item).is_absolute()
            and ".." not in PurePosixPath(item).parts
            for item in includes
        )
    )
    version = manifest.get("version") if isinstance(manifest, dict) else None
    runtime = manifest.get("runtime") if isinstance(manifest, dict) else None
    release = (
        _PUBLISHED_ADOBEPY_RELEASES.get((version, runtime))
        if isinstance(version, str) and isinstance(runtime, str)
        else None
    )
    try:
        release_cli_bytes = int(release["cli_bytes"]) if release else -1
        release_manifest_bytes = int(release["manifest_bytes"]) if release else -1
    except (KeyError, TypeError, ValueError):
        return None
    supplied_sha256 = environ.get("ADOBEPY_CLI_SHA256", "").lower()
    actual_sha256 = hashlib.sha256(contents).hexdigest()
    try:
        _version_key(version)
    except PreflightError:
        return None
    if (
        not contents
        or not isinstance(release, dict)
        or len(contents) != release_cli_bytes
        or actual_sha256 != release.get("cli_sha256")
        or len(manifest_contents) != release_manifest_bytes
        or hashlib.sha256(manifest_contents).hexdigest() != release.get("manifest_sha256")
        or (
            bool(supplied_sha256)
            and (
                re.fullmatch(r"[0-9a-f]{64}", supplied_sha256) is None
                or supplied_sha256 != actual_sha256
            )
        )
        or path.is_symlink()
        or path.name.casefold() not in {"adobepy", "adobepy.exe"}
        or path.parent.name != "bin"
        or manifest.get("name") != "adobepy"
        or not isinstance(runtime, str)
        or re.fullmatch(r"[A-Za-z0-9._-]{1,64}", runtime) is None
        or not safe_includes
        or relative_cli not in includes
        or re.fullmatch(
            rf"adobepy-{re.escape(version)}-[A-Za-z0-9._-]+",
            bundle.name,
        )
        is None
    ):
        return None
    return {
        "executable": str(path),
        "version": version,
        "runtime": runtime,
        "bytes": len(contents),
        "sha256": actual_sha256,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_bytes": len(manifest_contents),
        "manifest_sha256": hashlib.sha256(manifest_contents).hexdigest(),
        "provenance": "official_checksum_release",
        "source": {
            "repository": "https://github.com/dcc-mcp/adobepy",
            "release_tag": release["release_tag"],
            "asset": release["asset"],
            "archive_sha256": release["archive_sha256"],
        },
    }


def reattest_bridge_cli(path: Path, expected: Mapping[str, Any]) -> bool:
    """Recheck the exact official CLI and manifest immediately before execution."""
    try:
        expected_path = Path(expected["executable"]).resolve(strict=True)
        manifest_path = Path(expected["manifest_path"]).resolve(strict=True)
        expected_bytes = int(expected["bytes"])
        expected_manifest_bytes = int(expected["manifest_bytes"])
        expected_sha256 = expected["sha256"]
        expected_manifest_sha256 = expected["manifest_sha256"]
        selected_path = path.resolve(strict=True)
    except (KeyError, OSError, TypeError, ValueError):
        return False
    if (
        expected.get("provenance") != "official_checksum_release"
        or selected_path != expected_path
        or manifest_path != selected_path.parent.parent / "package-manifest.json"
        or not isinstance(expected_sha256, str)
        or not isinstance(expected_manifest_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256) is None
    ):
        return False
    contents = _stable_file_bytes(selected_path, 2_147_483_647)
    manifest_contents = _stable_file_bytes(manifest_path, 65_536)
    return bool(
        contents is not None
        and manifest_contents is not None
        and len(contents) == expected_bytes
        and hashlib.sha256(contents).hexdigest() == expected_sha256
        and len(manifest_contents) == expected_manifest_bytes
        and hashlib.sha256(manifest_contents).hexdigest() == expected_manifest_sha256
    )


def _resolve_bridge_cli(environ: Mapping[str, str]) -> Path | None:
    identity = _bridge_cli_identity(environ)
    return Path(identity["executable"]) if identity else None


def resolve_install(
    request: InstallRequest,
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> ResolvedInstall:
    active_platform = platform or sys.platform
    active_env = os.environ if environ is None else environ
    host_path, host_version, initial_host_identity = _resolve_host(
        request, active_platform, active_env
    )
    host_identity = trusted_host_attestation(host_path, active_platform, environ=active_env)
    if not host_identity:
        raise PreflightError(
            "host_attestation",
            "The signed After Effects host identity could not be recaptured",
        )
    if host_identity != initial_host_identity:
        raise PreflightError(
            "host_attestation",
            "The signed After Effects host identity changed during preflight",
        )
    python_path = Path(request.python or sys.executable).expanduser()
    if not python_path.is_file():
        raise PreflightError("python", f"Target Python does not exist: {python_path}")
    python_path = python_path.resolve()
    metadata = _python_metadata(python_path)
    try:
        reported_python = Path(metadata["python_executable"]).resolve()
        modules = metadata["modules"]
        core_schema = metadata["core_schema"]
    except (KeyError, OSError, TypeError) as exc:
        raise PreflightError("python", "Target Python omitted its runtime provenance") from exc
    if reported_python != python_path.resolve() or not isinstance(modules, dict):
        raise PreflightError(
            "python", "Target Python identity does not match the selected executable"
        )
    expected_distributions = {
        "adapter": "dcc-mcp-aftereffects",
        "core": "dcc-mcp-core",
        "adobepy": "adobepy",
    }
    for key, distribution in expected_distributions.items():
        module = modules.get(key)
        module_path = module.get("module_path") if isinstance(module, dict) else None
        try:
            trusted_module_path = bool(
                isinstance(module_path, str)
                and 0 < len(module_path) <= 4_096
                and "\0" not in module_path
                and Path(module_path).is_file()
            )
        except (OSError, ValueError):
            trusted_module_path = False
        if (
            not isinstance(module, dict)
            or module.get("distribution") != distribution
            or not trusted_module_path
        ):
            raise PreflightError(
                "python", "Target Python imports are not owned by their selected distributions"
            )
        _version_key(module.get("version"))
    if (
        not isinstance(core_schema, dict)
        or core_schema.get("id") != INSTALL_SOP_SCHEMA_ID
        or core_schema.get("size") != INSTALL_SOP_SCHEMA_SIZE
        or core_schema.get("sha256") != INSTALL_SOP_SCHEMA_SHA256
        or core_schema.get("record_owned") is not True
    ):
        raise PreflightError(
            "core", "Target Core does not contain the canonical Install SOP schema"
        )
    modules = capture_python_modules(modules)
    metadata["core"] = modules["core"]["version"]
    metadata["adobepy"] = modules["adobepy"]["version"]
    for name, minimum in (
        ("python", MIN_PYTHON_VERSION),
        ("core", MIN_CORE_VERSION),
        ("adobepy", MIN_ADOBEPY_VERSION),
    ):
        actual = _version_key(metadata[name])
        if actual < minimum:
            raise PreflightError(
                name,
                f"{name} {actual} is unsupported; version {minimum} or newer is required",
            )

    extension_override = active_env.get("DCC_MCP_AFTEREFFECTS_EXTENSION_DIR")
    extension_path = (
        Path(extension_override).expanduser()
        if extension_override
        else default_extension_path(platform=active_platform, environ=active_env)
    )
    state_dir = default_state_dir(platform=active_platform, environ=active_env)
    bridge_identity = _bridge_cli_identity(active_env)
    bridge_cli = Path(bridge_identity["executable"]) if bridge_identity else None
    if request.command in {"install", "upgrade", "verify"} and bridge_cli is None:
        raise PreflightError(
            "acquire",
            "The supported adobepy CLI is unavailable; set ADOBEPY_CLI to an official release binary",
            EXIT_ACQUIRE,
        )
    if bridge_identity and bridge_identity["version"] != metadata["adobepy"]:
        raise PreflightError(
            "acquire",
            "The adobepy CLI bundle version does not match the selected adobepy SDK",
            EXIT_ACQUIRE,
        )
    token = active_env.get("ADOBEPY_TOKEN")
    if request.command in {"install", "upgrade", "verify"} and (
        not token or len(token) > 4_096 or "\0" in token
    ):
        raise PreflightError(
            "authentication",
            "ADOBEPY_TOKEN must be configured in the installer environment",
        )
    broker_url = active_env.get("ADOBEPY_BROKER_URL", "http://127.0.0.1:47391")
    parsed_broker = urlparse(broker_url)
    try:
        broker_port = parsed_broker.port
    except ValueError as exc:
        raise PreflightError("broker", "ADOBEPY_BROKER_URL has an invalid port") from exc
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
        raise PreflightError(
            "broker", "ADOBEPY_BROKER_URL must be an uncredentialed loopback HTTP origin"
        )
    target = active_env.get("ADOBEPY_TARGET", "default")
    if _TARGET.fullmatch(target) is None:
        raise PreflightError("target", "ADOBEPY_TARGET must be a bounded canonical identifier")
    return ResolvedInstall(
        host_path=host_path,
        host_version=host_version,
        python_path=python_path.resolve(),
        python_version=metadata["python"],
        core_version=metadata["core"],
        extension_path=extension_path.resolve(),
        receipt_path=(state_dir / "receipts" / "aftereffects.json").resolve(),
        bootstrap_error_path=(state_dir / "bootstrap-errors.json").resolve(),
        adobepy_cli=bridge_cli,
        token=token,
        broker_url=broker_url,
        target=target,
        python_modules=modules,
        bridge_identity=bridge_identity or {},
        host_identity=host_identity,
    )


__all__ = [
    "MIN_ADOBEPY_VERSION",
    "MIN_CORE_VERSION",
    "MIN_HOST_VERSION",
    "MIN_PYTHON_VERSION",
    "PreflightError",
    "capture_python_modules",
    "default_extension_path",
    "default_state_dir",
    "host_process_executable",
    "recapture_host_attestation",
    "recapture_python_modules",
    "reattest_bridge_cli",
    "resolve_install",
]
