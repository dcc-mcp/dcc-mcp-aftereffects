"""Host, interpreter, profile, and external-bridge discovery."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
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
    """Use WinVerifyTrust directly before trusting PowerShell signature output."""
    if os.name != "nt":
        return False

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
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes.c_ulong),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.c_ulong),
            ("dwUIContext", ctypes.c_ulong),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    action = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None)
    trust_data = WINTRUST_DATA(
        ctypes.sizeof(WINTRUST_DATA),
        None,
        None,
        2,
        0,
        1,
        ctypes.pointer(file_info),
        0,
        None,
        None,
        0x00001000,
        0,
        None,
    )
    try:
        return (
            ctypes.windll.wintrust.WinVerifyTrust(
                None, ctypes.byref(action), ctypes.byref(trust_data)
            )
            == 0
        )
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
            or re.search(
                r"Windows PowerShell", str(payload.get("helperProduct", "")), re.IGNORECASE
            )
            is None
            or str(payload.get("helperOriginal", "")).casefold() != "powershell.exe"
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
        if helper_identity is None:
            return None
    host_identity = _stable_file_identity(_host_binary(path, platform), 2_147_483_647)
    if host_identity is None:
        return None
    evidence = _verified_host_evidence(path, platform, helper)
    if evidence is None:
        return None
    version, helper_metadata = evidence
    try:
        _version_key(version)
    except PreflightError:
        return None
    return {
        "platform": platform,
        "version": version,
        "host": host_identity,
        "signature_helper": {**helper_identity, **helper_metadata},
    }


def reattest_host(path: Path, expected: Mapping[str, Any]) -> bool:
    """Re-run signature verification and byte binding immediately before readiness."""
    try:
        platform = expected["platform"]
        helper = Path(expected["signature_helper"]["path"])
    except (KeyError, TypeError):
        return False
    if not isinstance(platform, str):
        return False
    current = trusted_host_attestation(path, platform, helper_path=helper)
    return current == dict(expected)


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
) -> tuple[Path, str]:
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
    version = _trusted_host_version(resolved_host, platform)
    if version is None:
        raise PreflightError(
            "host",
            "After Effects product metadata or platform signature could not be verified",
        )
    if _version_key(version) < MIN_HOST_VERSION:
        raise PreflightError(
            "host_version",
            f"After Effects {version} is unsupported; version {MIN_HOST_VERSION} or newer is required",
        )
    return resolved_host, version


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


def _python_metadata(python_path: Path) -> dict[str, Any]:
    script = r"""
import hashlib
import importlib.metadata as metadata
import importlib.resources as resources
import json
import pathlib
import sys
import urllib.parse
import urllib.request

import adobe.after_effects
import dcc_mcp_aftereffects
import dcc_mcp_core


def describe(distribution_name, package_name, module):
    distribution = metadata.distribution(distribution_name)
    module_path = pathlib.Path(module.__file__).resolve()
    record_paths = {
        pathlib.Path(distribution.locate_file(item)).resolve()
        for item in tuple(distribution.files or ())
    }
    record_owned = module_path in record_paths
    editable_root = None
    try:
        raw = distribution.read_text("direct_url.json")
        direct_url = json.loads(raw) if raw else None
        url = direct_url.get("url") if isinstance(direct_url, dict) else None
        editable = (
            direct_url.get("dir_info", {}).get("editable") is True
            if isinstance(direct_url, dict)
            else False
        )
        parsed = urllib.parse.urlsplit(url) if isinstance(url, str) else None
        if editable and parsed and parsed.scheme == "file" and not parsed.query and not parsed.fragment:
            editable_root = pathlib.Path(
                urllib.request.url2pathname(urllib.parse.unquote(parsed.path))
            ).resolve()
    except Exception:
        editable_root = None
    editable_owned = bool(
        editable_root
        and module_path
        in {
            editable_root / "src" / pathlib.Path(*package_name.split(".")) / "__init__.py",
            editable_root / pathlib.Path(*package_name.split(".")) / "__init__.py",
        }
    )
    return {
        "distribution": distribution_name,
        "version": distribution.version,
        "module_path": str(module_path),
        "owned": record_owned or editable_owned,
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
            "dcc-mcp-aftereffects", "dcc_mcp_aftereffects", dcc_mcp_aftereffects
        ),
        "core": describe("dcc-mcp-core", "dcc_mcp_core", dcc_mcp_core),
        "adobepy": describe("adobepy", "adobe.after_effects", adobe.after_effects),
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
    host_path, host_version = _resolve_host(request, active_platform, active_env)
    host_identity = trusted_host_attestation(host_path, active_platform, environ=active_env) or {}
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
            or module.get("owned") is not True
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
    "default_extension_path",
    "default_state_dir",
    "host_process_executable",
    "reattest_bridge_cli",
    "resolve_install",
]
