"""Host, interpreter, profile, and external-bridge discovery."""

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Mapping

from packaging.version import InvalidVersion, Version

from .install_contract import EXIT_ACQUIRE, EXIT_PREFLIGHT
from .install_models import InstallRequest, ResolvedInstall

MIN_HOST_VERSION = Version("24.0")
MIN_PYTHON_VERSION = Version("3.9")
MIN_CORE_VERSION = Version("0.19.91")
MIN_ADOBEPY_VERSION = Version("0.6.1")


class PreflightError(RuntimeError):
    def __init__(self, stage: str, message: str, exit_code: int = EXIT_PREFLIGHT):
        super().__init__(message)
        self.stage = stage
        self.exit_code = exit_code


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


def _host_version(path: Path) -> str:
    if path.suffix.lower() == ".app":
        plist_path = path / "Contents" / "Info.plist"
        if plist_path.is_file():
            with plist_path.open("rb") as handle:
                value = plistlib.load(handle).get("CFBundleShortVersionString")
            if value:
                return str(value)
    text = str(path)
    explicit = re.search(r"After Effects\s+(20\d{2})", text, flags=re.IGNORECASE)
    if explicit:
        return f"{int(explicit.group(1)) - 2000}.0"
    release = re.search(r"(?:^|[^\d])(\d{2}(?:\.\d+)+)(?:[^\d]|$)", text)
    if release:
        return release.group(1)
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
    if not host_path.exists():
        raise PreflightError("host", f"After Effects path does not exist: {host_path}")
    version = _host_version(host_path)
    if _version_key(version) < MIN_HOST_VERSION:
        raise PreflightError(
            "host_version",
            f"After Effects {version} is unsupported; version {MIN_HOST_VERSION} or newer is required",
        )
    return host_path.resolve(), version


def _version_key(value: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion as exc:
        raise PreflightError("version", f"Invalid version value: {value}") from exc


def _python_metadata(python_path: Path) -> dict[str, str]:
    script = (
        "import importlib.metadata as m,json,sys;"
        "import adobe,dcc_mcp_core;"
        "print(json.dumps({'python':'.'.join(map(str,sys.version_info[:3])),"
        "'core':str(dcc_mcp_core.__version__),'adobepy':m.version('adobepy')}))"
    )
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
        raise PreflightError("python", f"Target Python could not be inspected: {exc}") from exc
    if completed.returncode != 0:
        raise PreflightError(
            "python",
            "Target Python must import adobepy and dcc-mcp-core before host installation",
        )
    try:
        return json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise PreflightError("python", "Target Python returned invalid preflight metadata") from exc


def _resolve_bridge_cli(environ: Mapping[str, str]) -> Path | None:
    configured = environ.get("ADOBEPY_CLI")
    selected = configured or shutil.which("adobepy")
    if not selected:
        return None
    path = Path(selected).expanduser()
    return path.resolve() if path.is_file() else None


def resolve_install(
    request: InstallRequest,
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> ResolvedInstall:
    active_platform = platform or sys.platform
    active_env = os.environ if environ is None else environ
    host_path, host_version = _resolve_host(request, active_platform, active_env)
    python_path = Path(request.python or sys.executable).expanduser()
    if not python_path.is_file():
        raise PreflightError("python", f"Target Python does not exist: {python_path}")
    metadata = _python_metadata(python_path)
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
    bridge_cli = _resolve_bridge_cli(active_env)
    if request.command in {"install", "upgrade"} and bridge_cli is None:
        raise PreflightError(
            "acquire",
            "The supported adobepy CLI is unavailable; set ADOBEPY_CLI to an official release binary",
            EXIT_ACQUIRE,
        )
    token = active_env.get("ADOBEPY_TOKEN")
    if request.command in {"install", "upgrade", "verify"} and not token:
        raise PreflightError(
            "authentication",
            "ADOBEPY_TOKEN must be configured in the installer environment",
        )
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
        broker_url=active_env.get("ADOBEPY_BROKER_URL"),
        target=active_env.get("ADOBEPY_TARGET", "default"),
    )


__all__ = [
    "MIN_ADOBEPY_VERSION",
    "MIN_CORE_VERSION",
    "MIN_HOST_VERSION",
    "MIN_PYTHON_VERSION",
    "PreflightError",
    "default_extension_path",
    "default_state_dir",
    "resolve_install",
]
