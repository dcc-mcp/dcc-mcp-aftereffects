from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from dcc_mcp_aftereffects.install_contract import (
    EXIT_INSTALL,
    EXIT_OK,
    EXIT_PREFLIGHT,
)
from dcc_mcp_aftereffects.install_discovery import (
    capture_python_modules,
    default_extension_path,
)
from dcc_mcp_aftereffects.install_models import InstallRequest, ResolvedInstall
from dcc_mcp_aftereffects.install_service import LifecycleDependencies, run_lifecycle
from dcc_mcp_aftereffects.runtime import AfterEffectsStatus


class BridgeRunner:
    def __init__(self, *, leak: str | None = None):
        self.calls = []
        self.leak = leak

    def __call__(self, command, **kwargs):
        command = list(command)
        self.calls.append((command, kwargs))
        destination = Path(command[command.index("--dest") + 1])
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "manifest.xml").write_text("<ExtensionManifest />", encoding="utf-8")
        (destination / "adobepy.config.js").write_text(
            f"globalThis.__ADOBEPY_TOKEN='{kwargs['env']['ADOBEPY_TOKEN']}';",
            encoding="utf-8",
        )
        stdout = json.dumps(
            {
                "success": True,
                "host": "after-effects",
                "kind": "cep",
                "destination": str(destination),
                "config": str(destination / "adobepy.config.js"),
                "token_configured": True,
            }
        )
        if self.leak is not None:
            stdout += self.leak
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


def _python_module_identities(tmp_path: Path) -> dict[str, object]:
    root = tmp_path / "python-site"
    raw: dict[str, object] = {}
    for key, distribution, version, package in (
        ("adapter", "dcc-mcp-aftereffects", "0.7.0", "dcc_mcp_aftereffects"),
        ("core", "dcc-mcp-core", "0.20.21", "dcc_mcp_core"),
        ("adobepy", "adobepy", "0.6.2", "adobe.after_effects"),
    ):
        relative = Path(*package.split(".")) / "__init__.py"
        module = root / relative
        module.parent.mkdir(parents=True, exist_ok=True)
        contents = f"__version__ = {version!r}\n".encode()
        module.write_bytes(contents)
        normalized = distribution.replace("-", "_")
        metadata = root / f"{normalized}-{version}.dist-info"
        metadata.mkdir(parents=True)
        digest = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode().rstrip("=")
        record = {
            "path": relative.as_posix(),
            "hash": f"sha256={digest}",
            "size": len(contents),
        }
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n",
            encoding="utf-8",
        )
        (metadata / "RECORD").write_text(
            f"{relative.as_posix()},sha256={digest},{len(contents)}\n",
            encoding="utf-8",
        )
        raw[key] = {
            "name": distribution,
            "distribution": distribution,
            "version": version,
            "module_path": str(module.resolve()),
            "distribution_root": str(root.resolve()),
            "metadata_path": str(metadata.resolve()),
            "records": [record],
            "direct_url": None,
        }
    return capture_python_modules(raw)


def resolved_install(tmp_path: Path, secret: str = "bridge-token-secret") -> ResolvedInstall:
    def physical(path: Path) -> dict[str, int]:
        details = path.lstat()
        return {
            "device": int(details.st_dev),
            "inode": int(details.st_ino),
            "mode": int(details.st_mode),
            "links": int(details.st_nlink),
            "modified_ns": int(details.st_mtime_ns),
            "changed_ns": int(details.st_ctime_ns),
        }

    host = tmp_path / "Adobe After Effects 2024" / "Support Files" / "AfterFX.exe"
    host.parent.mkdir(parents=True)
    host.write_bytes(b"host")
    signature_helper = (
        tmp_path / "Windows" / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    signature_helper.parent.mkdir(parents=True)
    signature_helper.write_bytes(b"powershell")
    bridge_bundle = tmp_path / "adobepy-0.6.2-windows-x64"
    bridge_cli = bridge_bundle / "bin" / "adobepy.exe"
    bridge_cli.parent.mkdir(parents=True)
    bridge_cli.write_bytes(b"cli")
    bridge_manifest = bridge_bundle / "package-manifest.json"
    bridge_manifest.write_text(
        json.dumps(
            {
                "name": "adobepy",
                "version": "0.6.2",
                "runtime": "windows-x64",
                "includes": ["bin/adobepy.exe"],
            }
        ),
        encoding="utf-8",
    )
    cli_bytes = bridge_cli.read_bytes()
    manifest_bytes = bridge_manifest.read_bytes()
    return ResolvedInstall(
        host_path=host,
        host_version="24.6",
        python_path=Path(sys.executable),
        python_version="3.12.10",
        core_version="0.20.8",
        extension_path=tmp_path / "CEP" / "extensions" / "dcc-mcp-aftereffects",
        receipt_path=tmp_path / "state" / "receipts" / "aftereffects.json",
        bootstrap_error_path=tmp_path / "state" / "bootstrap-errors.json",
        adobepy_cli=bridge_cli,
        token=secret,
        broker_url="http://127.0.0.1:47391",
        target="default",
        bridge_identity={
            "executable": str(bridge_cli.resolve()),
            "version": "0.6.2",
            "runtime": "windows-x64",
            "bytes": len(cli_bytes),
            "sha256": hashlib.sha256(cli_bytes).hexdigest(),
            "physical": physical(bridge_cli),
            "manifest_path": str(bridge_manifest.resolve()),
            "manifest_bytes": len(manifest_bytes),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "manifest_physical": physical(bridge_manifest),
            "provenance": "official_checksum_release",
        },
        host_identity={
            "platform": "win32",
            "version": "24.6",
            "host": {
                "path": str(host.resolve()),
                "bytes": host.stat().st_size,
                "sha256": hashlib.sha256(host.read_bytes()).hexdigest(),
                "physical": physical(host),
            },
            "signature_helper": {
                "path": str(signature_helper.resolve()),
                "bytes": signature_helper.stat().st_size,
                "sha256": hashlib.sha256(signature_helper.read_bytes()).hexdigest(),
                "physical": physical(signature_helper),
                "subject": "CN=Microsoft Windows, O=Microsoft Corporation",
                "product": "Windows PowerShell",
                "original": "powershell.exe",
                "version": "10.0.26100.1",
            },
        },
        python_modules=_python_module_identities(tmp_path),
    )


def healthy_dependencies(runner: BridgeRunner) -> LifecycleDependencies:
    host_pid = 41_001
    broker_pid = 41_002

    def readiness(resolved: ResolvedInstall) -> AfterEffectsStatus:
        return AfterEffectsStatus(
            True,
            version=resolved.host_version,
            target=resolved.target,
            identity={
                "host": "after-effects",
                "bridge_kind": "cep",
                "target": resolved.target,
                "host_version": resolved.host_version,
                "bridge_version": "0.6.2",
                "host_pid": host_pid,
                "process_start_identity": "test-host-start:41001",
                "process_executable": str(resolved.host_path),
                "instance_id": "after-effects-test-instance",
                "profile_id": "cep-test-profile",
                "plugin_root": str(resolved.extension_path),
                "plugin_module_origin": str(resolved.extension_path / "manifest.xml"),
                "connected_at_epoch_ms": 1_777_777_777_000,
                "broker": {
                    "pid": broker_pid,
                    "process_start_identity": "test-broker-start:41002",
                    "executable": str(resolved.adobepy_cli),
                    "version": "0.6.2",
                    "instance_id": "adobepy-test-instance",
                },
            },
        )

    def process_probe(pid: int):
        if pid == host_pid:
            return {
                "ok": True,
                "executable": None,
                "process_start_identity": "test-host-start:41001",
            }
        if pid == broker_pid:
            return {
                "ok": True,
                "executable": None,
                "process_start_identity": "test-broker-start:41002",
            }
        return {"ok": False}

    def bound_process_probe(pid: int, resolved: ResolvedInstall):
        result = process_probe(pid)
        if pid == host_pid:
            result["executable"] = str(resolved.host_path)
        elif pid == broker_pid:
            result["executable"] = str(resolved.adobepy_cli)
        return result

    current: dict[str, ResolvedInstall] = {}

    def bound_readiness(resolved: ResolvedInstall) -> AfterEffectsStatus:
        current["resolved"] = resolved
        return readiness(resolved)

    def python_distributions(_python: Path, expected):
        observed = {}
        for key, identity in expected.items():
            direct_url_path = Path(identity["metadata_path"]) / "direct_url.json"
            observed[key] = {
                "name": identity["metadata_name"],
                "distribution": identity["distribution"],
                "version": identity["version"],
                "module_path": identity["module_path"],
                "distribution_root": identity["distribution_root"],
                "metadata_path": identity["metadata_path"],
                "direct_url": (
                    json.loads(direct_url_path.read_text(encoding="utf-8"))
                    if direct_url_path.is_file()
                    else None
                ),
                "records": [identity["record"]] if identity["record"] is not None else [],
            }
        return observed

    return LifecycleDependencies(
        bridge_runner=runner,
        import_probe=lambda _python: (True, "adapter imports passed"),
        readiness_probe=bound_readiness,
        process_probe=lambda pid: bound_process_probe(pid, current["resolved"]),
        host_attestation_probe=lambda path, expected: (
            dict(expected) if path == Path(expected["host"]["path"]) else None
        ),
        python_distribution_probe=python_distributions,
    )


def test_install_dry_run_is_a_non_mutating_schema_v1_plan(tmp_path):
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, dry_run=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_OK
    assert report["schema_version"] == 1
    assert report["status"] == "planned"
    assert report["dcc_type"] == "aftereffects"
    assert report["plan"]["mode"] == "fresh"
    assert report["plan"]["python"] == sys.executable
    assert report["receipt_path"] == str(resolved.receipt_path)
    assert report["verify"]["directly_usable"] is False
    assert runner.calls == []
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


def test_install_round_trip_uses_env_token_and_reaches_typed_readiness(tmp_path):
    secret = "never-put-this-token-in-argv"
    resolved = resolved_install(tmp_path, secret)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)

    install_report, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    receipt = json.loads(resolved.receipt_path.read_text(encoding="utf-8"))
    status_report, status_exit = run_lifecycle(
        InstallRequest("status", as_json=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    verify_report, verify_exit = run_lifecycle(
        InstallRequest("verify", as_json=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    uninstall_report, uninstall_exit = run_lifecycle(
        InstallRequest("uninstall", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert (install_exit, status_exit, verify_exit, uninstall_exit) == (0, 0, 0, 0)
    assert install_report["verify"]["directly_usable"] is True
    assert [step["id"] for step in install_report["steps"]] == [
        "preflight",
        "stage-bridge",
        "commit-extension",
        "write-receipt",
        "verify",
        "receipt",
        "host-attestation",
        "target-import",
        "typed-readiness",
    ]
    assert status_report["installation_state"] == "installed"
    assert verify_report["verify"]["directly_usable"] is True
    assert uninstall_report["status"] == "ok"
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert not list(
        resolved.extension_path.parent.glob(f".{resolved.extension_path.name}.recovery-*")
    )

    command, kwargs = runner.calls[0]
    assert "--token" not in command
    assert secret not in " ".join(command)
    assert kwargs["env"]["ADOBEPY_TOKEN"] == secret
    config_entry = next(item for item in receipt["files"] if item["path"] == "adobepy.config.js")
    assert config_entry["type"] == "file"
    assert config_entry["sensitive"] is True
    assert len(config_entry["sha256"]) == 64
    assert secret not in json.dumps(receipt)
    for report in (install_report, status_report, verify_report, uninstall_report):
        assert secret not in json.dumps(report)


def test_external_installer_output_that_leaks_the_token_fails_closed(tmp_path):
    secret = "leaked-token-must-be-redacted"
    resolved = resolved_install(tmp_path, secret)
    runner = BridgeRunner(leak=secret)

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    serialized = json.dumps(report)
    assert exit_code == EXIT_INSTALL
    assert secret not in serialized
    assert report["verify"]["failure_stage"] == "install"
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert secret not in " ".join(runner.calls[0][0])


def test_broker_url_credentials_never_reach_the_external_process(tmp_path):
    credential = "broker-url-secret"
    resolved = replace(
        resolved_install(tmp_path),
        broker_url=f"http://operator:{credential}@127.0.0.1:47391",
    )
    runner = BridgeRunner()

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_INSTALL
    assert runner.calls == []
    assert credential not in json.dumps(report)


def test_upgrade_rolls_back_when_receipt_commit_fails(tmp_path):
    resolved = resolved_install(tmp_path)
    initial_dependencies = healthy_dependencies(BridgeRunner())
    _, initial_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=initial_dependencies,
    )
    assert initial_exit == EXIT_OK
    old_manifest = (resolved.extension_path / "manifest.xml").read_bytes()
    old_receipt = resolved.receipt_path.read_bytes()
    dependencies = healthy_dependencies(BridgeRunner())
    dependencies.receipt_writer = lambda *_args: (_ for _ in ()).throw(OSError("disk full"))

    report, exit_code = run_lifecycle(
        InstallRequest("upgrade", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_INSTALL
    assert report["verify"]["failure_stage"] == "install"
    assert "receipt callback failed" in report["verify"]["failure_reason"].lower()
    assert (resolved.extension_path / "manifest.xml").read_bytes() == old_manifest
    assert resolved.receipt_path.read_bytes() == old_receipt


def test_uninstall_without_a_receipt_never_deletes_partial_files(tmp_path):
    resolved = resolved_install(tmp_path)
    resolved.extension_path.mkdir(parents=True)
    marker = resolved.extension_path / "operator-owned.txt"
    marker.write_text("preserve", encoding="utf-8")

    report, exit_code = run_lifecycle(
        InstallRequest("uninstall", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(BridgeRunner()),
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["installation_state"] == "partial"
    assert report["verify"]["failure_stage"] == "receipt"
    assert marker.read_text(encoding="utf-8") == "preserve"


def test_default_cep_paths_are_user_scoped_on_windows_and_macos(tmp_path):
    windows = default_extension_path(
        platform="win32",
        environ={"APPDATA": str(tmp_path / "Roaming")},
        home=tmp_path,
    )
    macos = default_extension_path(platform="darwin", environ={}, home=tmp_path)

    assert windows == tmp_path / "Roaming" / "Adobe" / "CEP" / "extensions" / "dcc-mcp-aftereffects"
    assert macos == (
        tmp_path
        / "Library"
        / "Application Support"
        / "Adobe"
        / "CEP"
        / "extensions"
        / "dcc-mcp-aftereffects"
    )
