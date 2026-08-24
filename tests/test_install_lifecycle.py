from __future__ import annotations

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
from dcc_mcp_aftereffects.install_discovery import default_extension_path
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


def resolved_install(tmp_path: Path, secret: str = "bridge-token-secret") -> ResolvedInstall:
    host = tmp_path / "Adobe After Effects 2024" / "Support Files" / "AfterFX.exe"
    host.parent.mkdir(parents=True)
    host.write_bytes(b"host")
    bridge_cli = tmp_path / "adobepy.exe"
    bridge_cli.write_bytes(b"cli")
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

    return LifecycleDependencies(
        bridge_runner=runner,
        import_probe=lambda _python: (True, "adapter imports passed"),
        readiness_probe=bound_readiness,
        process_probe=lambda pid: bound_process_probe(pid, current["resolved"]),
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
        "target-import",
        "typed-readiness",
    ]
    assert status_report["installation_state"] == "installed"
    assert verify_report["verify"]["directly_usable"] is True
    assert uninstall_report["status"] == "ok"
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()

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
    assert report["verify"]["failure_stage"] == "rollback"
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
