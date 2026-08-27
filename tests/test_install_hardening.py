from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.resources
import json
import os
import shutil
import subprocess
import sys
import zipfile
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from test_install_lifecycle import BridgeRunner, healthy_dependencies, resolved_install

import dcc_mcp_aftereffects.install_discovery as install_discovery
import dcc_mcp_aftereffects.install_io as install_io
import dcc_mcp_aftereffects.install_reporting as install_reporting
import dcc_mcp_aftereffects.install_service as install_service
from dcc_mcp_aftereffects.config import AfterEffectsConfig
from dcc_mcp_aftereffects.install_contract import (
    EXIT_INSTALL,
    EXIT_OK,
    EXIT_PREFLIGHT,
    EXIT_VERIFY,
)
from dcc_mcp_aftereffects.install_discovery import (
    PreflightError,
    _resolve_bridge_cli,
    _resolve_host,
    _trusted_host_version,
    _version_key,
    capture_python_modules,
    reattest_host,
    resolve_install,
    trusted_host_attestation,
)
from dcc_mcp_aftereffects.install_io import file_manifest
from dcc_mcp_aftereffects.install_models import InstallRequest
from dcc_mcp_aftereffects.install_reporting import build_preflight_report
from dcc_mcp_aftereffects.install_service import run_lifecycle
from dcc_mcp_aftereffects.install_verification import _validate_runtime_identity
from dcc_mcp_aftereffects.runtime import AfterEffectsStatus

SCHEMA_SHA256 = "3ca25788439917b4d4c0617230a762f9797756b5b54f45c8c4149f975b90f904"


def _validator() -> Draft202012Validator:
    raw = (
        importlib.resources.files("dcc_mcp_aftereffects.schemas")
        .joinpath("adapter-install-sop-v1.schema.json")
        .read_bytes()
    )
    assert len(raw) == 4_261
    assert hashlib.sha256(raw).hexdigest() == SCHEMA_SHA256
    assert b"\r\n" not in raw
    schema = json.loads(raw)
    assert schema["$id"] == "https://dcc-mcp.github.io/schemas/adapter-install-sop-v1.schema.json"
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _recording_windows_signature_runner(executed: list[list[str]]):
    def run(command, **_kwargs):
        executed.append([str(item) for item in command])
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {
                    "helperStatus": "Valid",
                    "helperSubject": "CN=Microsoft Windows, O=Microsoft Corporation",
                    "helperProduct": "Windows PowerShell",
                    "helperOriginal": "powershell.exe",
                    "helperVersion": "10.0.26100.1",
                    "status": "Valid",
                    "subject": "CN=Adobe Inc., O=Adobe Inc.",
                    "product": "Adobe After Effects",
                    "original": "AfterFX.exe",
                    "version": "25.0.0",
                }
            ),
            "",
        )

    return run


def test_packaged_schema_is_the_exact_core_contract() -> None:
    _validator()


def test_every_public_lifecycle_result_validates_canonical_schema(tmp_path: Path) -> None:
    validator = _validator()
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())

    install, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    reports = [install]
    exits = [install_exit]
    for verb in ("status", "verify", "upgrade", "uninstall"):
        report, exit_code = run_lifecycle(
            InstallRequest(verb, as_json=True, dry_run=verb in {"upgrade", "uninstall"}),
            resolved=resolved,
            dependencies=dependencies,
        )
        reports.append(report)
        exits.append(exit_code)

    assert exits == [EXIT_OK] * 5
    for report in reports:
        validator.validate(report)


def test_manifest_is_complete_typed_hashed_closure(tmp_path: Path) -> None:
    root = tmp_path / "bridge"
    (root / "nested").mkdir(parents=True)
    (root / "manifest.xml").write_text("manifest", encoding="utf-8")
    (root / "nested" / "main.js").write_text("main", encoding="utf-8")

    manifest = file_manifest(root)

    assert manifest == [
        {
            "path": "manifest.xml",
            "type": "file",
            "bytes": 8,
            "sha256": hashlib.sha256(b"manifest").hexdigest(),
        },
        {
            "path": "nested",
            "type": "directory",
            "bytes": 0,
            "sha256": hashlib.sha256(b"directory\0nested").hexdigest(),
        },
        {
            "path": "nested/main.js",
            "type": "file",
            "bytes": 4,
            "sha256": hashlib.sha256(b"main").hexdigest(),
        },
    ]


@pytest.mark.skipif(os.name == "nt", reason="Windows test runners may not allow symlinks")
def test_manifest_rejects_symlink_that_escapes_bridge(tmp_path: Path) -> None:
    root = tmp_path / "bridge"
    root.mkdir()
    (root / "escape").symlink_to("../../outside")

    with pytest.raises(OSError, match="Unsafe bridge symlink"):
        file_manifest(root)


@pytest.mark.skipif(os.name != "nt", reason="requires a native Windows directory junction")
def test_manifest_rejects_inner_junction_without_reading_external_bytes(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "bridge"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    external = outside / "operator.txt"
    external.write_bytes(b"operator-owned")
    junction = root / "linked"
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    original_read = Path.read_bytes

    def guarded_read(path: Path) -> bytes:
        if path.resolve() == external.resolve():
            raise AssertionError("external junction bytes were read")
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    with pytest.raises(OSError, match="reparse"):
        file_manifest(root)
    assert original_read(external) == b"operator-owned"


def test_host_attestation_uses_os_owned_helper_and_detects_later_byte_swaps(
    tmp_path: Path, monkeypatch
) -> None:
    system_root = tmp_path / "Windows"
    helper = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b"trusted-system-powershell")
    shadow = tmp_path / "shadow" / "powershell.exe"
    shadow.parent.mkdir()
    shadow.write_bytes(b"attacker-shadow")
    host = tmp_path / "Adobe After Effects 2025" / "Support Files" / "AfterFX.exe"
    host.parent.mkdir(parents=True)
    host.write_bytes(b"MZtrusted-afterfx")
    commands: list[list[str]] = []

    def signed_run(command, **_kwargs):
        commands.append([str(item) for item in command])
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "helperStatus": "Valid",
                    "helperSubject": "CN=Microsoft Windows, O=Microsoft Corporation",
                    "helperProduct": "Windows PowerShell",
                    "helperOriginal": "powershell.exe",
                    "helperVersion": "10.0.26100.1",
                    "status": "Valid",
                    "subject": "CN=Adobe Inc., O=Adobe Inc.",
                    "product": "Adobe After Effects",
                    "original": "AfterFX.exe",
                    "version": "25.0.0",
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(install_discovery.subprocess, "run", signed_run)
    monkeypatch.setattr(install_discovery, "_windows_directory", lambda: system_root)
    monkeypatch.setattr(install_discovery, "_win_verify_trust", lambda _path: True)
    identity = trusted_host_attestation(
        host,
        "win32",
        environ={"SystemRoot": str(system_root), "PATH": str(shadow.parent)},
    )

    assert identity is not None
    assert Path(commands[0][0]) == helper
    assert commands[0][0] != str(shadow)
    assert reattest_host(host, identity) is True

    host.write_bytes(b"MZreplaced-afterfx")
    assert reattest_host(host, identity) is False
    host.write_bytes(b"MZtrusted-afterfx")
    helper.write_bytes(b"replaced-helper")
    assert reattest_host(host, identity) is False

    helper.write_bytes(b"trusted-system-powershell")
    monkeypatch.setattr(install_discovery, "_win_verify_trust", lambda _path: False)
    assert (
        trusted_host_attestation(
            host,
            "win32",
            environ={"SystemRoot": str(system_root), "PATH": str(shadow.parent)},
        )
        is None
    )


def test_host_path_drift_fails_before_any_signature_helper_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = tmp_path / "Adobe After Effects 2025" / "Support Files" / "AfterFX.exe"
    host.parent.mkdir(parents=True)
    host.write_bytes(b"MZtrusted-afterfx")
    expected = _test_host_attestation(host, "25.0.0")
    expected["host"]["path"] = str(tmp_path / "foreign" / "AfterFX.exe")  # type: ignore[index]
    calls: list[Path] = []

    def attest(path: Path, *_args, **_kwargs):
        calls.append(path)
        return deepcopy(expected)

    monkeypatch.setattr(install_discovery, "trusted_host_attestation", attest)

    assert reattest_host(host, expected) is False
    assert calls == []


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows catalog trust APIs")
def test_native_windows_catalog_signed_powershell_is_trusted_without_environment() -> None:
    helper = install_discovery._signature_helper(
        "win32",
        {"SystemRoot": "C:/attacker", "SYSTEMROOT": "C:/attacker", "PATH": "C:/attacker"},
    )

    assert helper is not None
    path, identity = helper
    assert path == install_discovery._windows_directory() / Path(
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    assert identity["bytes"] > 0
    assert len(identity["sha256"]) == 64
    assert install_discovery._win_verify_trust(path) is True


def test_helper_native_trust_is_rechecked_immediately_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system_root = tmp_path / "Windows"
    helper = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b"trusted-helper")
    host = tmp_path / "Adobe After Effects 2025" / "Support Files" / "AfterFX.exe"
    host.parent.mkdir(parents=True)
    host.write_bytes(b"MZtrusted-afterfx")
    trust_results = iter([True, False])
    executed: list[list[str]] = []
    monkeypatch.setattr(install_discovery, "_windows_directory", lambda: system_root)
    monkeypatch.setattr(
        install_discovery,
        "_win_verify_trust",
        lambda _path: next(trust_results),
    )
    monkeypatch.setattr(
        install_discovery.subprocess,
        "run",
        _recording_windows_signature_runner(executed),
    )

    assert trusted_host_attestation(host, "win32", environ={}) is None
    assert executed == []


def test_helper_identity_is_recaptured_immediately_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system_root = tmp_path / "Windows"
    helper = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b"trusted-helper")
    host = tmp_path / "Adobe After Effects 2025" / "Support Files" / "AfterFX.exe"
    host.parent.mkdir(parents=True)
    host.write_bytes(b"MZtrusted-afterfx")
    helper_identities = iter(
        [
            {"path": str(helper), "bytes": 14, "sha256": "a" * 64},
            {"path": str(helper), "bytes": 14, "sha256": "b" * 64},
        ]
    )
    executed: list[list[str]] = []

    def identity(path: Path, _maximum: int):
        if path == helper:
            return next(helper_identities)
        return {"path": str(path), "bytes": 17, "sha256": "c" * 64}

    monkeypatch.setattr(install_discovery, "_windows_directory", lambda: system_root)
    monkeypatch.setattr(install_discovery, "_stable_file_identity", identity)
    monkeypatch.setattr(install_discovery, "_win_verify_trust", lambda _path: True)
    monkeypatch.setattr(
        install_discovery.subprocess,
        "run",
        _recording_windows_signature_runner(executed),
    )

    assert trusted_host_attestation(host, "win32", environ={}) is None
    assert executed == []


def test_upgrade_rolls_back_payload_and_receipt_when_live_verify_fails(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    old_runner = BridgeRunner()
    install, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(old_runner),
    )
    assert install_exit == EXIT_OK
    old_receipt = resolved.receipt_path.read_bytes()
    old_manifest = (resolved.extension_path / "manifest.xml").read_bytes()

    failing = healthy_dependencies(BridgeRunner())
    failing.readiness_probe = lambda _resolved: AfterEffectsStatus(
        False, reason="new CEP bridge did not bind the selected instance"
    )
    report, exit_code = run_lifecycle(
        InstallRequest("upgrade", as_json=True, yes=True),
        resolved=resolved,
        dependencies=failing,
    )

    assert exit_code == EXIT_VERIFY
    assert report["previous_install_restored"] is True
    assert resolved.receipt_path.read_bytes() == old_receipt
    assert (resolved.extension_path / "manifest.xml").read_bytes() == old_manifest


def test_install_refuses_to_overwrite_unreceipted_partial_tree(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    resolved.extension_path.mkdir(parents=True)
    operator_file = resolved.extension_path / "operator-owned.txt"
    operator_file.write_text("preserve", encoding="utf-8")
    runner = BridgeRunner()

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["installation_state"] == "partial"
    assert operator_file.read_text(encoding="utf-8") == "preserve"
    assert runner.calls == []


def test_fresh_install_import_failure_rolls_back_new_payload_and_receipt(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())
    dependencies.import_probe = lambda _python: (False, "selected imports unavailable")

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["verify"]["failure_stage"] == "import"
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


def test_uninstall_receipt_failure_restores_exact_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())
    _, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    assert install_exit == EXIT_OK
    receipt_before = resolved.receipt_path.read_bytes()
    manifest_before = file_manifest(resolved.extension_path)
    original_unlink = Path.unlink

    def fail_receipt_unlink(path: Path, *args, **kwargs):
        if path == resolved.receipt_path:
            raise OSError("simulated receipt lock")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_receipt_unlink)
    report, exit_code = run_lifecycle(
        InstallRequest("uninstall", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_INSTALL
    assert report["status"] == "failed"
    assert resolved.receipt_path.read_bytes() == receipt_before
    assert file_manifest(resolved.extension_path) == manifest_before


def test_uninstall_recovery_cleanup_failure_preserves_an_exact_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())
    _, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    assert install_exit == EXIT_OK
    receipt_before = resolved.receipt_path.read_bytes()
    manifest_before = file_manifest(resolved.extension_path)
    original_safe_remove = install_io.safe_remove_tree
    original_unlink = Path.unlink
    injected = False

    def partial_directory_cleanup(path: Path):
        nonlocal injected
        if (
            not injected
            and ".recovery-" in path.name
            and ".recovery-check-" not in path.name
            and path.is_dir()
        ):
            injected = True
            victim = next(item for item in path.rglob("*") if item.is_file())
            victim.unlink()
            return {"success": False, "errors": ["simulated partial cleanup"]}
        return original_safe_remove(path)

    def fail_atomic_recovery_unlink(path: Path, *args, **kwargs):
        nonlocal injected
        if not injected and ".recovery-" in path.name and path.suffix == ".zip":
            injected = True
            raise PermissionError("simulated atomic recovery cleanup lock")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(install_io, "safe_remove_tree", partial_directory_cleanup)
    monkeypatch.setattr(Path, "unlink", fail_atomic_recovery_unlink)

    report, exit_code = run_lifecycle(
        InstallRequest("uninstall", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert injected is True
    assert exit_code != EXIT_OK
    assert report["status"] in {"failed", "requires_restart"}
    assert resolved.receipt_path.read_bytes() == receipt_before
    assert file_manifest(resolved.extension_path) == manifest_before
    recovery_archives = list(
        resolved.extension_path.parent.glob(f".{resolved.extension_path.name}.recovery-*.zip")
    )
    assert len(recovery_archives) == 1
    assert zipfile.is_zipfile(recovery_archives[0])
    assert not [
        path
        for path in resolved.extension_path.parent.glob(
            f".{resolved.extension_path.name}.recovery-*"
        )
        if path.is_dir()
    ]


@pytest.mark.parametrize(
    "value",
    ["24.0rc1", "24.0+local", " 24.0", "24.0 ", "024.0", "24..0", "9" * 80],
)
def test_versions_reject_noncanonical_or_unbounded_values(value: str) -> None:
    with pytest.raises(PreflightError):
        _version_key(value)


def test_host_override_rejects_non_afterfx_executable(tmp_path: Path) -> None:
    imposter = tmp_path / "Adobe After Effects 2024" / "Support Files" / "python.exe"
    imposter.parent.mkdir(parents=True)
    imposter.write_bytes(b"not After Effects")

    with pytest.raises(PreflightError, match="canonical After Effects"):
        _resolve_host(InstallRequest("status", dcc_path=str(imposter)), "win32", {})


def test_host_override_rejects_unsigned_afterfx_spoof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spoof = tmp_path / "Adobe After Effects 2024" / "Support Files" / "AfterFX.exe"
    spoof.parent.mkdir(parents=True)
    spoof.write_bytes(b"MZunsigned-spoof")
    monkeypatch.setattr(
        "dcc_mcp_aftereffects.install_discovery._trusted_host_version",
        lambda _path, _platform: None,
    )

    with pytest.raises(PreflightError, match="metadata or platform signature"):
        _resolve_host(InstallRequest("status", dcc_path=str(spoof)), "win32", {})


@pytest.mark.parametrize(
    ("helper_product", "helper_original", "helper_is_valid"),
    [
        ("Windows PowerShell", "powershell.exe", True),
        ("Microsoft Windows Operating System", "powershell.exe", True),
        ("Microsoft® Windows® Operating System", "PowerShell.EXE.MUI", True),
        ("Microsoft(R) Windows(R) Operating System", "powershell.exe.mui", True),
        ("Untrusted Windows PowerShell", "powershell.exe", False),
        ("Windows PowerShell", "powershell.exe.backup", False),
    ],
)
@pytest.mark.parametrize(
    ("subject", "product", "original", "expected"),
    [
        ("CN=Adobe Inc., OU=Release", "Adobe After Effects 2024", "AfterFX.exe", "24.6.1"),
        ("CN=Example Corp", "Adobe After Effects 2024", "AfterFX.exe", None),
        ("CN=Adobe Inc.", "Example Renderer", "AfterFX.exe", None),
        ("CN=Adobe Inc.", "Adobe After Effects 2024", "renamed.exe", None),
    ],
)
def test_windows_host_trust_requires_adobe_signer_product_and_original_filename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    subject: str,
    product: str,
    original: str,
    expected: str | None,
    helper_product: str,
    helper_original: str,
    helper_is_valid: bool,
) -> None:
    host = tmp_path / "AfterFX.exe"
    host.write_bytes(b"MZ")
    helper = tmp_path / "Windows" / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b"trusted-powershell")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "Windows"))
    payload = json.dumps(
        {
            "helperStatus": "Valid",
            "helperSubject": "CN=Microsoft Windows, O=Microsoft Corporation",
            "helperProduct": helper_product,
            "helperOriginal": helper_original,
            "helperVersion": "10.0.26100.1",
            "status": "Valid",
            "subject": subject,
            "product": product,
            "original": original,
            "version": "24.6.1",
        }
    )
    monkeypatch.setattr(
        install_discovery.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, payload, ""),
    )
    monkeypatch.setattr(install_discovery, "_windows_directory", lambda: tmp_path / "Windows")
    monkeypatch.setattr(install_discovery, "_win_verify_trust", lambda _path: True)

    assert _trusted_host_version(host, "win32") == (expected if helper_is_valid else None)


def test_bridge_cli_requires_audited_release_manifest(tmp_path: Path) -> None:
    arbitrary = tmp_path / "adobepy.exe"
    arbitrary.write_bytes(b"arbitrary executable")

    assert _resolve_bridge_cli({"ADOBEPY_CLI": str(arbitrary)}) is None


def test_adjacent_manifest_cannot_authenticate_arbitrary_adobepy_cli(tmp_path: Path) -> None:
    cli = _release_cli(tmp_path)
    digest = hashlib.sha256(cli.read_bytes()).hexdigest()

    assert _resolve_bridge_cli({"ADOBEPY_CLI": str(cli), "ADOBEPY_CLI_SHA256": digest}) is None


def _release_cli(tmp_path: Path) -> Path:
    version = importlib.metadata.version("adobepy")
    bundle = tmp_path / f"adobepy-{version}-windows-x64"
    cli = bundle / "bin" / "adobepy.exe"
    cli.parent.mkdir(parents=True)
    cli.write_bytes(b"MZtrusted-test-cli")
    (bundle / "package-manifest.json").write_text(
        json.dumps(
            {
                "name": "adobepy",
                "version": version,
                "runtime": "windows-x64",
                "includes": ["bin/adobepy.exe"],
            }
        ),
        encoding="utf-8",
    )
    return cli


def _test_host_attestation(host: Path, version: str = "24.0") -> dict[str, object]:
    host_bytes = host.read_bytes() if host.is_file() else b"MZnative-test-host"
    helper = host.parent / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return {
        "platform": "win32",
        "version": version,
        "host": {
            "path": str(host.resolve()),
            "bytes": len(host_bytes),
            "sha256": hashlib.sha256(host_bytes).hexdigest(),
        },
        "signature_helper": {
            "path": str(helper.resolve()),
            "bytes": 23,
            "sha256": "b" * 64,
            "subject": "CN=Microsoft Windows, O=Microsoft Corporation",
            "product": "Windows PowerShell",
            "original": "powershell.exe",
            "version": "10.0.26100.1",
        },
    }


def _drifted_attestation(identity: dict[str, object], mode: str) -> dict[str, object] | None:
    if mode == "failure":
        return None
    if mode == "empty":
        return {}
    observed = deepcopy(identity)
    if mode == "identity-change":
        observed["host"]["sha256"] = "c" * 64  # type: ignore[index]
    elif mode == "path-drift":
        observed["host"]["path"] = "C:\\Foreign\\AfterFX.exe"  # type: ignore[index]
    elif mode == "metadata-drift":
        observed["signature_helper"]["product"] = "Foreign PowerShell"  # type: ignore[index]
    else:  # pragma: no cover - protects the test decision table itself
        raise AssertionError(f"unknown drift mode: {mode}")
    return observed


def _resolve_public_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    attestations: list[dict[str, object] | None] | None = None,
):
    host = tmp_path / "Adobe After Effects 2024" / "Support Files" / "AfterFX.exe"
    host.parent.mkdir(parents=True)
    host.write_bytes(b"MZnative-test-host")
    cli = _release_cli(tmp_path)
    version = importlib.metadata.version("adobepy")
    cli_sha256 = hashlib.sha256(cli.read_bytes()).hexdigest()
    manifest = cli.parent.parent / "package-manifest.json"
    manifest_bytes = manifest.read_bytes()
    monkeypatch.setitem(
        install_discovery._PUBLISHED_ADOBEPY_RELEASES,
        (version, "windows-x64"),
        {
            "cli_sha256": cli_sha256,
            "cli_bytes": str(cli.stat().st_size),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "manifest_bytes": str(len(manifest_bytes)),
            "archive_sha256": "a" * 64,
            "release_tag": f"adobepy-v{version}",
            "asset": f"adobepy-{version}-windows-x64.zip",
        },
    )
    stable_identity = _test_host_attestation(host)
    attestation_results = iter(attestations or [stable_identity, stable_identity])

    def attest(*_args, **_kwargs):
        return deepcopy(next(attestation_results))

    monkeypatch.setattr(install_discovery, "trusted_host_attestation", attest)
    environ = {
        "APPDATA": str(tmp_path / "Roaming"),
        "LOCALAPPDATA": str(tmp_path / "Local"),
        "ADOBEPY_CLI": str(cli),
        "ADOBEPY_CLI_SHA256": cli_sha256,
        "ADOBEPY_TOKEN": "test-token-not-for-argv",
        "ADOBEPY_BROKER_URL": "http://127.0.0.1:47391",
        "ADOBEPY_TARGET": "ae-test",
    }
    return resolve_install(
        InstallRequest(
            "install",
            dcc_path=str(host),
            python=str(Path(sys.executable).resolve()),
        ),
        platform="win32",
        environ=environ,
    )


def test_public_preflight_binds_host_python_core_schema_and_cli_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved = _resolve_public_install(tmp_path, monkeypatch)

    assert resolved.host_path.name == "AfterFX.exe"
    assert resolved.host_version == "24.0"
    assert set(resolved.python_modules) == {"adapter", "core", "adobepy"}
    assert all(module["owned"] is True for module in resolved.python_modules.values())
    assert resolved.core_version == importlib.metadata.version("dcc-mcp-core")
    assert resolved.bridge_identity["executable"] == str(resolved.adobepy_cli)
    assert len(resolved.bridge_identity["sha256"]) == 64
    assert resolved.target == "ae-test"


def test_public_preflight_rejects_shadow_adapter_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shadow = tmp_path / "shadow"
    package = shadow / "dcc_mcp_aftereffects"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("__version__ = '99.0'\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(shadow))

    with pytest.raises(PreflightError, match="owned by their selected distributions"):
        _resolve_public_install(tmp_path, monkeypatch)


@pytest.mark.parametrize("second", [None, {}], ids=["failure", "empty"])
def test_resolve_install_requires_a_nonempty_second_host_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    second: dict[str, object] | None,
) -> None:
    host = tmp_path / "Adobe After Effects 2024" / "Support Files" / "AfterFX.exe"
    initial = _test_host_attestation(host)

    with pytest.raises(PreflightError, match="could not be recaptured"):
        _resolve_public_install(
            tmp_path,
            monkeypatch,
            attestations=[initial, second],
        )


@pytest.mark.parametrize(
    "mode",
    ["identity-change", "path-drift", "metadata-drift"],
)
def test_resolve_install_rejects_any_second_attestation_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    host = tmp_path / "Adobe After Effects 2024" / "Support Files" / "AfterFX.exe"
    initial = _test_host_attestation(host)
    changed = _drifted_attestation(initial, mode)

    with pytest.raises(PreflightError, match="changed during preflight"):
        _resolve_public_install(
            tmp_path,
            monkeypatch,
            attestations=[initial, changed],
        )


@pytest.mark.parametrize(
    "mode",
    [
        "missing-expected",
        "failure",
        "empty",
        "identity-change",
        "path-drift",
        "metadata-drift",
    ],
)
def test_install_recaptures_the_exact_host_before_any_staging_or_installer_process(
    tmp_path: Path,
    mode: str,
) -> None:
    base = resolved_install(tmp_path)
    expected = _test_host_attestation(base.host_path, base.host_version)
    resolved_identity = {} if mode == "missing-expected" else expected
    resolved = replace(base, host_identity=resolved_identity)
    observed = expected if mode == "missing-expected" else _drifted_attestation(expected, mode)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)
    attestation_calls: list[tuple[Path, dict[str, object]]] = []

    def recapture(path: Path, identity: dict[str, object]):
        attestation_calls.append((path, deepcopy(identity)))
        return deepcopy(observed)

    dependencies.host_attestation_probe = recapture

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["verify"]["failure_stage"] == "host_attestation"
    expected_calls = [] if mode == "missing-expected" else [(resolved.host_path, expected)]
    assert attestation_calls == expected_calls
    assert runner.calls == []
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert not list(resolved.extension_path.parent.glob(f".{resolved.extension_path.name}.stage-*"))


@pytest.mark.parametrize(
    "mode",
    [
        "missing-expected",
        "failure",
        "empty",
        "identity-change",
        "path-drift",
        "metadata-drift",
    ],
)
def test_verify_requires_exact_host_recapture_before_import_or_runtime_processes(
    tmp_path: Path,
    mode: str,
) -> None:
    base = resolved_install(tmp_path)
    expected = _test_host_attestation(base.host_path, base.host_version)
    resolved = replace(base, host_identity=expected)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)
    dependencies.host_attestation_probe = lambda _path, identity: deepcopy(identity)

    _, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    assert install_exit == EXIT_OK

    verify_resolved = (
        replace(resolved, host_identity={}) if mode == "missing-expected" else resolved
    )
    observed = expected if mode == "missing-expected" else _drifted_attestation(expected, mode)
    dependencies.host_attestation_probe = lambda _path, _identity: deepcopy(observed)
    probe_calls = {"import": 0, "readiness": 0, "process": 0}
    original_import = dependencies.import_probe
    original_readiness = dependencies.readiness_probe
    original_process = dependencies.process_probe

    def import_probe(path: Path):
        probe_calls["import"] += 1
        return original_import(path)

    def readiness_probe(current):
        probe_calls["readiness"] += 1
        return original_readiness(current)

    def process_probe(pid: int):
        probe_calls["process"] += 1
        return original_process(pid)

    dependencies.import_probe = import_probe
    dependencies.readiness_probe = readiness_probe
    dependencies.process_probe = process_probe
    bridge_calls = len(runner.calls)

    report, exit_code = run_lifecycle(
        InstallRequest("verify", as_json=True),
        resolved=verify_resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["verify"]["failure_stage"] == "host_attestation"
    assert len(runner.calls) == bridge_calls
    assert probe_calls == {"import": 0, "readiness": 0, "process": 0}


def test_python_module_byte_drift_stops_before_staging_or_installer(
    tmp_path: Path,
) -> None:
    module = tmp_path / "site-packages" / "adobe" / "after_effects" / "__init__.py"
    module.parent.mkdir(parents=True)
    module.write_text("TRUSTED = True\n", encoding="utf-8")
    captured = {
        key: {
            "distribution": distribution,
            "version": version,
            "module_path": str(module),
            "owned": True,
        }
        for key, distribution, version in (
            ("adapter", "dcc-mcp-aftereffects", "0.7.0"),
            ("core", "dcc-mcp-core", "0.20.21"),
            ("adobepy", "adobepy", "0.6.2"),
        )
    }
    resolved = replace(resolved_install(tmp_path), python_modules=captured)
    module.write_text("FOREIGN_BUT_IMPORTABLE = True\n", encoding="utf-8")
    runner = BridgeRunner()

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["verify"]["failure_stage"] == "python_attestation"
    assert runner.calls == []
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


@pytest.mark.parametrize(
    "drift",
    [
        "same-bytes-independent-file",
        "different-bytes",
        "hardlink",
        "link-or-reparse",
        "module-path",
        "metadata-bytes",
        "metadata-independent-file",
    ],
)
def test_exact_python_identity_drift_has_zero_install_mutation(
    tmp_path: Path,
    drift: str,
) -> None:
    resolved = resolved_install(tmp_path)
    modules = deepcopy(dict(resolved.python_modules))
    adapter = modules["adapter"]
    module = Path(adapter["module_path"])
    metadata = Path(adapter["metadata_path"]) / "METADATA"
    if drift == "same-bytes-independent-file":
        replacement = module.with_suffix(".replacement")
        replacement.write_bytes(module.read_bytes())
        os.replace(replacement, module)
    elif drift == "different-bytes":
        module.write_text("FOREIGN_BUT_IMPORTABLE = True\n", encoding="utf-8")
    elif drift == "hardlink":
        foreign = module.with_suffix(".foreign")
        foreign.write_bytes(module.read_bytes())
        module.unlink()
        os.link(foreign, module)
    elif drift == "link-or-reparse":
        foreign = module.parent.with_name("foreign-adapter")
        shutil.copytree(module.parent, foreign)
        shutil.rmtree(module.parent)
        if os.name == "nt":
            linked = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(module.parent), str(foreign)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert linked.returncode == 0, linked.stderr
        else:
            module.parent.symlink_to(foreign, target_is_directory=True)
    elif drift == "module-path":
        foreign = module.with_suffix(".foreign")
        foreign.write_bytes(module.read_bytes())
        adapter["module_path"] = str(foreign)
        resolved = replace(resolved, python_modules=modules)
    elif drift == "metadata-bytes":
        metadata.write_text("Name: foreign\nVersion: 99\n", encoding="utf-8")
    elif drift == "metadata-independent-file":
        replacement = metadata.with_suffix(".replacement")
        replacement.write_bytes(metadata.read_bytes())
        os.replace(replacement, metadata)
    runner = BridgeRunner()

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["verify"]["failure_stage"] == "python_attestation"
    assert runner.calls == []
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert not list(resolved.extension_path.parent.glob(f".{resolved.extension_path.name}.stage-*"))


@pytest.mark.parametrize(
    "drift",
    ["same-bytes-independent-file", "hardlink", "module-path", "link-or-reparse"],
)
def test_installer_window_module_identity_drift_has_zero_publish(
    tmp_path: Path, drift: str
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    adapter_module = Path(resolved.python_modules["adapter"]["module_path"])

    def drifting_runner(*args, **kwargs):
        result = runner(*args, **kwargs)
        if drift == "same-bytes-independent-file":
            replacement = adapter_module.with_suffix(".installer-replacement")
            replacement.write_bytes(adapter_module.read_bytes())
            os.replace(replacement, adapter_module)
        elif drift == "hardlink":
            foreign = adapter_module.with_suffix(".installer-foreign")
            foreign.write_bytes(adapter_module.read_bytes())
            adapter_module.unlink()
            os.link(foreign, adapter_module)
        elif drift == "module-path":
            adapter_module.rename(adapter_module.with_suffix(".installer-moved"))
        else:
            foreign = adapter_module.parent.with_name("installer-foreign-adapter")
            shutil.copytree(adapter_module.parent, foreign)
            shutil.rmtree(adapter_module.parent)
            if os.name == "nt":
                linked = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(adapter_module.parent), str(foreign)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert linked.returncode == 0, linked.stderr
            else:
                adapter_module.parent.symlink_to(foreign, target_is_directory=True)
        return result

    dependencies = healthy_dependencies(runner)
    dependencies.bridge_runner = drifting_runner

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["status"] == "failed"
    assert report["verify"]["failure_stage"] == "python_attestation"
    assert len(runner.calls) == 1
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert not list(resolved.extension_path.parent.glob(f".{resolved.extension_path.name}.stage-*"))


def test_python_identity_drift_after_post_installer_check_has_zero_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    adapter_module = Path(resolved.python_modules["adapter"]["module_path"])
    original_recapture = install_service.recapture_python_modules
    recaptures = 0

    def drifting_recapture(expected, observed=None):
        nonlocal recaptures
        recaptures += 1
        current = original_recapture(expected, observed)
        if recaptures == 2 and current is not None:
            replacement = adapter_module.with_suffix(".pre-publish-replacement")
            replacement.write_bytes(adapter_module.read_bytes())
            os.replace(replacement, adapter_module)
        return current

    monkeypatch.setattr(install_service, "recapture_python_modules", drifting_recapture)

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["verify"]["failure_stage"] == "python_attestation"
    assert recaptures >= 3
    assert len(runner.calls) == 1
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


def test_python_identity_drift_before_finalize_rolls_back_new_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    adapter_module = Path(resolved.python_modules["adapter"]["module_path"])
    original_recapture = install_service.recapture_python_modules
    recaptures = 0

    def drifting_recapture(expected, observed=None):
        nonlocal recaptures
        recaptures += 1
        current = original_recapture(expected, observed)
        if recaptures == 4 and current is not None:
            replacement = adapter_module.with_suffix(".pre-finalize-replacement")
            replacement.write_bytes(adapter_module.read_bytes())
            os.replace(replacement, adapter_module)
        return current

    monkeypatch.setattr(install_service, "recapture_python_modules", drifting_recapture)

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["verify"]["failure_stage"] == "python_attestation"
    assert recaptures >= 5
    assert len(runner.calls) == 1
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


def test_python_identity_drift_before_receipt_publish_restores_prior_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)
    installed, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    assert install_exit == EXIT_OK, installed
    previous_receipt = resolved.receipt_path.read_bytes()
    previous_files = {
        path.relative_to(resolved.extension_path).as_posix(): path.read_bytes()
        for path in resolved.extension_path.rglob("*")
        if path.is_file()
    }

    adapter_module = Path(resolved.python_modules["adapter"]["module_path"])
    original_recapture = install_service.recapture_python_modules
    recaptures = 0

    def drifting_recapture(expected, observed=None):
        nonlocal recaptures
        recaptures += 1
        current = original_recapture(expected, observed)
        if recaptures == 3 and current is not None:
            replacement = adapter_module.with_suffix(".pre-receipt-replacement")
            replacement.write_bytes(adapter_module.read_bytes())
            os.replace(replacement, adapter_module)
        return current

    monkeypatch.setattr(install_service, "recapture_python_modules", drifting_recapture)

    report, exit_code = run_lifecycle(
        InstallRequest("upgrade", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["verify"]["failure_stage"] == "python_attestation"
    assert recaptures >= 4
    assert resolved.receipt_path.read_bytes() == previous_receipt
    assert {
        path.relative_to(resolved.extension_path).as_posix(): path.read_bytes()
        for path in resolved.extension_path.rglob("*")
        if path.is_file()
    } == previous_files
    assert not list(
        resolved.extension_path.parent.glob(f".{resolved.extension_path.name}.backup-*")
    )


def test_editable_source_replacement_has_zero_install_mutation(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    raw_modules: dict[str, object] = {}
    source = tmp_path / "editable-adapter"
    source_module = source / "src" / "dcc_mcp_aftereffects" / "__init__.py"
    source_module.parent.mkdir(parents=True)
    installed_adapter = Path(resolved.python_modules["adapter"]["module_path"])
    source_module.write_bytes(installed_adapter.read_bytes())
    editable = {"url": source.as_uri(), "dir_info": {"editable": True}}
    metadata_path = Path(resolved.python_modules["adapter"]["metadata_path"])
    (metadata_path / "direct_url.json").write_text(json.dumps(editable), encoding="utf-8")
    for key, identity in resolved.python_modules.items():
        raw_modules[key] = {
            "name": identity["metadata_name"],
            "distribution": identity["distribution"],
            "version": identity["version"],
            "module_path": str(source_module) if key == "adapter" else identity["module_path"],
            "distribution_root": identity["distribution_root"],
            "metadata_path": identity["metadata_path"],
            "records": [] if key == "adapter" else [identity["record"]],
            "direct_url": editable if key == "adapter" else None,
        }
    resolved = replace(resolved, python_modules=capture_python_modules(raw_modules))
    replacement = source.with_name("editable-adapter-replacement")
    shutil.copytree(source, replacement)
    shutil.rmtree(source)
    os.replace(replacement, source)
    runner = BridgeRunner()

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["verify"]["failure_stage"] == "python_attestation"
    assert runner.calls == []
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert not list(resolved.extension_path.parent.glob(f".{resolved.extension_path.name}.stage-*"))


def test_python_capture_binds_name_and_version_to_metadata_bytes(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    raw_modules: dict[str, object] = {}
    for key, identity in resolved.python_modules.items():
        raw_modules[key] = {
            "name": identity["metadata_name"],
            "distribution": identity["distribution"],
            "version": identity["version"],
            "module_path": identity["module_path"],
            "distribution_root": identity["distribution_root"],
            "metadata_path": identity["metadata_path"],
            "records": [identity["record"]],
            "direct_url": None,
        }
    adapter_metadata = Path(resolved.python_modules["adapter"]["metadata_path"]) / "METADATA"
    adapter_metadata.write_text(
        "Metadata-Version: 2.4\nName: foreign-package\nVersion: 99\n",
        encoding="utf-8",
    )

    with pytest.raises(PreflightError, match="owned by their selected distributions"):
        capture_python_modules(raw_modules)


def test_python_recapture_rederives_name_and_version_from_current_metadata(
    tmp_path: Path,
) -> None:
    resolved = resolved_install(tmp_path)
    modules = deepcopy(dict(resolved.python_modules))
    adapter = modules["adapter"]
    metadata_path = Path(adapter["metadata_path"])
    (metadata_path / "METADATA").write_text(
        "Metadata-Version: 2.4\nName: foreign-package\nVersion: 99\n",
        encoding="utf-8",
    )
    adapter["metadata_identity"] = install_discovery._metadata_identity(
        metadata_path, Path(adapter["distribution_root"])
    )

    assert install_discovery.recapture_python_modules(modules) is None


def test_target_interpreter_distribution_semantics_must_match_before_mutation(
    tmp_path: Path,
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)

    def foreign_distribution(_python: Path, expected):
        observed = {}
        for key, identity in expected.items():
            observed[key] = {
                "name": "foreign-package" if key == "adapter" else identity["metadata_name"],
                "distribution": identity["distribution"],
                "version": "99" if key == "adapter" else identity["version"],
                "module_path": identity["module_path"],
                "distribution_root": identity["distribution_root"],
                "metadata_path": identity["metadata_path"],
                "direct_url": None,
            }
        return observed

    dependencies.python_distribution_probe = foreign_distribution

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["verify"]["failure_stage"] == "python_attestation"
    assert runner.calls == []
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


@pytest.mark.parametrize(
    "drift",
    [
        "foreign-name",
        "foreign-version",
        "direct-url-source",
        "record-hash",
        "record-alias",
        "record-duplicate",
    ],
)
def test_distribution_semantic_drift_has_zero_install_mutation(tmp_path: Path, drift: str) -> None:
    resolved = resolved_install(tmp_path)
    modules = deepcopy(dict(resolved.python_modules))
    adapter = modules["adapter"]
    metadata_path = Path(adapter["metadata_path"])
    metadata_file = metadata_path / "METADATA"
    record_file = metadata_path / "RECORD"
    if drift == "foreign-name":
        metadata_file.write_text(
            "Metadata-Version: 2.4\nName: foreign-package\nVersion: 0.7.0\n",
            encoding="utf-8",
        )
    elif drift == "foreign-version":
        metadata_file.write_text(
            "Metadata-Version: 2.4\nName: dcc-mcp-aftereffects\nVersion: 99\n",
            encoding="utf-8",
        )
    elif drift == "direct-url-source":
        foreign_source = tmp_path / "foreign-editable"
        foreign_module = foreign_source / "src" / "dcc_mcp_aftereffects" / "__init__.py"
        foreign_module.parent.mkdir(parents=True)
        foreign_module.write_bytes(Path(adapter["module_path"]).read_bytes())
        (metadata_path / "direct_url.json").write_text(
            json.dumps({"url": foreign_source.as_uri(), "dir_info": {"editable": True}}),
            encoding="utf-8",
        )
    else:
        original_record = record_file.read_text(encoding="utf-8").strip()
        if drift == "record-hash":
            path, _digest, size = original_record.split(",")
            record_file.write_text(f"{path},sha256=AAAA,{size}\n", encoding="utf-8")
        elif drift == "record-alias":
            _path, digest, size = original_record.split(",")
            record_file.write_text(
                f"dcc_mcp_aftereffects/./__init__.py,{digest},{size}\n",
                encoding="utf-8",
            )
        else:
            record_file.write_text(f"{original_record}\n{original_record}\n", encoding="utf-8")
    adapter["metadata_identity"] = install_discovery._metadata_identity(
        metadata_path, Path(adapter["distribution_root"])
    )
    resolved = replace(resolved, python_modules=modules)
    runner = BridgeRunner()

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_PREFLIGHT
    assert report["verify"]["failure_stage"] == "python_attestation"
    assert runner.calls == []
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert not list(resolved.extension_path.parent.glob(f".{resolved.extension_path.name}.stage-*"))


def test_ready_probe_without_exact_runtime_identity_fails_closed(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)
    dependencies.readiness_probe = lambda _resolved: AfterEffectsStatus(
        True, version=resolved.host_version, target=resolved.target
    )

    report, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    status_report, status_exit = run_lifecycle(
        InstallRequest("status", as_json=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert install_exit == EXIT_VERIFY
    assert report["status"] == "failed"
    assert report["verify"]["failure_stage"] == "readiness_identity"
    assert len(runner.calls) == 1
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert status_exit == EXIT_OK
    assert status_report["installation_state"] == "fresh"


@pytest.mark.parametrize(
    "process_identity",
    [
        None,
        {},
        {"ok": False},
        {
            "ok": True,
            "executable": "C:/foreign/AfterFX.exe",
            "process_start_identity": "test-host-start:41001",
        },
    ],
    ids=["missing", "empty", "unavailable", "foreign-executable"],
)
def test_invalid_process_attestation_rolls_back_the_fresh_install(
    tmp_path: Path, process_identity: object
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)
    dependencies.process_probe = lambda _pid: process_identity  # type: ignore[assignment]

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    status_report, status_exit = run_lifecycle(
        InstallRequest("status", as_json=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["status"] == "failed"
    assert report["verify"]["failure_stage"] == "readiness_identity"
    assert len(runner.calls) == 1
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert status_exit == EXIT_OK
    assert status_report["installation_state"] == "fresh"


def test_process_attestation_failure_rolls_back_the_fresh_install(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)

    def unavailable(_pid: int):
        raise OSError("simulated process attestation failure")

    dependencies.process_probe = unavailable

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    status_report, status_exit = run_lifecycle(
        InstallRequest("status", as_json=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["status"] == "failed"
    assert report["verify"]["failure_stage"] == "readiness_identity"
    assert len(runner.calls) == 1
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    assert status_exit == EXIT_OK
    assert status_report["installation_state"] == "fresh"


class _ProcessBoundaryFault(BaseException):
    pass


class _ExplodingIdentity(dict):
    def __getitem__(self, key):
        if key == "host_pid":
            raise _ProcessBoundaryFault("identity-access")
        return super().__getitem__(key)


@pytest.mark.parametrize(
    "failure",
    [KeyError("process-shape"), _ProcessBoundaryFault("process-callback")],
    ids=["ordinary-key-error", "base-exception-callback"],
)
def test_process_attestation_callback_exceptions_roll_back_with_stable_primary_failure(
    tmp_path: Path, failure: BaseException
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)

    def unavailable(_pid: int):
        raise failure

    dependencies.process_probe = unavailable

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["status"] == "failed"
    assert report["verify"]["failure_stage"] == "readiness_identity"
    assert report["verify"]["error_type"] == "process_identity_mismatch"
    assert len(runner.calls) == 1
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


def test_process_attestation_shape_exception_rolls_back_with_stable_primary_failure(
    tmp_path: Path,
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)
    healthy = dependencies.readiness_probe(resolved)
    dependencies.readiness_probe = lambda _resolved: AfterEffectsStatus(
        True,
        version=resolved.host_version,
        target=resolved.target,
        identity=_ExplodingIdentity(healthy.identity or {}),
    )

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["verify"]["failure_stage"] == "readiness_identity"
    assert report["verify"]["error_type"] == "process_identity_mismatch"
    assert len(runner.calls) == 1
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


def test_readiness_callback_base_exception_rolls_back_with_stable_primary_failure(
    tmp_path: Path,
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)
    dependencies.readiness_probe = lambda _resolved: (_ for _ in ()).throw(
        _ProcessBoundaryFault("readiness-callback")
    )

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["verify"]["failure_stage"] == "readiness_identity"
    assert report["verify"]["error_type"] == "process_identity_mismatch"
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


def test_process_attestation_primary_failure_survives_rollback_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    dependencies = healthy_dependencies(runner)
    dependencies.process_probe = lambda _pid: (_ for _ in ()).throw(KeyError("process-shape"))
    original_rollback = install_io.InstallTransaction.rollback

    def rollback_then_fail(transaction):
        original_rollback(transaction)
        raise OSError("simulated rollback reporting failure")

    monkeypatch.setattr(install_io.InstallTransaction, "rollback", rollback_then_fail)

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["verify"]["failure_stage"] == "readiness_identity"
    assert report["verify"]["error_type"] == "process_identity_mismatch"
    assert report["rollback_failed"] is True
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


@pytest.mark.parametrize(
    ("field", "value", "error_type"),
    [
        ("process_executable", "C:/foreign/AfterFX.exe", "identity_mismatch"),
        ("process_start_identity", "stale-start", "process_identity_mismatch"),
        ("plugin_root", "C:/foreign/CEP", "identity_mismatch"),
        ("plugin_module_origin", "C:/foreign/main.js", "wrong_plugin_origin"),
        ("target", "foreign-target", "identity_mismatch"),
        ("host_version", "24.0rc1", "invalid_version"),
    ],
)
def test_verify_rejects_foreign_stale_or_noncanonical_cep_identity(
    tmp_path: Path, field: str, value: str, error_type: str
) -> None:
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())
    _, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    assert install_exit == EXIT_OK
    healthy = dependencies.readiness_probe(resolved)
    forged = dict(healthy.identity or {})
    forged[field] = value
    dependencies.readiness_probe = lambda _resolved: AfterEffectsStatus(
        True,
        version=resolved.host_version,
        target=resolved.target,
        identity=forged,
    )

    report, exit_code = run_lifecycle(
        InstallRequest("verify", as_json=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["verify"]["error_type"] == error_type


def test_extra_or_tampered_bridge_content_blocks_verify_and_uninstall(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())
    _, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    assert install_exit == EXIT_OK
    unowned = resolved.extension_path / "operator-owned.txt"
    unowned.write_text("preserve", encoding="utf-8")

    verify, verify_exit = run_lifecycle(
        InstallRequest("verify", as_json=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    uninstall, uninstall_exit = run_lifecycle(
        InstallRequest("uninstall", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert verify_exit == EXIT_VERIFY
    assert verify["verify"]["failure_stage"] == "receipt"
    assert uninstall_exit != EXIT_OK
    assert uninstall["status"] == "failed"
    assert unowned.read_text(encoding="utf-8") == "preserve"


def test_repeated_uninstall_of_absent_install_is_schema_valid_noop(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    report, exit_code = run_lifecycle(
        InstallRequest("uninstall", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(BridgeRunner()),
    )

    assert exit_code == EXIT_OK
    assert report["status"] == "ok"
    assert report["installation_state"] == "fresh"
    _validator().validate(report)


def test_probe_exception_becomes_stable_schema_valid_failure(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())
    dependencies.readiness_probe = lambda _resolved: (_ for _ in ()).throw(
        KeyError("secret-field-name")
    )

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_VERIFY
    assert report["status"] == "failed"
    assert report["verify"]["failure_stage"] == "readiness_identity"
    assert report["verify"]["error_type"] == "process_identity_mismatch"
    assert "secret-field-name" not in json.dumps(report)
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()
    _validator().validate(report)


@pytest.mark.parametrize("value", ["nan", "inf", "-1", "0", "3601"])
def test_runtime_timeout_is_finite_and_bounded(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("DCC_MCP_AFTEREFFECTS_BROKER_TIMEOUT_SECS", value)
    with pytest.raises(ValueError, match="timeout"):
        AfterEffectsConfig.from_env()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ADOBEPY_TARGET", "bad target"),
        ("ADOBEPY_TARGET", "x" * 129),
        ("ADOBEPY_BROKER_URL", "https://example.com:47391"),
        ("ADOBEPY_BROKER_URL", "http://user:secret@127.0.0.1:47391"),
        ("ADOBEPY_TOKEN", ""),
    ],
)
def test_runtime_security_values_are_bounded(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        AfterEffectsConfig.from_env()


def test_retry_command_preserves_exact_selected_context(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    request = InstallRequest(
        "verify",
        as_json=True,
        dcc_path=str(resolved.host_path),
        python=str(resolved.python_path),
    )
    dependencies = healthy_dependencies(BridgeRunner())
    dependencies.readiness_probe = lambda _resolved: AfterEffectsStatus(False, reason="not ready")
    resolved.extension_path.mkdir(parents=True)

    report, _ = run_lifecycle(request, resolved=resolved, dependencies=dependencies)
    command = report["next_steps"][0]["command"]

    assert command == [
        "dcc-mcp-aftereffects",
        "verify",
        "--json",
        "--dcc-path",
        str(resolved.host_path),
        "--python",
        str(resolved.python_path),
    ]


@pytest.mark.parametrize("replaced", ["cli", "manifest"])
def test_bridge_cli_is_rehashed_immediately_before_external_execution(
    tmp_path: Path, replaced: str
) -> None:
    resolved = resolved_install(tmp_path)
    runner = BridgeRunner()
    selected = (
        resolved.adobepy_cli
        if replaced == "cli"
        else Path(resolved.bridge_identity["manifest_path"])
    )
    selected.write_bytes(b"replaced-after-preflight")

    report, exit_code = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(runner),
    )

    assert exit_code == EXIT_INSTALL
    assert report["verify"]["failure_stage"] == "install"
    assert runner.calls == []


def test_macos_bundle_identity_binds_the_inner_after_effects_process(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    bundle = tmp_path / "Adobe After Effects 2025.app"
    executable = bundle / "Contents" / "MacOS" / "After Effects"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"mach-o-test-double")
    resolved = __import__("dataclasses").replace(resolved, host_path=bundle)
    resolved.extension_path.mkdir(parents=True)
    (resolved.extension_path / "manifest.xml").write_text("<ExtensionManifest />", encoding="utf-8")
    dependencies = healthy_dependencies(BridgeRunner())
    status = dependencies.readiness_probe(resolved)
    identity = dict(status.identity or {})
    identity["process_executable"] = str(executable)
    status = AfterEffectsStatus(
        True,
        version=resolved.host_version,
        target=resolved.target,
        identity=identity,
    )

    def process_probe(pid: int):
        if pid == identity["host_pid"]:
            return {
                "ok": True,
                "executable": str(executable),
                "process_start_identity": identity["process_start_identity"],
            }
        broker = identity["broker"]
        return {
            "ok": True,
            "executable": broker["executable"],
            "process_start_identity": broker["process_start_identity"],
        }

    valid, stage, _reason, error_type = _validate_runtime_identity(status, resolved, process_probe)

    assert (valid, stage, error_type) == (True, None, None)


def test_acquire_failure_has_pinned_executable_windows_remediation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(install_reporting.sys, "platform", "win32")
    request = InstallRequest(
        "install",
        as_json=True,
        yes=True,
        dcc_path="C:/Program Files/Adobe/AfterFX.exe",
        python="C:/Python/python.exe",
    )

    report = build_preflight_report(
        request,
        PreflightError("acquire", "supported CLI unavailable", 20),
    )

    _validator().validate(report)
    acquire = report["next_steps"][0]["command"]
    retry = report["next_steps"][1]["command"]
    assert acquire[:4] == [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
    ]
    assert "adobepy-v0.6.2" in acquire[4]
    assert "9ef9abb5e034359f12e9ce248b0030e38d34c76df343eb2713f18036068719a7" in acquire[4]
    assert "c02f28f07705b69a4f97f9f6639f0f80d1f5292115446801fbd92423336301aa" in acquire[4]
    assert retry == [
        "dcc-mcp-aftereffects",
        "install",
        "--json",
        "--dcc-path",
        "C:/Program Files/Adobe/AfterFX.exe",
        "--python",
        "C:/Python/python.exe",
        "--yes",
    ]


@pytest.mark.parametrize("platform_name", ["darwin", "linux"])
def test_non_windows_acquire_failure_has_no_dead_end_issue_view_remediation(
    monkeypatch: pytest.MonkeyPatch, platform_name: str
) -> None:
    monkeypatch.setattr(install_reporting.sys, "platform", platform_name)
    report = build_preflight_report(
        InstallRequest("install", as_json=True, yes=True),
        PreflightError("acquire", "supported CLI unavailable", 20),
    )

    _validator().validate(report)
    assert report["next_steps"] == []
