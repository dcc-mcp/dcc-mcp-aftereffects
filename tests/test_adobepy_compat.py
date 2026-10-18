"""Mandatory integration with the published adobepy 0.12 SDK (no live host)."""

import copy
import ctypes
import importlib.metadata
from dataclasses import replace
from types import SimpleNamespace

import pytest
from adobe.core import BrokerClient
from adobe.core.runtime_identity import RuntimeIdentityAttestation
from test_install_lifecycle import BridgeRunner, healthy_dependencies, resolved_install
from test_runtime import capability_payload

from dcc_mcp_aftereffects import install_io, install_verification
from dcc_mcp_aftereffects.runtime import _normalize_runtime_identity, probe_aftereffects


def identity_wire():
    return {
        "identityVersion": 1,
        "broker": {
            "pid": 42,
            "processStartIdentity": "windows-filetime:133700000000000000",
            "executablePath": "C:/adobepy/bin/adobepy.exe",
            "runtimeVersion": "0.12.0",
            "instanceId": "11111111-1111-4111-8111-111111111111",
        },
        "host": {
            "pid": 43,
            "processStartIdentity": "windows-filetime:133700000000000100",
            "executablePath": "C:/Adobe/AfterEffects.exe",
            "hostVersion": "24.6.2",
            "profileId": "profile-1",
        },
        "bridge": {
            "target": "default",
            "bridgeKind": "cep",
            "bridgeVersion": "0.1.0",
            "connectedAtEpochMs": 1_800_000_000_000,
            "instanceId": "22222222-2222-4222-8222-222222222222",
            "installedPluginRoot": "C:/CEP/aftereffects",
            "moduleOrigin": "C:/CEP/aftereffects/dist/bridge.js",
        },
    }


class PublishedSdkClient(BrokerClient):
    """Keep the SDK's real parsing/RPC surface; only replace network transport."""

    def __init__(self, wire=None):
        super().__init__(token="test-token", target="default")
        self.wire = identity_wire() if wire is None else wire
        self.requests = []

    def _get_json(self, path):
        assert path == "/v1/capabilities"
        return capability_payload()

    def _post_json(self, path, payload):
        self.requests.append((path, payload))
        assert payload["host"] == "after-effects"
        assert payload["target"] == "default"
        if path == "/v1/runtime-identity":
            return copy.deepcopy(self.wire)
        assert path == "/v1/rpc"
        assert (payload["namespace"], payload["method"]) == ("app", "getVersion")
        return {"result": "24.6.2"}


def test_published_sdk_typed_attestation_reaches_adapter():
    assert importlib.metadata.version("adobepy") == "0.12.0"
    client = PublishedSdkClient()
    status = probe_aftereffects(client=client)
    assert status.ready is True
    assert status.version == "24.6.2"
    assert status.identity == _normalize_runtime_identity(identity_wire())
    assert status.identity["broker"]["version"] == "0.12.0"
    assert status.identity["bridge_version"] == "0.1.0"
    assert [path for path, _ in client.requests] == ["/v1/rpc", "/v1/runtime-identity"]


def test_typed_and_wire_attestations_are_equivalent_and_validate_all_fields():
    wire = identity_wire()
    typed = RuntimeIdentityAttestation.from_broker(wire)
    assert _normalize_runtime_identity(typed) == _normalize_runtime_identity(wire)
    assert _normalize_runtime_identity(replace(typed, identity_version=2)) is None
    assert _normalize_runtime_identity({}) is None
    assert _normalize_runtime_identity({"host": "after-effects", "bridge_kind": "cep"}) is None
    for section, field, invalid in (
        ("broker", "pid", True),
        ("broker", "processStartIdentity", " "),
        ("host", "executablePath", "relative/host.exe"),
        ("bridge", "moduleOrigin", "C:/foreign/bridge.js"),
        ("bridge", "instanceId", "not-a-uuid"),
    ):
        malformed = copy.deepcopy(wire)
        malformed[section][field] = invalid
        assert _normalize_runtime_identity(malformed) is None


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("bridge", "target", "other"),
        ("bridge", "bridgeKind", "uxp"),
        ("host", "hostVersion", "99.0.0"),
    ],
)
def test_probe_rejects_valid_but_mismatched_attestation(section, field, value):
    wire = identity_wire()
    wire[section][field] = value
    status = probe_aftereffects(client=PublishedSdkClient(wire))
    assert status.ready is False
    assert status.error_type == "runtime_identity_mismatch"


def test_identity_unavailable_error_remains_fail_closed_and_redacted():
    client = PublishedSdkClient(
        {"error": {"code": -32010, "message": "private-token: no trusted launch receipt"}}
    )
    status = probe_aftereffects(client=client)
    assert status.ready is False
    assert status.identity is None
    assert status.error_type == "runtime_identity_unavailable"
    assert "private-token" not in status.reason


def test_empty_identity_never_counts_as_readiness():
    client = SimpleNamespace(capabilities=capability_payload)
    status = probe_aftereffects(
        client=client,
        app_factory=lambda **kwargs: SimpleNamespace(version="24.6.2", runtime_identity={}),
    )
    assert status.ready is False
    assert status.error_type == "runtime_identity_unavailable"


@pytest.mark.parametrize(
    ("seconds", "microseconds", "size_delta", "expected"),
    [
        (1_720_000_000, 12345, 0, "macos:1720000000:012345"),
        (0, 0, 0, None),
        (1, 0, -1, None),
        (1, 1_000_000, 0, None),
    ],
)
def test_macos_process_start_identity_matches_broker(
    monkeypatch, seconds, microseconds, size_delta, expected
):
    def proc_pidinfo(pid, flavor, arg, pointer, size):
        assert (pid, flavor, arg, size) == (4242, 3, 0, 136)
        pointer._obj.start_seconds = seconds
        pointer._obj.start_microseconds = microseconds
        return size + size_delta

    monkeypatch.setattr(install_verification.sys, "platform", "darwin")
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **kw: SimpleNamespace(proc_pidinfo=proc_pidinfo))
    assert install_verification._process_start_identity(4242) == expected


def test_macos_identity_fails_closed_without_libproc(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("unavailable")

    monkeypatch.setattr(install_verification.sys, "platform", "darwin")
    monkeypatch.setattr(ctypes, "CDLL", unavailable)
    assert install_verification._process_start_identity(4242) is None


def _install_with_layout(tmp_path, layout):
    resolved = resolved_install(tmp_path)
    destination = tmp_path / "staged"
    runner = BridgeRunner()

    def layout_runner(command, **kwargs):
        result = runner(command, **kwargs)
        if layout == "published":
            # Actual CLI layout has no root-level manifest.
            (destination / "manifest.xml").unlink()
        elif layout == "legacy":
            (destination / "CSXS" / "manifest.xml").unlink()
            (destination / "CSXS").rmdir()
        elif layout == "linked-directory":
            (destination / "CSXS").rename(tmp_path / "foreign")
            try:
                (destination / "CSXS").symlink_to(tmp_path / "foreign", target_is_directory=True)
            except OSError:
                pytest.skip("directory symlinks unavailable on this runner")
        return result

    return install_io.run_adobepy_install_bridge(
        cli=resolved.adobepy_cli,
        expected_identity=resolved.bridge_identity,
        destination=destination,
        token=resolved.token,
        broker_url=resolved.broker_url,
        target=resolved.target,
        runner=layout_runner,
    )


def test_install_accepts_published_nested_cep_manifest(tmp_path):
    result = _install_with_layout(tmp_path, "published")
    assert result["host"] == "after-effects"
    assert result["kind"] == "cep"
    assert (tmp_path / "staged" / "CSXS" / "manifest.xml").is_file()


@pytest.mark.parametrize("layout", ["legacy", "linked-directory"])
def test_install_rejects_missing_or_linked_csxs_directory(tmp_path, layout):
    with pytest.raises(install_io.InstallIoError, match="incomplete or mismatched"):
        _install_with_layout(tmp_path, layout)


def test_macos_identity_fails_closed_without_proc_pidinfo(monkeypatch):
    monkeypatch.setattr(install_verification.sys, "platform", "darwin")
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace())
    assert install_verification._process_start_identity(4242) is None


def test_nested_cep_recovery_archive_round_trip_and_directory_digest(tmp_path):
    source = tmp_path / "source"
    (source / "CSXS").mkdir(parents=True)
    (source / "empty").mkdir()
    (source / "CSXS" / "manifest.xml").write_bytes(b"<ExtensionManifest />")
    files = install_io.file_manifest(source)
    receipt = {
        "dcc_type": "aftereffects",
        "extension_path": str(source),
        "files": files,
        "manifest_sha256": install_io._manifest_digest(files),
    }
    archive = tmp_path / "recovery.zip"
    lease = install_io._write_recovery_archive(source, receipt, archive)
    try:
        archive_source = lease.read_bytes(maximum=272 * 1024 * 1024) if lease else archive
        restored = tmp_path / "restored"
        install_io._restore_recovery_archive(archive_source, restored, receipt)
        assert install_io.file_manifest(restored) == files
        malformed = copy.deepcopy(receipt)
        directory = next(item for item in malformed["files"] if item["type"] == "directory")
        directory["sha256"] = "0" * 64
        with pytest.raises(OSError):
            install_io._restore_recovery_archive(archive_source, tmp_path / "tampered", malformed)
    finally:
        if lease is not None:
            lease.close()


def test_typed_identity_preserves_exact_lifecycle_process_and_version_checks(tmp_path):
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())
    prior_status = dependencies.readiness_probe(resolved)
    prior = prior_status.identity
    module = resolved.extension_path / "dist" / "bridge.js"
    module.parent.mkdir(parents=True)
    module.write_text("// synthetic CEP module", encoding="utf-8")
    wire = identity_wire()
    wire["host"].update(
        {
            "pid": prior["host_pid"],
            "processStartIdentity": prior["process_start_identity"],
            "executablePath": prior["process_executable"],
            "hostVersion": prior["host_version"],
            "profileId": prior["profile_id"],
        }
    )
    wire["broker"].update(
        {
            "pid": prior["broker"]["pid"],
            "processStartIdentity": prior["broker"]["process_start_identity"],
            "executablePath": prior["broker"]["executable"],
        }
    )
    wire["bridge"].update(
        {
            "installedPluginRoot": str(resolved.extension_path),
            "moduleOrigin": str(module),
            "connectedAtEpochMs": prior["connected_at_epoch_ms"],
        }
    )
    status = probe_aftereffects(
        client=SimpleNamespace(capabilities=capability_payload),
        app_factory=lambda **kwargs: SimpleNamespace(
            version=resolved.host_version,
            runtime_identity=RuntimeIdentityAttestation.from_broker(wire),
        ),
    )
    assert status.ready is True
    assert install_verification._validate_runtime_identity(
        status, resolved, dependencies.process_probe
    ) == (True, None, None, None)

    def reused_pid(pid):
        observed = dependencies.process_probe(pid)
        return {**observed, "process_start_identity": "windows-filetime:999"}

    failed = install_verification._validate_runtime_identity(status, resolved, reused_pid)
    assert failed[0] is False
    assert failed[3] == "process_identity_mismatch"
    wrong_broker = copy.deepcopy(status.identity)
    wrong_broker["broker"]["version"] = "0.11.0"
    failed = install_verification._validate_runtime_identity(
        replace(status, identity=wrong_broker), resolved, dependencies.process_probe
    )
    assert failed[0] is False
    assert failed[3] == "identity_mismatch"
