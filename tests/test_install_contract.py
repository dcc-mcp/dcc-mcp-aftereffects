"""Guards the two distinct Install SOP version meanings against core drift.

The report document's ``schema_version`` field and the published Install SOP
schema *artifact* revision are different counters that happen to share a name
upstream. dcc-mcp-core assigns ``INSTALL_SOP_SCHEMA_VERSION`` to the artifact
revision (2 since 0.20.36) while the artifact pins the report field's ``const``
at 1. Emitting the artifact revision in a report makes every doctor/verify/
install result violate the very schema it declares, so the two are named
separately in ``install_contract`` and cross-checked here.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest


def _published_schema_const() -> int:
    """The ``schema_version`` value the resolved core's Install SOP pins."""
    from dcc_mcp_core.deployment import load_install_sop_schema

    return load_install_sop_schema()["properties"]["schema_version"]["const"]


def _installed_core_artifact(filename: str) -> tuple[str, int, str]:
    """Identify the Install SOP artifact bytes the *resolved* core ships."""
    import dcc_mcp_core

    raw = (pathlib.Path(dcc_mcp_core.__file__).parent / "schemas" / filename).read_bytes()
    return json.loads(raw)["$id"], len(raw), hashlib.sha256(raw).hexdigest()


def test_report_schema_version_matches_the_published_schema_const():
    # The report field must track the artifact's `const`, never the artifact
    # revision, so a core that moves the const has to break CI here instead of
    # shipping reports that fail their own schema.
    from dcc_mcp_aftereffects.install_contract import (
        SCHEMA_VERSION,
        report_schema_version,
    )

    assert SCHEMA_VERSION == _published_schema_const()
    assert report_schema_version() == SCHEMA_VERSION


def test_installed_core_artifact_matches_a_pinned_revision():
    # The regression this file exists to catch: preflight rejects any core whose
    # artifact bytes are not pinned, so every revision a supported core has
    # published has to be in the whitelist. Reading the installed core keeps
    # this honest on both CI dependency lanes (floor and latest), where the
    # resolved core -- and therefore the shipped artifact -- differs.
    from dcc_mcp_aftereffects.install_contract import INSTALL_SOP_ARTIFACT_PINS

    artifact_id, size, digest = _installed_core_artifact("adapter-install-sop-v1.schema.json")
    pins = INSTALL_SOP_ARTIFACT_PINS.get(artifact_id)

    assert pins is not None, f"unpinned Install SOP artifact: {artifact_id}"
    assert (size, digest) in pins, f"unpinned artifact revision: {artifact_id} {size} {digest}"


def test_unreadable_core_schema_stays_a_preflight_failure(monkeypatch):
    # Core funnels every schema-load failure into RuntimeError, so a plain
    # `except (OSError, TypeError, ValueError)` catches none of them. Left
    # uncaught, the error reaches the generic lifecycle fallback and the CLI
    # returns EXIT_INSTALL (30) with failure_stage=internal_error instead of
    # EXIT_PREFLIGHT (10) -- a different branch for any SOP-driven caller.
    from dcc_mcp_aftereffects.install_contract import (
        EXIT_INSTALL,
        EXIT_PREFLIGHT,
        report_schema_version,
    )
    from dcc_mcp_aftereffects.install_discovery import PreflightError

    assert EXIT_PREFLIGHT != EXIT_INSTALL

    monkeypatch.setattr(
        report_schema_version.__globals__["_install_sop"],
        "load_install_sop_schema",
        lambda: (_ for _ in ()).throw(
            RuntimeError("Install SOP schema integrity error: schema_digest_mismatch")
        ),
    )

    with pytest.raises(RuntimeError):
        report_schema_version()

    # The call site converts it, so the preflight exit code is preserved.
    with pytest.raises(PreflightError, match="could not be read"):
        try:
            report_schema_version()
        except Exception as exc:  # noqa: BLE001 - deliberate exit-code guard
            raise PreflightError(
                "core", "Target Core's Install SOP schema could not be read"
            ) from exc


def test_artifact_pins_are_exact_byte_identities():
    # The installed core is resolved at runtime, so every byte-exact revision of
    # a pinned artifact has to be accepted. Entries stay exact (size, sha256)
    # pairs -- they are never widened into a range.
    from dcc_mcp_aftereffects.install_contract import INSTALL_SOP_ARTIFACT_PINS

    assert INSTALL_SOP_ARTIFACT_PINS
    for artifact_id, pins in INSTALL_SOP_ARTIFACT_PINS.items():
        assert artifact_id.startswith("https://dcc-mcp.github.io/schemas/")
        assert pins
        for size, digest in pins:
            assert isinstance(size, int) and size > 0
            assert len(digest) == 64
            assert digest == digest.lower()


def test_emitted_reports_satisfy_the_published_schema():
    # Whole-document check, so a regression is caught even if the const above
    # and the report body ever disagree. The validator runs through the native
    # ABI, which a pure-Python core build does not ship; the const assertions
    # above stay unconditional.
    try:
        from dcc_mcp_core.deployment import validate_install_sop_report
    except ImportError:
        pytest.skip("resolved dcc-mcp-core has no Install SOP validator ABI")

    # The validator imports the native extension at *call* time and raises
    # RuntimeError when it is missing (a pure-Python core build), so probe the
    # ABI before calling -- an ImportError-only guard would FAIL rather than
    # skip on those builds.
    native_core = pytest.importorskip("dcc_mcp_core._core")
    if not callable(getattr(native_core, "_validate_install_sop_report_json", None)):
        pytest.skip("resolved dcc-mcp-core has no Install SOP validator ABI")

    from dcc_mcp_aftereffects.install_discovery import PreflightError
    from dcc_mcp_aftereffects.install_models import InstallRequest
    from dcc_mcp_aftereffects.install_reporting import build_preflight_report

    report = build_preflight_report(
        InstallRequest("install", as_json=True), PreflightError("host", "unit-test")
    )
    validate_install_sop_report(report)
    assert report["schema_version"] == _published_schema_const()
