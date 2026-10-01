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

import pytest


def _published_schema_const() -> int:
    """The ``schema_version`` value the resolved core's Install SOP pins."""
    from dcc_mcp_core.deployment import load_install_sop_schema

    return load_install_sop_schema()["properties"]["schema_version"]["const"]


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


def test_artifact_schema_version_tracks_core_without_hijacking_the_report_field():
    # `ARTIFACT_SCHEMA_VERSION` is the artifact revision and moves with core;
    # `SCHEMA_VERSION` must stay pinned to the report const regardless.
    import dcc_mcp_core

    from dcc_mcp_aftereffects.install_contract import (
        ARTIFACT_SCHEMA_VERSION,
        SCHEMA_VERSION,
    )

    assert ARTIFACT_SCHEMA_VERSION == dcc_mcp_core.INSTALL_SOP_SCHEMA_VERSION
    assert SCHEMA_VERSION == _published_schema_const()


def test_artifact_pins_admit_every_byte_exact_revision_core_published():
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

    from dcc_mcp_aftereffects.install_discovery import PreflightError
    from dcc_mcp_aftereffects.install_models import InstallRequest
    from dcc_mcp_aftereffects.install_reporting import build_preflight_report

    report = build_preflight_report(
        InstallRequest("install", as_json=True), PreflightError("host", "unit-test")
    )
    validate_install_sop_report(report)
    assert report["schema_version"] == _published_schema_const()
