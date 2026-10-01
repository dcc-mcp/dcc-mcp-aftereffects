"""Pinned shared Adapter Install SOP v1 contract."""

from __future__ import annotations

from dcc_mcp_core.deployment import install_sop as _install_sop

# `INSTALL_SOP_SCHEMA_VERSION` is the revision of the published Install SOP
# schema *artifact* (`adapter-install-sop-vN.schema.json`), 2 since
# dcc-mcp-core 0.20.36. It is NOT the value of the `schema_version` field that
# the artifact pins on a report document: that field is a separate, stable
# counter declared as `properties.schema_version.const` and stays at 1, because
# artifact revisions only add optional members. The two are named separately
# here -- conflating them makes every doctor/verify/install report fail
# validation the moment the resolved core advances.
ARTIFACT_SCHEMA_VERSION = _install_sop.INSTALL_SOP_SCHEMA_VERSION

# Value of the report document's own `schema_version` field, i.e. the `const`
# the published Install SOP schema enforces. Kept in sync with
# `load_install_sop_schema()["properties"]["schema_version"]["const"]` by
# tests/test_install_contract.py, which fails when the resolved core drifts.
SCHEMA_VERSION = 1

EXIT_OK = _install_sop.INSTALL_EXIT_OK
EXIT_PREFLIGHT = _install_sop.INSTALL_EXIT_PREFLIGHT
EXIT_ACQUIRE = _install_sop.INSTALL_EXIT_ACQUIRE
EXIT_INSTALL = _install_sop.INSTALL_EXIT_INSTALL
EXIT_VERIFY = _install_sop.INSTALL_EXIT_VERIFY
EXIT_REQUIRES_RESTART = _install_sop.INSTALL_EXIT_REQUIRES_RESTART
INSTALL_SOP_SCHEMA_ID = "https://dcc-mcp.github.io/schemas/adapter-install-sop-v1.schema.json"
INSTALL_SOP_SCHEMA_SIZE = 4_261
INSTALL_SOP_SCHEMA_SHA256 = "3ca25788439917b4d4c0617230a762f9797756b5b54f45c8c4149f975b90f904"

# dcc-mcp-core 0.20.35 re-published the *v1* artifact in place, keeping its
# `$id` while growing it from 4261 to 4899 bytes. The second revision is named
# alongside the first so the original bytes stay pinned instead of being
# silently overwritten by a supposedly immutable published artifact.
INSTALL_SOP_SCHEMA_SIZE_REVISION_2 = 4_899
INSTALL_SOP_SCHEMA_SHA256_REVISION_2 = (
    "2b3a8a101384a5163c7569c4a2b0de6586c672c5ee291735f94334a33b7d37a0"
)

# Integrity pins for the Install SOP artifact shipped inside dcc-mcp-core, as a
# whitelist of exact `(size, sha256)` pairs keyed by artifact `$id`.
#
# The installed core is resolved at runtime and the floor is `>=0.20.14`, so
# every byte-exact revision a supported core has published must be accepted or
# preflight rejects a legitimate core. An entry admits only exact,
# distribution-owned bytes -- never a range, and never content that the core
# distribution does not own.
INSTALL_SOP_ARTIFACT_PINS: dict[str, frozenset[tuple[int, str]]] = {
    INSTALL_SOP_SCHEMA_ID: frozenset(
        {
            (INSTALL_SOP_SCHEMA_SIZE, INSTALL_SOP_SCHEMA_SHA256),
            (INSTALL_SOP_SCHEMA_SIZE_REVISION_2, INSTALL_SOP_SCHEMA_SHA256_REVISION_2),
        }
    ),
}


def runtime_core_version() -> str:
    import dcc_mcp_core

    return str(getattr(dcc_mcp_core, "__version__", "unavailable"))


def report_schema_version() -> int:
    """The ``schema_version`` const the resolved core's Install SOP pins.

    Reports must carry :data:`SCHEMA_VERSION`. This reads the value back out of
    the artifact so a core that moves the ``const`` is detected at preflight
    time instead of shipping reports that violate their own declared schema.
    A core that cannot produce the document yields ``SCHEMA_VERSION``, so the
    report path stays usable; tests/test_install_contract.py is the guard that
    is guaranteed to run in CI.
    """
    try:
        schema = _install_sop.load_install_sop_schema()
        const = schema.get("properties", {}).get("schema_version", {}).get("const")
    except (AttributeError, OSError, TypeError, ValueError):
        return SCHEMA_VERSION
    return const if isinstance(const, int) and not isinstance(const, bool) else SCHEMA_VERSION


__all__ = [
    "ARTIFACT_SCHEMA_VERSION",
    "EXIT_ACQUIRE",
    "EXIT_INSTALL",
    "EXIT_OK",
    "EXIT_PREFLIGHT",
    "EXIT_REQUIRES_RESTART",
    "EXIT_VERIFY",
    "INSTALL_SOP_ARTIFACT_PINS",
    "INSTALL_SOP_SCHEMA_ID",
    "INSTALL_SOP_SCHEMA_SHA256",
    "INSTALL_SOP_SCHEMA_SHA256_REVISION_2",
    "INSTALL_SOP_SCHEMA_SIZE",
    "INSTALL_SOP_SCHEMA_SIZE_REVISION_2",
    "SCHEMA_VERSION",
    "report_schema_version",
    "runtime_core_version",
]
