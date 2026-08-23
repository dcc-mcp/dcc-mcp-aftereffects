"""Thin compatibility facade for the shared Adapter Install SOP v1 contract."""

from __future__ import annotations

try:
    from dcc_mcp_core.deployment import install_sop as _install_sop

    SCHEMA_VERSION = _install_sop.INSTALL_SOP_SCHEMA_VERSION
    EXIT_OK = _install_sop.INSTALL_EXIT_OK
    EXIT_PREFLIGHT = _install_sop.INSTALL_EXIT_PREFLIGHT
    EXIT_ACQUIRE = _install_sop.INSTALL_EXIT_ACQUIRE
    EXIT_INSTALL = _install_sop.INSTALL_EXIT_INSTALL
    EXIT_VERIFY = _install_sop.INSTALL_EXIT_VERIFY
    EXIT_REQUIRES_RESTART = _install_sop.INSTALL_EXIT_REQUIRES_RESTART
except (ImportError, AttributeError):  # Compatibility until dcc-mcp-core#2320 ships.
    SCHEMA_VERSION = 1
    EXIT_OK = 0
    EXIT_PREFLIGHT = 10
    EXIT_ACQUIRE = 20
    EXIT_INSTALL = 30
    EXIT_VERIFY = 40
    EXIT_REQUIRES_RESTART = 50


def runtime_core_version() -> str:
    import dcc_mcp_core

    return str(getattr(dcc_mcp_core, "__version__", "unavailable"))


__all__ = [
    "EXIT_ACQUIRE",
    "EXIT_INSTALL",
    "EXIT_OK",
    "EXIT_PREFLIGHT",
    "EXIT_REQUIRES_RESTART",
    "EXIT_VERIFY",
    "SCHEMA_VERSION",
    "runtime_core_version",
]
