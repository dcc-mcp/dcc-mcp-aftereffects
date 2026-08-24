"""Pinned shared Adapter Install SOP v1 contract."""

from __future__ import annotations

from dcc_mcp_core.deployment import install_sop as _install_sop

SCHEMA_VERSION = _install_sop.INSTALL_SOP_SCHEMA_VERSION
EXIT_OK = _install_sop.INSTALL_EXIT_OK
EXIT_PREFLIGHT = _install_sop.INSTALL_EXIT_PREFLIGHT
EXIT_ACQUIRE = _install_sop.INSTALL_EXIT_ACQUIRE
EXIT_INSTALL = _install_sop.INSTALL_EXIT_INSTALL
EXIT_VERIFY = _install_sop.INSTALL_EXIT_VERIFY
EXIT_REQUIRES_RESTART = _install_sop.INSTALL_EXIT_REQUIRES_RESTART
INSTALL_SOP_SCHEMA_ID = "https://dcc-mcp.github.io/schemas/adapter-install-sop-v1.schema.json"
INSTALL_SOP_SCHEMA_SIZE = 4_261
INSTALL_SOP_SCHEMA_SHA256 = "3ca25788439917b4d4c0617230a762f9797756b5b54f45c8c4149f975b90f904"


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
    "INSTALL_SOP_SCHEMA_ID",
    "INSTALL_SOP_SCHEMA_SHA256",
    "INSTALL_SOP_SCHEMA_SIZE",
    "SCHEMA_VERSION",
    "runtime_core_version",
]
