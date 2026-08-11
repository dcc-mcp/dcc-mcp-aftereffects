"""Declared capabilities for the After Effects adapter."""

from __future__ import annotations


def aftereffects_capabilities():
    from dcc_mcp_core import DccCapabilities

    return DccCapabilities(
        scene_info=True,
        file_operations=True,
        selection=True,
        scene_manager=True,
        transform=True,
        render_capture=True,
        hierarchy=True,
        has_embedded_python=False,
        bridge_kind="adobepy_broker",
        bridge_endpoint="http://127.0.0.1:47391",
        extensions={"official_dom": True, "extend_script": True},
    )


__all__ = ["aftereffects_capabilities"]
