from dcc_mcp_aftereffects.capabilities import aftereffects_capabilities


def test_aftereffects_declares_bridge_domain_capabilities():
    capabilities = aftereffects_capabilities()

    assert capabilities.scene_info is True
    assert capabilities.file_operations is True
    assert capabilities.selection is True
    assert capabilities.scene_manager is True
    assert capabilities.transform is True
    assert capabilities.render_capture is True
    assert capabilities.hierarchy is True
    assert capabilities.has_embedded_python is False
    assert capabilities.bridge_kind == "adobepy_broker"
    assert capabilities.extensions["official_dom"] is True
