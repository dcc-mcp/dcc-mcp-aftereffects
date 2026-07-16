import json
from pathlib import Path

from dcc_mcp_aftereffects import __version__


def test_version_metadata_is_synchronized():
    root = Path(__file__).parents[1]
    assert f'version = "{__version__}"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    manifest = json.loads((root / ".release-please-manifest.json").read_text(encoding="utf-8"))
    assert manifest["."] == __version__


def test_adapter_uses_shared_adobepy_runtime():
    root = Path(__file__).parents[1]
    assert '"adobepy>=0.5.0,<1.0.0"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    assert not (root / "src" / "dcc_mcp_aftereffects" / "bridge.py").exists()


def test_start_server_defers_port_resolution_to_core(monkeypatch):
    from types import SimpleNamespace

    from dcc_mcp_aftereffects import server as server_module

    ports = []
    stub = SimpleNamespace(
        is_running=False,
        register_builtin_actions=lambda: None,
        start=lambda: None,
        stop=lambda: None,
    )

    monkeypatch.setattr(server_module, "_server", None)
    monkeypatch.setattr(
        server_module,
        "AfterEffectsMcpServer",
        lambda port=None: ports.append(port) or stub,
    )
    monkeypatch.setenv("DCC_MCP_AFTEREFFECTS_PORT", "8765")

    server_module.start_server(0)
    server_module.stop_server()
    server_module.start_server()
    server_module.stop_server()

    assert ports == [0, None]
