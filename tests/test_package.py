import json
import re
from pathlib import Path

from packaging.requirements import Requirement

from dcc_mcp_aftereffects import __version__


def test_version_metadata_is_synchronized():
    root = Path(__file__).parents[1]
    assert f'version = "{__version__}"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    manifest = json.loads((root / ".release-please-manifest.json").read_text(encoding="utf-8"))
    assert manifest["."] == __version__
    install_guide = (root / "install.md").read_text(encoding="utf-8")
    install_version = re.search(
        r"Current adapter release: \*\*([^*]+)\*\* <!-- x-release-please-version -->",
        install_guide,
    )
    assert install_version and install_version.group(1) == __version__
    release_config = json.loads((root / "release-please-config.json").read_text(encoding="utf-8"))
    assert {"type": "generic", "path": "install.md"} in release_config["packages"]["."][
        "extra-files"
    ]


def test_adapter_uses_shared_adobepy_runtime():
    root = Path(__file__).parents[1]
    pyproject_path = root / "pyproject.toml"
    contents = pyproject_path.read_text(encoding="utf-8")
    adobepy = Requirement(re.search(r'"(adobepy[^"]+)"', contents).group(1))

    assert str(adobepy.specifier) == "==0.6.2"
    assert adobepy.specifier.contains("0.6.2")
    assert not adobepy.specifier.contains("0.8.0")
    assert '"dcc-mcp-core>=0.20.14,<1.0.0"' in contents
    assert not (root / "src" / "dcc_mcp_aftereffects" / "bridge.py").exists()


def test_start_server_defers_port_resolution_to_core(monkeypatch):
    from types import SimpleNamespace

    from dcc_mcp_aftereffects import server as server_module

    ports = []
    stub = SimpleNamespace(
        is_running=False,
        register_builtin_actions=lambda: None,
        run_registration=lambda **_kwargs: None,
        start=lambda: None,
        stop=lambda: None,
    )

    monkeypatch.setattr(server_module, "_server", None)
    monkeypatch.setattr(
        server_module,
        "AfterEffectsMcpServer",
        lambda port=None, **_kwargs: ports.append(port) or stub,
    )
    monkeypatch.setenv("DCC_MCP_AFTEREFFECTS_PORT", "8765")

    server_module.start_server(0)
    server_module.stop_server()
    server_module.start_server()
    server_module.stop_server()

    assert ports == [0, None]
