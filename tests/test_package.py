import json
import re
import subprocess
import sys
import zipfile
from email.parser import BytesParser
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


def test_built_wheel_skills_match_package_and_install_core_contract(tmp_path):
    root = Path(__file__).parents[1]
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path)],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(tmp_path.glob("*.whl"))
    expected = ">=0.20.14,<1.0.0"
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
        core = next(
            Requirement(value)
            for value in metadata.get_all("Requires-Dist", [])
            if Requirement(value).name == "dcc-mcp-core"
        )
        assert str(core.specifier) == "<1.0.0,>=0.20.14"
        skills = [
            name for name in archive.namelist() if "/skills/" in name and name.endswith("/SKILL.md")
        ]
        advertised = []
        for name in skills:
            contents = archive.read(name).decode("utf-8")
            if "dcc-mcp-core" in contents:
                advertised.append(name)
                assert f"dcc-mcp-core {expected}" in contents
        assert len(advertised) == 3
    install_guide = (root / "install.md").read_text(encoding="utf-8")
    assert install_guide.count(expected) >= 4


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
