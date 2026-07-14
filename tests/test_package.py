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
