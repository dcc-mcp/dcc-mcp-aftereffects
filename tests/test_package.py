import json
from pathlib import Path

from dcc_mcp_aftereffects import __version__


def test_version_metadata_is_synchronized():
    root = Path(__file__).parents[1]
    assert f'version = "{__version__}"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    manifest = json.loads((root / ".release-please-manifest.json").read_text(encoding="utf-8"))
    assert manifest["."] == __version__


def test_cep_panel_is_packaged_with_source():
    panel = Path(__file__).parents[1] / "src" / "dcc_mcp_aftereffects" / "aftereffects_cep"
    assert (panel / "CSXS" / "manifest.xml").is_file()
    assert (panel / "jsx" / "host.jsx").is_file()
