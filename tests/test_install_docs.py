from pathlib import Path


def test_install_runbook_covers_standard_lifecycle_and_platform_boundaries():
    root = Path(__file__).parents[1]
    text = (root / "install.md").read_text(encoding="utf-8")

    for heading in (
        "## Requirements",
        "## Supported versions",
        "## Agent quick path",
        "## Manual path",
        "## Verify",
        "## Upgrade",
        "## Uninstall",
        "## Troubleshooting",
    ):
        assert heading in text
    for platform in ("Windows", "macOS", "Linux"):
        assert platform in text
    for verb in ("install", "status", "verify", "upgrade", "uninstall"):
        assert f"dcc-mcp-aftereffects {verb}" in text
    assert "dcc-mcp-cli wait-ready --dcc-type aftereffects" in text
    assert "https://raw.githubusercontent.com/dcc-mcp/dcc-mcp-aftereffects/main/install.md" in text
    assert "%APPDATA%\\Adobe\\CEP\\extensions" in text
    assert "~/Library/Application Support/Adobe/CEP/extensions" in text
    assert "ADOBEPY_TOKEN" in text
    assert "--token" not in text


def test_ci_runs_plan_round_trip_and_secret_redaction_contracts():
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "Install lifecycle contract smoke" in workflow
    assert "tests/test_install_lifecycle.py" in workflow
    assert "tests/test_install_docs.py" in workflow
