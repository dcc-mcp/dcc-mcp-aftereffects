from dcc_mcp_aftereffects import cli


def test_cli_exposes_version_and_runtime_options():
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "--mcp-port",
            "0",
            "--broker-url",
            "http://127.0.0.1:47391",
            "--gateway-port",
            "9765",
            "--no-builtins",
        ]
    )

    assert args.mcp_port == 0
    assert args.broker_url == "http://127.0.0.1:47391"
    assert args.gateway_port == 9765
    assert args.no_builtins is True


def test_project_registers_a_console_entry_point():
    from pathlib import Path

    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")

    assert 'dcc-mcp-aftereffects = "dcc_mcp_aftereffects.cli:main"' in pyproject


def test_cli_exposes_standard_install_lifecycle_flags():
    parser = cli.build_parser()

    args = parser.parse_args(
        [
            "install",
            "--json",
            "--yes",
            "--dry-run",
            "--dcc-path",
            "C:/Program Files/Adobe/After Effects/AfterFX.exe",
            "--python",
            "C:/Python312/python.exe",
        ]
    )

    assert args.command == "install"
    assert args.json is True
    assert args.yes is True
    assert args.dry_run is True
    assert args.dcc_path.endswith("AfterFX.exe")
    assert args.python.endswith("python.exe")
