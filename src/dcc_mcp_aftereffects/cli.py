"""Command-line entry point for the After Effects MCP adapter."""

from __future__ import annotations

import argparse
import json
import signal
import time

from .__version__ import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dcc-mcp-aftereffects",
        description="Run the DCC MCP adapter for Adobe After Effects.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("install", "status", "verify", "uninstall", "upgrade"),
        help="run a standard host-integrated install lifecycle verb",
    )
    parser.add_argument("--mcp-port", type=int, default=None)
    parser.add_argument("--gateway-port", type=int, default=None)
    parser.add_argument("--broker-url", default=None)
    parser.add_argument("--skill-path", action="append", default=[])
    parser.add_argument("--no-builtins", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--dcc-path")
    parser.add_argument("--python")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _run_server(args: argparse.Namespace) -> None:
    from .server import start_server, stop_server

    server = start_server(
        port=args.mcp_port,
        broker_url=args.broker_url,
        gateway_port=args.gateway_port,
        extra_skill_paths=args.skill_path,
        include_bundled=not args.no_builtins,
    )
    stopped = False

    def request_stop(*_args: object) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)
    try:
        while not stopped and server.is_running:
            time.sleep(0.25)
    finally:
        stop_server()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:
        _run_server(args)
        return 0

    from .install_models import InstallRequest
    from .install_service import run_lifecycle

    request = InstallRequest(
        command=args.command,
        as_json=args.json,
        yes=args.yes,
        dry_run=args.dry_run,
        dcc_path=args.dcc_path,
        python=args.python,
    )
    report, exit_code = run_lifecycle(request)
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"{args.command}: {report['status']}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
