"""Command-line entry point for the After Effects MCP adapter."""

from __future__ import annotations

import argparse
import signal
import time

from .__version__ import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dcc-mcp-aftereffects",
        description="Run the DCC MCP adapter for Adobe After Effects.",
    )
    parser.add_argument("--mcp-port", type=int, default=None)
    parser.add_argument("--gateway-port", type=int, default=None)
    parser.add_argument("--broker-url", default=None)
    parser.add_argument("--skill-path", action="append", default=[])
    parser.add_argument("--no-builtins", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
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


if __name__ == "__main__":
    main()
