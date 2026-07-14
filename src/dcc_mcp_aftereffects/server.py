"""After Effects MCP server lifecycle."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from adobe.runtime import BrokerHandle, ensure_broker
from dcc_mcp_core import DccServerOptions
from dcc_mcp_core.server_base import DccServerBase

from .__version__ import __version__

DEFAULT_PORT = 8765
_server: Optional["AfterEffectsMcpServer"] = None


class AfterEffectsMcpServer(DccServerBase):
    """MCP server whose typed calls are completed by the CEP panel."""

    def __init__(self, port: int = DEFAULT_PORT) -> None:
        self.broker: Optional[BrokerHandle] = None
        options = DccServerOptions.from_env(
            "aftereffects",
            Path(__file__).resolve().parent / "skills",
            port=port,
            server_name="dcc-mcp-aftereffects",
            server_version=__version__,
        )
        super().__init__(options=options)

    def start(self, **kwargs):
        self.broker = ensure_broker()
        try:
            return super().start(**kwargs)
        except Exception:
            self.broker.stop()
            self.broker = None
            raise

    def stop(self) -> None:
        try:
            super().stop()
        finally:
            if self.broker is not None:
                self.broker.stop()
                self.broker = None


def start_server(port: Optional[int] = None) -> AfterEffectsMcpServer:
    global _server
    if _server is None or not _server.is_running:
        _server = AfterEffectsMcpServer(
            port or int(os.environ.get("DCC_MCP_AFTEREFFECTS_PORT", DEFAULT_PORT))
        )
        _server.register_builtin_actions()
        _server.start()
    return _server


def stop_server() -> None:
    global _server
    if _server is not None:
        _server.stop()
        _server = None
