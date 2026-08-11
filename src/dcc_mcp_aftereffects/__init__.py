"""Adobe After Effects MCP adapter."""

from .__version__ import __version__
from .server import AfterEffectsMcpServer, start_server, stop_server

__all__ = ["AfterEffectsMcpServer", "__version__", "start_server", "stop_server"]
