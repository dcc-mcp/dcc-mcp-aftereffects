"""Adobe After Effects MCP adapter."""

from .__version__ import __version__
from .server import AfterEffectsMcpServer

__all__ = ["AfterEffectsMcpServer", "__version__"]
