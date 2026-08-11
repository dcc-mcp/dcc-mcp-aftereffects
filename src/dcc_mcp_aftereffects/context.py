"""Bounded After Effects project context snapshots."""

from __future__ import annotations

from typing import Any, Callable

from adobe.after_effects import AfterEffects
from adobe.core import BrokerClient
from dcc_mcp_core import DccContextSnapshot


def collect_context(
    *,
    broker_url: str | None,
    token: str | None,
    target: str,
    timeout: float,
    client_factory: Callable[..., Any] = BrokerClient,
    app_factory: Callable[..., Any] = AfterEffects,
) -> DccContextSnapshot:
    """Collect small non-path project metadata for post-tool context."""
    client = client_factory(
        broker_url=broker_url,
        token=token,
        target=target,
        timeout=timeout,
    )
    app = app_factory(client=client)
    project = app.project
    active = app.active_item
    return DccContextSnapshot(
        dcc="aftereffects",
        document={"name": project.name} if project is not None else None,
        active_object={"name": active.name} if active is not None else None,
        counts={"items": int(project.item_count)} if project is not None else {},
        metadata={"version": str(app.version), "target": target},
    )


__all__ = ["collect_context"]
