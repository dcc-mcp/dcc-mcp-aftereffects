"""Host-specific readiness for the adobepy-backed After Effects adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from adobe.after_effects import AfterEffects
from adobe.core import BrokerClient
from adobe.core.errors import IdentityUnavailableError
from adobe.core.runtime_identity import RuntimeIdentityAttestation

from .bridge_rejection import BrokerRejection, extract_rejection

REQUIRED_METHODS: Mapping[str, tuple[str, ...]] = {
    "app": ("getVersion", "openProject"),
    "project": (
        "getActive",
        "getItems",
        "getCompositions",
        "getFootageItems",
        "getFolders",
        "getActiveItem",
        "getSelectedItems",
        "save",
        "importFile",
        "createComposition",
    ),
    "item": ("getById", "getByName"),
    "layer": (
        "getLayers",
        "getSelected",
        "getById",
        "createText",
        "createSolid",
        "createFootage",
        "setTransform",
        "setKeyframes",
        "moveToBeginning",
        "moveToEnd",
        "moveBefore",
        "moveAfter",
    ),
    "mask": ("getMasks",),
    "effect": ("getEffects", "getByName"),
    "text": ("getSourceText", "setSourceText"),
    "renderQueue": (
        "get",
        "getItems",
        "getItemByIndex",
        "addComposition",
        "queueSelectedCompositions",
        "render",
        "pauseRendering",
        "stopRendering",
        "showWindow",
        "queueInAME",
        "setQueueNotify",
    ),
    "renderQueueItem": (
        "applyTemplate",
        "setSettings",
        "setRender",
        "setQueueItemNotify",
    ),
    "outputModule": (
        "getModules",
        "getByIndex",
        "applyTemplate",
        "setSettings",
        "setOutputPath",
        "saveAsTemplate",
    ),
    "dom": ("root", "get", "set", "call", "construct", "keys", "snapshot", "release"),
    "raw": ("evalExtendScript",),
}


@dataclass(frozen=True)
class AfterEffectsStatus:
    ready: bool
    reason: str = ""
    version: str | None = None
    target: str = "default"
    identity: Mapping[str, Any] | None = None
    error_type: str | None = None
    # Public-safe, structured broker rejection (code/message/missingFields),
    # or None when the failure carries no structured broker error.
    rejection: Mapping[str, Any] | None = None


def _reason_with_rejection(base: str, rejection: BrokerRejection | None) -> str:
    """Append a bounded, public-safe broker rejection to a failure reason."""
    if rejection is None:
        return base
    return f"{base}; {rejection.render()}"


def _not_ready(
    reason: str,
    *,
    target: str,
    error_type: str | None,
    rejection: BrokerRejection | None,
) -> AfterEffectsStatus:
    return AfterEffectsStatus(
        False,
        _reason_with_rejection(reason, rejection),
        target=target,
        error_type=error_type,
        rejection=rejection.as_public_dict() if rejection is not None else None,
    )


def _matching_session(payloads: list[Mapping[str, Any]], target: str) -> Mapping[str, Any] | None:
    matches = []
    for payload in payloads:
        capabilities = payload.get("capabilities", {})
        if (
            capabilities.get("host") == "after-effects"
            and capabilities.get("bridgeKind") == "cep"
            and payload.get("target", "default") == target
        ):
            matches.append(payload)
    return matches[0] if len(matches) == 1 else None


def _missing_methods(capabilities: Mapping[str, Any]) -> list[str]:
    advertised = capabilities.get("methods", {})
    return [
        f"{namespace}.{method}"
        for namespace, methods in REQUIRED_METHODS.items()
        for method in methods
        if method not in advertised.get(namespace, ())
    ]


def _normalize_runtime_identity(value: object) -> dict[str, Any] | None:
    """Validate the published SDK attestation before adapting the receipt schema."""
    try:
        if isinstance(value, RuntimeIdentityAttestation):
            # Dataclasses can be constructed directly; validate them as strictly as wire data.
            value = value.to_wire()
        attestation = RuntimeIdentityAttestation.from_broker(value)
    except (AttributeError, TypeError, ValueError):
        return None
    broker, host, bridge = attestation.broker, attestation.host, attestation.bridge
    return {
        "host": "after-effects",
        "host_pid": host.pid,
        "process_start_identity": host.process_start_identity,
        "process_executable": host.executable_path,
        "host_version": host.host_version,
        "profile_id": host.profile_id,
        "target": bridge.target,
        "bridge_kind": bridge.bridge_kind,
        "bridge_version": bridge.bridge_version,
        "instance_id": bridge.instance_id,
        "plugin_root": bridge.installed_plugin_root,
        "plugin_module_origin": bridge.module_origin,
        "connected_at_epoch_ms": bridge.connected_at_epoch_ms,
        "broker": {
            "pid": broker.pid,
            "process_start_identity": broker.process_start_identity,
            "executable": broker.executable_path,
            "version": broker.runtime_version,
            "instance_id": broker.instance_id,
        },
    }


def probe_aftereffects(
    *,
    broker_url: str | None = None,
    token: str | None = None,
    target: str = "default",
    timeout: float = 5.0,
    client: BrokerClient | None = None,
    app_factory: Callable[..., Any] = AfterEffects,
) -> AfterEffectsStatus:
    """Require a complete AE capability session and one real host RPC."""
    active_client = client or BrokerClient(
        broker_url=broker_url,
        token=token,
        target=target,
        timeout=timeout,
    )
    try:
        capabilities_response = active_client.capabilities()
        if isinstance(capabilities_response, Mapping):
            # A broker can answer the capabilities GET with a JSON-RPC error
            # envelope instead of a session list; surface that rejection too.
            rejection = extract_rejection(capabilities_response, token=token)
            if rejection is not None:
                return _not_ready(
                    "adobepy broker capability probe failed",
                    target=target,
                    error_type="broker_probe_failed",
                    rejection=rejection,
                )
            session = None
        else:
            session = _matching_session(capabilities_response, target)
    except Exception as exc:  # noqa: BLE001 - readiness must remain queryable
        return _not_ready(
            "adobepy broker capability probe failed",
            target=target,
            error_type="broker_probe_failed",
            rejection=extract_rejection(exc, token=token),
        )
    if session is None:
        return AfterEffectsStatus(
            False,
            "after-effects bridge session is not connected",
            target=target,
        )

    capabilities = session.get("capabilities", {})
    missing = _missing_methods(capabilities)
    if missing:
        return AfterEffectsStatus(
            False,
            "missing bridge methods: " + ", ".join(missing),
            target=target,
        )
    if "officialDom" not in capabilities.get("features", ()):
        return AfterEffectsStatus(False, "official DOM capability is unavailable", target=target)

    try:
        app = app_factory(client=active_client)
        version = str(app.version)
        runtime_identity = getattr(app, "runtime_identity", None)
        identity = runtime_identity() if callable(runtime_identity) else runtime_identity
    except IdentityUnavailableError as exc:
        return _not_ready(
            "adobepy has no trusted After Effects CEP runtime identity",
            target=target,
            error_type="runtime_identity_unavailable",
            rejection=extract_rejection(exc, token=token),
        )
    except Exception as exc:  # noqa: BLE001 - readiness reports stable host failures
        return _not_ready(
            "typed After Effects runtime probe failed",
            target=target,
            error_type="host_rpc_failed",
            rejection=extract_rejection(exc, token=token),
        )
    identity = _normalize_runtime_identity(identity)
    if identity is None:
        return AfterEffectsStatus(
            False,
            "adobepy did not attest the exact After Effects CEP runtime identity",
            version=version,
            target=target,
            error_type="runtime_identity_unavailable",
        )
    if (
        identity["target"] != target
        or identity["bridge_kind"] != "cep"
        or identity["host_version"] != version
    ):
        return AfterEffectsStatus(
            False,
            "The runtime identity does not match the selected After Effects session",
            version=version,
            target=target,
            error_type="runtime_identity_mismatch",
        )
    return AfterEffectsStatus(
        True,
        version=version,
        target=target,
        identity=dict(identity),
    )


__all__ = ["AfterEffectsStatus", "REQUIRED_METHODS", "probe_aftereffects"]
