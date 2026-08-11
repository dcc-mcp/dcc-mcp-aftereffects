from types import SimpleNamespace

from dcc_mcp_aftereffects.runtime import REQUIRED_METHODS, probe_aftereffects


def capability_payload(host="after-effects", methods=None, target="default"):
    return [
        {
            "target": target,
            "capabilities": {
                "host": host,
                "bridgeKind": "cep",
                "bridgeVersion": "0.1.0",
                "features": ["officialDom"],
                "namespaces": list((methods or REQUIRED_METHODS).keys()),
                "methods": methods or REQUIRED_METHODS,
            },
        }
    ]


def test_probe_requires_matching_aftereffects_session():
    client = SimpleNamespace(capabilities=lambda: capability_payload(host="illustrator"))

    status = probe_aftereffects(client=client, app_factory=lambda **_kwargs: None)

    assert status.ready is False
    assert status.reason == "after-effects bridge session is not connected"


def test_probe_requires_complete_bridge_contract():
    client = SimpleNamespace(
        capabilities=lambda: capability_payload(methods={"app": ["getVersion"]})
    )

    status = probe_aftereffects(client=client, app_factory=lambda **_kwargs: None)

    assert status.ready is False
    assert "missing bridge methods" in status.reason


def test_probe_verifies_a_real_host_call():
    client = SimpleNamespace(capabilities=lambda: capability_payload())

    status = probe_aftereffects(
        client=client,
        app_factory=lambda **_kwargs: SimpleNamespace(version="24.6.2x2"),
    )

    assert status.ready is True
    assert status.version == "24.6.2x2"
    assert status.target == "default"


def test_probe_reports_host_call_failure_without_claiming_readiness():
    client = SimpleNamespace(capabilities=lambda: capability_payload())

    def fail(**_kwargs):
        raise RuntimeError("host unavailable")

    status = probe_aftereffects(client=client, app_factory=fail)

    assert status.ready is False
    assert status.reason == "host unavailable"
