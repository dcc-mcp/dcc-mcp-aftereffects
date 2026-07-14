import threading

from dcc_mcp_aftereffects.bridge import BridgeBroker


def test_broker_delivers_and_resolves_a_typed_request():
    broker = BridgeBroker("TEST_AFTEREFFECTS", 0)
    result = {}
    thread = threading.Thread(
        target=lambda: result.setdefault("value", broker.submit("inspect_project", {}))
    )
    thread.start()
    job = broker.next()
    broker.resolve(job["id"], {"project_name": "demo"}, None)
    thread.join(timeout=1)
    assert result["value"] == {"project_name": "demo"}
