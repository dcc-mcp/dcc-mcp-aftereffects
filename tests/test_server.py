from unittest import mock

from adobe.runtime import BrokerHandle

from dcc_mcp_aftereffects.config import AfterEffectsConfig
from dcc_mcp_aftereffects.runtime import AfterEffectsStatus
from dcc_mcp_aftereffects.server import AfterEffectsMcpServer


def test_server_uses_host_rpc_for_readiness_and_owned_broker_lifecycle():
    broker = BrokerHandle("http://127.0.0.1:47391", "token")
    broker.stop = mock.Mock()
    broker_factory = mock.Mock(return_value=broker)
    readiness_probe = mock.Mock(
        return_value=AfterEffectsStatus(True, version="24.6", target="default")
    )
    server = AfterEffectsMcpServer(
        gateway_port=0,
        config=AfterEffectsConfig(timeout=1.0, poll_interval=60.0),
        broker_factory=broker_factory,
        readiness_probe=readiness_probe,
    )

    with mock.patch("dcc_mcp_aftereffects.server.DccServerBase.start", return_value=object()):
        server.start(install_atexit_hook=False)

    assert server.bridge_status.ready is True
    broker_factory.assert_called_once_with(broker_url=None, token=None, timeout=1.0)
    readiness_probe.assert_called_once_with(
        broker_url=broker.url,
        token=broker.token,
        target="default",
        timeout=1.0,
    )
    assert server._readiness.probe.report()["dcc"] is True

    with mock.patch("dcc_mcp_aftereffects.server.DccServerBase.stop"):
        server.stop()
    broker.stop.assert_called_once_with()


def test_unready_host_keeps_dcc_readiness_red():
    server = AfterEffectsMcpServer(
        gateway_port=0,
        config=AfterEffectsConfig(),
        readiness_probe=mock.Mock(
            return_value=AfterEffectsStatus(False, "after-effects bridge session is not connected")
        ),
    )

    status = server._sample_bridge()

    assert status.ready is False
    assert server._readiness.probe.report()["dcc"] is False
