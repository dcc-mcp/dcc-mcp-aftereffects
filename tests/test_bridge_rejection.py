"""Connection/session failures must surface the broker's structured rejection.

Reproduces the ``-32010`` / ``adapterOwnedLaunchReceipt`` fail-closed scenario
from the AE Bridge report without a separate WebSocket handshake, and asserts
that the surfaced copy stays public-safe.  Broker free-form ``message`` text is
never trusted: it is echoed only when it exactly matches a curated allowlist
literal, so short credentials, opaque token fragments and local paths are
always replaced by the code-selected public-safe message.
"""

from types import SimpleNamespace

import pytest
from adobe.core.errors import error_from_rpc
from test_runtime import capability_payload

from dcc_mcp_aftereffects.bridge_rejection import (
    BrokerRejection,
    extract_rejection,
    public_message,
)
from dcc_mcp_aftereffects.runtime import probe_aftereffects

REJECTION_RPC = {
    "code": -32010,
    "message": "After Effects runtime identity requires an adapter-owned launch receipt",
    "data": {"host": "after-effects", "missingFields": ["adapterOwnedLaunchReceipt"]},
}

CURATED_32010 = (
    "After Effects runtime identity requires a trusted adapter-owned launch "
    "receipt; the connection stays fail-closed"
)


def _rejection_exception():
    """Build the exact SDK exception the broker rejection produces."""
    return error_from_rpc(dict(REJECTION_RPC))


def _app_with_rejecting_runtime_identity(**_kwargs):
    # A valid capability session gets the probe to the runtime-identity RPC,
    # which then fails closed with the structured broker rejection.
    def reject():
        raise _rejection_exception()

    return SimpleNamespace(version="25.6x101", runtime_identity=reject)


# --- module-level extraction / public-safety ---------------------------------


def test_extract_rejection_from_sdk_exception():
    rejection = extract_rejection(_rejection_exception())
    assert isinstance(rejection, BrokerRejection)
    assert rejection.code == -32010
    assert rejection.message == REJECTION_RPC["message"]
    assert rejection.missing_fields == ("adapterOwnedLaunchReceipt",)
    assert rejection.as_public_dict() == {
        "code": -32010,
        "message": REJECTION_RPC["message"],
        "missingFields": ["adapterOwnedLaunchReceipt"],
    }
    rendered = rejection.render()
    assert "-32010" in rendered
    assert REJECTION_RPC["message"] in rendered
    assert "adapterOwnedLaunchReceipt" in rendered


def test_extract_rejection_from_envelope_and_bare_error():
    envelope = {"error": dict(REJECTION_RPC)}
    for source in (envelope, dict(REJECTION_RPC)):
        rejection = extract_rejection(source)
        assert rejection is not None
        assert rejection.code == -32010
        assert rejection.missing_fields == ("adapterOwnedLaunchReceipt",)


def test_generic_failure_has_no_structured_rejection():
    # Transport/logic failures without a numeric broker code keep their fixed
    # reasons; no free-form broker text is echoed.
    assert extract_rejection(RuntimeError("host unavailable")) is None
    assert extract_rejection({"error": {"message": "no code here"}}) is None
    assert extract_rejection([capability_payload()]) is None


@pytest.mark.parametrize(
    "unsafe, leaked",
    [
        # Shapes the old blacklist happened to catch.
        ("private-token: no trusted launch receipt", "private-token"),
        ("rejected at C:/Users/secret/bridge.js", "C:/Users/secret"),
        (
            "bearer abcdefghijklmnopqrstuvwxyz0123456789 rejected",
            "abcdefghijklmnopqrstuvwxyz0123456789",
        ),
        ("credential=abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123456789"),
        # Regression: explicit credential label with a SHORT value.  The old
        # implementation echoed these verbatim because no blacklist regex hit.
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("api_key=abcd1234 short", "abcd1234"),
        ("password=hunter2; receipt missing", "hunter2"),
        # Regression: long message whose tail is an opaque token.  The old
        # implementation truncated to 220 chars FIRST, leaving a 27-character
        # token prefix that no longer matched the >=28 character opaque rule.
        ("Refused: " + "x " * 92 + "a" * 32, "a" * 27),
        # Regression: arbitrary clean-looking free text is NOT echoed unless it
        # is on the strict allowlist.  A regex miss is not proof of safety.
        ("broker refused the session", "broker refused"),
        ("connection rejected by adapter", "rejected by adapter"),
        ("After Effects runtime identity requires a launch receipt (retry later)", "retry later"),
    ],
)
def test_public_message_never_echoes_untrusted_broker_text(unsafe, leaked):
    message = public_message(unsafe, token="private-token", code=-32010)
    assert message == CURATED_32010
    assert "fail-closed" in message
    assert leaked not in message


def test_public_message_only_echoes_allowlisted_broker_text():
    # The canonical -32010 wording is the one exact literal allowed through.
    assert (
        public_message(REJECTION_RPC["message"], token=None, code=-32010)
        == REJECTION_RPC["message"]
    )
    # Surrounding whitespace is normalized away - still the same allowlisted
    # literal, nothing attacker-controlled is echoed.
    assert (
        public_message(" " + REJECTION_RPC["message"] + " ", token=None, code=-32010)
        == REJECTION_RPC["message"]
    )
    # Near misses (extra words or different wording) are not allowlisted.
    for variant in (
        REJECTION_RPC["message"] + " (retry later)",
        REJECTION_RPC["message"].replace("adapter-owned", "trusted"),
    ):
        assert public_message(variant, token=None, code=-32010) == CURATED_32010


def test_public_message_does_not_leak_truncated_token_fragment():
    raw = "Refused: " + "x " * 92 + "a" * 32
    message = public_message(raw, token=None, code=-32010)
    assert message == CURATED_32010
    assert "a" * 27 not in message
    assert "x " * 10 not in message


def test_public_message_redacts_the_configured_token():
    message = public_message("session refused for tok_abc123", token="tok_abc123", code=-32010)
    assert "tok_abc123" not in message
    assert "fail-closed" in message


def test_missing_fields_are_validated_identifiers():
    rejection = extract_rejection(
        {
            "code": -32010,
            "message": REJECTION_RPC["message"],
            "data": {
                "missingFields": [
                    "adapterOwnedLaunchReceipt",
                    "C:/secret/token",
                    "privateTokenValue",
                    "trustedReceipt",
                    "a" * 200,
                ]
            },
        }
    )
    assert rejection is not None
    assert rejection.missing_fields == ("adapterOwnedLaunchReceipt", "trustedReceipt")


# --- probe_aftereffects reproduces the -32010 scenario -----------------------


def test_runtime_identity_rejection_is_surfaced_in_reason():
    status = probe_aftereffects(
        client=SimpleNamespace(capabilities=lambda: capability_payload()),
        app_factory=_app_with_rejecting_runtime_identity,
    )

    assert status.ready is False
    assert status.identity is None
    assert status.error_type == "runtime_identity_unavailable"
    assert "-32010" in status.reason
    assert REJECTION_RPC["message"] in status.reason
    assert "adapterOwnedLaunchReceipt" in status.reason
    assert status.rejection == {
        "code": -32010,
        "message": REJECTION_RPC["message"],
        "missingFields": ["adapterOwnedLaunchReceipt"],
    }


def test_capabilities_error_envelope_is_surfaced():
    client = SimpleNamespace(capabilities=lambda: {"error": dict(REJECTION_RPC)})
    status = probe_aftereffects(client=client, app_factory=lambda **_kw: None)

    assert status.ready is False
    assert status.error_type == "broker_probe_failed"
    assert "-32010" in status.reason
    assert "adapterOwnedLaunchReceipt" in status.reason
    assert status.rejection["missingFields"] == ["adapterOwnedLaunchReceipt"]


def test_capabilities_structured_exception_is_surfaced():
    def boom():
        raise _rejection_exception()

    client = SimpleNamespace(capabilities=boom)
    status = probe_aftereffects(client=client, app_factory=lambda **_kw: None)

    assert status.ready is False
    assert status.error_type == "broker_probe_failed"
    assert "-32010" in status.reason
    assert "adapterOwnedLaunchReceipt" in status.reason


def test_secret_bearing_broker_message_stays_redacted_but_code_is_shown():
    def reject():
        raise error_from_rpc(
            {
                "code": -32010,
                "message": "private-token: no trusted launch receipt",
                "data": {"missingFields": ["adapterOwnedLaunchReceipt"]},
            }
        )

    status = probe_aftereffects(
        client=SimpleNamespace(capabilities=lambda: capability_payload()),
        app_factory=lambda **_kw: SimpleNamespace(version="25.6x101", runtime_identity=reject),
    )

    assert "private-token" not in status.reason
    assert "private-token" not in status.rejection["message"]
    assert "-32010" in status.reason
    assert "adapterOwnedLaunchReceipt" in status.reason
    assert "fail-closed" in status.reason


@pytest.mark.parametrize(
    "secret_message, leaked",
    [
        # Explicit credential label with a short value (Basic auth / api_key).
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("api_key=abcd1234 short", "abcd1234"),
        # Opaque token tail that a truncate-first implementation would emit as
        # a 27-character prefix.
        ("Refused: " + "x " * 92 + "a" * 32, "a" * 27),
    ],
)
def test_credential_shaped_broker_message_never_reaches_status(secret_message, leaked):
    def reject():
        raise error_from_rpc(
            {
                "code": -32010,
                "message": secret_message,
                "data": {"missingFields": ["adapterOwnedLaunchReceipt"]},
            }
        )

    status = probe_aftereffects(
        client=SimpleNamespace(capabilities=lambda: capability_payload()),
        app_factory=lambda **_kw: SimpleNamespace(version="25.6x101", runtime_identity=reject),
    )

    assert status.ready is False
    assert leaked not in status.reason
    assert leaked not in status.rejection["message"]
    assert status.rejection["message"] == CURATED_32010
    assert "-32010" in status.reason
    assert "adapterOwnedLaunchReceipt" in status.reason
    assert "fail-closed" in status.reason


def test_no_session_keeps_generic_reason_without_fabricating_a_rejection():
    # When the broker advertises no session there is no structured error to
    # surface; do not invent one (no forged receipt).
    client = SimpleNamespace(capabilities=lambda: capability_payload(host="illustrator"))
    status = probe_aftereffects(client=client, app_factory=lambda **_kw: None)

    assert status.ready is False
    assert status.reason == "after-effects bridge session is not connected"
    assert status.rejection is None


def test_generic_host_failure_keeps_its_fixed_reason():
    def fail(**_kwargs):
        raise RuntimeError("host unavailable")

    status = probe_aftereffects(
        client=SimpleNamespace(capabilities=lambda: capability_payload()),
        app_factory=fail,
    )
    assert status.reason == "typed After Effects runtime probe failed"
    assert status.rejection is None


# --- the verify report (what the panel/CLI shows) ----------------------------


def test_verify_failure_reason_carries_the_broker_rejection(tmp_path):
    from test_install_lifecycle import BridgeRunner, healthy_dependencies, resolved_install

    from dcc_mcp_aftereffects.install_contract import EXIT_OK
    from dcc_mcp_aftereffects.install_models import InstallRequest
    from dcc_mcp_aftereffects.install_service import run_lifecycle

    status = probe_aftereffects(
        client=SimpleNamespace(capabilities=lambda: capability_payload()),
        app_factory=_app_with_rejecting_runtime_identity,
    )
    assert status.rejection is not None

    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())
    # verify requires a complete install receipt; install first, then swap in
    # the rejecting readiness probe so the failure reaches typed-readiness.
    _, install_exit = run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )
    assert install_exit == EXIT_OK
    dependencies.readiness_probe = lambda _resolved: status

    report, _exit_code = run_lifecycle(
        InstallRequest("verify", as_json=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    failure_reason = report["verify"]["failure_reason"]
    assert "-32010" in failure_reason
    assert REJECTION_RPC["message"] in failure_reason
    assert "adapterOwnedLaunchReceipt" in failure_reason
    readiness_step = next(step for step in report["steps"] if step["id"] == "typed-readiness")
    assert "-32010" in readiness_step["message"]
