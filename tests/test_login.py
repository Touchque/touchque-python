from unittest.mock import MagicMock, patch
import pytest

from touchque.resources.login import Login
from touchque.exceptions import TouchqueRejectedException, TouchqueTimeoutException


def test_request_posts_required_and_optional_fields():
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t"}
    login = Login(http)

    login.request("a@b.com", type="WITHDRAW", reference_id="txn_1", require_biometric=True)

    http.post.assert_called_once_with(
        "/login/request",
        {"externalUsername": "a@b.com", "type": "WITHDRAW", "referenceId": "txn_1", "requireBiometric": True},
    )


def test_status_gets_expected_path():
    http = MagicMock()
    http.get.return_value = {"status": "PENDING"}
    login = Login(http)

    result = login.status("req_1")

    http.get.assert_called_once_with("/login/status/req_1")
    assert result["status"] == "PENDING"


@patch("touchque.resources.login.time.sleep", return_value=None)
def test_verify_returns_approved_true_once_confirmed(_sleep):
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t"}
    http.get.side_effect = [{"status": "PENDING"}, {"status": "CONFIRMED"}]
    login = Login(http)

    result = login.verify("a@b.com")

    assert result["approved"] is True
    assert result["status"] == "CONFIRMED"
    assert result["requestId"] == "req_1"


@patch("touchque.resources.login.time.sleep", return_value=None)
def test_verify_raises_rejected_exception_when_status_is_rejected(_sleep):
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t"}
    http.get.return_value = {"status": "REJECTED"}
    login = Login(http)

    with pytest.raises(TouchqueRejectedException):
        login.verify("a@b.com")


@patch("touchque.resources.login.time.sleep", return_value=None)
def test_verify_raises_timeout_exception_after_timeout_ms_elapses(_sleep):
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t"}
    http.get.return_value = {"status": "PENDING"}
    login = Login(http)

    with pytest.raises(TouchqueTimeoutException):
        login.verify("a@b.com", timeout_ms=1)


@patch("touchque.resources.login.time.sleep", return_value=None)
def test_wait_for_approval_returns_approved_true_once_confirmed(sleep):
    http = MagicMock()
    http.get.side_effect = [{"status": "PENDING"}, {"status": "CONFIRMED", "confirmedVia": "DEVICE", "provisional": True}]
    login = Login(http)

    result = login.wait_for_approval("req_1", poll_interval_ms=250)

    assert result["approved"] is True
    assert result["status"] == "CONFIRMED"
    assert result["requestId"] == "req_1"
    assert result["confirmedVia"] == "DEVICE"
    assert result["provisional"] is True
    http.get.assert_called_with("/login/status/req_1")
    http.post.assert_not_called()
    sleep.assert_called_once_with(0.25)


@patch("touchque.resources.login.time.sleep", return_value=None)
def test_wait_for_approval_raises_rejected_or_timeout_for_a_closed_request(_sleep):
    http = MagicMock()
    http.get.return_value = {"status": "REJECTED"}
    with pytest.raises(TouchqueRejectedException):
        Login(http).wait_for_approval("req_1")

    http.get.return_value = {"status": "EXPIRED"}
    with pytest.raises(TouchqueTimeoutException):
        Login(http).wait_for_approval("req_1")


@patch("touchque.resources.login.time.sleep", return_value=None)
def test_wait_for_approval_raises_timeout_after_timeout_ms_elapses(_sleep):
    http = MagicMock()
    http.get.return_value = {"status": "PENDING"}

    with pytest.raises(TouchqueTimeoutException):
        Login(http).wait_for_approval("req_1", timeout_ms=1)


@patch("touchque.resources.login.time.sleep", return_value=None)
def test_wait_for_approval_raises_passkey_required_when_the_request_moves_to_a_passkey(_sleep):
    from touchque import TouchquePasskeyRequiredError
    http = MagicMock()
    http.get.side_effect = [{"status": "PENDING"}, {"status": "PENDING", "requiresPasskey": True}]
    with pytest.raises(TouchquePasskeyRequiredError) as err:
        Login(http).wait_for_approval("req_1")
    assert err.value.request_id == "req_1"
    assert err.value.reason == "step_up"


def test_approve_with_recovery_code_posts_expected_payload():
    http = MagicMock()
    http.post.return_value = {"success": True, "message": "approved"}
    login = Login(http)

    result = login.approve_with_recovery_code("req_1", "ABCD-1234")

    http.post.assert_called_once_with("/login/recovery", {"requestId": "req_1", "code": "ABCD-1234"})
    assert result["success"] is True


def test_request_forwards_details_for_the_approval_screen():
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1"}
    login = Login(http)

    login.request("a@b.com", type="WITHDRAW", client_ip="203.0.113.7",
                  details={"Amount": "1,250.00 USD", "Recipient": "Jane Doe"})

    http.post.assert_called_once_with(
        "/login/request",
        {"externalUsername": "a@b.com", "type": "WITHDRAW", "clientIp": "203.0.113.7",
         "details": {"Amount": "1,250.00 USD", "Recipient": "Jane Doe"}},
    )


@patch("touchque.resources.login.time.sleep", return_value=None)
def test_verify_raises_passkey_required_when_the_request_moves_to_a_passkey_mid_flight(_sleep):
    # Vishing Shield: the user tapped Approve during a call; the request is still open for a passkey.
    from touchque import TouchquePasskeyRequiredError
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t"}
    http.get.side_effect = [{"status": "PENDING"}, {"status": "PENDING", "requiresPasskey": True}]
    with pytest.raises(TouchquePasskeyRequiredError) as err:
        Login(http).verify("a@b.com")
    assert err.value.request_id == "req_1"
    assert err.value.reason == "step_up"


def test_webhook_reason_and_event_constants():
    from touchque import WebhookReasons, WebhookEvents
    assert WebhookReasons.VISHING_SUSPECTED == 'vishing_suspected'
    assert WebhookReasons.PHISHING_ORIGIN == 'phishing_origin'
    assert WebhookReasons.USER_REPORTED_COACHED == 'user_reported_coached'
    assert WebhookEvents.APPROVAL_REVOKED == 'APPROVAL_REVOKED'
    assert WebhookEvents.APPROVAL_RECONFIRMED == 'APPROVAL_RECONFIRMED'


def test_request_and_verify_forward_the_browser_proof():
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t"}
    Login(http).request("a@b.com", browser_proof="eyJ2IjoxfQ")
    http.post.assert_called_with(
        "/login/request", {"externalUsername": "a@b.com", "type": "LOGIN", "browserProof": "eyJ2IjoxfQ"})
    http.get.return_value = {"status": "CONFIRMED"}
    Login(http).verify("a@b.com", browser_proof="eyJ2IjoxfQ")
    assert http.post.call_args[0][1]["browserProof"] == "eyJ2IjoxfQ"


def test_request_and_verify_send_challenge_digits_only_as_2_or_3():
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t"}
    login = Login(http)

    login.request("a@b.com", require_number_match=True, challenge_digits=3)
    assert http.post.call_args[0][1] == {"externalUsername": "a@b.com", "type": "LOGIN", "requireNumberMatch": True, "challengeDigits": 3}
    login.request("a@b.com", challenge_digits=4)
    assert "challengeDigits" not in http.post.call_args[0][1]


def test_request_sends_expires_in_when_given():
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t"}
    login = Login(http)
    login.request("a@b.com", type="AGENT_ON_BEHALF", expires_in=180, client_signals="eyJ2IjoxfQ")
    assert http.post.call_args[0][1] == {"externalUsername": "a@b.com", "type": "AGENT_ON_BEHALF", "expiresIn": 180, "clientSignals": "eyJ2IjoxfQ"}
    login.request("a@b.com")
    assert "expiresIn" not in http.post.call_args[0][1]


def test_request_forwards_security_changes_destination_and_locale():
    from datetime import datetime, timezone
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t", "destination": {"known": False, "lookalike": []}}
    login = Login(http)

    login.request(
        "a@b.com", type="PAYOUT",
        security_changes={"mfa": datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc), "password": datetime(2026, 10, 25, 8, 0), "device": 1761465600000, "email": None},
        destination={"kind": "iban", "value": "TR33 0006 1005 1978 6457 8413 26", "known": []},
        locale="en",
    )

    http.post.assert_called_once_with("/login/request", {
        "externalUsername": "a@b.com", "type": "PAYOUT",
        "securityChanges": {"mfa": "2026-10-26T08:00:00+00:00", "password": "2026-10-25T08:00:00+00:00", "device": 1761465600000},
        "destination": {"kind": "iban", "value": "TR33 0006 1005 1978 6457 8413 26", "known": []},
        "locale": "en",
    })
