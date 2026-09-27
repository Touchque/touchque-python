from unittest.mock import MagicMock, patch
import pytest

from touchque.resources.login import Login
from touchque.exceptions import TouchQueRejectedException, TouchQueTimeoutException


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

    with pytest.raises(TouchQueRejectedException):
        login.verify("a@b.com")


@patch("touchque.resources.login.time.sleep", return_value=None)
def test_verify_raises_timeout_exception_after_timeout_ms_elapses(_sleep):
    http = MagicMock()
    http.post.return_value = {"requestId": "req_1", "message": "ok", "expiresAt": "t"}
    http.get.return_value = {"status": "PENDING"}
    login = Login(http)

    with pytest.raises(TouchQueTimeoutException):
        login.verify("a@b.com", timeout_ms=1)


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
