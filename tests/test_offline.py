from unittest.mock import MagicMock
import pytest

from touchque.resources.offline import Offline
from touchque.exceptions import TouchQueAPIException


def test_challenge_posts_expected_fields():
    http = MagicMock()
    http.post.return_value = {"challengeId": "c1", "qr": "TQ2.x", "qrDataUrl": "data:x", "expiresAt": "t", "expiresInSeconds": 120, "totpAvailable": True}
    off = Offline(http)

    off.challenge("a@b.com", type="WITHDRAW", details={"Amount": "10 EUR"}, ttl_seconds=60)

    http.post.assert_called_once_with(
        "/offline/challenge",
        {"externalUsername": "a@b.com", "type": "WITHDRAW", "details": {"Amount": "10 EUR"}, "ttlSeconds": 60},
    )


def test_verify_returns_approved_false_with_reason_instead_of_raising():
    http = MagicMock()
    http.post.side_effect = TouchQueAPIException("bad code", status=401, code=None, reason="invalid_code", attempts_left=3)
    off = Offline(http)

    result = off.verify("c1", "WRONG12")

    assert result == {"approved": False, "reason": "invalid_code", "attemptsLeft": 3}


def test_verify_reraises_server_errors():
    http = MagicMock()
    http.post.side_effect = TouchQueAPIException("boom", status=500)
    off = Offline(http)

    with pytest.raises(TouchQueAPIException):
        off.verify("c1", "AAAA123")


def test_verify_totp_posts_type_for_critical_action_checks():
    http = MagicMock()
    http.post.return_value = {"approved": True, "externalUsername": "a@b.com"}
    off = Offline(http)

    result = off.verify_totp("a@b.com", "123456", type="WITHDRAW")

    http.post.assert_called_once_with("/offline/totp/verify", {"externalUsername": "a@b.com", "code": "123456", "type": "WITHDRAW"})
    assert result["approved"] is True


def test_challenge_links_the_push_and_asks_for_number_matching():
    http = MagicMock()
    http.post.return_value = {"challengeId": "c1", "challengeCode": "47"}
    off = Offline(http)

    ch = off.challenge("a@b.com", type="LOGIN", request_id="req-1", require_number_match=True)

    http.post.assert_called_once_with(
        "/offline/challenge",
        {"externalUsername": "a@b.com", "type": "LOGIN", "requestId": "req-1", "requireNumberMatch": True},
    )
    assert ch["challengeCode"] == "47"


def test_verify_totp_forwards_request_id_and_a_rejected_request_is_a_result():
    http = MagicMock()
    http.post.side_effect = TouchQueAPIException("rejected", status=410, code=None, reason="request_rejected")
    off = Offline(http)

    result = off.verify_totp("a@b.com", "ABCDEFG", request_id="req-1")

    assert http.post.call_args[0][1]["requestId"] == "req-1"
    assert result["approved"] is False and result["reason"] == "request_rejected"
