from unittest.mock import MagicMock
import pytest

from touchque.resources.offline import Offline
from touchque.exceptions import TouchQueAPIException
from .fake_api import fake_api  # noqa: F401 (fixture)


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


def test_totp_verifiers_posts_users_and_window():
    http = MagicMock()
    http.post.return_value = {"users": []}
    off = Offline(http)

    off.totp_verifiers(["a@b.com"])
    http.post.assert_called_with("/offline/totp/verifiers", {"externalUsernames": ["a@b.com"]})
    off.totp_verifiers(["a@b.com"], from_step=10, steps=2)
    http.post.assert_called_with("/offline/totp/verifiers", {"externalUsernames": ["a@b.com"], "fromStep": 10, "steps": 2})


def test_match_totp_verifier_against_the_fake_api(fake_api):
    from touchque import Config, TouchQue
    import time as _time

    fake_api.link("vpn@example.com")
    tq = TouchQue(Config(api_key="tq_test_key", api_secret="test_secret", base_url=fake_api.base_url))
    now = _time.time()
    step = int(now // 30)
    v = tq.offline.totp_verifiers(["vpn@example.com", "nobody@example.com"], from_step=step - 1, steps=4)
    assert [u["externalUsername"] for u in v["users"]] == ["vpn@example.com"]
    user = v["users"][0]
    # The fake's code is K7P2QXA at every step.
    assert Offline.match_totp_verifier(v, user, "k7p-2qxa", at=now) == step
    assert Offline.match_totp_verifier(v, user, "K7P2QXB", at=now) is None
    assert Offline.match_totp_verifier(v, user, "K7P2QXA", at=now + 3600) is None
    assert Offline.match_totp_verifier(v, user, "K7P2QX1", at=now) is None
