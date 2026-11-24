import base64
import json
import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest

from touchque.resources.offline import Offline
from touchque.exceptions import TouchqueAPIException
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
    http.post.side_effect = TouchqueAPIException("bad code", status=401, code=None, reason="invalid_code", attempts_left=3)
    off = Offline(http)

    result = off.verify("c1", "WRONG12")

    assert result == {"approved": False, "reason": "invalid_code", "attemptsLeft": 3}


def test_verify_reraises_server_errors():
    http = MagicMock()
    http.post.side_effect = TouchqueAPIException("boom", status=500)
    off = Offline(http)

    with pytest.raises(TouchqueAPIException):
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


def test_challenge_asks_for_the_compact_qr_and_its_terminal_drawing():
    http = MagicMock()
    http.post.return_value = {"challengeId": "c1", "qr": "TQ3:X", "qrFormat": "compact", "qrDataUrl": None,
                              "qrTerminal": "█▀█\n▀▀▀"}
    off = Offline(http)

    ch = off.challenge("a@b.com", type="LOGIN", include_qr_image=False, qr_format="compact", include_qr_terminal=True)

    http.post.assert_called_once_with(
        "/offline/challenge",
        {"externalUsername": "a@b.com", "type": "LOGIN", "includeQrImage": False, "qrFormat": "compact",
         "includeQrTerminal": True},
    )
    assert (ch["qrFormat"], ch["qrTerminal"]) == ("compact", "█▀█\n▀▀▀")


def test_challenge_compact_qr_against_the_fake_api(fake_api):
    from touchque import Config, Touchque

    tq = Touchque(Config(api_key="tq_test_key", api_secret="test_secret", base_url=fake_api.base_url))
    ch = tq.offline.challenge("a@b.com", qr_format="compact", include_qr_terminal=True)
    body = [c for c in fake_api.calls() if c["path"] == "/offline/challenge"][-1]["body"]
    assert body == {"externalUsername": "a@b.com", "type": "LOGIN", "qrFormat": "compact", "includeQrTerminal": True}
    assert ch["qr"].startswith("TQ3:") and ch["qrFormat"] == "compact" and "\n" in ch["qrTerminal"]

    standard = tq.offline.challenge("a@b.com")
    body = [c for c in fake_api.calls() if c["path"] == "/offline/challenge"][-1]["body"]
    assert body == {"externalUsername": "a@b.com", "type": "LOGIN"}
    assert standard["qr"].startswith("TQ2.") and standard["qrFormat"] == "standard" and "qrTerminal" not in standard


def test_verify_totp_forwards_request_id_and_a_rejected_request_is_a_result():
    http = MagicMock()
    http.post.side_effect = TouchqueAPIException("rejected", status=410, code=None, reason="request_rejected")
    off = Offline(http)

    result = off.verify_totp("a@b.com", "ABCDEFG", request_id="req-1")

    assert http.post.call_args[0][1]["requestId"] == "req-1"
    assert result["approved"] is False and result["reason"] == "request_rejected"


def test_totp_verifiers_posts_users_and_window():
    http = MagicMock()
    http.post.return_value = {"users": []}
    off = Offline(http)

    scope = {"id": "acme", "name": "Acme"}
    off.totp_verifiers(["a@b.com"], scope)
    http.post.assert_called_with("/offline/totp/verifiers", {"externalUsernames": ["a@b.com"], "scope": scope})
    off.totp_verifiers(["a@b.com"], scope, from_step=10, steps=2)
    http.post.assert_called_with("/offline/totp/verifiers", {"externalUsernames": ["a@b.com"], "scope": scope, "fromStep": 10, "steps": 2})


def test_match_totp_verifier_against_the_fake_api(fake_api):
    from touchque import Config, Touchque
    import time as _time

    fake_api.link("vpn@example.com")
    tq = Touchque(Config(api_key="tq_test_key", api_secret="test_secret", base_url=fake_api.base_url))
    now = _time.time()
    step = int(now // 30)
    v = tq.offline.totp_verifiers(["vpn@example.com", "nobody@example.com"], {"id": "acme", "name": "Acme"}, from_step=step - 1, steps=4)
    assert [u["externalUsername"] for u in v["users"]] == ["vpn@example.com"]
    user = v["users"][0]
    assert v["digestsPerStep"] == 1 and v["scope"] == {"id": "acme", "name": "Acme"}
    # The fake's outage code is K7P2QXA at every step (one digest a step).
    assert Offline.match_totp_verifier(v, user, "k7p-2qxa", at=now) == step
    assert Offline.match_totp_verifier(v, user, "K7P2QXB", at=now) is None
    assert Offline.match_totp_verifier(v, user, "K7P2QXA", at=now + 3600) is None
    assert Offline.match_totp_verifier(v, user, "K7P2QX1", at=now) is None


def test_match_totp_verifier_two_digests_per_step_when_digests_per_step_is_absent():
    import base64
    import hashlib

    salt = bytes([7]) * 16
    start = 1000

    def h(code, step):
        return hashlib.pbkdf2_hmac("sha256", code.encode(), salt + f":{step}".encode(), 10, 4)

    parts = b"".join(h("AAAAAA2", s) + h("BBBBBB2", s) for s in range(start, start + 4))
    v = {"stepSeconds": 30, "fromStep": start, "steps": 4, "notAfterStep": start + 3,
         "kdf": {"name": "pbkdf2-sha256", "iterations": 10, "length": 4}, "users": []}
    user = {"externalUsername": "a@b.com", "fromStep": start, "salt": base64.b64encode(salt).decode(),
            "digests": base64.b64encode(parts).decode()}
    at = (start + 1) * 30 + 5
    assert Offline.match_totp_verifier(v, user, "aaa-aaa2", at=at) == start + 1
    assert Offline.match_totp_verifier(v, user, "BBBBBB2", at=at) == start + 1
    assert Offline.match_totp_verifier(v, user, "CCCCCC2", at=at) is None


# Offline sign-in packs. The shared vectors (fixtures/offline-device-vectors.json) come from the platform;
# the shared fake API answers 1,000 iterations and the code of slot i is _fake_device_code(i).
_DEVICE_VECTORS = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'offline-device-vectors.json')
_DEVICE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _device_vectors():
    with open(_DEVICE_VECTORS, encoding='utf-8') as f:
        return json.load(f)


def _fake_device_code(index):
    return "ABCDEFGH" + _DEVICE_ALPHABET[index % 32] + _DEVICE_ALPHABET[(index // 32) % 32]


def test_issue_device_pack_posts_the_person_the_device_and_the_account():
    http = MagicMock()
    http.post.return_value = {"scope": {"id": "pc-1", "name": "LAPTOP-JANE", "epoch": "0123456789abcdef"}, "slots": []}
    off = Offline(http)

    off.issue_device_pack("jane@acme.com", {"id": "pc-1", "name": "LAPTOP-JANE"}, "ACME\\jane")
    http.post.assert_called_with("/offline/device-packs", {
        "externalUsername": "jane@acme.com", "scope": {"id": "pc-1", "name": "LAPTOP-JANE"}, "account": "ACME\\jane"})

    off.issue_device_pack("jane@acme.com", {"id": "pc-1", "name": "LAPTOP-JANE"}, "ACME\\jane", count=5, valid_days=7)
    http.post.assert_called_with("/offline/device-packs", {
        "externalUsername": "jane@acme.com", "scope": {"id": "pc-1", "name": "LAPTOP-JANE"}, "account": "ACME\\jane",
        "count": 5, "validDays": 7})


def test_revoke_and_report_device_packs_post_the_scope_id_and_times_in_utc():
    http = MagicMock()
    off = Offline(http)

    off.revoke_device_scope("pc-1")
    http.post.assert_called_with("/offline/device-packs/revoke", {"scopeId": "pc-1"})
    off.revoke_device_scope("pc-1", external_username="jane@acme.com", reason="lost")
    http.post.assert_called_with("/offline/device-packs/revoke", {"scopeId": "pc-1", "externalUsername": "jane@acme.com", "reason": "lost"})

    istanbul = timezone(timedelta(hours=3))
    off.report_device_pack_use("pc-1", "jane@acme.com", [
        {"index": 7, "at": datetime(2026, 11, 12, 11, 30, tzinfo=istanbul)},
        {"index": 8, "at": datetime(2026, 11, 12, 9, 0)},
        {"index": 9, "at": "2026-11-12T09:30:00.000Z"},
    ])
    http.post.assert_called_with("/offline/device-packs/report", {
        "scopeId": "pc-1", "externalUsername": "jane@acme.com",
        "used": [{"index": 7, "at": "2026-11-12T08:30:00.000Z"}, {"index": 8, "at": "2026-11-12T09:00:00.000Z"},
                 {"index": 9, "at": "2026-11-12T09:30:00.000Z"}]})


def test_device_code_helpers_follow_the_shared_vectors():
    vectors = _device_vectors()
    for case in vectors["normalize"]:
        assert Offline.normalize_device_code(case["input"]) == case["expected"]
    for case in vectors["codes"]:
        assert Offline.normalize_device_code(case["expectedCode"]) == case["expectedCode"]
    assert Offline.format_device_code(vectors["slotQr"]["expectedCode"]) == vectors["slotQr"]["expectedFormatted"]
    assert Offline.format_device_code(" 5kmy9 tpzaq\n") == "5KMY9-TPZAQ"
    assert [Offline.normalize_device_code(None), Offline.normalize_device_code("5KMY9-TPZAQ1"),
            Offline.format_device_code("5KMY9-TPZA")] == [None, None, None]

    d = vectors["digest"]
    slot = {"index": d["index"], "salt": base64.b64encode(bytes.fromhex(d["saltHex"])).decode(),
            "digest": base64.b64encode(bytes.fromhex(d["expectedDigestHex"])).decode()}
    assert Offline.verify_device_code(d["kdf"], slot, d["code"]) is True
    assert Offline.verify_device_code(d["kdf"], slot, vectors["slotQr"]["expectedFormatted"].lower()) is True
    assert Offline.verify_device_code(d["kdf"], slot, "PDG4MSATZB") is False  # another slot's code
    assert Offline.verify_device_code(d["kdf"], dict(slot, index=d["index"] + 1), d["code"]) is False  # the index is in the salt
    assert Offline.verify_device_code(dict(d["kdf"], name="scrypt"), slot, d["code"]) is False
    assert Offline.verify_device_code(dict(d["kdf"], length=32), slot, d["code"]) is False
    assert Offline.verify_device_code(d["kdf"], dict(slot, salt="not base64!"), d["code"]) is False


def test_verify_device_code_refuses_a_malformed_code_without_computing():
    # A billion iterations would take minutes: an answer in time means nothing was computed.
    slow = {"name": "pbkdf2-sha256", "iterations": 1_000_000_000, "length": 16}
    slot = {"index": 7, "salt": base64.b64encode(bytes(16)).decode(), "digest": base64.b64encode(bytes(16)).decode()}
    started = time.monotonic()
    for typed in ["", "5KMY9TPZA", "5KMY9TPZAQ1", "ABCDEFGHI0", "ABCDEFGHIO", "5KMY9_TPZAQ", None]:
        assert Offline.verify_device_code(slow, slot, typed) is False
    assert time.monotonic() - started < 1


def test_device_packs_against_the_fake_api(fake_api):
    from touchque import Config, Touchque

    fake_api.link("jane@acme.com")
    tq = Touchque(Config(api_key="tq_test_key", api_secret="test_secret", base_url=fake_api.base_url))
    scope = {"id": "pc-0f1e2d3c4b5a6978", "name": "LAPTOP-JANE"}

    pack = tq.offline.issue_device_pack("jane@acme.com", scope, "ACME\\jane", count=3)
    body = [c for c in fake_api.calls() if c["path"] == "/offline/device-packs"][-1]["body"]
    assert body == {"externalUsername": "jane@acme.com", "scope": scope, "account": "ACME\\jane", "count": 3}
    assert [s["index"] for s in pack["slots"]] == [1, 2, 3]
    assert (pack["scope"]["epoch"], pack["codeLength"], pack["kdf"]["iterations"], pack["slots"][0]["qr"]) == \
        ("0123456789abcdef", 10, 1000, "TQ4:SLOT1")
    assert Offline.verify_device_code(pack["kdf"], pack["slots"][0], Offline.format_device_code(_fake_device_code(1)).lower())
    assert not Offline.verify_device_code(pack["kdf"], pack["slots"][0], _fake_device_code(2))
    assert tq.offline.verify_device_code(pack["kdf"], pack["slots"][1], _fake_device_code(2))
    # The next pack continues the indexes.
    again = tq.offline.issue_device_pack("jane@acme.com", scope, "ACME\\jane", count=2)
    assert [s["index"] for s in again["slots"]] == [4, 5]

    now = datetime.now(timezone.utc)
    assert tq.offline.report_device_pack_use(scope["id"], "jane@acme.com", [{"index": 1, "at": now}, {"index": 99, "at": now}]) == \
        {"recorded": 1, "ignored": 1}
    with pytest.raises(TouchqueAPIException) as unknown:
        tq.offline.report_device_pack_use("pc-other", "jane@acme.com", [{"index": 1, "at": now}])
    assert unknown.value.status == 404

    assert tq.offline.revoke_device_scope(scope["id"], reason="lost") == {"revoked": 1}
    assert [c for c in fake_api.calls() if c["path"] == "/offline/device-packs/revoke"][-1]["body"] == {"scopeId": scope["id"], "reason": "lost"}
    with pytest.raises(TouchqueAPIException) as revoked:
        tq.offline.issue_device_pack("jane@acme.com", scope, "ACME\\jane")
    assert revoked.value.status == 409

    with pytest.raises(TouchqueAPIException) as unlinked:
        tq.offline.issue_device_pack("nobody@acme.com", scope, "ACME\\nobody")
    assert unlinked.value.status == 404
    fake_api.opts(devicePacksDisabled=True)
    with pytest.raises(TouchqueAPIException) as disabled:
        tq.offline.issue_device_pack("jane@acme.com", {"id": "pc-2", "name": "KIOSK"}, "kiosk")
    assert disabled.value.status == 403
