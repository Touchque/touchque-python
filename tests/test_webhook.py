import hmac
import hashlib
import json
import time
from datetime import datetime, timezone

import pytest

from touchque.config import Config
from touchque.resources.webhook import Webhook
from touchque.exceptions import TouchqueWebhookSignatureException

SECRET = "whsec_test"


def server_webhook(payload: dict, secret: str = SECRET) -> str:
    """
    Reproduce the API server exactly: sign stableStringify(payload)
    (top-level keys sorted, no `signature` field, compact) and deliver the
    body as {...payload, signature}.
    """
    ordered = {k: payload[k] for k in sorted(payload)}
    canonical = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)
    signature = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return json.dumps({**payload, "signature": signature})


def fresh_payload(**overrides) -> dict:
    base = {
        "event": "login.confirmed",
        "requestId": "req_1",
        "status": "SUCCESS",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "jti": "jti_1",
    }
    base.update(overrides)
    return base


def make_webhook() -> Webhook:
    return Webhook(Config(api_key="tq_auth_test123", api_secret=SECRET))


def test_verifies_a_genuine_server_signed_callback():
    payload = fresh_payload()
    raw_body = server_webhook(payload)

    result = make_webhook().verify(raw_body)

    assert result["requestId"] == "req_1"
    assert result["event"] == "login.confirmed"


def test_accepts_the_signature_from_the_header_too():
    payload = fresh_payload()
    raw_body = server_webhook(payload)
    header_sig = json.loads(raw_body)["signature"]
    body_without_sig = json.dumps(payload)

    result = make_webhook().verify(body_without_sig, header_sig)

    assert result["requestId"] == "req_1"


def test_rejects_a_tampered_body():
    payload = fresh_payload()
    raw_body = server_webhook(payload)
    tampered = raw_body.replace("req_1", "req_evil")

    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(tampered)


def test_rejects_a_wrong_secret():
    raw_body = server_webhook(fresh_payload(), secret="not_the_secret")

    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(raw_body)


def test_rejects_a_missing_signature():
    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(json.dumps(fresh_payload()))


def test_rejects_a_non_ascii_signature_as_a_bad_signature():
    payload = fresh_payload()
    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(json.dumps(payload), "é")
    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(json.dumps({**payload, "signature": "é" * 64}))
    # An unpaired surrogate (json.dumps writes the escape \ud800) cannot be encoded: still a bad signature.
    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(json.dumps({**payload, "signature": "\ud800" * 64}))
    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(json.dumps(payload), "\udc00")


def test_rejects_malformed_json():
    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify("not json")


def test_rejects_a_body_nested_too_deep_or_with_a_number_too_long():
    # json.loads raises RecursionError for the first, and ValueError (not JSONDecodeError) for the second on
    # Python 3.11+: both are a bad body, not a crash.
    for body in ('{"a":' + "[" * 100000 + "]" * 100000 + "}", '{"a":' + "1" * 5000 + "}"):
        with pytest.raises(TouchqueWebhookSignatureException):
            make_webhook().verify(body, "0" * 64)


def test_rejects_a_non_object_body():
    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify("[1,2,3]")


def test_rejects_a_stale_timestamp_as_replay():
    old = datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat()
    raw_body = server_webhook(fresh_payload(timestamp=old))

    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(raw_body)


def test_replay_check_can_be_disabled():
    old = datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat()
    raw_body = server_webhook(fresh_payload(timestamp=old))

    result = make_webhook().verify(raw_body, tolerance_seconds=0)

    assert result["requestId"] == "req_1"


def test_the_error_never_leaks_the_expected_signature():
    raw_body = server_webhook(fresh_payload(), secret="wrong")

    with pytest.raises(TouchqueWebhookSignatureException) as exc:
        make_webhook().verify(raw_body)

    assert "Expected" not in str(exc.value)
    assert hashlib.sha256(b"").hexdigest()[:8] not in str(exc.value)


def test_preserves_nested_object_key_order_empty_objects_and_numbers():
    # Regression lock: canonicalization sorts ONLY the top-level keys. Nested
    # objects keep their key order, empty objects stay objects, and precise
    # numbers are not reformatted — matching the server's stableStringify.
    payload = fresh_payload(
        context={"z": 1, "a": 2, "inner": {"y": True, "x": False}},
        meta={},
        ledger_balance=123456789.123456789,
        riskFactors=["new_device", "unusual_time_of_day"],
    )
    raw_body = server_webhook(payload)

    result = make_webhook().verify(raw_body)

    assert result["requestId"] == "req_1"
    assert result["context"] == {"z": 1, "a": 2, "inner": {"y": True, "x": False}}
    assert result["meta"] == {}


def _js_iso_now() -> str:
    """new Date().toISOString(): milliseconds and Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@pytest.mark.parametrize("password_json,password", [
    ("s3cret", "s3cret"),
    ("pässwörd 🔑 \\\"q\\\"", "pässwörd 🔑 \"q\""),
    # An unpaired surrogate a customer typed: JSON.stringify writes it as an escape and signs that text (a pair
    # stays one character). The payload has U+FFFD in its place, so the password can be encoded.
    ("a\\ud800b\\udc00", "a\ufffdb\ufffd"),
    ("\\ud800\U00010000", "\ufffd\U00010000"),
])
def test_verifies_a_user_store_request_as_the_server_signs_it(password_json, password):
    # As the API server asks the user store: payload { event, tenant, email, password, timestamp, jti }, signed over stableStringify
    # (top-level keys sorted), sent as {...payload, signature} with the same signature in x-signature.
    ts, jti = _js_iso_now(), "3f1c9e0a-6d2b-4c1e-9a57-0b8e2d4f6a11"
    canonical = (
        '{"email":"ada@acme.test","event":"user_store.verify_password","jti":"%s","password":"%s",'
        '"tenant":"acme","timestamp":"%s"}' % (jti, password_json, ts)
    )
    signature = hmac.new(SECRET.encode(), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    raw_body = (
        '{"event":"user_store.verify_password","tenant":"acme","email":"ada@acme.test","password":"%s",'
        '"timestamp":"%s","jti":"%s","signature":"%s"}' % (password_json, ts, jti, signature)
    )

    for header in (signature, None):
        result = make_webhook().verify(raw_body, header)
        assert (result["event"], result["email"], result["password"]) == ("user_store.verify_password", "ada@acme.test", password)
        result["password"].encode("utf-8")
    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(raw_body.replace('"tenant":"acme"', '"tenant":"evil"'), signature)


# ── Cross-language SDK contract fixtures (fixtures/webhook-vectors.json) ──
import os
from touchque.resources.webhook import _canonicalize

_WH_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "fixtures", "webhook-vectors.json"
)
with open(_WH_FIXTURE_PATH) as _f:
    _WH_FIXTURE = json.load(_f)


@pytest.mark.parametrize("vec", _WH_FIXTURE["vectors"], ids=lambda v: v["description"])
def test_webhook_canonical_matches_backend_vector(vec):
    assert _canonicalize(vec["payload"]) == vec["expected_canonical"]
    wh = Webhook(Config(api_key="tq_x", api_secret=_WH_FIXTURE["secret"]))
    result = wh.verify(vec["delivered_body"], tolerance_seconds=0)  # fixtures have a fixed timestamp
    assert result["requestId"] == vec["payload"]["requestId"]


# ── Touchque Login user-store requests as the backend sends them (fixtures/user-store-vectors.json) ──

with open(os.path.join(os.path.dirname(__file__), "..", "fixtures", "user-store-vectors.json"), encoding="utf-8") as _f:
    _US_VECTORS = json.load(_f)["vectors"]


@pytest.mark.parametrize("vec", _US_VECTORS, ids=lambda v: v["name"])
def test_user_store_request_matches_backend_vector(vec):
    # What a verifier builds from the body: for a valid vector, exactly the text Touchque signed.
    assert _canonicalize(json.loads(vec["body"])) == vec["canonical"]
    wh = Webhook(Config(api_key="tq_x", api_secret=vec["secret"]))
    for signature in (vec["x_signature"], None):  # the x-signature header, or the body's signature field
        if vec["valid"]:
            payload = wh.verify(vec["body"], signature, tolerance_seconds=0)  # fixed timestamps in the past
            assert payload == vec["expected_payload"]
            json.dumps(payload, ensure_ascii=False).encode("utf-8")  # every string can be encoded and read
        else:
            with pytest.raises(TouchqueWebhookSignatureException):
                wh.verify(vec["body"], signature, tolerance_seconds=0)


def test_a_user_store_body_carrying_the_replacement_character_instead_fails():
    # The signature covers the unpaired surrogate as sent (\ud800), not the U+FFFD handed back: a body with
    # U+FFFD there instead, escaped or raw, is not what Touchque signed.
    vec = next(v for v in _US_VECTORS if v["name"] == "verify_password_unpaired_high_surrogates")
    wh = Webhook(Config(api_key="tq_x", api_secret=vec["secret"]))
    assert wh.verify(vec["body"], vec["x_signature"], tolerance_seconds=0)["password"] == "ab\ufffdcd\ufffd"
    for changed in (vec["body"].replace("\\ud800", "\\ufffd"), vec["body"].replace("\\ud800", "\ufffd")):
        assert changed != vec["body"]
        with pytest.raises(TouchqueWebhookSignatureException):
            wh.verify(changed, vec["x_signature"], tolerance_seconds=0)


# ── Replay protection (A12) ──

def test_a_missing_or_invalid_timestamp_fails_closed():
    no_ts = fresh_payload()
    del no_ts["timestamp"]
    for body in (server_webhook(no_ts), server_webhook(fresh_payload(timestamp="not-a-date"))):
        with pytest.raises(TouchqueWebhookSignatureException):
            make_webhook().verify(body)


def test_replay_cache_rejects_the_second_delivery_of_the_same_jti():
    from touchque import MemoryReplayCache, TouchqueWebhookReplayException

    cache = MemoryReplayCache()
    wh = make_webhook()
    body = server_webhook(fresh_payload(jti="once"))
    assert wh.verify(body, replay_cache=cache)["jti"] == "once"
    with pytest.raises(TouchqueWebhookReplayException) as exc:
        wh.verify(body, replay_cache=cache)
    assert exc.value.jti == "once"
    assert isinstance(exc.value, TouchqueWebhookSignatureException)
    wh.verify(server_webhook(fresh_payload(jti="other")), replay_cache=cache)
    no_jti = fresh_payload()
    del no_jti["jti"]
    with pytest.raises(TouchqueWebhookSignatureException):
        wh.verify(server_webhook(no_jti), replay_cache=cache)


def test_a_forged_webhook_does_not_poison_the_replay_cache():
    from touchque import MemoryReplayCache

    cache = MemoryReplayCache()
    with pytest.raises(TouchqueWebhookSignatureException):
        make_webhook().verify(server_webhook(fresh_payload(jti="victim"), secret="wrong"), replay_cache=cache)
    make_webhook().verify(server_webhook(fresh_payload(jti="victim")), replay_cache=cache)


def test_memory_replay_cache_forgets_expired_entries(monkeypatch):
    from touchque import MemoryReplayCache
    import touchque.resources.webhook as mod

    clock = [1000.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    cache = MemoryReplayCache()
    assert cache.check_and_set("x", 10) is True
    assert cache.check_and_set("x", 10) is False
    clock[0] += 11
    assert cache.check_and_set("x", 10) is True


def test_mobile_recovery_and_assist_event_constants_match_the_backend():
    # The API server sends exactly these names for the Mobile SDK, recovery and the help desk.
    from touchque import WebhookEvents

    assert WebhookEvents.MOBILE_PUSH == "MOBILE_PUSH"
    recovery = ["STARTED", "DEVICE_BOUND", "COOLING", "COMPLETED", "VETOED", "EXPIRED", "FAILED"]
    assist = ["OPENED", "ENDED", "CHECK_PASSED", "CHECK_FAILED", "UNFROZEN", "CLAIM_CONFIRMED", "CLAIM_UNVERIFIED"]
    for name in ["RECOVERY_" + s for s in recovery] + ["ASSIST_" + s for s in assist]:
        assert getattr(WebhookEvents, name) == name
