import hmac
import hashlib
import json
import time
from datetime import datetime, timezone

import pytest

from touchque.config import Config
from touchque.resources.webhook import Webhook
from touchque.exceptions import TouchQueWebhookSignatureException

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

    with pytest.raises(TouchQueWebhookSignatureException):
        make_webhook().verify(tampered)


def test_rejects_a_wrong_secret():
    raw_body = server_webhook(fresh_payload(), secret="not_the_secret")

    with pytest.raises(TouchQueWebhookSignatureException):
        make_webhook().verify(raw_body)


def test_rejects_a_missing_signature():
    with pytest.raises(TouchQueWebhookSignatureException):
        make_webhook().verify(json.dumps(fresh_payload()))


def test_rejects_malformed_json():
    with pytest.raises(TouchQueWebhookSignatureException):
        make_webhook().verify("not json")


def test_rejects_a_non_object_body():
    with pytest.raises(TouchQueWebhookSignatureException):
        make_webhook().verify("[1,2,3]")


def test_rejects_a_stale_timestamp_as_replay():
    old = datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat()
    raw_body = server_webhook(fresh_payload(timestamp=old))

    with pytest.raises(TouchQueWebhookSignatureException):
        make_webhook().verify(raw_body)


def test_replay_check_can_be_disabled():
    old = datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat()
    raw_body = server_webhook(fresh_payload(timestamp=old))

    result = make_webhook().verify(raw_body, tolerance_seconds=0)

    assert result["requestId"] == "req_1"


def test_the_error_never_leaks_the_expected_signature():
    raw_body = server_webhook(fresh_payload(), secret="wrong")

    with pytest.raises(TouchQueWebhookSignatureException) as exc:
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


# ── Cross-language SDK contract fixtures (fixtures/webhook-vectors.json) ──
import os
from touchque.resources.webhook import _canonicalize

_WH_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "fixtures", "webhook-vectors.json"
)
with open(_WH_FIXTURE_PATH) as _f:
    _WH_FIXTURE = json.load(_f)


@pytest.mark.parametrize("vec", _WH_FIXTURE["vectors"], ids=lambda v: v["description"])
def test_webhook_canonical_matches_backend_vector(vec):
    assert _canonicalize(vec["payload"]) == vec["expected_canonical"]
    wh = Webhook(Config(api_key="tq_x", api_secret=_WH_FIXTURE["secret"]))
    result = wh.verify(vec["delivered_body"], tolerance_seconds=0)  # fixtures have a fixed timestamp
    assert result["requestId"] == vec["payload"]["requestId"]
