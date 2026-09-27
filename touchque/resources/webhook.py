import json
import time
import hmac
import hashlib
from datetime import datetime
from typing import Any, Dict, Optional

from ..config import Config
from ..exceptions import TouchQueWebhookSignatureException

# Default replay window: reject a callback whose signed `timestamp` is more
# than this many seconds away from now. Matches the server's replay guard.
DEFAULT_TOLERANCE_SECONDS = 300


def _canonicalize(payload: Dict[str, Any]) -> str:
    """
    Reproduce the server's ``stableStringify``:
    drop the ``signature`` field, sort the TOP-LEVEL keys, and serialize
    with no whitespace. Nested values keep their order, exactly as
    ``JSON.stringify`` leaves them.
    """
    without_sig = {k: v for k, v in payload.items() if k != "signature"}
    ordered = {k: without_sig[k] for k in sorted(without_sig)}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)


def _parse_iso_timestamp(value: Any) -> Optional[float]:
    if not isinstance(value, str):
        return None
    try:
        text = value.replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


class Webhook:
    def __init__(self, config: Config):
        self._config = config

    def verify(
        self,
        raw_body: str,
        signature: Optional[str] = None,
        tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    ) -> Dict[str, Any]:
        """
        Verify the signature of an incoming TouchQue webhook and return the
        decoded payload.

        Args:
            raw_body: The raw request body, exactly as received (do not
                re-serialize it).
            signature: The ``x-signature`` header value. Optional — if omitted,
                the ``signature`` field carried inside the body is used.
            tolerance_seconds: Reject a callback whose signed ``timestamp`` is
                further than this from now (replay protection). Pass ``0`` to
                disable the check.

        Raises:
            TouchQueWebhookSignatureException: signature missing, malformed
                body, signature mismatch, or a stale (replayed) callback.
        """
        if not isinstance(raw_body, str):
            raise TouchQueWebhookSignatureException("raw_body must be a string")

        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            raise TouchQueWebhookSignatureException("Invalid JSON payload")
        if not isinstance(payload, dict):
            raise TouchQueWebhookSignatureException("Webhook payload must be a JSON object")

        provided = signature or payload.get("signature")
        if not isinstance(provided, str) or not provided:
            raise TouchQueWebhookSignatureException("No signature provided")

        mac = hmac.new(
            self._config.api_secret.encode("utf-8"),
            _canonicalize(payload).encode("utf-8"),
            hashlib.sha256,
        )
        # Do NOT put the expected signature in the exception — a caller that
        # surfaces the error text would hand an attacker a signing oracle.
        if not hmac.compare_digest(mac.hexdigest(), provided):
            raise TouchQueWebhookSignatureException("Invalid webhook signature")

        if tolerance_seconds and tolerance_seconds > 0:
            ts = _parse_iso_timestamp(payload.get("timestamp"))
            if ts is not None and abs(time.time() - ts) > tolerance_seconds:
                raise TouchQueWebhookSignatureException("Webhook timestamp is outside the allowed window")

        return payload
