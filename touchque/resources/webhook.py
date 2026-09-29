import json
import time
import hmac
import hashlib
import threading
from datetime import datetime
from typing import Any, Dict, Optional

from ..config import Config
from ..exceptions import TouchQueWebhookReplayException, TouchQueWebhookSignatureException

# Default replay window: reject a callback whose signed `timestamp` is more
# than this many seconds away from now. Matches the server's replay guard.
DEFAULT_TOLERANCE_SECONDS = 300


class ReplayCache:
    """
    Storage for webhook ``jti`` values already accepted. ``check_and_set``
    must atomically record ``jti`` for ``ttl_seconds`` and return ``True`` if
    it was NOT seen before. Subclass it (or duck-type it) over Redis / your
    database when you run several processes.
    """

    def check_and_set(self, jti: str, ttl_seconds: int) -> bool:
        raise NotImplementedError


class MemoryReplayCache(ReplayCache):
    """In-process :class:`ReplayCache`. Entries expire; the dict is capped. Thread-safe."""

    def __init__(self, max_entries: int = 100_000):
        self._seen: Dict[str, float] = {}
        self._max = max_entries
        self._lock = threading.Lock()

    def check_and_set(self, jti: str, ttl_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            expires = self._seen.get(jti)
            if expires is not None and expires > now:
                return False
            if len(self._seen) >= self._max:
                for key in [k for k, exp in self._seen.items() if exp <= now]:
                    del self._seen[key]
                while len(self._seen) >= self._max:
                    self._seen.pop(next(iter(self._seen)))
            self._seen[jti] = now + ttl_seconds
            return True


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
        replay_cache: Optional[ReplayCache] = None,
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
                missing, invalid or further than this from now (replay
                protection). Pass ``0`` to disable the check.
            replay_cache: Optional :class:`ReplayCache` (e.g. a shared
                :class:`MemoryReplayCache`). A second delivery of the same
                ``jti`` raises :class:`TouchQueWebhookReplayException`.

        Raises:
            TouchQueWebhookSignatureException: signature missing, malformed
                body, signature mismatch, or a stale callback.
            TouchQueWebhookReplayException: this ``jti`` was already accepted
                (a subclass of the above, so existing handlers still reject it).
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

        # TouchQue always signs a timestamp, so a missing or unparseable one
        # fails closed instead of skipping the freshness check.
        if tolerance_seconds and tolerance_seconds > 0:
            ts = _parse_iso_timestamp(payload.get("timestamp"))
            if ts is None:
                raise TouchQueWebhookSignatureException("Webhook timestamp is missing or invalid")
            if abs(time.time() - ts) > tolerance_seconds:
                raise TouchQueWebhookSignatureException("Webhook timestamp is outside the allowed window")

        if replay_cache is not None:
            jti = payload.get("jti")
            if not isinstance(jti, str) or not jti:
                raise TouchQueWebhookSignatureException("Webhook jti is missing")
            # Remember it for twice the window so it outlives any timestamp
            # that could still pass the freshness check.
            ttl = max((tolerance_seconds or 0) * 2, 600)
            if not replay_cache.check_and_set(jti, ttl):
                raise TouchQueWebhookReplayException(jti)

        return payload
