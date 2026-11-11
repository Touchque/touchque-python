import json
import time
import hmac
import hashlib
import threading
from datetime import datetime
from typing import Any, Dict, Optional

from ..config import Config
from ..exceptions import TouchqueWebhookReplayException, TouchqueWebhookSignatureException

# Default replay window: reject a callback whose signed `timestamp` is more
# than this many seconds away from now. Matches the server's replay guard.
DEFAULT_TOLERANCE_SECONDS = 300


class WebhookReasons:
    """``reason`` values of a REJECTED login webhook. Treat a value you do not
    know as a rejection: new ones are added in minor versions."""
    USER_REJECTED = 'user_rejected'
    #: The user said "this wasn't me": 2FA is frozen.
    USER_REPORTED_FRAUD = 'user_reported_fraud'
    #: The user said someone on the phone told them to approve: 2FA is frozen; treat it as a takeover in progress.
    USER_REPORTED_COACHED = 'user_reported_coached'
    #: An AI agent's request: the user said no and blocked the agent from asking them again (no 2FA freeze).
    USER_BLOCKED_AGENT = 'user_blocked_agent'
    RISK_REVERSED = 'risk_reversed'
    RISK_STEP_UP = 'risk_step_up'
    APPROVAL_SIGNATURE_INVALID = 'approval_signature_invalid'
    DEVICE_INTEGRITY_FAILED = 'device_integrity_failed'
    #: Vishing Shield: approved during a call (or with the screen shared / remote-controlled), critical, no passkey.
    VISHING_SUSPECTED = 'vishing_suspected'
    #: Mirror Alarm: the sign-in page was not on your site (a real-time phishing proxy).
    PHISHING_ORIGIN = 'phishing_origin'


class WebhookEvents:
    """``event`` values of Touchque's event webhooks. Ignore types you do not know."""
    DEVICE_LINKED = 'DEVICE_LINKED'
    DEVICE_UNLINKED = 'DEVICE_UNLINKED'
    PASSKEY_REGISTERED = 'PASSKEY_REGISTERED'
    PASSKEY_DELETED = 'PASSKEY_DELETED'
    #: Device risk: an identification or a device_risk.check raised a signal that asks for more. Never a trait.
    DEVICE_RISK_SIGNAL = 'DEVICE_RISK_SIGNAL'
    #: Device risk: an alert rule of the workspace went off.
    DEVICE_RISK_ALERT = 'DEVICE_RISK_ALERT'
    #: After the call, the user confirmed a provisional approval was theirs: critical actions are allowed again.
    APPROVAL_RECONFIRMED = 'APPROVAL_RECONFIRMED'
    #: The user took an approval back (``reason``: ``COACHED`` or ``UNDO``): end the session built on it.
    APPROVAL_REVOKED = 'APPROVAL_REVOKED'
    # AI agents (client.agents): changes partners may act on, and what Touchque noticed.
    #: An AI agent was registered.
    AGENT_CREATED = 'AGENT_CREATED'
    #: An AI agent was suspended (through the API or the dashboard): its tokens stopped working.
    AGENT_SUSPENDED = 'AGENT_SUSPENDED'
    #: An AI agent may act again.
    AGENT_RESUMED = 'AGENT_RESUMED'
    #: An AI agent was revoked for good.
    AGENT_REVOKED = 'AGENT_REVOKED'
    #: A key was added to an AI agent.
    AGENT_KEY_ADDED = 'AGENT_KEY_ADDED'
    #: A key was removed from an AI agent; tokens bound to it stopped working.
    AGENT_KEY_REMOVED = 'AGENT_KEY_REMOVED'
    #: The kill switch stopped every AI agent of the workspace.
    AGENTS_PAUSED = 'AGENTS_PAUSED'
    #: The kill switch was turned off.
    AGENTS_RESUMED = 'AGENTS_RESUMED'
    #: An AI agent's policy changed.
    AGENT_POLICY_CHANGED = 'AGENT_POLICY_CHANGED'
    AGENT_WORKSPACE_POLICY_CHANGED = 'AGENT_WORKSPACE_POLICY_CHANGED'
    #: An approval token was used.
    AGENT_APPROVAL_REDEEMED = 'AGENT_APPROVAL_REDEEMED'
    #: A person stopped an AI agent from asking them ("this wasn't me", coached, or three rejections).
    AGENT_BLOCKED_BY_PERSON = 'AGENT_BLOCKED_BY_PERSON'
    #: An admin let an AI agent ask a person again.
    AGENT_UNBLOCKED_FOR_PERSON = 'AGENT_UNBLOCKED_FOR_PERSON'
    #: An AI agent sent the same request to the same person three times in 10 minutes.
    AGENT_LOOP_DETECTED = 'AGENT_LOOP_DETECTED'
    #: An AI agent asked a person for a mandate.
    AGENT_MANDATE_REQUESTED = 'AGENT_MANDATE_REQUESTED'
    #: A mandate was ended.
    AGENT_MANDATE_REVOKED = 'AGENT_MANDATE_REVOKED'
    #: An AI agent's text carried an instruction to the model or a link that carries data; the request was refused.
    AGENT_INJECTION_SUSPECTED = 'AGENT_INJECTION_SUSPECTED'
    #: An approval came back sooner than a person can answer; it is never usable.
    AGENT_INHUMAN_APPROVAL = 'AGENT_INHUMAN_APPROVAL'
    #: A new or renamed AI agent's name read like another agent's; it was refused.
    AGENT_LOOKALIKE_NAME = 'AGENT_LOOKALIKE_NAME'
    #: Mobile SDK: send this push with your own keys (``mobile_push_from_webhook``).
    MOBILE_PUSH = 'MOBILE_PUSH'
    # Never Locked Out (client.recovery): every step of a recovery.
    #: A recovery started; the vouchers were asked.
    RECOVERY_STARTED = 'RECOVERY_STARTED'
    #: The new phone was bound to the recovery.
    RECOVERY_DEVICE_BOUND = 'RECOVERY_DEVICE_BOUND'
    #: The vouchers' quorum was reached: the account moves at ``coolOffUntil`` unless vetoed.
    RECOVERY_COOLING = 'RECOVERY_COOLING'
    #: The account moved to the new phone (``method``: ``vouch`` or ``old_phone``); ``DEVICE_LINKED`` follows.
    RECOVERY_COMPLETED = 'RECOVERY_COMPLETED'
    #: The recovery was stopped (the old phone, an admin or a voucher).
    RECOVERY_VETOED = 'RECOVERY_VETOED'
    #: The recovery ended unused (``reason``: ``not_bound`` in time, or ``replaced`` by a new one).
    RECOVERY_EXPIRED = 'RECOVERY_EXPIRED'
    #: The recovery ended without a move (``reason``, e.g. ``not_enough_approvals``).
    RECOVERY_FAILED = 'RECOVERY_FAILED'
    # Help desk (client.assist): IT working on a person's account.
    #: A help desk agent started working on the account.
    ASSIST_OPENED = 'ASSIST_OPENED'
    #: The help desk session ended.
    ASSIST_ENDED = 'ASSIST_ENDED'
    #: The person confirmed the help desk's check on their phone.
    ASSIST_CHECK_PASSED = 'ASSIST_CHECK_PASSED'
    #: The check failed (``outcome``: ``wrong_number``, ``not_me``, ``coached``, ``declined``): page someone.
    ASSIST_CHECK_FAILED = 'ASSIST_CHECK_FAILED'
    #: The help desk lifted the person's approval freeze after a check on the phone.
    ASSIST_UNFROZEN = 'ASSIST_UNFROZEN'
    #: The person checked that the agent from IT is really working on their account.
    ASSIST_CLAIM_CONFIRMED = 'ASSIST_CLAIM_CONFIRMED'
    #: Nobody from IT was working on the account: someone is pretending to be IT. No ``assistId``; page someone.
    ASSIST_CLAIM_UNVERIFIED = 'ASSIST_CLAIM_UNVERIFIED'


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
        Verify the signature of an incoming Touchque webhook and return the
        decoded payload.

        Args:
            raw_body: The raw request body as text, exactly as received (do
                not re-serialize it), e.g. Flask's
                ``request.get_data(as_text=True)``.
            signature: The ``x-signature`` header value. Optional — if omitted,
                the ``signature`` field carried inside the body is used.
            tolerance_seconds: Reject a callback whose signed ``timestamp`` is
                missing, invalid or further than this from now (replay
                protection). Pass ``0`` to disable the check.
            replay_cache: Optional :class:`ReplayCache` (e.g. a shared
                :class:`MemoryReplayCache`). A second delivery of the same
                ``jti`` raises :class:`TouchqueWebhookReplayException`.

        Raises:
            TouchqueWebhookSignatureException: signature missing, malformed
                body, signature mismatch, or a stale callback.
            TouchqueWebhookReplayException: this ``jti`` was already accepted
                (a subclass of the above, so existing handlers still reject it).
        """
        if not isinstance(raw_body, str):
            raise TouchqueWebhookSignatureException("raw_body must be a string")

        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            raise TouchqueWebhookSignatureException("Invalid JSON payload")
        if not isinstance(payload, dict):
            raise TouchqueWebhookSignatureException("Webhook payload must be a JSON object")

        provided = signature or payload.get("signature")
        if not isinstance(provided, str) or not provided:
            raise TouchqueWebhookSignatureException("No signature provided")

        mac = hmac.new(
            self._config.api_secret.encode("utf-8"),
            _canonicalize(payload).encode("utf-8"),
            hashlib.sha256,
        )
        # Do NOT put the expected signature in the exception — a caller that
        # surfaces the error text would hand an attacker a signing oracle.
        # Compared as bytes: compare_digest raises TypeError for a str with non-ASCII text.
        if not hmac.compare_digest(mac.hexdigest().encode("ascii"), provided.encode("utf-8")):
            raise TouchqueWebhookSignatureException("Invalid webhook signature")

        # Touchque always signs a timestamp, so a missing or unparseable one
        # fails closed instead of skipping the freshness check.
        if tolerance_seconds and tolerance_seconds > 0:
            ts = _parse_iso_timestamp(payload.get("timestamp"))
            if ts is None:
                raise TouchqueWebhookSignatureException("Webhook timestamp is missing or invalid")
            if abs(time.time() - ts) > tolerance_seconds:
                raise TouchqueWebhookSignatureException("Webhook timestamp is outside the allowed window")

        if replay_cache is not None:
            jti = payload.get("jti")
            if not isinstance(jti, str) or not jti:
                raise TouchqueWebhookSignatureException("Webhook jti is missing")
            # Remember it for twice the window so it outlives any timestamp
            # that could still pass the freshness check.
            ttl = max((tolerance_seconds or 0) * 2, 600)
            if not replay_cache.check_and_set(jti, ttl):
                raise TouchqueWebhookReplayException(jti)

        return payload
