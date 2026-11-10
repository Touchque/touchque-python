import base64
import hashlib
import hmac
import time
from typing import Any, Dict, List, Optional

from ..http_client import HttpClient
from ..exceptions import TouchQueAPIException

_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'


class Offline:
    """Offline Sign — QR challenge / typed code approvals that work with the
    phone offline (no internet on the device)."""

    def __init__(self, http: HttpClient):
        self._http = http

    def challenge(
        self,
        external_username: str,
        type: str = 'LOGIN',
        details: Optional[Any] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        include_qr_image: bool = True,
        request_id: Optional[str] = None,
        require_number_match: bool = False,
    ) -> Dict[str, Any]:
        """Issues an offline QR challenge. Returns
        ``{challengeId, qr, qrDataUrl, expiresAt, expiresInSeconds, totpAvailable}``
        (+ ``challengeCode`` when number matching applies: print it under the QR; the
        phone offers it among two decoys and the user taps the match).
        ``details`` is REQUIRED for critical action types.

        ``request_id`` is the push this QR is a fallback for: once the phone REJECTS it the QR
        is dead (no new QR is issued, a code for the old one is refused with ``request_rejected``),
        and a push with number matching makes the QR show the same number. Always pass it
        when the QR follows a push.
        """
        body: Dict[str, Any] = {'externalUsername': external_username, 'type': type}
        if details is not None:
            body['details'] = details
        if client_ip is not None:
            body['clientIp'] = client_ip
        if user_agent is not None:
            body['userAgent'] = user_agent
        if ttl_seconds is not None:
            body['ttlSeconds'] = ttl_seconds
        if not include_qr_image:
            body['includeQrImage'] = False
        if request_id is not None:
            body['requestId'] = request_id
        if require_number_match:
            body['requireNumberMatch'] = True
        return self._http.post('/offline/challenge', body)

    def verify(self, challenge_id: str, code: str) -> Dict[str, Any]:
        """Verifies the 7-character code shown on the phone. Never raises for
        a wrong/expired/used code — check ``approved``; ``reason`` is one of
        ``invalid_code | locked | expired | used | unknown_challenge |
        request_rejected | too_many_failures | device_not_enrolled``.
        """
        return self._not_approved_as_result(
            lambda: self._http.post('/offline/verify', {'challengeId': challenge_id, 'code': code})
        )

    def verify_totp(self, external_username: str, code: str, type: str = 'LOGIN',
                     client_ip: Optional[str] = None, request_id: Optional[str] = None) -> Dict[str, Any]:
        """Verifies the rolling time-based code (no QR scan needed). Refused
        for critical action types. ``request_id``: the push this sign-in belongs
        to — a code is refused (``request_rejected``) once the phone rejected it."""
        body: Dict[str, Any] = {'externalUsername': external_username, 'code': code, 'type': type}
        if client_ip is not None:
            body['clientIp'] = client_ip
        if request_id is not None:
            body['requestId'] = request_id
        return self._not_approved_as_result(lambda: self._http.post('/offline/totp/verify', body))

    def totp_verifiers(self, external_usernames: List[str], from_step: Optional[int] = None,
                       steps: Optional[int] = None) -> Dict[str, Any]:
        """For checking typed time-based codes while your server cannot reach
        TouchQue (an outage): salted, slow digests of each user's next codes,
        never a key. Up to 1,000 users and 24,000 user-steps a call; ``steps`` 1-480 (default 480, four hours)
        from ``from_step`` (default: the current 30-second step). Returns
        ``{stepSeconds, fromStep, steps, notAfterStep, kdf, users: [{externalUsername,
        fromStep, salt, digests}]}`` with only the users who can use time-based codes
        now. Check a typed code with :meth:`match_totp_verifier`. Requires the
        workspace policies ``offlineTotpEnabled`` and ``outageVerifiersEnabled``.
        Fetch again every few minutes: removed and frozen users fall out."""
        body: Dict[str, Any] = {'externalUsernames': list(external_usernames)}
        if from_step is not None:
            body['fromStep'] = from_step
        if steps is not None:
            body['steps'] = steps
        return self._http.post('/offline/totp/verifiers', body)

    @staticmethod
    def match_totp_verifier(verifiers: Dict[str, Any], user: Dict[str, Any], code: str,
                            at: Optional[float] = None) -> Optional[int]:
        """Checks a typed code against one user's digests from
        :meth:`totp_verifiers` without calling TouchQue. Returns the step the
        code belongs to (the current one or one either side), or ``None``.
        Accept each step once: remember the step you accepted for the user and
        refuse codes for it or an older one. ``at``: Unix time (default now)."""
        given = ''.join(code.upper().split()).replace('-', '') if isinstance(code, str) else ''
        if len(given) != 7 or any(c not in _CODE_ALPHABET for c in given):
            return None
        kdf = verifiers['kdf']
        length = kdf['length']
        now = int((time.time() if at is None else at) // verifiers['stepSeconds'])
        salt = base64.b64decode(user['salt'])
        digests = base64.b64decode(user['digests'])
        for step in (now, now - 1, now + 1):
            if step < user['fromStep'] or step > verifiers['notAfterStep']:
                continue
            i = (step - user['fromStep']) * 2 * length
            if i + 2 * length > len(digests):
                continue
            got = hashlib.pbkdf2_hmac('sha256', given.encode(), salt + f':{step}'.encode(), kdf['iterations'], length)
            if hmac.compare_digest(digests[i:i + length], got) or hmac.compare_digest(digests[i + length:i + 2 * length], got):
                return step
        return None

    @staticmethod
    def _not_approved_as_result(call) -> Dict[str, Any]:
        try:
            return call()
        except TouchQueAPIException as err:
            if err.status is not None and err.status < 500:
                return {
                    'approved': False,
                    'reason': err.reason or err.code or (err.data or {}).get('error'),
                    'attemptsLeft': err.attempts_left,
                }
            raise
