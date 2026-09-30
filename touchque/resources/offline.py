from typing import Any, Dict, Optional

from ..http_client import HttpClient
from ..exceptions import TouchQueAPIException


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
