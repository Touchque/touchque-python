"""Pairing a browser by QR code: your page shows a QR code, the person scans it
with the TouchQue app, and the phone that scanned is the one asked to approve.

1. Your page gets the thumbprint of its browser key (``@touchque/web``
   ``browserKey.thumbprint()``) and sends it to your server.
2. ``create(key_thumbprint, client_ip=..., user_agent=...)`` registers a
   pairing and returns ``uri`` (``touchque://pair-browser?...``): show it as a
   QR code. It can be scanned once, for ``ttl_seconds`` (default 120). The
   nonce in it never leaves your server and the QR: TouchQue keeps only its hash.
3. Poll ``get(pairing_id)``: ``scanned`` once a phone holding one of your users'
   accounts read it (``externalUsername``, ``proximity``), ``confirmed`` once
   the person went on, ``reported`` when they said someone told them to scan
   it (their 2FA freezes).
4. ``login.request(external_username, qr_pairing=pairing_id)`` asks that phone,
   once, with number matching; the browser key's fingerprint is one of the rows
   the phone signs. When your own checks say no, ``refuse(pairing_id, reason,
   message)`` and the phone shows why.
"""
import base64
import hashlib
import os as _os  # create() takes an `os` argument, which would hide the module there
import re
from typing import Any, Dict, Optional
from urllib.parse import quote

from ..exceptions import TouchQueConfigException
from ..http_client import HttpClient

#: What ``refuse`` may tell the phone.
QR_PAIRING_REFUSAL_REASONS = ('policy', 'device_not_approved', 'too_many_browsers', 'rate_limited', 'no_account', 'other')

_B64URL_43 = re.compile(r'^[A-Za-z0-9_-]{43}$')


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def qr_pairing_uri(pairing_id: str, nonce: str, key_thumbprint: str) -> str:
    """What the QR code says: ``touchque://pair-browser?v=1&p=<pairing>&n=<nonce>&k=<key thumbprint>``."""
    q = lambda v: quote(v, safe='')  # noqa: E731
    return f'touchque://pair-browser?v=1&p={q(pairing_id)}&n={q(nonce)}&k={q(key_thumbprint)}'


def _path(pairing_id: str, method: str, rest: str = '') -> str:
    if not isinstance(pairing_id, str) or not pairing_id:
        raise TouchQueConfigException(f'qr_pairings.{method}() needs the pairing_id.')
    return f'/qr-pairings/{quote(pairing_id, safe="")}{rest}'


class QrPairings:
    """Browser pairings by QR code (``POST /qr-pairings``)."""

    def __init__(self, http: HttpClient):
        self._http = http

    def create(self, key_thumbprint: str, client_ip: Optional[str] = None, user_agent: Optional[str] = None,
               browser: Optional[str] = None, os_name: Optional[str] = None, ttl_seconds: Optional[int] = None,
               os: Optional[str] = None) -> Dict[str, Any]:
        """Registers a pairing for one browser: ``{pairingId, expiresAt, nonce, uri}``; show ``uri`` as a QR code.
        ``os=`` is the same as ``os_name=`` (the name the other SDKs use)."""
        if os_name is None:
            os_name = os
        if not isinstance(key_thumbprint, str) or not _B64URL_43.match(key_thumbprint):
            raise TouchQueConfigException('qr_pairings.create() needs key_thumbprint: the RFC 7638 thumbprint of the browser key, base64url (43 characters).')
        if ttl_seconds is not None and (not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 30 <= ttl_seconds <= 300):
            raise TouchQueConfigException('qr_pairings.create(): ttl_seconds must be 30 to 300.')
        nonce = _b64url(_os.urandom(32))
        body: Dict[str, Any] = {'nonceHash': _b64url(hashlib.sha256(nonce.encode('utf-8')).digest()), 'keyThumbprint': key_thumbprint}
        for key, value in (('clientIp', client_ip), ('userAgent', user_agent), ('browser', browser), ('os', os_name), ('ttlSeconds', ttl_seconds)):
            if value is not None and value != '':
                body[key] = value
        created = self._http.post('/qr-pairings', body)
        return {**created, 'nonce': nonce, 'uri': qr_pairing_uri(created['pairingId'], nonce, key_thumbprint)}

    def get(self, pairing_id: str) -> Dict[str, Any]:
        """Where a pairing stands; once scanned, who scanned it and how near the phone was."""
        return self._http.get(_path(pairing_id, 'get'))

    def refuse(self, pairing_id: str, reason: str, message: str, case_code: Optional[str] = None,
               device_code: Optional[str] = None) -> Dict[str, Any]:
        """Your own checks refused a scanned pairing; the phone shows ``message``.
        Only a ``scanned`` or ``confirmed`` pairing can be refused (409 ``not_open``)."""
        if reason not in QR_PAIRING_REFUSAL_REASONS:
            raise TouchQueConfigException(f'qr_pairings.refuse(): reason must be one of {", ".join(QR_PAIRING_REFUSAL_REASONS)}.')
        if not isinstance(message, str) or not message.strip():
            raise TouchQueConfigException('qr_pairings.refuse() needs message: what the phone shows (up to 300 characters).')
        body: Dict[str, Any] = {'reason': reason, 'message': message}
        if case_code:
            body['caseCode'] = case_code
        if device_code:
            body['deviceCode'] = device_code
        return self._http.post(_path(pairing_id, 'refuse', '/outcome'), body)
