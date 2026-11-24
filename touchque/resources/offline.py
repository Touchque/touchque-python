import base64
import hashlib
import hmac
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from ..http_client import HttpClient
from ..exceptions import TouchqueAPIException

_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
_DEVICE_CODE_LENGTH = 10
# a-z to A-Z (ASCII only); spaces, tabs, line breaks and dashes dropped.
_DEVICE_CODE_TABLE = str.maketrans('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', ' \t\n\r\f\v-')


def _utc_iso(at: Union[str, datetime]) -> str:
    """A datetime as ISO 8601 in UTC (a naive one is taken as UTC); a string as given."""
    if isinstance(at, datetime):
        aware = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
        return aware.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    return at


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


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
        qr_format: Optional[str] = None,
        include_qr_terminal: bool = False,
    ) -> Dict[str, Any]:
        """Issues an offline QR challenge. Returns
        ``{challengeId, qr, qrFormat, qrDataUrl, expiresAt, expiresInSeconds, totpAvailable}``
        (+ ``challengeCode`` when number matching applies: print it under the QR; the
        phone offers it among two decoys and the user taps the match).
        ``details`` is REQUIRED for critical action types.

        ``request_id`` is the push this QR is a fallback for: once the phone REJECTS it the QR
        is dead (no new QR is issued, a code for the old one is refused with ``request_rejected``),
        and a push with number matching makes the QR show the same number. Always pass it
        when the QR follows a push.

        ``qr_format='compact'``: a smaller QR (``qr`` starts with ``TQ3:``) for terminals and
        small screens, the same challenge and the same 7-character code; it carries no location
        block, so put what the phone should show in ``details``. The default is ``'standard'``
        (``TQ2.``); the answer's ``qrFormat`` says which format ``qr`` is.
        ``include_qr_terminal=True`` adds ``qrTerminal``: the QR drawn with Unicode half blocks
        (lines separated by ``\\n``), ready to print in a terminal (``None`` when it could not be drawn).
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
        if qr_format is not None:
            body['qrFormat'] = qr_format
        if include_qr_terminal:
            body['includeQrTerminal'] = True
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

    def totp_verifiers(self, external_usernames: List[str], scope: Dict[str, str],
                       from_step: Optional[int] = None, steps: Optional[int] = None) -> Dict[str, Any]:
        """For checking typed codes while your server cannot reach Touchque (an
        outage): salted, slow digests of each user's next OUTAGE codes for one
        scope, never a key. Outage codes are not the normal time-based code:
        each scope (an organization, or your own outage server) has its own,
        the user's phone shows them under the normal code ("<name>: code for
        when Touchque can't be reached") once a call has named the scope for
        the user, and :meth:`verify_totp` never accepts them.

        ``scope`` is required: ``{'id': ..., 'name': ...}``, ``id`` 1-64
        characters of a-z, 0-9, ".", "_", "-" (compared in lower case), ``name``
        1-80 characters shown on the phone. Up to 1,000 users and 24,000
        user-steps a call; ``steps`` 1-480 (default 480, four hours) from
        ``from_step`` (default: the current 30-second step). Returns
        ``{stepSeconds, fromStep, steps, notAfterStep, scope, digestsPerStep, kdf,
        users: [{externalUsername, fromStep, salt, digests}]}`` with only the
        users who can use time-based codes now and whose phone shows this scope.
        Check a typed code with :meth:`match_totp_verifier`. Requires the
        workspace policies ``offlineTotpEnabled`` and ``outageVerifiersEnabled``.
        Fetch again every few minutes from the step you have: removed and frozen
        users fall out. Quotas are per scope (429 ``scope_quota_exceeded``) and
        per workspace. A call without a scope is refused with 400 ``scope_required``."""
        body: Dict[str, Any] = {'externalUsernames': list(external_usernames),
                                'scope': {'id': scope['id'], 'name': scope['name']}}
        if from_step is not None:
            body['fromStep'] = from_step
        if steps is not None:
            body['steps'] = steps
        return self._http.post('/offline/totp/verifiers', body)

    @staticmethod
    def match_totp_verifier(verifiers: Dict[str, Any], user: Dict[str, Any], code: str,
                            at: Optional[float] = None) -> Optional[int]:
        """Checks a typed code against one user's digests from
        :meth:`totp_verifiers` without calling Touchque. Returns the step the
        code belongs to (the current one or one either side), or ``None``.
        Accept each step once: remember the step you accepted for the user and
        refuse codes for it or an older one. ``at``: Unix time (default now)."""
        given = ''.join(code.upper().split()).replace('-', '') if isinstance(code, str) else ''
        if len(given) != 7 or any(c not in _CODE_ALPHABET for c in given):
            return None
        kdf = verifiers['kdf']
        length = kdf['length']
        per = verifiers.get('digestsPerStep') or 2
        now = int((time.time() if at is None else at) // verifiers['stepSeconds'])
        salt = base64.b64decode(user['salt'])
        digests = base64.b64decode(user['digests'])
        for step in (now, now - 1, now + 1):
            if step < user['fromStep'] or step > verifiers['notAfterStep']:
                continue
            i = (step - user['fromStep']) * per * length
            if i + per * length > len(digests):
                continue
            got = hashlib.pbkdf2_hmac('sha256', given.encode(), salt + f':{step}'.encode(), kdf['iterations'], length)
            for k in range(per):
                if hmac.compare_digest(digests[i + k * length:i + (k + 1) * length], got):
                    return step
        return None

    def issue_device_pack(self, external_username: str, scope: Dict[str, str], account: str,
                          count: Optional[int] = None, valid_days: Optional[int] = None) -> Dict[str, Any]:
        """The next offline sign-ins of a person on one device (a laptop, a kiosk, a field
        tablet) that must sign them in with no network. Ask only right after a sign-in the person
        approved on the phone at that device itself, never for a remote session.

        ``scope`` is the device: ``{'id': ..., 'name': ...}``, ``id`` 1-64 characters of a-z, 0-9,
        ".", "_", "-" starting with a letter or a digit (compared in lower case; one id per device
        install), ``name`` 1-80 characters shown on the phone. ``account`` (1-255 characters, shown
        on the phone) is the account the person signs in to there. ``count`` 1-20 slots (default
        10), valid ``valid_days`` 1-30 days (default 14). Returns ``{scope: {id, name, epoch},
        account, validUntil, codeLength, kdf: {name, iterations, length}, slots: [{index, salt,
        digest, qr, qrTerminal}]}``: per slot the slow digest of a 10-character code and a QR
        (``TQ4:``) only the person's phone opens; nothing in it can produce a code. Offline, the
        device shows the lowest unused slot's QR, the person scans it with the Touchque app,
        approves and types the code (XXXXX-XXXXX); check it with :meth:`verify_device_code`.
        Indexes continue from the device's last pack and are never issued twice.

        Requires the workspace policies ``offlineSignEnabled`` and ``offlineDevicePacksEnabled``
        (403 ``offline_device_packs_disabled``); refused under a passkey-only policy (403
        ``phishing_resistant_required``), for a phone not enrolled for offline sign (409
        ``device_not_enrolled_for_offline``), for a revoked device (409 ``scope_revoked``) and after
        12 packs an hour per person and device (429 ``too_many_packs``)."""
        body: Dict[str, Any] = {'externalUsername': external_username,
                                'scope': {'id': scope['id'], 'name': scope['name']}, 'account': account}
        if count is not None:
            body['count'] = count
        if valid_days is not None:
            body['validDays'] = valid_days
        return self._http.post('/offline/device-packs', body)

    def revoke_device_scope(self, scope_id: str, external_username: Optional[str] = None,
                            reason: Optional[str] = None) -> Dict[str, Any]:
        """A device's offline sign-ins stop (lost, stolen, reinstalled): it gets no more packs,
        and the person's phone refuses its codes once it has the list. Without
        ``external_username``, every person's packs on that device. ``reason``: up to 64
        characters (default ``revoked``). Returns ``{revoked}``, how many packs were revoked. A
        reinstalled device needs a new scope id."""
        body: Dict[str, Any] = {'scopeId': scope_id}
        if external_username is not None:
            body['externalUsername'] = external_username
        if reason is not None:
            body['reason'] = reason
        return self._http.post('/offline/device-packs/revoke', body)

    def report_device_pack_use(self, scope_id: str, external_username: str,
                               used: List[Dict[str, Any]]) -> Dict[str, Any]:
        """The slots a device accepted while it had no network, sent once it is back online:
        ``used`` is 1-100 ``{'index': ..., 'at': ...}`` (``at``: a datetime, a naive one taken as
        UTC, or an ISO 8601 string, within the last 60 days). Touchque writes one log row per slot
        with the time it happened. Returns ``{recorded, ignored}`` (an index never issued or
        repeated, or a time out of range, is ignored); 404 ``unknown_scope`` when the device has no
        pack for that person."""
        body = {'scopeId': scope_id, 'externalUsername': external_username,
                'used': [{'index': u['index'], 'at': _utc_iso(u['at'])} for u in used]}
        return self._http.post('/offline/device-packs/report', body)

    @staticmethod
    def normalize_device_code(code: Any) -> Optional[str]:
        """A typed offline sign-in code in its canonical form: upper case, without spaces or
        dashes. ``None`` unless it is exactly 10 characters of the codes' alphabet (A-Z and 2-9
        without I and O)."""
        if not isinstance(code, str):
            return None
        given = code.translate(_DEVICE_CODE_TABLE)
        if len(given) != _DEVICE_CODE_LENGTH or any(c not in _CODE_ALPHABET for c in given):
            return None
        return given

    @staticmethod
    def format_device_code(code: Any) -> Optional[str]:
        """An offline sign-in code the way the phone shows it, ``XXXXX-XXXXX``; ``None`` unless
        :meth:`normalize_device_code` accepts it."""
        given = Offline.normalize_device_code(code)
        return None if given is None else f'{given[:5]}-{given[5:]}'

    @staticmethod
    def verify_device_code(kdf: Mapping, slot: Mapping, code: str) -> bool:
        """Checks the code a person typed against one slot of an offline sign-in pack (the
        pack's ``kdf`` and one of its ``slots``), on the device and with no network:
        PBKDF2-SHA256(code, salt || ":" || index, kdf iterations, kdf length) compared in constant
        time with the slot's digest. Case, spaces and dashes are ignored; anything that is not 10
        characters of the codes' alphabet is ``False`` without computing the digest, and so is a
        KDF other than pbkdf2-sha256. Check the lowest unused slot only. The digest takes a moment
        by design (600,000 iterations)."""
        given = Offline.normalize_device_code(code)
        if given is None or not isinstance(kdf, Mapping) or not isinstance(slot, Mapping):
            return False
        name = kdf.get('name')
        if name and name != 'pbkdf2-sha256':
            return False
        iterations, length, index = kdf.get('iterations'), kdf.get('length'), slot.get('index')
        if not (_positive_int(iterations) and _positive_int(length) and _positive_int(index)) or iterations > 0x7fffffff:
            return False
        try:
            salt = base64.b64decode(slot['salt'], validate=True)
            digest = base64.b64decode(slot['digest'], validate=True)
        except (KeyError, TypeError, ValueError):
            return False
        if len(digest) != length:
            return False
        got = hashlib.pbkdf2_hmac('sha256', given.encode('ascii'), salt + b':' + str(index).encode('ascii'), iterations, length)
        return hmac.compare_digest(got, digest)

    @staticmethod
    def _not_approved_as_result(call) -> Dict[str, Any]:
        try:
            return call()
        except TouchqueAPIException as err:
            if err.status is not None and err.status < 500:
                return {
                    'approved': False,
                    'reason': err.reason or err.code or (err.data or {}).get('error'),
                    'attemptsLeft': err.attempts_left,
                }
            raise
