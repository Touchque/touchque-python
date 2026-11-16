"""
A fake Touchque client for your app's tests: no network, no API keys and no
Node.js. ``FakeTouchque`` is a real ``Touchque`` whose API calls are answered
in memory, so the real guard runs: your routes answer exactly what they will
answer in production (202 + token, then your view once approved).

    from touchque.testing import FakeTouchque

    def test_transfer_needs_an_approval():
        tq = FakeTouchque()                    # every user has a phone linked
        client = create_app(touchque=tq).test_client()

        first = client.post('/transfer', json={'amount': 5})
        assert first.status_code == 202
        tq.approve()                           # the person approves on the phone
        done = client.post('/transfer', json={'amount': 5},
                           headers={'X-Touchque-Token': first.get_json()['token']})
        assert done.status_code == 200

Routes that were given no ``client`` use the default one: ``tq.install()`` (or
``with FakeTouchque() as tq:``) makes the fake that default until
``tq.uninstall()``.

It answers the calls the step-up guard makes (approval requests, first-time
linking, offline codes, silent sign-in checks), defining action types and
checking a first-time QR as the phone does (``auth.validate_secret``, with
its ``setupContext``), like the shared fake API the SDKs' own tests use. Any
other call raises ``TouchqueAPIException`` 404.

Because the real guard runs, the answers are the guard's own: every poll of a
waiting request carries its ``expiresAt``, and a guard that may not show a
first-time QR (``run_guard(..., enroll=False)``, the relay's ``POST /login``
without ``get_login_user``) answers a user with no phone
``{"touchque": {"state": "enroll", "reason": "enrollment_off"}}``.
"""
import ipaddress
import json
import re
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlsplit

from . import client as _client_module
from .client import Touchque
from .config import Config
from .http_client import HttpClient, _build_query
from .steps import _iso_from_ms, _iso_ms

__all__ = ['FakeTouchque', 'FakeClient']

_Answer = Tuple[int, Any]
_NOT_INSTALLED = object()


def _now_ms() -> int:
    return int(time.time() * 1000)


# ── 2FA setup context: where a first-time QR was asked for ───────────────
# Kept with the secret (never in the QR) and answered by validate as the API does (the shared fake
# API's rules): the IP address only when it is one and not a loopback one (a port, brackets and
# ::ffff: dropped), shown only when public; the User-Agent without control characters, at most 512
# characters; neither kept: setupContext None.

_IPV4_PORT = re.compile(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3}):[0-9]{1,5}')
_BRACKETED = re.compile(r'\[([^\]]+)\](?::[0-9]{1,5})?')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
# The phone shows no private, carrier-grade NAT, unique-local or link-local address; documentation ranges are shown.
_NOT_SHOWN = tuple(ipaddress.ip_network(n) for n in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16', 'fc00::/7', 'fe80::/10'))
# The fake's GeoIP: two documentation addresses; any other place is unknown (location None).
_SETUP_PLACES = {
    '203.0.113.7': {'city': 'Berlin', 'country': 'Germany', 'countryCode': 'DE'},
    '198.51.100.23': {'city': 'New York', 'country': 'United States', 'countryCode': 'US'},
}
_INTEGRATION = {'companyName': 'Fake workspace', 'icon': 'key-outline', 'color': '#007AFF', 'logo': None,
                'logoDark': None, 'logoVersion': None}


def _ip(text: str) -> Optional[Any]:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _kept_ip(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    ip = value.strip()
    for pattern in (_IPV4_PORT, _BRACKETED):
        m = pattern.fullmatch(ip)
        if m:
            ip = m.group(1)
    if ip[:7].lower() == '::ffff:' and isinstance(_ip(ip[7:]), ipaddress.IPv4Address):
        ip = ip[7:]
    return ip if _ip(ip) is not None and ip != '::1' and not ip.startswith('127.') else None


def _kept_user_agent(value: Any) -> Optional[str]:
    text = _CONTROL.sub('', value).strip() if isinstance(value, str) else ''
    return text[:512] if text else None


def _setup_device(ua: Optional[str]) -> Optional[Dict[str, Optional[str]]]:
    """A tiny User-Agent parse with the API's names; not a browser (curl, an HTTP client) or nothing known: None."""
    if not ua or not ua.startswith('Mozilla/'):
        return None
    browser = next((name for pattern, name in (
        (r'EdgA?/|EdgiOS/', 'Edge'), (r'Firefox/|FxiOS/', 'Firefox'), (r'CriOS/|Chrome/', 'Chrome'),
        (r'Version/[0-9.]+.*Safari/', 'Safari')) if re.search(pattern, ua)), None)
    os_name = next((name for pattern, name in (
        (r'iPad', 'iPadOS'), (r'iPhone|iPod', 'iOS'), (r'Android', 'Android'), (r'Windows NT', 'Windows'),
        (r'Mac OS X|Macintosh', 'macOS'), (r'Linux', 'Linux')) if re.search(pattern, ua)), None)
    if not browser and not os_name:
        return None
    return {'browser': browser, 'os': os_name,
            'model': 'iPhone' if 'iPhone' in ua else 'iPad' if 'iPad' in ua else None}


def _setup_context_of(setup: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kept_ip, kept_ua = _kept_ip(setup['clientIp']), _kept_user_agent(setup['userAgent'])
    if not kept_ip and not kept_ua:
        return None
    addr = _ip(kept_ip) if kept_ip else None
    shown = kept_ip if addr is not None and not any(addr in net for net in _NOT_SHOWN) else None
    place = _SETUP_PLACES.get(shown) if shown else None
    return {'ip': shown, 'location': dict(place) if place else None, 'device': _setup_device(kept_ua),
            'requestedAt': setup['requestedAt'], 'farFromPhone': None}


class FakeTouchque(Touchque):
    """A ``Touchque`` client that answers in memory, for your app's tests.

    ``linked`` (default ``True``): every user has a phone linked, so a guarded
    route sends a push. ``unlink(user)`` gives that user the first-time QR
    instead; with ``linked=False`` only the users you ``link()`` have one.

    The phone is yours to drive: ``approve()``, ``reject()`` or ``expire()``
    the latest request (or one by its id), or set ``auto_approve`` to approve
    every request as it is made. ``requests`` lists the approval requests
    (``id``, ``user``, ``type``, ``details``, ``referenceId``, ``status``:
    ``PENDING`` / ``CONFIRMED`` / ``REJECTED`` / ``EXPIRED``, and
    ``expiresAt``: 30 seconds after it was made, carried by the step and
    every poll), ``calls`` every API call (``method``, ``path``, ``body``), in
    order. The fake never expires a request by time: call ``expire()``.

    ``number_match``: pushes ask for the number ``'47'``. ``secret_ttl_ms``:
    how long a first-time QR works (5 minutes, like the API). The offline code
    is ``'ABCD123'`` and the time-based code ``'123456'``.

    ``setups`` lists the first-time QRs made (``auth.generate_secret`` and
    ``reset_secret``, the guard's and the relay's included): ``user``,
    ``secret``, ``clientIp`` and ``userAgent`` as your app sent them (``None``
    when it sent none), ``requestedAt`` and ``expiresAt``. ``auth.validate_secret``
    answers like the API, with ``setupContext``: the fake's GeoIP knows
    ``203.0.113.7`` (Berlin) and ``198.51.100.23`` (New York), a loopback or
    private address is not shown (``ip`` ``None``), ``setupContext`` is
    ``None`` for a QR asked for without them, a reset's too (never the old
    QR's), and ``farFromPhone`` is always ``None``.
    """

    #: The code the phone shows for an offline QR (``X-Touchque-Code``).
    offline_code = 'ABCD123'
    #: The time-based code (``X-Touchque-Code-Type: totp``).
    totp_code = '123456'

    def __init__(self, *, linked: bool = True, auto_approve: bool = False, number_match: bool = False):
        self._lock = threading.RLock()
        self.linked_by_default = linked
        #: Approve every new request at once, as if the person tapped Approve straight away.
        self.auto_approve = auto_approve
        #: Ask for the number '47' on every push.
        self.number_match = number_match
        #: How long a first-time QR works, in ms.
        self.secret_ttl_ms = 300000
        #: The approval requests made so far, oldest first.
        self.requests: List[Dict[str, Any]] = []
        #: Every API call so far: ``{'method', 'path', 'body'}``, oldest first.
        self.calls: List[Dict[str, Any]] = []
        #: The first-time QRs made so far: ``{'user', 'secret', 'clientIp', 'userAgent', 'requestedAt',
        #: 'expiresAt'}``, oldest first. Only a user's newest one validates.
        self.setups: List[Dict[str, Any]] = []
        self._used_at: Dict[str, str] = {}
        self._linked: Set[str] = set()
        self._unlinked: Set[str] = set()
        self._pending: Dict[str, int] = {}
        self._challenges: Dict[str, Dict[str, Any]] = {}
        self._action_types: Dict[str, Dict[str, Any]] = {}
        self._seq = 0
        self._replaced: Any = _NOT_INSTALLED
        # Signs the guard tokens only: nothing leaves the process.
        super().__init__(Config(api_key='tq_fake_key', api_secret='fake_secret', base_url='http://localhost'))

    def _http_client(self) -> HttpClient:
        return _FakeTransport(self)

    # ── the phone ────────────────────────────────────────────────────────

    def link(self, user: str) -> None:
        """``user`` has a phone linked (as if they scanned the first-time QR)."""
        with self._lock:
            self._linked.add(user)
            self._unlinked.discard(user)
            self._pending.pop(user, None)

    def unlink(self, user: str) -> None:
        """``user`` has no phone linked: a guarded route shows them the first-time QR."""
        with self._lock:
            self._unlinked.add(user)
            self._linked.discard(user)
            self._pending.pop(user, None)

    def is_linked(self, user: str) -> bool:
        with self._lock:
            return user in self._linked or (self.linked_by_default and user not in self._unlinked)

    def approve(self, request_id: Optional[str] = None, via: str = 'DEVICE') -> str:
        """The person approves on the phone: the latest request, or ``request_id``.
        ``via='WEBAUTHN'`` approves it with a passkey. Returns the request's id."""
        with self._lock:
            r = self._pick(request_id)
            r['status'], r['confirmedVia'] = 'CONFIRMED', via
            return r['id']

    def reject(self, request_id: Optional[str] = None) -> str:
        """The person taps Reject: the latest request, or ``request_id``."""
        with self._lock:
            r = self._pick(request_id)
            r['status'] = 'REJECTED'
            return r['id']

    def expire(self, request_id: Optional[str] = None) -> str:
        """Nobody answered in time: the latest request, or ``request_id``."""
        with self._lock:
            r = self._pick(request_id)
            r['status'] = 'EXPIRED'
            return r['id']

    # ── the default client ───────────────────────────────────────────────

    def install(self) -> 'FakeTouchque':
        """Makes this the default client (``get_default_client()``), which the
        adapters use when they were given no ``client``, until ``uninstall()``."""
        with self._lock:
            previous = _client_module._swap_default_client(self)
            if self._replaced is _NOT_INSTALLED:
                self._replaced = previous
        return self

    def uninstall(self) -> None:
        """Puts back the default client that ``install()`` replaced."""
        with self._lock:
            if self._replaced is not _NOT_INSTALLED:
                _client_module._swap_default_client(self._replaced)
                self._replaced = _NOT_INSTALLED

    def __enter__(self) -> 'FakeTouchque':
        return self.install()

    def __exit__(self, *exc: Any) -> None:
        self.uninstall()

    # ── the API, in memory ───────────────────────────────────────────────

    def _pick(self, request_id: Optional[str]) -> Dict[str, Any]:
        r = self._find(request_id) if request_id else (self.requests[-1] if self.requests else None)
        if r is None:
            raise LookupError(f'FakeTouchque: no approval request {request_id}' if request_id
                              else 'FakeTouchque: no approval request yet')
        return r

    def _find(self, request_id: Optional[str]) -> Optional[Dict[str, Any]]:
        return next((r for r in self.requests if r['id'] == request_id), None)

    def _answer(self, method: str, url: str, body: Any) -> _Answer:
        path = urlsplit(url).path
        with self._lock:
            self.calls.append({'method': method, 'path': path, 'body': body})
            for route_method, pattern, handler in _ROUTES:
                m = pattern.fullmatch(path) if route_method == method else None
                if m:
                    return handler(self, body if isinstance(body, dict) else {}, *(unquote(g) for g in m.groups()))
            return 404, {'error': f'FakeTouchque does not answer {method} {path}'}

    def _login_request(self, b: Dict[str, Any]) -> _Answer:
        user = b.get('externalUsername')
        if not self.is_linked(user):
            return 404, {'code': 'device_not_linked', 'error': 'No linked device found for this user'}
        self._seq += 1
        number = '47' if self.number_match or b.get('requireNumberMatch') is True else None
        r = {
            'id': '00000000-0000-4000-8000-%012d' % self._seq, 'user': user, 'type': b.get('type'),
            'referenceId': b.get('referenceId'), 'details': b.get('details'), 'status': 'PENDING',
            'consumed': False, 'challengeCode': number, 'confirmedVia': None,
            'expiresAt': _iso_from_ms(_now_ms() + 30000),
        }
        if self.auto_approve:
            r['status'], r['confirmedVia'] = 'CONFIRMED', 'DEVICE'
        self.requests.append(r)
        return 200, {'message': 'Request sent', 'requestId': r['id'], 'challengeCode': number,
                     'expiresAt': r['expiresAt'], 'caseCode': 'K7P-2QX'}

    @staticmethod
    def _approval(r: Dict[str, Any]) -> Dict[str, Any]:
        passkey = r['confirmedVia'] == 'WEBAUTHN'
        return {
            'externalUsername': r['user'], 'type': r['type'], 'referenceId': r['referenceId'], 'details': r['details'],
            'confirmedVia': r['confirmedVia'],
            'assurance': {'phishingResistant': passkey, 'method': 'passkey' if passkey else 'push'}
            if r['status'] == 'CONFIRMED' else None,
            'provisional': False, 'reconfirmedAt': None, 'revoked': False, 'revokeReason': None,
        }

    def _login_status(self, b: Dict[str, Any], request_id: str) -> _Answer:
        r = self._find(request_id)
        if r is None:
            return 404, {'code': 'not_found'}
        # Like the API: the request's live expiry, which the guard's polls carry.
        return 200, {'status': r['status'], 'consumed': r['consumed'], 'expiresAt': r['expiresAt'],
                     **self._approval(r)}

    def _login_consume(self, b: Dict[str, Any], request_id: str) -> _Answer:
        r = self._find(request_id)
        if r is None:
            return 404, {'code': 'not_found'}
        if r['status'] != 'CONFIRMED':
            return 409, {'code': {'REJECTED': 'rejected', 'EXPIRED': 'expired'}.get(r['status'], 'not_approved')}
        if r['consumed']:
            return 409, {'code': 'already_used'}
        r['consumed'] = True
        return 200, {'consumed': True, 'requestId': r['id'], 'approvalProof': None, **self._approval(r)}

    def _new_secret(self, user: str, b: Dict[str, Any]) -> Dict[str, Any]:
        self._seq += 1
        now = _now_ms()
        expires = now + self.secret_ttl_ms
        self._pending[user] = expires
        secret = 'S%d' % self._seq
        # Where the QR was asked for (2FA setup context): kept with the secret, never in the QR.
        self.setups.append({'user': user, 'secret': secret, 'clientIp': b.get('clientIp'),
                            'userAgent': b.get('userAgent'), 'requestedAt': _iso_from_ms(now),
                            'expiresAt': _iso_from_ms(expires)})
        return {'secret': secret, 'qrCodeDataUrl': 'data:image/png;base64,QR%d-%s' % (self._seq, user),
                'externalUsername': user, 'expiresAt': _iso_from_ms(expires), 'ttlMs': self.secret_ttl_ms,
                'recoveryCodes': ['r%d' % self._seq]}

    def _generate_secret(self, b: Dict[str, Any]) -> _Answer:
        user = b.get('externalUsername')
        if self.is_linked(user):
            return 409, {'error': 'already linked'}
        if user in self._pending:
            return 409, {'error': 'Secret already generated'}
        return 200, self._new_secret(user, b)

    def _reset_secret(self, b: Dict[str, Any]) -> _Answer:
        # Like the API: a reset unlinks the phone (the guard only resets a user it found not linked).
        user = b.get('externalUsername')
        self._unlinked.add(user)
        self._linked.discard(user)
        return 200, {'success': True, **self._new_secret(user, b)}

    def _validate_secret(self, b: Dict[str, Any]) -> _Answer:
        # The phone after scanning the QR. Like the API: 400 without a secret, 404 one never made (or replaced by a
        # newer one for its user), 409 its user linked since, 410 expired, else valid with the brand and setupContext.
        secret = b.get('secret')
        if not secret:
            return 400, {'error': 'secret is required'}
        setup = next((s for s in reversed(self.setups) if s['secret'] == secret), None)
        newest = next((s for s in reversed(self.setups) if setup and s['user'] == setup['user']), None)
        if setup is None or newest is not setup:
            return 404, {'valid': False, 'message': 'Secret not found - invalid code', 'reason': 'not_found'}
        if self.is_linked(setup['user']):
            used_at = self._used_at.setdefault(secret, _iso_from_ms(_now_ms()))  # when the fake first saw it linked
            return 409, {'valid': False, 'message': 'This secret has already been used', 'reason': 'already_used',
                         'usedAt': used_at}
        if _now_ms() > (_iso_ms(setup['expiresAt']) or 0):
            return 410, {'valid': False, 'message': 'Secret has expired - generate a new code', 'reason': 'expired',
                         'expiredAt': setup['expiresAt']}
        return 200, {'valid': True, 'externalUsername': setup['user'], 'integrationId': 'int-1',
                     'integration': dict(_INTEGRATION), 'setupContext': _setup_context_of(setup)}

    def _get_user(self, b: Dict[str, Any], user: str) -> _Answer:
        linked = self.is_linked(user)
        if not linked and user not in self._pending:
            return 404, {'error': 'not found'}
        return 200, {'externalUsername': user, 'deviceId': 'dev-1' if linked else None, 'used': linked,
                     'frozen': False, 'device': None}

    def _offline_challenge(self, b: Dict[str, Any]) -> _Answer:
        rid = b.get('requestId')
        follows = self._find(rid) if rid else None
        if rid and follows is None:
            return 404, {'error': 'request_not_found'}
        if follows and follows['status'] == 'REJECTED':
            return 409, {'error': 'request_rejected'}
        self._seq += 1
        challenge_id = 'ch-%d' % self._seq
        self._challenges[challenge_id] = {'user': b.get('externalUsername'), 'type': b.get('type'), 'used': False,
                                          'requestId': rid}
        out = {'challengeId': challenge_id, 'qr': 'TQ2.fake', 'qrDataUrl': 'data:image/png;base64,OFFLINE',
               'expiresAt': _iso_from_ms(_now_ms() + 120000), 'expiresInSeconds': 120, 'totpAvailable': True}
        number = (follows or {}).get('challengeCode') or ('47' if b.get('requireNumberMatch') is True else None)
        if number:
            out['challengeCode'] = number
        return 200, out

    def _rejected(self, request_id: Optional[str]) -> bool:
        r = self._find(request_id) if request_id else None
        return bool(r and r['status'] == 'REJECTED')

    def _offline_verify(self, b: Dict[str, Any]) -> _Answer:
        ch = self._challenges.get(b.get('challengeId'))
        if ch is None:
            return 404, {'approved': False, 'reason': 'unknown_challenge'}
        if ch['used']:
            return 410, {'approved': False, 'reason': 'used'}
        if self._rejected(ch['requestId']):
            return 410, {'approved': False, 'reason': 'request_rejected'}
        if b.get('code') != self.offline_code:
            return 401, {'approved': False, 'reason': 'invalid_code', 'attemptsLeft': 4}
        ch['used'] = True
        return 200, {'approved': True, 'challengeId': b.get('challengeId'), 'externalUsername': ch['user'],
                     'type': ch['type']}

    def _offline_totp_verify(self, b: Dict[str, Any]) -> _Answer:
        if self._rejected(b.get('requestId')):
            return 410, {'approved': False, 'reason': 'request_rejected'}
        if b.get('code') != self.totp_code:
            return 401, {'approved': False, 'reason': 'invalid_code'}
        return 200, {'approved': True, 'externalUsername': b.get('externalUsername')}

    def _risk_check(self, b: Dict[str, Any]) -> _Answer:
        # Silent sign-ins: the fake always asks the phone.
        reason = ({'code': 'new_browser', 'text': 'This browser has not been approved on the phone for this account'}
                  if b.get('browserProof') else
                  {'code': 'no_browser_key', 'text': 'No device-bound browser key was presented'})
        return 200, {'prompt': True, 'reasons': [reason], 'assurance': 'normal', 'silentMode': 'enforce',
                     'caseCode': 'CHK-2QX'}

    def _define_action_type(self, b: Dict[str, Any]) -> _Answer:
        self._seq += 1
        defined = {'id': 'at-%d' % self._seq, 'type': b.get('type'), 'name': b.get('name'),
                   'description': b.get('description') or '', 'critical': bool(b.get('critical')), 'active': True}
        self._action_types[b.get('type')] = defined
        return 200, defined

    def _list_action_types(self, b: Dict[str, Any]) -> _Answer:
        return 200, list(self._action_types.values())


# What the fake answers: method, path pattern, handler(fake, body, *path parts).
_ROUTES = tuple(
    (method, re.compile(pattern), handler) for method, pattern, handler in (
        ('POST', r'/login/request', FakeTouchque._login_request),
        ('GET', r'/login/status/([^/]+)', FakeTouchque._login_status),
        ('POST', r'/login/([^/]+)/consume', FakeTouchque._login_consume),
        ('POST', r'/auth/generate-secret', FakeTouchque._generate_secret),
        ('POST', r'/auth/secret/reset', FakeTouchque._reset_secret),
        ('POST', r'/auth/secret/validate', FakeTouchque._validate_secret),
        ('GET', r'/users/([^/]+)', FakeTouchque._get_user),
        ('POST', r'/offline/challenge', FakeTouchque._offline_challenge),
        ('POST', r'/offline/verify', FakeTouchque._offline_verify),
        ('POST', r'/offline/totp/verify', FakeTouchque._offline_totp_verify),
        ('POST', r'/risk/check', FakeTouchque._risk_check),
        ('POST', r'/action-types', FakeTouchque._define_action_type),
        ('GET', r'/action-types', FakeTouchque._list_action_types),
    )
)


class _FakeTransport(HttpClient):
    """The HTTP client of a ``FakeTouchque``: every call goes to the fake as
    JSON, and comes back as JSON or as the exception the real client raises."""

    def __init__(self, fake: FakeTouchque):
        super().__init__(fake.config)
        self._fake = fake

    def _call(self, method: str, endpoint: str, body: Any) -> Dict[str, Any]:
        sent = json.loads(json.dumps(body)) if body is not None else {}
        status, data = self._fake._answer(method, endpoint, sent)
        return self._result(status, json.loads(json.dumps(data)))

    def post(self, endpoint: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._call('POST', endpoint, body)

    def _send(self, method: str, endpoint: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._call(method, endpoint, body)

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._call('GET', endpoint + _build_query(params), None)

    def get_text(self, endpoint: str) -> str:
        return json.dumps(self._call('GET', endpoint, None))

    def delete(self, endpoint: str) -> Dict[str, Any]:
        return self._call('DELETE', endpoint, None)


#: Another name for ``FakeTouchque``.
FakeClient = FakeTouchque
