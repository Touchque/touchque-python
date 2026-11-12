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
linking, offline codes, silent sign-in checks) and defining action types,
like the shared fake API the SDKs' own tests use. Any other call raises
``TouchqueAPIException`` 404.

Because the real guard runs, the answers are the guard's own: every poll of a
waiting request carries its ``expiresAt``, and a guard that may not show a
first-time QR (``run_guard(..., enroll=False)``, the relay's ``POST /login``
without ``get_login_user``) answers a user with no phone
``{"touchque": {"state": "enroll", "reason": "enrollment_off"}}``.
"""
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
from .steps import _iso_from_ms

__all__ = ['FakeTouchque', 'FakeClient']

_Answer = Tuple[int, Any]
_NOT_INSTALLED = object()


def _now_ms() -> int:
    return int(time.time() * 1000)


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

    def _new_secret(self, user: str) -> Dict[str, Any]:
        self._seq += 1
        expires = _now_ms() + self.secret_ttl_ms
        self._pending[user] = expires
        return {'secret': 'S%d' % self._seq, 'qrCodeDataUrl': 'data:image/png;base64,QR%d-%s' % (self._seq, user),
                'externalUsername': user, 'expiresAt': _iso_from_ms(expires), 'ttlMs': self.secret_ttl_ms,
                'recoveryCodes': ['r%d' % self._seq]}

    def _generate_secret(self, b: Dict[str, Any]) -> _Answer:
        user = b.get('externalUsername')
        if self.is_linked(user):
            return 409, {'error': 'already linked'}
        if user in self._pending:
            return 409, {'error': 'Secret already generated'}
        return 200, self._new_secret(user)

    def _reset_secret(self, b: Dict[str, Any]) -> _Answer:
        # Like the API: a reset unlinks the phone (the guard only resets a user it found not linked).
        user = b.get('externalUsername')
        self._unlinked.add(user)
        self._linked.discard(user)
        return 200, {'success': True, **self._new_secret(user)}

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
