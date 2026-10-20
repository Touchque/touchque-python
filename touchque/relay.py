"""
Framework-agnostic relay: the routes every partner backend needs for classic
push 2FA, offline codes and passkeys, so you don't hand-write them. The Flask,
FastAPI and Django adapters in ``touchque.contrib`` are thin wrappers over
``RelayHandler.handle()``. Same routes and behaviour as the Node SDK's
``touchqueRouter``.

Routes (relative to wherever you mount the relay):

  POST   /enroll/start                    (auth required) -> generate_secret response
  GET    /enroll/status                   (auth required) -> {linked, used, deviceId}
  POST   /login                           (pre-auth) -> 202 {touchque: step, token} until approved
  POST   /offline/challenge               (pre-auth, body.externalUsername) -> QR for a phone with no internet
  POST   /offline/verify                  (pre-auth, body.challengeId/code)
  POST   /offline/totp                    (pre-auth, body.externalUsername/code) -> time-based code fallback
  POST   /passkey/authenticate/options    (pre-auth, body.email; none = any passkey, for autofill)
  POST   /passkey/authenticate/verify     (pre-auth, body.attemptId/response)
  POST   /passkey/login/options           (pre-auth, body.requestId - approve a pending 2FA request)
  POST   /passkey/login/verify            (pre-auth, body.requestId/response)
  POST   /passkey/register/options        (auth required)
  POST   /passkey/register/verify         (auth required)
  GET    /passkey/credentials             (auth required)
  DELETE /passkey/credentials/<id>        (auth required)

"Auth required" routes answer 401 ``UNAUTHORIZED_FOR_2FA`` when
``get_user_id(request)`` returns nothing.

Pre-auth routes are rate limited per IP and per username by default
(``rate_limit``), and TouchQue itself caps approval pushes per user. Set
``get_login_user`` so POST /login and the offline routes only work for a user
who already passed YOUR first factor (password step): then nobody can make
TouchQue push to, or lock out, an arbitrary user through your server. The
offline routes are OFF until you do (or explicitly opt out with
``allow_offline_without_first_factor=True``): with the username taken from
the body, anyone could burn a user's offline attempts and lock them out.
"""
import inspect
import logging
import re
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Tuple, Union

from .exceptions import (
    TouchQueAPIException, TouchQuePasskeyRequiredError, TouchQueRejectedException, TouchQueTimeoutException,
)
from .guard import SilentSignIn, guard_input_from_headers, is_status_poll, run_guard, silent_input_from_headers
from .rate_limiter import FixedWindowLimiter

# A 1.5 s poll for a 2-minute push is 80 requests: one attempt's worth of polls.
POLLS_PER_ATTEMPT = 10
#: Reserved action: the approval on the phone that unlocks adding a passkey.
PASSKEY_ENROLL_ACTION = 'PASSKEY_ENROLL'

if TYPE_CHECKING:
    from .client import TouchQue

logger = logging.getLogger('touchque')

#: Every (method, sub-path) the relay answers. ``<id>`` is one path segment.
RELAY_ROUTES = (
    ('POST', '/enroll/start'),
    ('GET', '/enroll/status'),
    ('POST', '/login'),
    ('POST', '/offline/challenge'),
    ('POST', '/offline/verify'),
    ('POST', '/offline/totp'),
    ('POST', '/passkey/authenticate/options'),
    ('POST', '/passkey/authenticate/verify'),
    ('POST', '/passkey/login/options'),
    ('POST', '/passkey/login/verify'),
    ('POST', '/passkey/register/options'),
    ('POST', '/passkey/register/verify'),
    ('GET', '/passkey/credentials'),
    ('DELETE', '/passkey/credentials/<id>'),
)

_CREDENTIAL_PATH = re.compile(r'^/passkey/credentials/([^/]+)$')

_warned_pre_auth = False


class RelayResponse:
    """What the adapter should send: ``status``, a JSON-serialisable ``body``
    and extra ``headers`` (``Retry-After``, ``Cache-Control``)."""

    __slots__ = ('status', 'body', 'headers')

    def __init__(self, status: int, body: Any, headers: Optional[Dict[str, str]] = None):
        self.status = status
        self.body = body
        self.headers = headers or {}

    def __repr__(self) -> str:
        return 'RelayResponse(status=%r, body=%r, headers=%r)' % (self.status, self.body, self.headers)


class _Done(BaseException):
    """Internal: carries an early response out of a helper. A BaseException so the
    routes' ``except Exception`` error mapping never swallows it."""

    def __init__(self, response: RelayResponse):
        super().__init__()
        self.response = response


def _json(body: Any, status: int = 200, headers: Optional[Dict[str, str]] = None) -> RelayResponse:
    return RelayResponse(status, body, headers)


def _field(body: Any, name: str) -> Any:
    return body.get(name) if isinstance(body, dict) else None


def _non_empty_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    """Drops ``None`` values (JSON.stringify drops ``undefined`` the same way)."""
    return {k: v for k, v in d.items() if v is not None}


def _auth_result_error(error: BaseException) -> RelayResponse:
    """Same status-code mapping as the step-up guard adapters - kept in sync."""
    if isinstance(error, TouchQueRejectedException):
        return _json({'error': '2FA_REJECTED', 'message': 'User rejected the 2FA request on their device.'}, 403)
    if isinstance(error, TouchQuePasskeyRequiredError):
        return _json({'error': 'PASSKEY_REQUIRED', 'requestId': error.request_id,
                      'message': 'Approve this sign-in with your passkey.'}, 409)
    if isinstance(error, TouchQueTimeoutException):
        return _json({'error': '2FA_TIMEOUT', 'message': 'User did not respond to the 2FA request in time.'}, 408)
    # A real API error (e.g. 404 "no linked device for this user") still carries a useful
    # client-range status + message - surface it. Only a network failure or an unexpected
    # error falls through to 503.
    status = getattr(error, 'status', None)
    if isinstance(status, int) and not isinstance(status, bool) and status < 500:
        data = getattr(error, 'data', None)
        data = data if isinstance(data, dict) else {}
        return _json({'error': data.get('error') or data.get('message') or str(error) or 'request_failed'}, status)
    logger.error('[TouchQue Relay Error] %r', error)
    return _json({'error': '2FA_UNAVAILABLE', 'message': 'The 2FA verification service is temporarily unavailable.'},
                 503)


def _relay_error(error: BaseException) -> RelayResponse:
    """For plain relay routes: a client-range TouchQue status is forwarded with its
    machine-readable code only - never TouchQue's internal message text - anything
    else becomes 502."""
    if isinstance(error, TouchQueAPIException) and error.status is not None and error.status < 500:
        data = error.data if isinstance(error.data, dict) else {}
        return _json({'error': error.code or data.get('error') or 'request_failed'}, error.status)
    return _json({'error': 'relay_error'}, 502)


class RelayHandler:
    """
    The relay routes, independent of any web framework.

    ``client``: a ``TouchQue`` instance (default: ``get_default_client()``).

    ``get_user_id(request)``: REQUIRED. The signed-in user's identifier for
    the "auth required" routes (enrollment, passkey registration and
    management). Return ``None`` when nobody is signed in - the route answers 401.

    ``get_login_user(request)``: STRONGLY RECOMMENDED. The user who already
    passed your first factor (e.g. the password step stored in the session).
    When set, POST /login, /offline/challenge and /offline/totp act for this
    user and IGNORE any username in the request body; when it returns nothing
    they answer 401 ``FIRST_FACTOR_REQUIRED``.

    ``rate_limit``: built-in limits for the pre-auth routes, per client IP and
    per username, per route. On by default (20 per IP and 5 per username per
    minute). A dict with ``window_ms`` / ``per_ip`` / ``per_user`` overrides
    them; ``False`` turns the limiter off (if you already limit in front).
    The adapters use the framework's client address - make sure it is the
    real client behind a proxy (e.g. werkzeug ``ProxyFix``).

    ``allow_offline_without_first_factor``: the offline routes answer 403
    ``OFFLINE_REQUIRES_FIRST_FACTOR`` unless ``get_login_user`` is set. Set
    this to ``True`` only if they really should trust the username in the body.

    ``action_type``: action type for POST /login and the offline routes. Default ``'LOGIN'``.

    ``get_details(request)``: optional transaction context shown on the
    approval screen. Build it from server-side state - the request body is
    attacker-controlled.

    ``silent_sign_in``: silent sign-ins for POST /login (default off). When
    on, a new sign-in whose browser sent its device-bound key proof
    (``X-TouchQue-Browser``, added by ``@touchque/web`` with
    ``browserKey: true``) first asks TouchQue whether anything about it is
    new. If nothing is, it succeeds at once with no push (``on_authenticated``
    gets ``via: 'silent'``; the answer's ``assurance['method']`` is
    ``'silent'``). Otherwise, and on any error, the usual push starts and its
    approval makes the browser known. Set ``get_login_user`` too: the user
    must have passed your password step. ``{'max_age_seconds': n}`` sets your
    own limit on how long ago the last phone approval in that browser may be.

    ``on_authenticated(request, response, info)``: called right before the
    relay sends its own success response for POST /login (once approved),
    /offline/verify, /offline/totp, /passkey/authenticate/verify and
    /passkey/login/verify. ``info`` is ``{"externalUsername", "requestId"
    (when known), "via": "login" | "passkey" | "offline" | "offline-totp" |
    "silent"}``. Open your session here: mutate ``request`` (session) or
    ``response`` (``set_cookie``); do not build a response yourself.

    Callbacks receive the framework's native request object.
    """

    def __init__(
        self,
        client: Optional['TouchQue'] = None,
        get_user_id: Optional[Callable[[Any], Optional[str]]] = None,
        get_login_user: Optional[Callable[[Any], Optional[str]]] = None,
        rate_limit: Union[Dict[str, int], bool, None] = None,
        allow_offline_without_first_factor: bool = False,
        action_type: str = 'LOGIN',
        get_details: Optional[Callable[[Any], Any]] = None,
        on_authenticated: Optional[Callable[[Any, Any, Dict[str, Any]], Any]] = None,
        silent_sign_in: SilentSignIn = False,
    ):
        global _warned_pre_auth
        if get_user_id is None:
            raise TypeError('RelayHandler: get_user_id is required')
        self._client = client
        self.get_user_id = get_user_id
        self.get_login_user = get_login_user
        self.action_type = action_type
        self.get_details = get_details
        self.on_authenticated = on_authenticated
        self.silent_sign_in = silent_sign_in
        if rate_limit is False:
            self.limiter = None  # type: Optional[FixedWindowLimiter]
        else:
            opts = rate_limit if isinstance(rate_limit, dict) else {}
            self.limiter = FixedWindowLimiter(
                window_ms=opts.get('window_ms'), per_ip=opts.get('per_ip'), per_user=opts.get('per_user'))
        self.offline_enabled = bool(get_login_user) or allow_offline_without_first_factor is True

        if not get_login_user and not _warned_pre_auth:
            _warned_pre_auth = True
            logger.warning(
                '[TouchQue] RelayHandler: POST /login takes the username from the request body%s. Set '
                '`get_login_user` to bind them to your first factor (password step) so they cannot be used '
                'against arbitrary users.',
                ', and so do the offline routes' if self.offline_enabled
                else '; the offline routes are disabled until you set it')

    @property
    def client(self) -> 'TouchQue':
        if self._client is None:
            from .client import get_default_client
            self._client = get_default_client()
        return self._client

    # ── entry point ─────────────────────────────────────────────────────
    def handle(
        self,
        method: str,
        path: str,
        body: Any = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        get_header: Optional[Callable[[str], Optional[str]]] = None,
        request: Any = None,
        response: Any = None,
        run_async: Optional[Callable[[Any], Any]] = None,
    ) -> Optional[RelayResponse]:
        """Runs one relay route.

        ``method``/``path``: HTTP method and the sub-path below the mount
        point (e.g. ``'/login'``). ``body``: the parsed JSON body (or None).
        ``get_header``: case-insensitive header getter. ``request`` /
        ``response``: the framework's native objects, passed to the callbacks
        as-is. ``run_async``: how to resolve an awaitable returned by a
        callback (the FastAPI adapter supplies it).

        Returns the response to send, or ``None`` when no route matches.
        """
        ctx = _Ctx(self, (method or '').upper(), _norm_path(path), body, ip, user_agent,
                   get_header or (lambda name: None), request, response, run_async)
        try:
            return ctx.dispatch()
        except _Done as done:
            return done.response


def _norm_path(path: str) -> str:
    return '/' + (path or '').strip('/')


class _Ctx:
    """One request through the relay."""

    def __init__(self, h: RelayHandler, method: str, path: str, body: Any, ip: Optional[str],
                 user_agent: Optional[str], get_header: Callable[[str], Optional[str]], request: Any,
                 response: Any, run_async: Optional[Callable[[Any], Any]]):
        self.h = h
        self.method = method
        self.path = path
        self.body = body
        self.ip = ip
        self.user_agent = user_agent
        self.get_header = get_header
        self.request = request
        self.response = response
        self.run_async = run_async

    # ── helpers ─────────────────────────────────────────────────────────
    def call(self, fn: Callable, *args: Any) -> Any:
        result = fn(*args)
        if inspect.isawaitable(result):
            if self.run_async is None:
                if inspect.iscoroutine(result):
                    result.close()
                raise TypeError('TouchQue relay: an async callback needs an async adapter (touchque.contrib.fastapi)')
            result = self.run_async(result)
        return result

    def require_user_id(self) -> str:
        user_id = self.call(self.h.get_user_id, self.request)
        if not user_id:
            raise _Done(_json({
                'error': 'UNAUTHORIZED_FOR_2FA',
                'message': 'Could not find user ID in request. Put your own auth in front of this relay.',
            }, 401))
        return user_id

    def offline_allowed(self) -> None:
        if not self.h.offline_enabled:
            raise _Done(_json({
                'error': 'OFFLINE_REQUIRES_FIRST_FACTOR',
                'message': 'Offline sign-in is disabled: configure get_login_user (or '
                           'allow_offline_without_first_factor) on the TouchQue relay.',
            }, 403))

    def allow(self, route: str, user: Optional[str] = None, ip_factor: int = 1) -> None:
        """Answers 429 when this IP or this user is over the limit for ``route``."""
        limiter = self.h.limiter
        if limiter is None:
            return
        ip_wait = limiter.hit('ip|%s|%s' % (route, self.ip or 'unknown'), limiter.per_ip * ip_factor)
        user_wait = limiter.hit('user|%s|%s' % (route, user), limiter.per_user) if user else 0
        wait = max(ip_wait, user_wait)
        if not wait:
            return
        raise _Done(_json({'error': 'RATE_LIMITED', 'message': 'Too many attempts. Try again later.',
                           'retryAfter': wait}, 429, {'Retry-After': str(wait)}))

    def expected_login_user(self) -> Optional[str]:
        return self.call(self.h.get_login_user, self.request)

    def login_user(self, body_field: str) -> str:
        """Who a pre-auth route acts for: the first-factor user when configured, otherwise the typed username."""
        if self.h.get_login_user:
            u = self.expected_login_user()
            if not u:
                raise _Done(_json({'error': 'FIRST_FACTOR_REQUIRED', 'message': 'Sign in with your password first.'},
                                  401))
            return str(u).lower()
        typed = str(_field(self.body, body_field) or '').lower()
        if not typed:
            raise _Done(_json({'error': 'externalUsername_required'}, 400))
        return typed

    def details(self) -> Any:
        return self.call(self.h.get_details, self.request) if self.h.get_details else None

    def authenticated(self, info: Dict[str, Any]) -> None:
        if self.h.on_authenticated:
            self.call(self.h.on_authenticated, self.request, self.response, info)

    def same_user(self, expected: Any, actual: str) -> bool:
        return bool(expected) and str(expected).lower() == actual.lower()

    # ── routing ─────────────────────────────────────────────────────────
    def dispatch(self) -> Optional[RelayResponse]:
        routes = {
            ('POST', '/enroll/start'): self.enroll_start,
            ('GET', '/enroll/status'): self.enroll_status,
            ('POST', '/login'): self.login,
            ('POST', '/offline/challenge'): self.offline_challenge,
            ('POST', '/offline/verify'): self.offline_verify,
            ('POST', '/offline/totp'): self.offline_totp,
            ('POST', '/passkey/authenticate/options'): self.passkey_authenticate_options,
            ('POST', '/passkey/authenticate/verify'): self.passkey_authenticate_verify,
            ('POST', '/passkey/login/options'): self.passkey_login_options,
            ('POST', '/passkey/login/verify'): self.passkey_login_verify,
            ('POST', '/passkey/register/options'): self.passkey_register_options,
            ('POST', '/passkey/register/verify'): self.passkey_register_verify,
            ('GET', '/passkey/credentials'): self.passkey_credentials,
        }  # type: Dict[Tuple[str, str], Callable[[], RelayResponse]]
        route = routes.get((self.method, self.path))
        if route is not None:
            return route()
        m = _CREDENTIAL_PATH.match(self.path)
        if m and self.method == 'DELETE':
            return self.passkey_credential_delete(m.group(1))
        return None

    # ── classic push 2FA: enrollment ────────────────────────────────────
    def enroll_start(self) -> RelayResponse:
        user_id = self.require_user_id()
        tq = self.h.client
        try:
            return _json(tq.auth.generate_secret(user_id))
        except Exception as error:  # noqa: BLE001 - mapped below, like the Node router
            # 409: either a QR was issued and not scanned yet (safe to issue a new one - no
            # phone to lose), or a phone is ALREADY linked. Replacing a linked phone must never
            # happen from a plain session: that is exactly how an attacker with a stolen
            # password would swap in their own phone.
            if getattr(error, 'status', None) == 409:
                try:
                    current = tq.auth.get_user(user_id)
                    if current.get('used') or current.get('deviceId'):
                        return _json({'error': 'already_linked',
                                      'message': 'A phone is already linked to this account.'}, 409)
                    return _json(tq.auth.reset_secret(user_id))
                except Exception as retry_error:  # noqa: BLE001
                    return _relay_error(retry_error)
            return _relay_error(error)

    def enroll_status(self) -> RelayResponse:
        user_id = self.require_user_id()
        try:
            u = self.h.client.auth.get_user(user_id)
            out = {'linked': bool(u.get('used') and u.get('deviceId'))}  # type: Dict[str, Any]
            for key in ('used', 'deviceId'):
                if key in u:
                    out[key] = u[key]
            return _json(out)
        except Exception as error:  # noqa: BLE001
            if getattr(error, 'status', None) == 404:
                return _json({'linked': False, 'used': False, 'deviceId': None})
            return _relay_error(error)

    # ── classic push 2FA: login ─────────────────────────────────────────
    def login(self) -> RelayResponse:
        external_username = self.login_user('externalUsername')
        details = self.details()
        headers_in = guard_input_from_headers(self.get_header)
        # Polling an approval already sent is not a new attempt: it has its own,
        # larger per-IP budget and never uses the user's push budget.
        if is_status_poll(self.h.client, external_username, self.h.action_type, details=details, **headers_in):
            self.allow('login-poll', ip_factor=POLLS_PER_ATTEMPT)
        else:
            self.allow('login', external_username)
        # Same two-phase contract as the step-up guard: 202 with the step (matching number /
        # first-time QR / offline QR) until approved; the page re-sends with X-TouchQue-Token.
        result = run_guard(
            self.h.client, external_username, self.h.action_type,
            details=details, ip=self.ip, user_agent=self.user_agent,
            # Pre-auth: a typed username proves nothing, so no linking QR unless
            # get_login_user ties this route to the password step.
            enroll=bool(self.h.get_login_user),
            **headers_in,
            **silent_input_from_headers(self.h.silent_sign_in, self.get_header)
        )
        approved = result.get('approved')
        if not approved:
            headers = {}
            retry = (result['body'].get('touchque') or {}).get('retryAfter')
            if retry:
                headers['Retry-After'] = str(retry)
            headers['Cache-Control'] = 'no-store'
            return _json(result['body'], result['status'], headers)
        try:
            confirmed = approved.get('confirmedVia')
            via = 'offline-totp' if confirmed == 'OFFLINE_TOTP' else 'offline' if confirmed == 'OFFLINE_CODE' \
                else 'silent' if confirmed == 'SILENT' else 'login'
            self.authenticated({'externalUsername': external_username, 'requestId': approved.get('requestId'),
                                'via': via})
            return _json(_compact({'status': 'success', 'requestId': approved.get('requestId'),
                                   'assurance': approved.get('assurance')}))
        except Exception as error:  # noqa: BLE001
            return _auth_result_error(error)

    # ── offline sign: QR challenge / typed code ─────────────────────────
    # The username used for on_authenticated is the one TouchQue returns for the
    # challenge/code, never the one in the request body.
    def offline_challenge(self) -> RelayResponse:
        self.offline_allowed()
        external_username = self.login_user('externalUsername')
        self.allow('offline-challenge', external_username)
        try:
            # `requestId` (the push this QR follows) makes a phone-side rejection kill the QR
            # and carries the number.
            c = self.h.client.offline.challenge(
                external_username, type=self.h.action_type, client_ip=self.ip, user_agent=self.user_agent,
                details=self.details(), request_id=_non_empty_str(_field(self.body, 'requestId')),
            )
            out = {k: c[k] for k in ('challengeId', 'qr', 'qrDataUrl', 'expiresAt', 'expiresInSeconds',
                                     'totpAvailable') if k in c}
            if c.get('challengeCode'):
                out['challengeCode'] = c['challengeCode']
            return _json(out)
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    def offline_verify(self) -> RelayResponse:
        self.offline_allowed()
        self.allow('offline-verify')
        try:
            r = self.h.client.offline.verify(str(_field(self.body, 'challengeId') or ''),
                                             str(_field(self.body, 'code') or ''))
            if not r.get('approved') or not r.get('externalUsername'):
                return _json(_compact({'approved': False, 'reason': r.get('reason'),
                                       'attemptsLeft': r.get('attemptsLeft')}),
                             401 if r.get('reason') == 'invalid_code' else 400)
            # With a first factor, the code must belong to the user who passed it.
            if self.h.get_login_user:
                if not self.same_user(self.expected_login_user(), r['externalUsername']):
                    return _json({'approved': False, 'reason': 'invalid_code'}, 401)
            self.authenticated({'externalUsername': r['externalUsername'], 'requestId': r.get('challengeId'),
                                'via': 'offline'})
            return _json(_compact({'status': 'success', 'approved': True, 'requestId': r.get('challengeId')}))
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    def offline_totp(self) -> RelayResponse:
        self.offline_allowed()
        external_username = self.login_user('externalUsername')
        self.allow('offline-totp', external_username)
        try:
            r = self.h.client.offline.verify_totp(
                external_username, str(_field(self.body, 'code') or ''), type=self.h.action_type,
                client_ip=self.ip, request_id=_non_empty_str(_field(self.body, 'requestId')),
            )
            if not r.get('approved') or not r.get('externalUsername'):
                return _json(_compact({'approved': False, 'reason': r.get('reason')}),
                             401 if r.get('reason') == 'invalid_code' else 400)
            self.authenticated({'externalUsername': r['externalUsername'], 'via': 'offline-totp'})
            return _json({'status': 'success', 'approved': True})
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    # ── passkey: passwordless sign-in ───────────────────────────────────
    def passkey_authenticate_options(self) -> RelayResponse:
        email = str(_field(self.body, 'email') or '').lower()
        self.allow('passkey-options', email or None)
        try:
            return _json(self.h.client.webauthn.primary_options(email or None))
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    def passkey_authenticate_verify(self) -> RelayResponse:
        self.allow('passkey-verify')
        try:
            r = self.h.client.webauthn.primary_verify(_field(self.body, 'attemptId'), _field(self.body, 'response'))
            if r.get('success'):
                self.authenticated({'externalUsername': r.get('externalUsername'), 'requestId': r.get('requestId'),
                                    'via': 'passkey'})
                return _json(_compact({'status': 'success', 'requestId': r.get('requestId')}))
            if r.get('requiresStepUp'):
                return _json({'requiresStepUp': True})
            return _json({'error': 'verification_failed'}, 401)
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    # ── passkey: approve an already-pending 2FA request (second factor) ─
    def passkey_login_options(self) -> RelayResponse:
        self.allow('passkey-approve')
        try:
            return _json(self.h.client.webauthn.authenticate_options(_field(self.body, 'requestId')))
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    def passkey_login_verify(self) -> RelayResponse:
        self.allow('passkey-approve')
        try:
            r = self.h.client.webauthn.authenticate_verify(_field(self.body, 'requestId'),
                                                           _field(self.body, 'response'))
            approved_user = r.get('externalUsername')
            # Open the session only for the user TouchQue says was approved. A name sent by the
            # browser is never trusted: anyone could approve their own request and claim to be
            # someone else.
            if r.get('success') and self.h.get_login_user and isinstance(approved_user, str):
                if not self.same_user(self.expected_login_user(), approved_user):
                    return _json({'error': 'verification_failed'}, 401)
            if r.get('success') and isinstance(approved_user, str) and approved_user:
                self.authenticated({'externalUsername': approved_user,
                                    'requestId': r.get('requestId') or _field(self.body, 'requestId'),
                                    'via': 'passkey'})
            return _json(r)
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    # ── passkey: enrollment / management (auth required) ────────────────
    def passkey_register_options(self) -> RelayResponse:
        """A user with a linked phone approves adding a passkey there first: a
        passkey approves requests on its own, so a stolen session of your app
        must not be able to add one. Same two-phase contract as /login: 202
        with the step (and number to show) until approved, then the options."""
        user_id = self.require_user_id()
        headers_in = guard_input_from_headers(self.get_header)
        try:
            if not headers_in.get('token'):
                try:
                    return _json(self.h.client.webauthn.register_options(user_id, discoverable=True))
                except TouchQueAPIException as error:
                    if not (error.status == 403 and error.code == 'enrollment_approval_required'):
                        raise
            if is_status_poll(self.h.client, user_id, PASSKEY_ENROLL_ACTION, **headers_in):
                self.allow('login-poll', ip_factor=POLLS_PER_ATTEMPT)
            else:
                self.allow('passkey-enroll', user_id)
            result = run_guard(self.h.client, user_id, PASSKEY_ENROLL_ACTION, ip=self.ip, user_agent=self.user_agent,
                               enroll=False, **headers_in)
            approved = result.get('approved')
            if not approved:
                headers = {'Cache-Control': 'no-store'}
                retry = (result['body'].get('touchque') or {}).get('retryAfter')
                if retry:
                    headers['Retry-After'] = str(retry)
                return _json(result['body'], result['status'], headers)
            return _json(self.h.client.webauthn.register_options(
                user_id, discoverable=True, approval_request_id=approved.get('requestId')))
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    def passkey_register_verify(self) -> RelayResponse:
        user_id = self.require_user_id()
        try:
            return _json(self.h.client.webauthn.register_verify(
                user_id, _field(self.body, 'response'), label=_field(self.body, 'label')))
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    def passkey_credentials(self) -> RelayResponse:
        user_id = self.require_user_id()
        try:
            return _json(self.h.client.webauthn.list_credentials(user_id))
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)

    def passkey_credential_delete(self, credential_id: str) -> RelayResponse:
        user_id = self.require_user_id()
        try:
            return _json(self.h.client.webauthn.delete_credential(credential_id, external_username=user_id))
        except Exception as error:  # noqa: BLE001
            return _relay_error(error)


__all__ = ['RelayHandler', 'RelayResponse', 'RELAY_ROUTES', 'FixedWindowLimiter']
