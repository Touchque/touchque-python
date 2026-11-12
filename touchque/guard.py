"""
Framework-agnostic step-up guard. The Django, FastAPI and Flask adapters in
``touchque.contrib`` are thin wrappers over ``run_guard()``.

Contract (same in every Touchque server SDK):
  1st request            -> 202 {"touchque": step, "token": ...}   show the step in your UI
  repeat with the token   -> 202 while waiting, then the protected handler runs once
  refused                 -> 403 / 408 / 423 / 429 {"touchque": {"state": ..., ...}}
  not set up / API down   -> 500 misconfigured / 503 unavailable

While the first-time QR is up, polls answer {"touchque": {"state": "enroll",
"expiresAt": ...}} without "enroll": keep showing the QR you have. A new QR
comes with enroll.qrCodeDataUrl when the old one expired.

Request headers the browser sends back:
  X-Touchque-Token         the token from the last response
  X-Touchque-Offline: 1    switch to offline approval (phone has no internet)
  X-Touchque-Code          the code from the phone (offline QR code, or with
  X-Touchque-Code-Type: totp   the rolling time-based code)
  X-Touchque-Browser       the browser's device-bound key proof (silent sign-ins,
                           read only when the adapter's ``silent_sign_in`` is on)
"""
import copy
import dataclasses
import inspect
import json
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, Optional, Union

from .exceptions import TouchqueAPIException, TouchqueConfigException, TouchqueNetworkException
from .steps import (
    LoginDetails, _iso_from_ms, _iso_ms, check, complete, details_digest, normalize_details, sign_guard_token,
    start, verify_guard_token,
)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .client import Touchque

logger = logging.getLogger('touchque')

TOKEN_TTL_MS = 10 * 60 * 1000

#: A first-time QR this close to its expiry is not kept: the next poll shows a new one.
ENROLL_QR_MARGIN_MS = 15 * 1000

#: ``error_body``: your own error shape for an adapter's refusals. It gets the
#: refusal (``status``, ``code``, ``message``, ``touchque``); see ``guard_response_body``.
ErrorBody = Callable[[Dict[str, Any]], Any]

#: ``before_start``: called right before a first-time-QR token starts anything; a
#: result it returns (``{'status', 'body'}``) is answered instead. See ``run_guard``.
BeforeStart = Callable[[], Optional[Dict[str, Any]]]

# What a refusal's ``message`` says when the guard set none, by state.
_REFUSAL_MESSAGES = {
    'rejected': 'The approval was rejected.',
    'expired': 'The approval expired. Try again.',
    'frozen': 'Too many rejected approvals. Try again later.',
    'rate_limited': 'Too many attempts. Try again later.',
}

_warned_unconfigured = False

TOKEN_HEADER = 'x-touchque-token'
OFFLINE_HEADER = 'x-touchque-offline'
CODE_HEADER = 'x-touchque-code'
CODE_TYPE_HEADER = 'x-touchque-code-type'
BROWSER_HEADER = 'x-touchque-browser'

#: A real browser proof is a few hundred characters; anything far larger is not one.
MAX_BROWSER_PROOF = 4096

#: ``silent_sign_in``: ``True``, or ``{'max_age_seconds': n}`` for your own limit
#: on the age of the last phone approval in the browser (``0`` = always ask;
#: Touchque never goes beyond its own limit, 7 days).
SilentSignIn = Union[bool, Dict[str, Any], None]


def _silent_on(option: SilentSignIn) -> bool:
    # A dict turns it on even when empty (``{}``: Touchque's own limit only).
    return isinstance(option, dict) or bool(option)


_STATUS = {
    'waiting': 202, 'enroll': 202, 'passkey_required': 202, 'offline': 202,
    'approved': 200, 'rejected': 403, 'blocked': 403, 'expired': 408, 'frozen': 423, 'rate_limited': 429,
}


def guard_input_from_headers(get: Callable[[str], Optional[str]]) -> Dict[str, Any]:
    """Reads the guard headers from any case-insensitive header getter."""
    offline = get(OFFLINE_HEADER)
    return {
        'token': get(TOKEN_HEADER) or None,
        'offline': offline in ('1', 'true'),
        'code': get(CODE_HEADER) or None,
        'code_type': get(CODE_TYPE_HEADER) or None,
    }


def silent_input_from_headers(option: SilentSignIn, get: Callable[[str], Optional[str]]) -> Dict[str, Any]:
    """The ``run_guard`` keyword arguments an adapter adds for silent sign-ins:
    the ``X-Touchque-Browser`` proof, read only when ``option`` is on."""
    if not _silent_on(option):
        return {}
    return {'silent_sign_in': option, 'browser_proof': get(BROWSER_HEADER) or None}


def is_status_poll(client: Optional['Touchque'], user: Optional[str], action: str, details: Optional[LoginDetails] = None,
                   reference_id: Optional[str] = None, token: Optional[str] = None, offline: bool = False,
                   code: Optional[str] = None, **_: Any) -> bool:
    """True when this request only polls an approval that is already on its way:
    a valid token bound to this user/action/details, still waiting (or showing
    the first-time QR while it is up: more than 15 s before its expiry), and
    no offline switch or typed code. Relays do not count it against the
    per-user push limit (with a 1.5 s poll the 6th poll was refused after
    7.5 s). The poll that renews an expiring QR, and a replayed old token,
    still count; a first-time-QR poll that starts something after all (the
    phone got linked, the QR expired meanwhile) is charged through
    ``run_guard``'s ``before_start``, so only pure link-state reads stay free.
    ``client``: as ``run_guard``'s; ``None`` is the default client, and False
    while it cannot be built (``TQ_API_KEY`` / ``TQ_API_SECRET`` not set)."""
    if not user or not token or offline or code:
        return False
    if client is None:
        client = _client_from_env()
        if client is None:
            return False
    claims = verify_guard_token(client._api_secret, token)
    if not claims or claims.get('u') != user or claims.get('a') != action \
            or claims.get('d') != details_digest(details) or claims.get('r') != (reference_id or None):
        return False
    if claims.get('st') == 'enroll':
        ee = _enroll_expiry_claim(claims)
        return ee is not None and time.time() * 1000 < ee - ENROLL_QR_MARGIN_MS
    return bool(claims.get('rid')) and claims.get('st') in ('waiting', 'passkey_required', 'offline')


def _enroll_expiry_claim(claims: Dict[str, Any]) -> Optional[int]:
    """The first-time QR's expiry (claim ``ee``, ms since the epoch) of an ``enroll`` token, or None."""
    ee = claims.get('ee')
    return int(ee) if isinstance(ee, (int, float)) and not isinstance(ee, bool) and ee > 0 else None


def run_guard(
    client: Optional['Touchque'],
    user: Optional[str],
    action: str,
    details: Optional[LoginDetails] = None,
    reference_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    token: Optional[str] = None,
    offline: bool = False,
    code: Optional[str] = None,
    code_type: Optional[str] = None,
    enroll: bool = True,
    browser_proof: Optional[str] = None,
    silent_sign_in: SilentSignIn = False,
    context: Optional[Dict[str, Any]] = None,
    before_start: Optional[BeforeStart] = None,
) -> Dict[str, Any]:
    """Runs one step of the guard. Returns either
    ``{"approved": {...}, "status": 200}`` (run your protected action) or
    ``{"status": <code>, "body": {"touchque": step, "token": ...}}``
    (send that JSON body with that status code). API errors and a missing
    setup answer 503 ``unavailable`` / 500 ``misconfigured`` instead of raising.

    ``client``: your ``Touchque``, or ``None`` for ``get_default_client()``,
    built from ``TQ_API_KEY`` / ``TQ_API_SECRET`` on first use. Without them
    the answer is 500 ``misconfigured`` (401 when ``user`` is empty), logged
    once per process.

    ``browser_proof``: the browser's device-bound key proof
    (``X-Touchque-Browser``), passed through untouched and attached to the
    push, so its approval makes the browser known.

    ``silent_sign_in`` (default off): a new attempt that carries
    ``browser_proof`` first asks Touchque (``risk.check``); when it answers
    exactly ``prompt: False`` the guard approves at once, with no push
    (``assurance['method'] == 'silent'``, ``confirmedVia == 'SILENT'``,
    ``requestId == 'silent'``, ``reasons``). Otherwise, and on any error in
    the check, the usual push starts. ``{'max_age_seconds': n}`` sets your own
    limit on how long ago the last phone approval in that browser may be.

    ``context``: for your Touchque Actions only (``event.context``).

    ``before_start``: for a rate limit in front of the guard. Called at most
    once, only for a first-time-QR token (``enroll`` with its expiry), right
    before the guard starts anything instead of keeping the QR: a silent check
    or a push now that the phone is linked, or a new QR (the old one expired,
    is about to, or is gone). Return a result (``{'status', 'body'}``) to answer
    it instead, e.g. your 429; return ``None`` to go on. The relay charges its
    per-user limit here, as for a fresh attempt.
    """
    if not user:
        return {'status': 401, 'body': {
            'touchque': {'state': 'blocked', 'reason': 'unauthenticated'},
            'error': {'code': 'unauthenticated', 'message': 'Sign in first.'},
        }}
    if client is None:
        client = _client_from_env()
        if client is None:
            return _misconfigured()
    secret = client._api_secret

    norm = normalize_details(details)
    base = {'u': user, 'a': action, 'd': details_digest(details), 'r': reference_id or None}

    def issue(step: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if norm and not step.get('details') and step.get('state') != 'blocked':
            step['details'] = norm
        claims = {**base, 'st': step['state'], 'rid': step.get('requestId'), 'n': step.get('number'),
                  'oc': (step.get('offline') or {}).get('challengeId'), 'exp': int(time.time() * 1000) + TOKEN_TTL_MS}
        if step.get('caseCode'):
            claims['cc'] = step['caseCode']  # "Why?": still shown while it waits
        qr = step.get('enroll')
        if step['state'] == 'enroll' and isinstance(qr, dict) and qr.get('qrCodeDataUrl'):
            ee = _iso_ms(qr.get('expiresAt'))
            if ee is not None:
                claims['ee'] = ee  # the first-time QR's expiry: polls keep it until then
        if extra:
            claims.update(extra)
        signed = sign_guard_token(secret, claims)
        return {'status': _STATUS[step['state']], 'body': {'touchque': step, 'token': signed}}

    try:
        claims = verify_guard_token(secret, token)
        bound = claims if claims and claims.get('u') == base['u'] and claims.get('a') == base['a'] \
            and claims.get('d') == base['d'] and claims.get('r') == base['r'] else None

        # Offline: the user typed the code from the phone.
        if bound and code and (bound.get('st') == 'offline' or code_type == 'totp'):
            is_totp = code_type == 'totp'
            if is_totp:
                res = client.offline.verify_totp(user, code, type=action, client_ip=ip, request_id=bound.get('rid'))
            else:
                res = client.offline.verify(str(bound.get('oc')), code)
            for_this = (not res.get('externalUsername') or res['externalUsername'].lower() == user.lower()) \
                and (not res.get('type') or res.get('type') == action)
            if res.get('approved') and for_this:
                method = 'offline_totp' if is_totp else 'offline_code'
                return {'status': 200, 'approved': {
                    'requestId': bound.get('oc') or 'offline-totp', 'user': user, 'action': action,
                    'assurance': {'phishingResistant': False, 'method': method},
                    'confirmedVia': 'OFFLINE_TOTP' if is_totp else 'OFFLINE_CODE', 'approvalProof': None,
                }}
            if res.get('reason') == 'invalid_code' and not is_totp:
                return issue({'state': 'offline', 'offline': {'challengeId': str(bound.get('oc')),
                                                                'attemptsLeft': res.get('attemptsLeft')}},
                             {'oc': bound.get('oc'), 'rid': bound.get('rid'), 'n': bound.get('n')})
            if res.get('reason') == 'invalid_code':
                return issue({'state': 'offline', 'reason': 'invalid_code'},
                             {'oc': bound.get('oc'), 'rid': bound.get('rid'), 'n': bound.get('n')})
            # The phone rejected the push this QR belongs to: the whole sign-in is over.
            if res.get('reason') == 'request_rejected':
                return issue({'state': 'rejected', 'requestId': bound.get('rid'), 'reason': 'request_rejected'})
            # The push now waits for a passkey (Vishing Shield): no code may finish it.
            if res.get('reason') == 'passkey_required' and bound.get('rid'):
                return issue({'state': 'passkey_required', 'requestId': bound['rid'], 'number': bound.get('n')}, {'n': bound.get('n')})
            return issue({'state': 'expired' if res.get('reason') == 'expired' else 'blocked',
                           'reason': res.get('reason') or 'offline_failed'})

        if offline:
            try:
                # Link the QR to the push it follows: a phone-side rejection kills it, and a push that
                # asked for number matching makes the QR ask for the same number.
                rid = (bound or {}).get('rid')
                ch = client.offline.challenge(user, type=action, details=norm or None, client_ip=ip,
                                              user_agent=user_agent, request_id=rid)
                offline_step = {
                    'challengeId': ch.get('challengeId'), 'qrDataUrl': ch.get('qrDataUrl'),
                    'expiresAt': ch.get('expiresAt'), 'totpAvailable': ch.get('totpAvailable'),
                }
                if ch.get('challengeCode'):
                    offline_step['challengeCode'] = ch['challengeCode']
                return issue({'state': 'offline', 'offline': offline_step},
                             {'rid': rid, 'n': ch.get('challengeCode') or (bound or {}).get('n')})
            except TouchqueAPIException as err:
                if err.status == 409 and (err.code or (err.data or {}).get('error')) == 'request_rejected':
                    return issue({'state': 'rejected', 'requestId': (bound or {}).get('rid'), 'reason': 'request_rejected'})
                # The push it would follow now waits for a passkey (Vishing Shield): no QR, run the passkey.
                if (bound or {}).get('rid') and (err.code or (err.data or {}).get('error')) == 'passkey_required':
                    return issue({'state': 'passkey_required', 'requestId': bound['rid'], 'number': bound.get('n')}, {'n': bound.get('n')})
                if err.status is not None and err.status < 500:
                    return issue({'state': 'blocked', 'reason': err.code or (err.data or {}).get('error') or 'offline_unavailable'})
                raise

        # Waiting on a push / passkey — or showing the offline QR next to a push that is still open: poll, and
        # run the action once approved. While the QR is up a phone-side REJECT ends the attempt at once.
        if bound and bound.get('rid') and bound.get('st') in ('waiting', 'passkey_required', 'offline'):
            now = check(client, bound['rid'])
            if now['state'] == 'approved':
                try:
                    approved = complete(client, bound['rid'], user, action, details, reference_id)
                    return {'status': 200, 'approved': approved}
                except TouchqueAPIException as err:
                    if err.status == 409:
                        return issue({'state': 'expired', 'reason': err.code or 'already_used'})
                    raise
            # The push behind the QR was moved to a passkey after a tap during a call (Vishing Shield):
            # the QR's code would be refused now, so switch to the passkey.
            if bound.get('st') == 'offline' and now['state'] == 'passkey_required':
                return issue({'state': 'passkey_required', 'requestId': bound['rid'], 'number': bound.get('n')}, {'n': bound.get('n')})
            if bound.get('st') == 'offline' and now['state'] in ('waiting', 'expired'):
                # Still (or no longer) pending: nothing changed for the user — keep showing the QR they have.
                return issue({'state': 'offline', 'offline': {'challengeId': str(bound.get('oc'))}},
                             {'oc': bound.get('oc'), 'rid': bound['rid'], 'n': bound.get('n')})
            if now['state'] in ('waiting', 'passkey_required'):
                waiting = {'state': now['state'], 'requestId': bound['rid'], 'number': bound.get('n')}
                if bound.get('cc'):
                    waiting['caseCode'] = bound['cc']
                return issue(waiting, {'n': bound.get('n')})
            return issue({'state': now['state'], 'requestId': bound['rid']})

        # The first-time QR is on screen: while the phone is not linked and the QR still works, answer
        # without a new one (each new QR would replace the one being scanned, and its recovery codes).
        ee = _enroll_expiry_claim(bound) if bound and bound.get('st') == 'enroll' else None
        if ee is not None:
            if not _linked_or_qr_gone(client, user) and time.time() * 1000 < ee - ENROLL_QR_MARGIN_MS:
                return issue({'state': 'enroll', 'expiresAt': _iso_from_ms(ee)}, {'ee': ee})
            # About to start (a push now that the phone is linked, or a new QR): a rate limit in front of the
            # guard charges it here like a fresh attempt, so a replayed token cannot start on a poll budget.
            if before_start is not None:
                answer = before_start()
                if answer is not None:
                    return answer

        # Anything else (no/foreign token, enrollment finished, the QR expired, new attempt): start.
        proof = browser_proof if isinstance(browser_proof, str) and browser_proof \
            and len(browser_proof) <= MAX_BROWSER_PROOF else None
        if proof and _silent_on(silent_sign_in):
            silent = _silent_approval(client, user, action, proof, ip, user_agent, silent_sign_in, context)
            if silent:
                return {'status': 200, 'approved': silent}
        return issue(start(client, action, user, details=norm or None, reference_id=reference_id, ip=ip,
                           user_agent=user_agent, enroll=enroll, browser_proof=proof, context=context))
    except TouchqueConfigException as err:
        logger.error('[Touchque] %s', err)
        return _misconfigured()
    except (TouchqueNetworkException, TouchqueAPIException) as err:
        logger.error('[Touchque] approval failed: %s: %s', type(err).__name__, err)
        return {'status': 503, 'body': {
            'touchque': {'state': 'blocked', 'reason': 'unavailable'},
            'error': {'code': 'unavailable', 'message': 'Two-factor approval is temporarily unavailable.'},
        }}


def _misconfigured() -> Dict[str, Any]:
    return {'status': 500, 'body': {
        'touchque': {'state': 'blocked', 'reason': 'misconfigured'},
        'error': {'code': 'misconfigured', 'message': 'Two-factor approval is not configured correctly.'},
    }}


def _client_from_env() -> Optional['Touchque']:
    """``get_default_client()``, or None (logged once per process) when it
    cannot be built: TQ_API_KEY / TQ_API_SECRET missing or invalid."""
    global _warned_unconfigured
    from .client import get_default_client
    try:
        return get_default_client()
    except TouchqueConfigException as err:
        if not _warned_unconfigured:
            _warned_unconfigured = True
            if not os.environ.get('TQ_API_KEY') or not os.environ.get('TQ_API_SECRET'):
                logger.error('[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: '
                             'routes guarded by Touchque answer 500 misconfigured.')
            else:
                logger.error('[Touchque] %s', err)
        return None


def _linked_or_qr_gone(client: 'Touchque', user: str) -> bool:
    """Whether the user linked a phone (``used``, or a ``deviceId``) or their
    first-time QR is gone (404). Other API errors raise, as any in the guard."""
    try:
        current = client.auth.get_user(user)
    except TouchqueAPIException as err:
        if err.status == 404:
            return True
        raise
    return bool(current.get('used') or current.get('deviceId'))


def _step_of(result: Dict[str, Any]) -> Dict[str, Any]:
    body = result.get('body')
    step = body.get('touchque') if isinstance(body, dict) else None
    return step if isinstance(step, dict) else {}


def guard_response_headers(result: Dict[str, Any]) -> Dict[str, str]:
    """The headers to send with a ``run_guard`` result that is not an approval:
    ``Cache-Control: no-store``, ``Retry-After`` when the step has
    ``retryAfter`` (423, 429), and on a refusal (status >= 400)
    ``X-Touchque-State`` and ``X-Touchque-Reason`` (when the step has a
    reason). ``@touchque/web`` builds the step from them when the body has no
    ``touchque`` (an ``error_body`` that is not an object)."""
    step = _step_of(result)
    headers = {'Cache-Control': 'no-store'}
    if step.get('retryAfter'):
        headers['Retry-After'] = str(step['retryAfter'])
    if result['status'] >= 400:
        if step.get('state'):
            headers['X-Touchque-State'] = str(step['state'])
        if step.get('reason'):
            headers['X-Touchque-Reason'] = str(step['reason'])
    return headers


def _refusal(result: Dict[str, Any]) -> Dict[str, Any]:
    body = result['body']
    step = _step_of(result)
    error = body.get('error') or {}
    return {
        'status': result['status'],
        'code': error.get('code') or step.get('reason') or step.get('state'),
        'message': error.get('message') or _REFUSAL_MESSAGES.get(step.get('state'), 'The approval was refused.'),
        'touchque': copy.deepcopy(step),  # a copy: the callback cannot change the step that is sent
    }


def _plain(value: Any) -> Any:
    """A dataclass or a pydantic model as the dict it stands for; anything else as it is."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    pydantic = sys.modules.get('pydantic')  # only when the app uses pydantic: never imported here
    if pydantic is not None and isinstance(value, getattr(pydantic, 'BaseModel', ())):
        return value.model_dump(mode='json') if hasattr(value, 'model_dump') else value.dict()
    return value


def _custom_body(result: Dict[str, Any], custom: Any, encode: Optional[Callable[[Any], str]] = None,
                 plain: bool = True) -> Any:
    """What ``error_body`` returned, as the response will carry it: encoded the
    way the framework encodes the response (``encode``), so a value it cannot
    encode raises here, not in the framework. What encodes to a JSON object
    gets ``touchque`` set to the step; anything else is sent as it is.
    ``plain=False``: ``encode`` takes dataclasses and pydantic models itself
    (FastAPI's ``jsonable_encoder``, with their aliases)."""
    if inspect.isawaitable(custom):
        if inspect.iscoroutine(custom):
            custom.close()
        raise TypeError('error_body returned an awaitable: only the FastAPI adapter awaits it')
    data = json.loads((encode or json.dumps)(_plain(custom) if plain else custom))
    if isinstance(data, dict):
        data['touchque'] = _step_of(result)
    return data


def _error_body_failed(result: Dict[str, Any], err: BaseException) -> Any:
    logger.error('[Touchque] error_body failed: %s', str(err) or type(err).__name__)
    return result['body']


def guard_response_body(result: Dict[str, Any], error_body: Optional[ErrorBody] = None,
                        encode: Optional[Callable[[Any], str]] = None) -> Any:
    """The JSON an adapter sends for a ``run_guard`` result that is not an
    approval: ``result['body']``, or for a refusal (status >= 400) what
    ``error_body`` makes of it. ``error_body`` gets
    ``{'status', 'code', 'message', 'touchque'}``: ``code`` is the guard's
    ``error.code``, else the step's ``reason``, else its ``state``; ``message``
    the guard's ``error.message``, else a sentence for the state;
    ``touchque`` a copy of the step. Its result counts by its JSON encoding
    (``encode``, default ``json.dumps``; dataclasses and pydantic models as
    their fields): an object is sent with ``touchque`` set to the step
    (``@touchque/web`` still sees the state; no ``token``), anything else as
    it is. If it raises, or its result cannot be encoded, the default body is
    sent and the error logged. Never called for a 202 step."""
    if error_body is None or result['status'] < 400:
        return result['body']
    try:
        return _custom_body(result, error_body(_refusal(result)), encode)
    except Exception as err:  # noqa: BLE001 - your callback must not turn a refusal into a crash
        return _error_body_failed(result, err)


def _silent_approval(client: 'Touchque', user: str, action: str, browser_proof: str, ip: Optional[str],
                     user_agent: Optional[str], silent_sign_in: SilentSignIn,
                     context: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Asks Touchque whether this known browser may sign in without the phone.
    Fails closed: only an answer of exactly ``prompt: False`` approves; any
    error (network, 4xx, 5xx, a server without silent sign-ins) means "ask as
    usual" and returns ``None``."""
    try:
        max_age = silent_sign_in.get('max_age_seconds') if isinstance(silent_sign_in, dict) else None
        res = client.risk.check(user, type=action, client_ip=ip, user_agent=user_agent,
                                browser_proof=browser_proof, max_age_seconds=max_age, context=context)
        if not isinstance(res, dict) or res.get('prompt') is not False:
            return None
        reasons = res.get('reasons')
        return {
            'requestId': 'silent', 'user': user, 'action': action,
            'assurance': {'phishingResistant': False, 'method': 'silent'},
            'confirmedVia': 'SILENT', 'approvalProof': None,
            # Why Touchque let this known browser in; nothing was sent to the phone.
            'reasons': reasons if isinstance(reasons, list) else [],
        }
    except Exception as err:  # noqa: BLE001 - fail closed: any error asks on the phone as usual
        logger.warning('[Touchque] silent sign-in check failed, asking on the phone: %s: %s', type(err).__name__, err)
        return None
