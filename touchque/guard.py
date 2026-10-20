"""
Framework-agnostic step-up guard. The Django, FastAPI and Flask adapters in
``touchque.contrib`` are thin wrappers over ``run_guard()``.

Contract (same in every TouchQue server SDK):
  1st request            -> 202 {"touchque": step, "token": ...}   show the step in your UI
  repeat with the token   -> 202 while waiting, then the protected handler runs once
  refused                 -> 403 / 408 / 423 / 429 {"touchque": {"state": ..., ...}}

Request headers the browser sends back:
  X-TouchQue-Token         the token from the last response
  X-TouchQue-Offline: 1    switch to offline approval (phone has no internet)
  X-TouchQue-Code          the code from the phone (offline QR code, or with
  X-TouchQue-Code-Type: totp   the rolling time-based code)
  X-TouchQue-Browser       the browser's device-bound key proof (silent sign-ins,
                           read only when the adapter's ``silent_sign_in`` is on)
"""
import logging
import time
from typing import Any, Callable, Dict, Optional, Union

from .exceptions import TouchQueAPIException, TouchQueConfigException, TouchQueNetworkException
from .steps import (
    LoginDetails, check, complete, details_digest, normalize_details, sign_guard_token, start,
    verify_guard_token,
)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .client import TouchQue

logger = logging.getLogger('touchque')

TOKEN_TTL_MS = 10 * 60 * 1000

TOKEN_HEADER = 'x-touchque-token'
OFFLINE_HEADER = 'x-touchque-offline'
CODE_HEADER = 'x-touchque-code'
CODE_TYPE_HEADER = 'x-touchque-code-type'
BROWSER_HEADER = 'x-touchque-browser'

#: A real browser proof is a few hundred characters; anything far larger is not one.
MAX_BROWSER_PROOF = 4096

#: ``silent_sign_in``: ``True``, or ``{'max_age_seconds': n}`` for your own limit
#: on the age of the last phone approval in the browser (``0`` = always ask;
#: TouchQue never goes beyond its own limit, 7 days).
SilentSignIn = Union[bool, Dict[str, Any], None]


def _silent_on(option: SilentSignIn) -> bool:
    # A dict turns it on even when empty (``{}``: TouchQue's own limit only).
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
    the ``X-TouchQue-Browser`` proof, read only when ``option`` is on."""
    if not _silent_on(option):
        return {}
    return {'silent_sign_in': option, 'browser_proof': get(BROWSER_HEADER) or None}


def is_status_poll(client: 'TouchQue', user: Optional[str], action: str, details: Optional[LoginDetails] = None,
                   reference_id: Optional[str] = None, token: Optional[str] = None, offline: bool = False,
                   code: Optional[str] = None, **_: Any) -> bool:
    """True when this request only polls an approval that is already on its way:
    a valid token bound to this user/action/details, still waiting, and no
    offline switch or typed code. It can only read the status, never start a
    push, so relays do not count it against the per-user push limit (with a
    1.5 s poll the 6th poll was refused after 7.5 s)."""
    if not user or not token or offline or code:
        return False
    claims = verify_guard_token(client._api_secret, token)
    if not claims or not claims.get('rid'):
        return False
    return claims.get('u') == user and claims.get('a') == action \
        and claims.get('d') == details_digest(details) and claims.get('r') == (reference_id or None) \
        and claims.get('st') in ('waiting', 'passkey_required', 'offline')


def run_guard(
    client: 'TouchQue',
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
) -> Dict[str, Any]:
    """Runs one step of the guard. Returns either
    ``{"approved": {...}, "status": 200}`` (run your protected action) or
    ``{"status": <code>, "body": {"touchque": step, "token": ...}}``
    (send that JSON body with that status code).

    ``browser_proof``: the browser's device-bound key proof
    (``X-TouchQue-Browser``), passed through untouched and attached to the
    push, so its approval makes the browser known.

    ``silent_sign_in`` (default off): a new attempt that carries
    ``browser_proof`` first asks TouchQue (``risk.check``); when it answers
    exactly ``prompt: False`` the guard approves at once, with no push
    (``assurance['method'] == 'silent'``, ``confirmedVia == 'SILENT'``,
    ``requestId == 'silent'``, ``reasons``). Otherwise, and on any error in
    the check, the usual push starts. ``{'max_age_seconds': n}`` sets your own
    limit on how long ago the last phone approval in that browser may be.

    ``context``: for your TouchQue Actions only (``event.context``).
    """
    if not user:
        return {'status': 401, 'body': {
            'touchque': {'state': 'blocked', 'reason': 'unauthenticated'},
            'error': {'code': 'unauthenticated', 'message': 'Sign in first.'},
        }}

    norm = normalize_details(details)
    base = {'u': user, 'a': action, 'd': details_digest(details), 'r': reference_id or None}

    def issue(step: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if norm and not step.get('details') and step.get('state') != 'blocked':
            step['details'] = norm
        claims = {**base, 'st': step['state'], 'rid': step.get('requestId'), 'n': step.get('number'),
                  'oc': (step.get('offline') or {}).get('challengeId'), 'exp': int(time.time() * 1000) + TOKEN_TTL_MS}
        if step.get('caseCode'):
            claims['cc'] = step['caseCode']  # "Why?": still shown while it waits
        if extra:
            claims.update(extra)
        signed = sign_guard_token(client._api_secret, claims)
        return {'status': _STATUS[step['state']], 'body': {'touchque': step, 'token': signed}}

    try:
        claims = verify_guard_token(client._api_secret, token)
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
            except TouchQueAPIException as err:
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
                except TouchQueAPIException as err:
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

        # Anything else (no/foreign token, enrollment finished, new attempt): start.
        proof = browser_proof if isinstance(browser_proof, str) and browser_proof \
            and len(browser_proof) <= MAX_BROWSER_PROOF else None
        if proof and _silent_on(silent_sign_in):
            silent = _silent_approval(client, user, action, proof, ip, user_agent, silent_sign_in, context)
            if silent:
                return {'status': 200, 'approved': silent}
        return issue(start(client, action, user, details=norm or None, reference_id=reference_id, ip=ip,
                           user_agent=user_agent, enroll=enroll, browser_proof=proof, context=context))
    except TouchQueConfigException as err:
        logger.error('[TouchQue] %s', err)
        return {'status': 500, 'body': {
            'touchque': {'state': 'blocked', 'reason': 'misconfigured'},
            'error': {'code': 'misconfigured', 'message': 'Two-factor approval is not configured correctly.'},
        }}
    except (TouchQueNetworkException, TouchQueAPIException) as err:
        logger.error('[TouchQue] approval failed: %s', err)
        return {'status': 503, 'body': {
            'touchque': {'state': 'blocked', 'reason': 'unavailable'},
            'error': {'code': 'unavailable', 'message': 'Two-factor approval is temporarily unavailable.'},
        }}


def _silent_approval(client: 'TouchQue', user: str, action: str, browser_proof: str, ip: Optional[str],
                     user_agent: Optional[str], silent_sign_in: SilentSignIn,
                     context: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Asks TouchQue whether this known browser may sign in without the phone.
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
            # Why TouchQue let this known browser in; nothing was sent to the phone.
            'reasons': reasons if isinstance(reasons, list) else [],
        }
    except Exception as err:  # noqa: BLE001 - fail closed: any error asks on the phone as usual
        logger.warning('[TouchQue] silent sign-in check failed, asking on the phone: %s', err)
        return None
