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
"""
import logging
import time
from typing import Any, Callable, Dict, Optional

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
) -> Dict[str, Any]:
    """Runs one step of the guard. Returns either
    ``{"approved": {...}, "status": 200}`` (run your protected action) or
    ``{"status": <code>, "body": {"touchque": step, "token": ...}}``
    (send that JSON body with that status code).
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
            if bound.get('st') == 'offline' and now['state'] in ('waiting', 'expired', 'passkey_required'):
                # Still (or no longer) pending: nothing changed for the user — keep showing the QR they have.
                return issue({'state': 'offline', 'offline': {'challengeId': str(bound.get('oc'))}},
                             {'oc': bound.get('oc'), 'rid': bound['rid'], 'n': bound.get('n')})
            if now['state'] in ('waiting', 'passkey_required'):
                return issue({'state': now['state'], 'requestId': bound['rid'], 'number': bound.get('n')}, {'n': bound.get('n')})
            return issue({'state': now['state'], 'requestId': bound['rid']})

        # Anything else (no/foreign token, enrollment finished, new attempt): start.
        return issue(start(client, action, user, details=norm or None, reference_id=reference_id, ip=ip, user_agent=user_agent))
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
