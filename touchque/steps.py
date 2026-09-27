"""
The headless step-up flow shared by every integration (Django, FastAPI,
Flask, or your own framework): start -> show the step in YOUR UI -> check ->
complete exactly once.

A "step" is plain JSON-serializable data: what state the approval is in and
whatever the user has to see (the matching number, the enrollment QR code,
the offline QR code). It never contains API secrets.
"""
import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional, Union

from .exceptions import TouchQueAPIException, TouchQueConfigException, TouchQueException
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .client import TouchQue

LoginDetails = Union[Dict[str, Any], List[Dict[str, Any]]]

# States: waiting | approved | rejected | expired | enroll | passkey_required
#         | offline | blocked | frozen | rate_limited


def normalize_details(details: Optional[LoginDetails]) -> List[Dict[str, str]]:
    """Same normalization the API does: a dict or a list of {label, value} -> [{label, value}] strings."""
    if not details:
        return []
    if isinstance(details, list):
        pairs = [(d['label'], d['value']) for d in details]
    else:
        pairs = list(details.items())
    return [{'label': str(label).strip(), 'value': str(value).strip()} for label, value in pairs]


def details_digest(details: Optional[LoginDetails]) -> str:
    pairs = normalize_details(details)
    if not pairs:
        return ''
    canonical = '\x1e'.join(f"{p['label']}\x1f{p['value']}" for p in pairs)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _err_code(err: TouchQueAPIException) -> Optional[str]:
    return err.code or (err.data or {}).get('error')


def start(client: 'TouchQue', action: str, user: str, details: Optional[LoginDetails] = None,
          reference_id: Optional[str] = None, ip: Optional[str] = None, user_agent: Optional[str] = None,
          enroll: bool = True) -> Dict[str, Any]:
    """Starts an approval for `action` — never waits."""
    if not user:
        raise TouchQueConfigException('start() needs the user id')
    norm = normalize_details(details)
    try:
        res = client.login.request(
            user, type=action, reference_id=reference_id, client_ip=ip, user_agent=user_agent,
            details=norm or None,
        )
        if res.get('requiresPasskey'):
            return {'state': 'passkey_required', 'requestId': res.get('requestId'),
                    'expiresAt': res.get('expiresAt'), 'details': norm or None}
        return {
            'state': 'waiting', 'requestId': res.get('requestId'), 'number': res.get('challengeCode'),
            'expiresAt': res.get('expiresAt'), 'details': norm or None,
        }
    except TouchQueAPIException as err:
        code = _err_code(err)
        if err.status == 404 and (code == 'device_not_linked' or 'linked device' in str(err).lower()):
            if not enroll:
                return {'state': 'enroll'}
            return _enroll_step(client, user)
        if err.status == 423:
            return {'state': 'frozen', 'retryAfter': err.retry_after}
        if err.status == 429:
            return {'state': 'rate_limited', 'retryAfter': err.retry_after}
        if err.status == 400 and (code == 'unknown_action' or 'invalid action type' in str(err).lower()):
            raise TouchQueConfigException(
                f'Unknown action "{action}". Create it once with client.actions.define("{action}") '
                'or in the Dashboard (Action Types).'
            ) from err
        if err.status == 403:
            reason = (err.reason if code == 'blocked' else None) \
                or ('passkey_not_registered' if code in ('passkey_not_registered',) or (err.data or {}).get('error') == 'phishing_resistant_required' else None) \
                or ('action_disabled' if code == 'action_disabled' else None) \
                or code or 'blocked'
            return {'state': 'blocked', 'reason': reason}
        raise


def _enroll_step(client: 'TouchQue', user: str) -> Dict[str, Any]:
    """First-time linking. Never unlinks a phone: a secret is only re-issued
    when the account is confirmed NOT linked."""
    try:
        gen = client.auth.generate_secret(user)
        return {'state': 'enroll', 'enroll': {
            'qrCodeDataUrl': gen.get('qrCodeDataUrl'), 'recoveryCodes': gen.get('recoveryCodes'),
            'expiresAt': gen.get('expiresAt'),
        }}
    except TouchQueAPIException as err:
        if err.status != 409:
            raise
        try:
            current = client.auth.get_user(user)
        except TouchQueAPIException:
            current = None
        if current and (current.get('used') or current.get('deviceId')):
            return {'state': 'enroll', 'reason': 'already_linked'}
        reset = client.auth.reset_secret(user)
        return {'state': 'enroll', 'enroll': {
            'qrCodeDataUrl': reset.get('qrCodeDataUrl'), 'recoveryCodes': reset.get('recoveryCodes'),
            'expiresAt': reset.get('expiresAt'),
        }}


_STATE_MAP = {'PENDING': 'waiting', 'CONFIRMED': 'approved', 'REJECTED': 'rejected', 'EXPIRED': 'expired'}


def check(client: 'TouchQue', request_id: str) -> Dict[str, Any]:
    """Current state of a started approval."""
    s = client.login.status(request_id)
    state = 'passkey_required' if s.get('status') == 'PENDING' and s.get('requiresPasskey') \
        else _STATE_MAP.get(s.get('status'), 'waiting')
    step: Dict[str, Any] = {'state': state, 'requestId': request_id}
    if state == 'approved' and s.get('assurance'):
        step['assurance'] = s['assurance']
    return step


def complete(client: 'TouchQue', request_id: str, user: str, action: str,
             details: Optional[LoginDetails] = None, reference_id: Optional[str] = None) -> Dict[str, Any]:
    """Uses an approved request exactly once and checks it is for THIS user,
    action and transaction. Raises TouchQueException if it was already used,
    not approved, or approved for something else."""
    res = client.login.consume(request_id)
    same_user = str(res.get('externalUsername', '')).lower() == str(user).lower()
    same_details = details_digest(details) == details_digest(res.get('details') or [])
    same_ref = (res.get('referenceId') or None) == (reference_id or None)
    if not same_user or res.get('type') != action or not same_details or not same_ref:
        raise TouchQueException('TouchQue: this approval is for a different user, action or transaction.')
    return {
        'requestId': request_id,
        'user': res.get('externalUsername'),
        'action': res.get('type'),
        'assurance': res.get('assurance'),
        'confirmedVia': res.get('confirmedVia'),
        'approvalProof': res.get('approvalProof'),
    }


# ── Guard token ──────────────────────────────────────────────────────────
# The browser echoes this back while it waits. It is signed with a key derived
# from the API secret and binds the approval to one user, action and
# transaction, so it cannot be replayed for another user, amount or route.

def _token_key(api_secret: str) -> bytes:
    return hmac.new(api_secret.encode('utf-8'), b'touchque-guard-token-v1', hashlib.sha256).digest()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _from_b64u(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sign_guard_token(api_secret: str, claims: Dict[str, Any]) -> str:
    body = _b64u(json.dumps(claims, separators=(',', ':')).encode('utf-8'))
    mac = _b64u(hmac.new(_token_key(api_secret), body.encode('ascii'), hashlib.sha256).digest())
    return f"v1.{body}.{mac}"


def verify_guard_token(api_secret: str, token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not isinstance(token, str) or len(token) > 4096:
        return None
    parts = token.split('.')
    if len(parts) != 3 or parts[0] != 'v1':
        return None
    _, body, mac = parts
    expected = _b64u(hmac.new(_token_key(api_secret), body.encode('ascii'), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, mac):
        return None
    try:
        claims = json.loads(_from_b64u(body))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(claims.get('exp'), (int, float)) or claims['exp'] < time.time() * 1000:
        return None
    return claims
