"""Shared Signals (OpenID Shared Signals Framework 1.0): Security Event Tokens.

An identity provider sends a SET (RFC 8417) when something happens to a
person's account after sign-in: CAEP session-revoked, credential-change,
device-compliance-change; RISC account-disabled, credential-compromise.
Touchque SSO sends them for an organization's members to the receivers its
admin adds (Organization > Continuous access). Your app ends the person's
sessions or asks them to sign in again.

Push delivery (RFC 8935), the SET is the request body (application/secevent+jwt)::

    verifier = SecurityEventVerifier(issuer='https://sso.touchque.com', audience='https://app.example.com')

    @app.post('/ssf')
    def ssf():
        try:
            event = verifier.verify(request.get_data(as_text=True))
        except SecurityEventError as e:
            return {'err': e.code, 'description': str(e)}, 400
        if event.name == 'session-revoked':
            end_sessions_of(event.subject.get('email'))
        return '', 202

Poll delivery (RFC 8936): ``poll_security_events(url=..., token=..., ack=[...])``.

A SET does not expire: it says what happened. Keep the jtis you handled and
skip a repeat. Needs the optional ``cryptography`` package:
``pip install "touchque-authenticator[agent]"``.
"""

import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

from .exceptions import TouchqueConfigException
from .mcp_auth import _json_part, _b64d, _public_key, _verify
from .cross_app_access import _get_json, _safe_url

SET_TYP = 'secevent+jwt'
_NAMESPACE = re.compile(r'^https://schemas\.openid\.net/secevent/(caep|risc|ssf)/event-type/([a-z0-9-]+)$')

#: The event types Touchque sends, by their short name.
SECURITY_EVENT_TYPES = {
    'session-revoked': 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
    'credential-change': 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
    'device-compliance-change': 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
    'account-disabled': 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
    'credential-compromise': 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
    'verification': 'https://schemas.openid.net/secevent/ssf/event-type/verification',
    'stream-updated': 'https://schemas.openid.net/secevent/ssf/event-type/stream-updated',
}


class SecurityEventError(Exception):
    """A refused SET. ``code`` is the RFC 8935 error to answer with (HTTP 400 ``{"err": code}``):
    invalid_request, invalid_key, invalid_issuer or invalid_audience; temporarily_unavailable
    when the issuer's keys could not be read (answer 503: the transmitter tries again)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class SecurityEvent:
    jti: str
    issuer: str
    audience: List[str]
    #: Seconds since the epoch.
    issued_at: int
    #: Touchque puts the case code of its decision here ("Why?" in the dashboard).
    txn: Optional[str]
    #: The subject as sent (sub_id): {'format': 'email', 'email': ...} for a person.
    subject: Dict[str, Any]
    #: The event type URI.
    type: str
    #: Its short name (session-revoked ...) for CAEP, RISC and SSF types; None for others.
    name: Optional[str]
    #: The event's own claims (event_timestamp, reason_admin, credential_type ...).
    claims: Dict[str, Any]


class SecurityEventVerifier:
    """Checks a SET: signature (RS256, the issuer's keys), typ, issuer, audience, one event."""

    def __init__(self, issuer: str, audience: str, jwks_uri: Optional[str] = None, jwks: Optional[Dict[str, Any]] = None,
                 clock_skew: int = 300):
        if not issuer or not audience:
            raise TouchqueConfigException("SecurityEventVerifier needs issuer (the transmitter) and audience (your stream's aud)")
        self.issuer = issuer
        self.audience = audience
        self.jwks_uri = jwks_uri
        self.skew = clock_skew
        self._pinned = jwks is not None
        self._keys: Dict[str, Any] = {}
        self._keys_at = 0.0
        self._tried_at = 0.0
        self._lock = threading.Lock()
        if jwks is not None:
            self._set_keys(jwks)

    def _set_keys(self, jwks: Dict[str, Any]) -> None:
        self._keys = {k['kid']: _public_key(k) for k in jwks.get('keys', []) if k.get('kid')}
        self._keys_at = time.time()

    def _load_keys(self) -> None:
        if not self.jwks_uri:
            meta = _get_json(self.issuer.rstrip('/') + '/.well-known/ssf-configuration')
            if meta.get('issuer') != self.issuer or not isinstance(meta.get('jwks_uri'), str):
                raise RuntimeError("the transmitter's metadata does not match its issuer")
            self.jwks_uri = meta['jwks_uri']
        if not _safe_url(self.jwks_uri):
            raise RuntimeError(f'{self.jwks_uri} must be an https URL')
        self._set_keys(_get_json(self.jwks_uri))

    def _key_for(self, kid: str):
        if self._pinned:
            return self._keys.get(kid)
        with self._lock:
            if not self._keys_at or time.time() - self._keys_at > 3600:
                self._load_keys()
            if kid not in self._keys and time.time() - self._tried_at > 300:
                self._tried_at = time.time()
                self._load_keys()
            return self._keys.get(kid)

    def verify(self, token: str) -> SecurityEvent:
        parts = token.strip().split('.') if isinstance(token, str) else []
        if len(parts) != 3:
            raise SecurityEventError('invalid_request', 'not a JWT')
        try:
            head = _json_part(parts[0])
            c = _json_part(parts[1])
        except Exception:
            raise SecurityEventError('invalid_request', 'not a JWT')
        if str(head.get('typ') or '').lower() != SET_TYP:
            raise SecurityEventError('invalid_request', 'not a Security Event Token (typ secevent+jwt)')
        if head.get('alg') != 'RS256' or not isinstance(head.get('kid'), str):
            raise SecurityEventError('invalid_key', 'unsupported signature')
        try:
            key = self._key_for(head['kid'])
        except Exception as e:
            raise SecurityEventError('temporarily_unavailable', f"the transmitter's keys could not be read: {e}")
        try:
            sig = _b64d(parts[2])
        except Exception:
            raise SecurityEventError('invalid_key', 'signature does not verify')
        if key is None or not _verify(f'{parts[0]}.{parts[1]}'.encode('ascii'), sig, 'RS256', key):
            raise SecurityEventError('invalid_key', 'signature does not verify')
        if c.get('iss') != self.issuer:
            raise SecurityEventError('invalid_issuer', 'another issuer')
        aud = c.get('aud')
        audience = [a for a in (aud if isinstance(aud, list) else [aud]) if isinstance(a, str)]
        if self.audience not in audience:
            raise SecurityEventError('invalid_audience', 'not for this receiver')
        iat = c.get('iat')
        if not isinstance(c.get('jti'), str) or not isinstance(iat, int) or isinstance(iat, bool):
            raise SecurityEventError('invalid_request', 'jti and iat are required')
        if iat - self.skew > int(time.time()):
            raise SecurityEventError('invalid_request', 'issued in the future')
        events = c.get('events')
        if not isinstance(events, dict) or len(events) != 1:
            raise SecurityEventError('invalid_request', 'a SET carries exactly one event')
        (type_, claims), = events.items()
        m = _NAMESPACE.match(type_)
        sub = c.get('sub_id')
        return SecurityEvent(
            jti=c['jti'], issuer=c['iss'], audience=audience, issued_at=iat, txn=c['txn'] if isinstance(c.get('txn'), str) else None,
            subject=sub if isinstance(sub, dict) else {}, type=type_, name=m.group(2) if m else None,
            claims=claims if isinstance(claims, dict) else {},
        )


def poll_security_events(*, url: str, token: str, ack: Optional[List[str]] = None,
                         set_errs: Optional[Dict[str, Dict[str, str]]] = None, max_events: Optional[int] = None,
                         return_immediately: Optional[bool] = None) -> Dict[str, Any]:
    """One poll (RFC 8936): acknowledges what you handled and returns
    ``{'sets': {jti: token}, 'more_available': bool}``."""
    if not _safe_url(url):
        raise TouchqueConfigException(f'{url} must be an https URL')
    if not token:
        raise TouchqueConfigException("poll_security_events needs the stream's token")
    body: Dict[str, Any] = {}
    if ack is not None:
        body['ack'] = ack
    if set_errs is not None:
        body['setErrs'] = set_errs
    if max_events is not None:
        body['maxEvents'] = max_events
    if return_immediately is not None:
        body['returnImmediately'] = return_immediately
    r = requests.post(url, json=body, timeout=30, allow_redirects=False,
                      headers={'Accept': 'application/json', 'Authorization': f'Bearer {token}'})
    try:
        data = r.json()
    except ValueError:
        data = {}
    if r.status_code != 200:
        raise SecurityEventError(str(data.get('error') or 'server_error'), f'{url} answered {r.status_code}')
    sets = data.get('sets')
    return {'sets': sets if isinstance(sets, dict) else {}, 'more_available': data.get('moreAvailable') is True}
