"""The agent side: an AI agent calls Touchque with its OWN key, never with your
API key. ``TouchqueAgent`` signs a private_key_jwt assertion (RFC 7523) for a
10-minute token bound to its key with DPoP (RFC 9449), and proves the key on
every call, so a stolen token is useless on its own.

    agent = TouchqueAgent()            # TQ_AGENT_ID, TQ_AGENT_KEY (a JWK as JSON, or PEM)
    me = agent.me()

Needs the optional ``cryptography`` package: ``pip install "touchque-authenticator[agent]"``.
"""
import base64
import hashlib
import json
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import requests

from .exceptions import (
    TouchqueAPIException, TouchqueApprovalError, TouchqueConfigException, TouchqueNetworkException, TouchqueTimeoutException,
    api_exception,
)

__all__ = ['TouchqueAgent', 'generate_agent_key', 'jwk_thumbprint', 'AGENT_ASSERTION_TYPE']

AGENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
_AGENT_ID = re.compile(r'^agt_[a-z2-9]{20}$')
_LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}
_ENDED = {'rejected', 'blocked', 'revoked', 'expired', 'stale', 'redeemed'}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, separators=(',', ':'))


def jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """RFC 7638 thumbprint of a P-256 or Ed25519 public key (the default kid)."""
    if jwk.get('kty') == 'EC':
        members = {'crv': jwk['crv'], 'kty': 'EC', 'x': jwk['x'], 'y': jwk['y']}
    else:
        members = {'crv': jwk['crv'], 'kty': jwk['kty'], 'x': jwk['x']}
    return _b64url(hashlib.sha256(_json(members).encode('utf-8')).digest())


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError('TouchqueAgent needs the cryptography package: pip install "touchque-authenticator[agent]"') from exc
    return hashes, serialization, ec, ed25519, decode_dss_signature


def _public_jwk(key) -> Dict[str, Any]:
    hashes, serialization, ec, ed25519, _ = _crypto()
    if isinstance(key, ed25519.Ed25519PrivateKey):
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {'kty': 'OKP', 'crv': 'Ed25519', 'x': _b64url(raw)}
    numbers = key.public_key().public_numbers()
    return {'kty': 'EC', 'crv': 'P-256', 'x': _b64url(numbers.x.to_bytes(32, 'big')), 'y': _b64url(numbers.y.to_bytes(32, 'big'))}


def generate_agent_key(alg: str = 'ES256') -> Dict[str, Dict[str, Any]]:
    """A new key pair for an agent: ES256 (P-256, default) or EdDSA (Ed25519).
    Returns ``{'private_jwk': ..., 'public_jwk': ...}``; kid = the RFC 7638
    thumbprint. Register ``public_jwk``; keep ``private_jwk`` where the agent runs."""
    hashes, serialization, ec, ed25519, _ = _crypto()
    if alg == 'EdDSA':
        key = ed25519.Ed25519PrivateKey.generate()
        d = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    elif alg == 'ES256':
        key = ec.generate_private_key(ec.SECP256R1())
        d = key.private_numbers().private_value.to_bytes(32, 'big')
    else:
        raise TouchqueConfigException('alg must be ES256 or EdDSA')
    public = _public_jwk(key)
    kid = jwk_thumbprint(public)
    return {
        'private_jwk': dict(public, d=_b64url(d), kid=kid, alg=alg),
        'public_jwk': dict(public, kid=kid, alg=alg),
    }


def _load_private_key(value: Union[Dict[str, Any], str, Any]):
    hashes, serialization, ec, ed25519, _ = _crypto()
    try:
        if isinstance(value, str) and value.strip().startswith('{'):
            value = json.loads(value)
        if isinstance(value, dict):
            d = _b64url_decode(value['d'])
            if value.get('kty') == 'OKP' and value.get('crv') == 'Ed25519':
                return ed25519.Ed25519PrivateKey.from_private_bytes(d)
            if value.get('kty') == 'EC' and value.get('crv') == 'P-256':
                return ec.derive_private_key(int.from_bytes(d, 'big'), ec.SECP256R1())
            raise ValueError('unsupported key')
        if isinstance(value, (str, bytes)):
            data = value.encode('utf-8') if isinstance(value, str) else value
            return serialization.load_pem_private_key(data, password=None)
        if isinstance(value, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
            return value
    except Exception as exc:
        raise TouchqueConfigException("private_key must be the agent's private key: a JWK (dict or JSON), a PEM string or a cryptography key") from exc
    raise TouchqueConfigException("private_key must be the agent's private key: a JWK (dict or JSON), a PEM string or a cryptography key")


class TouchqueAgent:
    """An AI agent's own Touchque client (see the module docstring)."""

    def __init__(self, agent_id: Optional[str] = None, private_key: Union[Dict[str, Any], str, Any, None] = None,
                 kid: Optional[str] = None, base_url: Optional[str] = None, scope: Optional[str] = None,
                 timeout: int = 10000):
        agent_id = agent_id if agent_id is not None else os.environ.get('TQ_AGENT_ID', '')
        if not _AGENT_ID.match(agent_id or ''):
            raise TouchqueConfigException('Set TQ_AGENT_ID (or pass agent_id): the agt_... id from client.agents.create()')
        key_input = private_key if private_key is not None else os.environ.get('TQ_AGENT_KEY')
        if not key_input:
            raise TouchqueConfigException("Set TQ_AGENT_KEY (or pass private_key): the agent's private key")
        hashes, serialization, ec, ed25519, _ = _crypto()
        self.agent_id = agent_id
        self._key = _load_private_key(key_input)
        if isinstance(self._key, ec.EllipticCurvePrivateKey) and not isinstance(self._key.curve, ec.SECP256R1):
            raise TouchqueConfigException('An EC agent key must be on P-256')
        if not isinstance(self._key, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
            raise TouchqueConfigException('The agent key must be EC P-256 or Ed25519')
        self._alg = 'EdDSA' if isinstance(self._key, ed25519.Ed25519PrivateKey) else 'ES256'
        self._public_jwk = _public_jwk(self._key)
        given_kid = None
        if isinstance(key_input, str) and key_input.strip().startswith('{'):
            given_kid = json.loads(key_input).get('kid')
        elif isinstance(key_input, dict):
            given_kid = key_input.get('kid')
        self._kid = kid or given_kid or jwk_thumbprint(self._public_jwk)
        self.base_url = (base_url or os.environ.get('TQ_API_URL') or 'https://api.touchque.com').rstrip('/')
        parsed = urlparse(self.base_url)
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and (parsed.hostname or '') in _LOCAL_HOSTS):
            raise TouchqueConfigException(f'Refusing a plaintext base_url for "{parsed.hostname}": use https://')
        self._scope = scope
        self._timeout = timeout / 1000.0
        self._token: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()

    # ── signing ──────────────────────────────────────────────────────────

    def _sign(self, header: Dict[str, Any], payload: Dict[str, Any]) -> str:
        hashes, serialization, ec, ed25519, decode_dss_signature = _crypto()
        signing_input = f"{_b64url(_json(dict(header, alg=self._alg)).encode())}.{_b64url(_json(payload).encode())}"
        if self._alg == 'EdDSA':
            sig = self._key.sign(signing_input.encode('ascii'))
        else:
            r, s = decode_dss_signature(self._key.sign(signing_input.encode('ascii'), ec.ECDSA(hashes.SHA256())))
            sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        return f'{signing_input}.{_b64url(sig)}'

    def _dpop(self, method: str, url: str, access_token: Optional[str] = None) -> str:
        claims: Dict[str, Any] = {'htm': method, 'htu': url, 'iat': int(time.time()), 'jti': str(uuid.uuid4())}
        if access_token:
            claims['ath'] = _b64url(hashlib.sha256(access_token.encode('ascii')).digest())
        return self._sign({'typ': 'dpop+jwt', 'jwk': self._public_jwk}, claims)

    @staticmethod
    def _error(response: 'requests.Response') -> TouchqueAPIException:
        try:
            data = response.json()
        except ValueError:
            data = {}
        retry_after = data.get('retry_after', data.get('retryAfter'))
        return api_exception(
            data.get('error_description') or data.get('error') or 'Unknown API Error',
            status=response.status_code,
            code=data.get('code') or data.get('error'),
            reason=data.get('reason'),
            retry_after=retry_after if isinstance(retry_after, int) else None,
            data=data,
            case_code=data.get('caseCode') if isinstance(data.get('caseCode'), str) else None,
        )

    # ── token ────────────────────────────────────────────────────────────

    def _fetch_token(self) -> str:
        url = f'{self.base_url}/agents/token'
        now = int(time.time())
        assertion = self._sign({'typ': 'JWT', 'kid': self._kid},
                               {'iss': self.agent_id, 'sub': self.agent_id, 'aud': url, 'iat': now, 'exp': now + 60, 'jti': str(uuid.uuid4())})
        form = {'grant_type': 'client_credentials', 'client_assertion_type': AGENT_ASSERTION_TYPE, 'client_assertion': assertion}
        if self._scope:
            form['scope'] = self._scope
        try:
            response = requests.post(url, data=form, headers={'DPoP': self._dpop('POST', url)}, timeout=self._timeout, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise TouchqueNetworkException(f'Network Error: {e}') from e
        if response.status_code != 200:
            raise self._error(response)
        data = response.json()
        self._token = {'value': data['access_token'], 'expires_at': time.time() + int(data.get('expires_in', 600))}
        return self._token['value']

    def access_token(self) -> str:
        """The agent's current token (renewed a minute before it expires)."""
        with self._lock:
            if self._token and self._token['expires_at'] - time.time() > 60:
                return self._token['value']
            return self._fetch_token()

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, retried: bool = False) -> Dict[str, Any]:
        token = self.access_token()
        url = f'{self.base_url}{path}'
        headers = {'Authorization': f'DPoP {token}', 'DPoP': self._dpop(method, url.split('?')[0], token)}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        try:
            response = requests.request(method, url, data=_json(body) if body is not None else None, headers=headers,
                                        timeout=self._timeout, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise TouchqueNetworkException(f'Network Error: {e}') from e
        if response.status_code == 401 and not retried:
            try:
                code = response.json().get('code')
            except ValueError:
                code = None
            if code == 'invalid_token':
                self._token = None
                return self._request(method, path, body, retried=True)
        if response.status_code >= 300:
            raise self._error(response)
        return response.json()

    def me(self) -> Dict[str, Any]:
        """The agent as Touchque sees it: its action types, owner, review date and workspace."""
        return self._request('GET', '/agents/me')

    def request_approval(self, user: str, type: str, authorization_details: List[Dict[str, Any]], reason: Optional[str] = None,
                         presence: Optional[str] = None, expires_in: Optional[int] = None, locale: Optional[str] = None,
                         reference_id: Optional[str] = None, client_ip: Optional[str] = None,
                         user_agent: Optional[str] = None, mandate_id: Optional[str] = None) -> Dict[str, Any]:
        """Asks the person to approve on their Touchque phone. Show
        ``challengeCode`` in your conversation (presence ``interactive``, the
        default): the person types it on the phone. Touchque draws the phone's
        rows from ``authorization_details``; ``reason`` is shown as unverified.
        ``requiresPasskey`` (over the policy's requirePasskeyAbove): the person
        approves with a passkey on your page instead, not on the phone."""
        body: Dict[str, Any] = {'externalUsername': user, 'type': type, 'authorizationDetails': authorization_details}
        for key, value in (('reason', reason), ('presence', presence), ('expiresIn', expires_in), ('locale', locale),
                           ('referenceId', reference_id), ('clientIp', client_ip), ('userAgent', user_agent), ('mandateId', mandate_id)):
            if value is not None:
                body[key] = value
        return self._request('POST', '/agents/approvals', body)

    def request_mandate(self, user: str, type: str, max_count: int, max_total: Dict[str, str], per_request: Optional[str] = None,
                        recipients: Optional[List[str]] = None, valid_for: Optional[int] = None, reason: Optional[str] = None,
                        expires_in: Optional[int] = None, locale: Optional[str] = None) -> Dict[str, Any]:
        """Asks the person for a mandate: one approval on the phone for a bounded
        series of requests (how many, how much in total and per request, to whom,
        until when). Show ``challengeCode``; once ``active``, pass ``mandate_id`` to
        ``request_approval`` and each request within it is approved without a push."""
        body: Dict[str, Any] = {'externalUsername': user, 'type': type, 'maxCount': max_count, 'maxTotal': max_total}
        for key, value in (('perRequest', per_request), ('recipients', recipients), ('validFor', valid_for), ('reason', reason),
                           ('expiresIn', expires_in), ('locale', locale)):
            if value is not None:
                body[key] = value
        return self._request('POST', '/agents/mandates', body)

    def get_connection_token(self, user: str, connection: str, scope: Optional[str] = None) -> Dict[str, Any]:
        """The token vault: a person's own access token at another service, for a connection that
        names this agent (``client.agents.vault``): ``{'access_token', 'token_type': 'Bearer',
        'expires_in'?, 'scope', 'connection'}``. Touchque refreshes it; the refresh token never
        leaves. TouchqueAPIException not_connected when nothing is kept for them."""
        body: Dict[str, Any] = {'externalUsername': user, 'connection': connection}
        if scope:
            body['scope'] = scope
        return self._request('POST', '/agents/vault/token', body)

    def get_mandate(self, mandate_id: str) -> Dict[str, Any]:
        """A mandate's state and what is left."""
        return self._request('GET', f'/agents/mandates/{mandate_id}')

    def revoke_mandate(self, mandate_id: str) -> Dict[str, Any]:
        """Gives up a mandate (when the task is done early, for example)."""
        return self._request('POST', f'/agents/mandates/{mandate_id}/revoke', {})

    def get_approval(self, approval_id: str) -> Dict[str, Any]:
        """Where an approval request is; ``approvalToken`` once approved."""
        return self._request('GET', f'/agents/approvals/{approval_id}')

    def wait_for_approval(self, approval_id: str, timeout: float = 600, interval: float = 2) -> Dict[str, Any]:
        """Polls until the person approves (returns the state holding
        ``approvalToken``). Raises TouchqueApprovalError when it ends otherwise
        and TouchqueTimeoutException after ``timeout`` seconds. An approval given
        during a phone call stays ``provisional`` until the phone confirms it, and
        four eyes stay ``awaiting_second`` until the second person answers."""
        interval = max(0.5, interval)
        end = time.time() + timeout
        while True:
            state = self.get_approval(approval_id)
            if state.get('status') == 'approved' and state.get('approvalToken'):
                return state
            if state.get('status') in _ENDED:
                raise TouchqueApprovalError(approval_id, state['status'], state.get('reason'))
            if time.time() + interval > end:
                raise TouchqueTimeoutException(f"Touchque: approval '{approval_id}' was not approved within {timeout}s")
            time.sleep(interval)
