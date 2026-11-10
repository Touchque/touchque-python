"""Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
draft-ietf-oauth-identity-assertion-authz-grant, an open standard).

An organization's identity provider (TouchQue SSO) decides which of its apps
may reach which other service for its members; the app trades a member's ID
token for an ID-JAG there, then the ID-JAG for an access token at the other
service's authorization server, with no consent screen per member.

Your app, signed in with TouchQue SSO (an OpenID Connect app with a secret)::

    jag = request_id_jag(issuer='https://sso.touchque.com', client_id=client_id, client_secret=secret,
                         id_token=id_token, audience='https://auth.files.example')
    tokens = redeem_id_jag(token_endpoint='https://auth.files.example/token', client_id='acme',
                           client_secret=files_secret, assertion=jag['assertion'])

Your own authorization server, taking ID-JAGs from an organization's identity provider::

    verifier = IdJagVerifier(issuer='https://sso.touchque.com', audience='https://auth.files.example')
    claims = verifier.verify(form['assertion'], client_id=authenticated_client_id)
    # claims['sub'] (the member at that identity provider), claims['email'], claims['scopes'], claims['resource']

Needs the optional ``cryptography`` package for verifying: ``pip install "touchque-authenticator[agent]"``.
"""

import base64
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import quote, urlparse

import requests

from .exceptions import TouchQueConfigException
from .mcp_auth import _json_part, _b64d, _public_key, _verify

__all__ = [
    'ID_JAG_TOKEN_TYPE', 'ID_TOKEN_TYPE', 'TOKEN_EXCHANGE_GRANT', 'JWT_BEARER_GRANT',
    'IdJagError', 'IdJagVerifier', 'request_id_jag', 'redeem_id_jag',
]

ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag'
ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token'
TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
_TYP = 'oauth-id-jag+jwt'
_ALGS = ('RS256', 'ES256', 'EdDSA')


class IdJagError(Exception):
    """A refused ID-JAG or exchange; ``code`` is the OAuth error (invalid_grant for a bad ID-JAG)."""

    def __init__(self, code: str, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.code = code
        self.status = status


def _safe_url(value: str) -> bool:
    u = urlparse(value or '')
    return u.scheme == 'https' or (u.scheme == 'http' and u.hostname in ('localhost', '127.0.0.1', '::1'))


def _get_json(url: str) -> Dict[str, Any]:
    r = requests.get(url, timeout=5, allow_redirects=False, headers={'Accept': 'application/json'})
    if r.status_code != 200:
        raise RuntimeError(f'{url} answered {r.status_code}')
    return r.json()


def _discover(issuer: str) -> Dict[str, Any]:
    meta = _get_json(issuer.rstrip('/') + '/.well-known/openid-configuration')
    if meta.get('issuer') != issuer:
        raise TouchQueConfigException("the identity provider's metadata does not match its issuer")
    return meta


class IdJagVerifier:
    """Checks the ID-JAG an authenticated client presents at your authorization server (jwt-bearer grant)."""

    def __init__(self, issuer: str, audience: str, jwks_uri: Optional[str] = None, clock_skew: int = 60,
                 first_use: Optional[Callable[[str, int], bool]] = None):
        if not issuer or not audience:
            raise TouchQueConfigException("IdJagVerifier needs issuer (the identity provider) and audience (your authorization server's issuer)")
        self.issuer = issuer
        self.audience = audience
        self.jwks_uri = jwks_uri
        self.skew = clock_skew
        # Records an ID-JAG's jti and says whether it is new; memory in this process by default.
        self.first_use = first_use or self._remember_once
        self._keys: Dict[str, Any] = {}
        self._keys_at = 0.0
        self._tried_at = 0.0
        self._seen: Dict[str, int] = {}
        self._lock = threading.Lock()

    def _remember_once(self, jti: str, expires_at: int) -> bool:
        now = int(time.time())
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[k]
            if jti in self._seen:
                return False
            self._seen[jti] = expires_at + self.skew
            return True

    def _load_keys(self) -> None:
        if not self.jwks_uri:
            meta = _discover(self.issuer)
            if not isinstance(meta.get('jwks_uri'), str):
                raise TouchQueConfigException('the identity provider names no jwks_uri')
            self.jwks_uri = meta['jwks_uri']
        jwks = _get_json(self.jwks_uri)
        self._keys = {k['kid']: _public_key(k) for k in jwks.get('keys', []) if k.get('kid')}
        self._keys_at = time.time()

    def _key_for(self, kid: str):
        if not self._keys_at or time.time() - self._keys_at > 600:
            self._load_keys()
        if kid not in self._keys and time.time() - self._tried_at > 60:
            self._tried_at = time.time()
            self._load_keys()
        return self._keys.get(kid)

    def verify(self, assertion: str, client_id: str) -> Dict[str, Any]:
        """The ID-JAG, checked and used once: its claims, or IdJagError (code invalid_grant)."""
        def bad(message: str) -> IdJagError:
            return IdJagError('invalid_grant', message)

        parts = assertion.split('.') if isinstance(assertion, str) else []
        if len(parts) != 3:
            raise bad('assertion is not a JWT')
        try:
            head = _json_part(parts[0])
            c = _json_part(parts[1])
            sig = _b64d(parts[2])
        except ValueError:
            raise bad('assertion is not a JWT')
        if head.get('typ') != _TYP:
            raise bad('not an ID-JAG (typ oauth-id-jag+jwt)')
        if head.get('alg') not in _ALGS or not isinstance(head.get('kid'), str):
            raise bad('unsupported signature')
        try:
            key = self._key_for(head['kid'])
        except Exception as err:  # the provider's keys could not be read
            raise IdJagError('temporarily_unavailable', f"the identity provider's keys could not be read: {err}")
        if key is None or not _verify(f'{parts[0]}.{parts[1]}'.encode(), sig, head['alg'], key):
            raise bad('signature does not verify')
        now = int(time.time())
        auds = c.get('aud') if isinstance(c.get('aud'), list) else [c.get('aud')]
        if c.get('iss') != self.issuer:
            raise bad('another issuer')
        if len(auds) != 1 or auds[0] != self.audience:
            raise bad('not for this authorization server')
        if not isinstance(c.get('client_id'), str) or c['client_id'] != client_id:
            raise bad('issued to another client')
        if not isinstance(c.get('exp'), (int, float)) or c['exp'] + self.skew < now:
            raise bad('expired')
        if not isinstance(c.get('iat'), (int, float)) or c['iat'] - self.skew > now:
            raise bad('issued in the future')
        if not isinstance(c.get('sub'), str) or not isinstance(c.get('jti'), str):
            raise bad('sub and jti are required')
        if not self.first_use(c['jti'], int(c['exp'])):
            raise bad('already used')
        scope = c.get('scope')
        return {
            'iss': c['iss'], 'sub': c['sub'], 'aud': auds[0], 'client_id': c['client_id'], 'jti': c['jti'],
            'issued_at': int(c['iat']), 'expires_at': int(c['exp']),
            'scopes': scope.split(' ') if isinstance(scope, str) and scope else [],
            'resource': c.get('resource'), 'tenant': c.get('tenant'), 'email': c.get('email'),
            'auth_time': c.get('auth_time'), 'amr': c.get('amr'), 'claims': c,
        }


def _post_form(url: str, form: Dict[str, Optional[str]], basic: Optional[tuple] = None) -> Dict[str, Any]:
    if not _safe_url(url):
        raise TouchQueConfigException(f'{url} must be an https URL')
    headers = {'Accept': 'application/json'}
    if basic:
        raw = f'{quote(basic[0], safe="")}:{quote(basic[1], safe="")}'
        headers['Authorization'] = 'Basic ' + base64.b64encode(raw.encode()).decode()
    r = requests.post(url, data={k: v for k, v in form.items() if v is not None}, headers=headers, timeout=10, allow_redirects=False)
    try:
        data = r.json()
    except ValueError:
        data = {}
    if r.status_code >= 400:
        raise IdJagError(str(data.get('error') or 'server_error'), str(data.get('error_description') or f'{url} answered {r.status_code}'), r.status_code)
    return data


def _scope_text(scope: Union[str, List[str], None]) -> Optional[str]:
    return ' '.join(scope) if isinstance(scope, (list, tuple)) else scope


def request_id_jag(*, client_id: str, client_secret: str, id_token: str, audience: str, issuer: Optional[str] = None,
                   token_endpoint: Optional[str] = None, resource: Optional[str] = None,
                   scope: Union[str, List[str], None] = None) -> Dict[str, Any]:
    """Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic):
    ``{'assertion', 'expires_in', 'scope'}``."""
    if not token_endpoint:
        if not issuer:
            raise TouchQueConfigException('request_id_jag needs issuer or token_endpoint')
        token_endpoint = _discover(issuer).get('token_endpoint')
        if not isinstance(token_endpoint, str):
            raise TouchQueConfigException('the identity provider names no token_endpoint')
    data = _post_form(token_endpoint, {
        'grant_type': TOKEN_EXCHANGE_GRANT, 'requested_token_type': ID_JAG_TOKEN_TYPE,
        'subject_token': id_token, 'subject_token_type': ID_TOKEN_TYPE,
        'audience': audience, 'resource': resource, 'scope': _scope_text(scope),
    }, (client_id, client_secret))
    if data.get('issued_token_type') != ID_JAG_TOKEN_TYPE or not isinstance(data.get('access_token'), str):
        raise IdJagError('invalid_response', 'the identity provider did not answer with an ID-JAG')
    return {'assertion': data['access_token'], 'expires_in': data.get('expires_in'), 'scope': data.get('scope')}


def redeem_id_jag(*, token_endpoint: str, client_id: str, assertion: str, client_secret: Optional[str] = None,
                  resource: Optional[str] = None, scope: Union[str, List[str], None] = None) -> Dict[str, Any]:
    """Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer)."""
    form = {'grant_type': JWT_BEARER_GRANT, 'assertion': assertion, 'resource': resource, 'scope': _scope_text(scope)}
    if not client_secret:
        form['client_id'] = client_id
    return _post_form(token_endpoint, form, (client_id, client_secret) if client_secret else None)
