"""An organization's AI agent on Touchque SSO (Organization → AI agents in the
dashboard): it gets 5-minute tokens for one of the organization's apps,
proving who it is with its own key (private_key_jwt) or with the token its
platform already gives it (GitHub Actions, GitLab, Google Cloud, Azure,
Kubernetes), and binds each token to a DPoP key made when it starts. The app
checks the token with Touchque's JWKS and the DPoP proof on every call.

    agent = TouchqueOrgAgent(agent_id='oagt_...', private_key=os.environ['TQ_ORG_AGENT_KEY'])
    response = agent.request('GET', 'https://payments.acme.com/invoices', resource='tqapp_...')

    # In a GitHub Actions job (permissions: id-token: write), with no key to store:
    agent = TouchqueOrgAgent(agent_id='oagt_...', assertion=github_actions_token('touchque'))

Acting for a member, when its admin allowed it (Organization → AI agents → Access):

    token = agent.exchange_token(subject_token=members_access_token, resource='tqapp_...')    # RFC 8693
    ask = agent.ask_member('ada@acme.com', binding_message='Pay invoice 42', authorization_details=[payment])
    reply(f"Type {ask['binding_code']} in the Touchque app.")
    approved = agent.wait_for_member(ask)                                                     # CIBA, poll mode

The token vault: a member's own account at another service they connected on Touchque, a fresh
provider token (never the refresh token)::

    google = agent.get_connection_token(members_access_token, 'google')

A shared account (a site with only a password): the member's own Touchque extension signs in, in their
browser, after their phone approves with the agent named; the agent never sees the password::

    ask = agent.ask_to_open_shared_account('k3J...', 'ada@acme.com', message='Post the launch photo')
    reply(f"Open {ask['open_url']} in your browser to let me in.")
    result = agent.wait_for_shared_account(ask)   # status: opened | refused | declined | expired

Needs the optional ``cryptography`` package: ``pip install "touchque-authenticator[agent]"``.
"""
import hashlib
import os
import re
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional, Tuple, Union
from urllib.parse import urlparse

import requests

from .agent import AGENT_ASSERTION_TYPE, TouchqueAgent, _b64url, _crypto, _json, _load_private_key, _public_jwk, jwk_thumbprint
from .exceptions import TouchqueAPIException, TouchqueConfigException, TouchqueNetworkException, TouchqueTimeoutException

__all__ = ['TouchqueOrgAgent', 'github_actions_token', 'file_token']

_ORG_AGENT_ID = re.compile(r'^oagt_[a-z2-9]{20}$')
_LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}
_CIBA_GRANT = 'urn:openid:params:grant-type:ciba'
_TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
_ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
_CONNECTION_TOKEN_TYPE = 'urn:touchque:params:oauth:token-type:connection-access-token'


def github_actions_token(audience: str = 'touchque') -> Callable[[], str]:
    """The token a GitHub Actions job may ask for (the job needs ``permissions: id-token: write``)."""
    def fetch() -> str:
        url = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL')
        bearer = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
        if not url or not bearer:
            raise TouchqueConfigException('Not in a GitHub Actions job with `permissions: id-token: write`')
        response = requests.get(url, params={'audience': audience}, headers={'Authorization': f'Bearer {bearer}'}, timeout=10)
        value = response.json().get('value') if response.ok else None
        if not value:
            raise TouchqueConfigException('GitHub gave no token')
        return value
    return fetch


def file_token(path: str) -> Callable[[], str]:
    """A token the platform writes to a file and renews (a Kubernetes projected service account token...)."""
    def read() -> str:
        with open(path, encoding='utf-8') as f:
            return f.read().strip()
    return read


class TouchqueOrgAgent:
    """An organization's AI agent (see the module docstring)."""

    def __init__(self, agent_id: Optional[str] = None, private_key: Union[Dict[str, Any], str, Any, None] = None,
                 kid: Optional[str] = None, assertion: Optional[Callable[[], str]] = None, issuer: Optional[str] = None,
                 resource: Optional[str] = None, scope: Optional[str] = None, timeout: int = 10000):
        agent_id = agent_id if agent_id is not None else os.environ.get('TQ_ORG_AGENT_ID', '')
        if not _ORG_AGENT_ID.match(agent_id or ''):
            raise TouchqueConfigException('Set TQ_ORG_AGENT_ID (or pass agent_id): the oagt_... id from Organization → AI agents')
        self.agent_id = agent_id
        self.issuer = (issuer or os.environ.get('TQ_SSO_URL') or 'https://sso.touchque.com').rstrip('/')
        parsed = urlparse(self.issuer)
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and (parsed.hostname or '') in _LOCAL_HOSTS):
            raise TouchqueConfigException(f'Refusing a plaintext issuer for "{parsed.hostname}": use https://')
        self._assertion_source = assertion
        if assertion is None:
            key_input = private_key if private_key is not None else os.environ.get('TQ_ORG_AGENT_KEY')
            if not key_input:
                raise TouchqueConfigException("Pass private_key (or set TQ_ORG_AGENT_KEY), or assertion with the platform's token")
            self._key = _load_private_key(key_input)
            self._key_alg = 'EdDSA' if type(self._key).__name__.startswith('Ed25519') else 'ES256'
            given = key_input.get('kid') if isinstance(key_input, dict) else None
            self._kid = kid or given or jwk_thumbprint(_public_jwk(self._key))
        hashes, serialization, ec, ed25519, _ = _crypto()
        # The DPoP key: made here, never leaves this process.
        self._dpop_key = ec.generate_private_key(ec.SECP256R1())
        self._dpop_jwk = _public_jwk(self._dpop_key)
        self._resource = resource
        self._scope = scope
        self._timeout = timeout / 1000.0
        self._tokens: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _jws(alg: str, key: Any, header: Dict[str, Any], payload: Dict[str, Any]) -> str:
        hashes, serialization, ec, ed25519, decode_dss_signature = _crypto()
        signing_input = f"{_b64url(_json(dict(header, alg=alg)).encode())}.{_b64url(_json(payload).encode())}"
        if alg == 'EdDSA':
            sig = key.sign(signing_input.encode('ascii'))
        else:
            r, s = decode_dss_signature(key.sign(signing_input.encode('ascii'), ec.ECDSA(hashes.SHA256())))
            sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        return f'{signing_input}.{_b64url(sig)}'

    def dpop_proof(self, method: str, url: str, access_token: Optional[str] = None) -> str:
        """A DPoP proof (RFC 9449) for one request: with the token, for a call to the app."""
        u = urlparse(url)
        claims: Dict[str, Any] = {'htm': method.upper(), 'htu': f'{u.scheme}://{u.netloc}{u.path}', 'iat': int(time.time()), 'jti': str(uuid.uuid4())}
        if access_token:
            claims['ath'] = _b64url(hashlib.sha256(access_token.encode('ascii')).digest())
        return self._jws('ES256', self._dpop_key, {'typ': 'dpop+jwt', 'jwk': self._dpop_jwk}, claims)

    def _assertion(self, token_url: str) -> str:
        if self._assertion_source is not None:
            return self._assertion_source()
        now = int(time.time())
        return self._jws(self._key_alg, self._key, {'typ': 'JWT', 'kid': self._kid},
                         {'iss': self.agent_id, 'sub': self.agent_id, 'aud': token_url, 'iat': now, 'exp': now + 60, 'jti': str(uuid.uuid4())})

    def _post(self, path: str, fields: Dict[str, Any], dpop: bool) -> Dict[str, Any]:
        url = f'{self.issuer}{path}'
        form = {'client_id': self.agent_id, 'client_assertion_type': AGENT_ASSERTION_TYPE, 'client_assertion': self._assertion(f'{self.issuer}/sso/token')}
        form.update({k: v for k, v in fields.items() if v not in (None, '')})
        try:
            response = requests.post(url, data=form, headers={'DPoP': self.dpop_proof('POST', url)} if dpop else {}, timeout=self._timeout, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise TouchqueNetworkException(str(e)) from e
        if response.status_code != 200:
            raise TouchqueAgent._error(response)
        return response.json()

    @staticmethod
    def _token_of(data: Dict[str, Any]) -> Dict[str, Any]:
        token = {'access_token': data['access_token'], 'token_type': 'DPoP', 'expires_in': data.get('expires_in', 300), 'scope': data.get('scope', '')}
        if isinstance(data.get('authorization_details'), list):
            token['authorization_details'] = data['authorization_details']
        return token

    def get_token(self, resource: Optional[str] = None, scope: Optional[str] = None) -> Dict[str, Any]:
        """A token for one app (renewed 30 seconds before it expires):
        ``{'access_token', 'token_type': 'DPoP', 'expires_in', 'scope'}``."""
        resource = resource or self._resource
        scope = scope or self._scope
        cache_key = (resource or '', scope or '')
        with self._lock:
            hit = self._tokens.get(cache_key)
            if hit and hit['expires_at'] - time.time() > 30:
                return hit['token']
            token = self._token_of(self._post('/sso/token', {'grant_type': 'client_credentials', 'resource': resource, 'scope': scope}, True))
            self._tokens[cache_key] = {'token': token, 'expires_at': time.time() + token['expires_in']}
            return token

    def exchange_token(self, subject_token: str, resource: Optional[str] = None, scope: Optional[str] = None) -> Dict[str, Any]:
        """A token for a member, with their own access token for one of the
        agent's apps (RFC 8693 token exchange): sub is the member, act the agent."""
        return self._token_of(self._post('/sso/token', {
            'grant_type': _TOKEN_EXCHANGE_GRANT, 'subject_token': subject_token, 'subject_token_type': _ACCESS_TOKEN_TYPE,
            'resource': resource or self._resource, 'scope': scope or self._scope,
        }, True))

    def get_connection_token(self, subject_token: str, connection: str, scope: Optional[str] = None) -> Dict[str, Any]:
        """The token vault: a member's own access token at another service (Google, Microsoft 365,
        GitHub...) they connected on Touchque, for a connection that names this agent:
        ``{'access_token', 'token_type': 'Bearer', 'expires_in'?, 'scope', 'connection'}``.
        ``subject_token`` is the member's token, as for ``exchange_token``; ``scope`` may only narrow
        what the member granted. Touchque refreshes it; the refresh token never leaves.
        TouchqueAPIException invalid_grant: the member has not connected it (or disconnected, or left)."""
        data = self._post('/sso/token', {
            'grant_type': _TOKEN_EXCHANGE_GRANT, 'subject_token': subject_token, 'subject_token_type': _ACCESS_TOKEN_TYPE,
            'requested_token_type': _CONNECTION_TOKEN_TYPE, 'connection': connection, 'scope': scope,
        }, True)
        out = {'access_token': data['access_token'], 'token_type': 'Bearer', 'scope': data.get('scope') or '', 'connection': data.get('connection') or connection}
        if isinstance(data.get('expires_in'), int):
            out['expires_in'] = data['expires_in']
        return out

    def ask_to_open_shared_account(self, account: str, login_hint: str, message: Optional[str] = None) -> Dict[str, Any]:
        """Asks to open a shared account (its key, from Organization -> AI agents -> Access) for a member:
        ``{'ask_id', 'open_url', 'status', 'expires_in'}``. The member opens ``open_url`` in the browser
        where their Touchque extension is paired; their phone approves with this agent named and the
        extension signs in there. The agent never sees the password. ``message`` (at most 64
        characters) is shown to the member marked unverified."""
        return self._post('/sso/agents/shared-accounts/asks', {'account': account, 'login_hint': login_hint, 'binding_message': message}, False)

    def shared_account_ask_status(self, ask_id: str) -> Dict[str, Any]:
        """Where an ask stands: ``{'status', 'reason'?, 'case_code'?}``; only whether it opened, never
        anything of the account."""
        return self._post(f'/sso/agents/shared-accounts/asks/{ask_id}', {}, False)

    def wait_for_shared_account(self, ask: Dict[str, Any], interval: float = 3.0) -> Dict[str, Any]:
        """Polls an ask until it ends: opened, refused, declined or expired."""
        deadline = time.time() + int(ask.get('expires_in') or 600) + 5
        while True:
            s = self.shared_account_ask_status(ask['ask_id'])
            if s.get('status') not in ('waiting_member', 'asked_phone') or time.time() > deadline:
                return s
            time.sleep(interval)

    def ask_member(self, login_hint: str, binding_message: Optional[str] = None, authorization_details: Optional[list] = None,
                   resource: Optional[str] = None, scope: Optional[str] = None, requested_expiry: Optional[int] = None) -> Dict[str, Any]:
        """Asks a member to approve on their phone (CIBA): ``{'auth_req_id',
        'expires_in', 'interval', 'binding_code'}``. Show binding_code in the
        conversation, then ``wait_for_member``."""
        data = self._post('/sso/bc-authorize', {
            'login_hint': login_hint, 'binding_message': binding_message, 'resource': resource or self._resource, 'scope': scope or self._scope,
            'authorization_details': _json(authorization_details) if authorization_details else None,
            'requested_expiry': str(requested_expiry) if requested_expiry else None,
        }, False)
        return {'auth_req_id': data['auth_req_id'], 'expires_in': data.get('expires_in', 300), 'interval': data.get('interval', 5),
                **({'binding_code': data['binding_code']} if data.get('binding_code') else {})}

    def wait_for_member(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """The member's answer (polling at the interval, slower when asked): the
        token once they approve; TouchqueAPIException access_denied or
        expired_token otherwise, TouchqueTimeoutException after it expired."""
        interval = max(1, int(request.get('interval', 5)))
        deadline = time.time() + request.get('expires_in', 300) + 5
        while time.time() < deadline:
            time.sleep(interval)
            try:
                return self._token_of(self._post('/sso/token', {'grant_type': _CIBA_GRANT, 'auth_req_id': request['auth_req_id']}, True))
            except TouchqueAPIException as e:
                if e.code == 'authorization_pending':
                    continue
                if e.code == 'slow_down':
                    interval += 5
                    continue
                raise
        raise TouchqueTimeoutException('The member did not answer in time')

    def authorization(self, method: str, url: str, resource: Optional[str] = None, scope: Optional[str] = None) -> Dict[str, str]:
        """The two headers for one call to the app: Authorization: DPoP <token> and its proof."""
        token = self.get_token(resource, scope)['access_token']
        return {'Authorization': f'DPoP {token}', 'DPoP': self.dpop_proof(method, url, token)}

    def request(self, method: str, url: str, resource: Optional[str] = None, scope: Optional[str] = None, **kwargs) -> requests.Response:
        """``requests.request`` with the agent's token and a fresh proof."""
        headers = dict(kwargs.pop('headers', None) or {})
        headers.update(self.authorization(method, url, resource, scope))
        kwargs.setdefault('timeout', self._timeout)
        return requests.request(method, url, headers=headers, **kwargs)
