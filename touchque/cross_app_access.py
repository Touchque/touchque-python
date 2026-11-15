"""Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
draft-ietf-oauth-identity-assertion-authz-grant, an open standard).

An organization's identity provider (Touchque SSO) decides which of its apps
may reach which other service for its members; the app trades a member's ID
token for an ID-JAG there, then the ID-JAG for an access token at the other
service's authorization server, with no consent screen per member.

Your app, signed in with Touchque SSO (an OpenID Connect app with a secret)::

    jag = request_id_jag(issuer='https://sso.touchque.com', client_id=client_id, client_secret=secret,
                         id_token=id_token, audience='https://auth.files.example')
    tokens = redeem_id_jag(token_endpoint='https://auth.files.example/token', client_id='acme',
                           client_secret=files_secret, assertion=jag['assertion'])

Your own authorization server, taking ID-JAGs from an organization's identity provider::

    verifier = IdJagVerifier(issuer='https://sso.touchque.com', audience='https://auth.files.example')
    claims = verifier.verify(form['assertion'], client_id=authenticated_client_id)
    # claims['sub'] (the member at that identity provider), claims['email'], claims['scopes'], claims['resource']

Sender-constrained with DPoP (RFC 9449), optional: give the same key to both calls. The ID-JAG is
then bound to it (``cnf.jkt``) and is useless to anyone who copies it without the key::

    dpop_key = create_id_jag_dpop_key()
    jag = request_id_jag(..., dpop_key=dpop_key)     # jag['dpop_bound']: the identity provider bound it
    tokens = redeem_id_jag(..., assertion=jag['assertion'], dpop_key=dpop_key)

A token endpoint that answers ``use_dpop_nonce`` with a valid ``DPoP-Nonce`` (RFC 9449 nonce
syntax) gets the same request once more, with a proof that carries the nonce. The access token is
DPoP-bound too: a request with it carries a proof for that method, URL and token::

    proof = id_jag_dpop_proof(dpop_key, url, method='GET', access_token=tokens['access_token'])
    requests.get(url, headers={'Authorization': f"DPoP {tokens['access_token']}", 'DPoP': proof})

An authorization server that checks DPoP proofs checks the proof (and any nonce it requires) before
``verify``, which uses up the ID-JAG's jti, and passes the proof key's thumbprint; a bound ID-JAG
without it is refused::

    claims = verifier.verify(form['assertion'], client_id=authenticated_client_id, dpop_jkt=proof_jkt)

Needs the optional ``cryptography`` package for verifying and for DPoP: ``pip install "touchque-authenticator[agent]"``.
"""

import base64
import hashlib
import re
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import quote, urlparse, urlsplit

import requests

from .agent import _b64url, _crypto, _json, _public_jwk, jwk_thumbprint
from .exceptions import TouchqueConfigException
from .mcp_auth import _json_part, _b64d, _public_key, _verify

__all__ = [
    'ID_JAG_TOKEN_TYPE', 'ID_TOKEN_TYPE', 'TOKEN_EXCHANGE_GRANT', 'JWT_BEARER_GRANT',
    'IdJagError', 'IdJagVerifier', 'IdJagDpopKey', 'create_id_jag_dpop_key', 'id_jag_dpop_proof',
    'request_id_jag', 'redeem_id_jag',
]

ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag'
ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token'
TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
_TYP = 'oauth-id-jag+jwt'
_ALGS = ('RS256', 'ES256', 'EdDSA')
_DEFAULT_PORTS = {'http': 80, 'https': 443}
# RFC 9110 token characters (an HTTP method, an auth-scheme, an auth-param name).
_HTTP_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_METHOD = re.compile(_HTTP_TOKEN)
# RFC 9449 section 8: DPoP-Nonce = 1*NQCHAR, NQCHAR = %x21 / %x23-5B / %x5D-7E (printable ASCII
# except space, double quote and backslash).
_NONCE = re.compile(r'[\x21\x23-\x5b\x5d-\x7e]+')
# A DPoP challenge (RFC 9449 section 9) with error use_dpop_nonce, among any others in WWW-Authenticate.
# A search takes time linear in the header's length (the tests time 64 KB headers).
_NONCE_CHALLENGE = re.compile(
    r'(?:^|,)\s*(?i:dpop)\s+(?:' + _HTTP_TOKEN + r'\s*=\s*(?:"(?:[^"\\]|\\.)*"|' + _HTTP_TOKEN + r')\s*,\s*)*'
    r'(?i:error)\s*=\s*(?:"use_dpop_nonce"|use_dpop_nonce)\s*(?:,|$)')


class IdJagError(Exception):
    """A refused ID-JAG or exchange; ``code`` is the OAuth error (invalid_grant for a bad ID-JAG).
    ``dpop_nonce`` is the latest valid ``DPoP-Nonce`` (RFC 9449) the server sent during the call (the
    retried request's answer's, else the first answer's), for a retry by hand; ``None`` without one."""

    def __init__(self, code: str, message: str, status: Optional[int] = None, dpop_nonce: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.dpop_nonce = dpop_nonce


class IdJagDpopKey:
    """A DPoP key (RFC 9449, P-256) that binds an ID-JAG to its holder; keep it in this process."""

    def __init__(self, private_key: Any, public_jwk: Dict[str, Any], thumbprint: str):
        self.private_key = private_key
        self.public_jwk = public_jwk
        # RFC 7638 thumbprint: the ID-JAG's cnf.jkt.
        self.thumbprint = thumbprint

    def __repr__(self) -> str:
        return f'IdJagDpopKey(thumbprint={self.thumbprint!r})'


def create_id_jag_dpop_key() -> IdJagDpopKey:
    """A fresh DPoP key for ``request_id_jag`` and ``redeem_id_jag``."""
    _, _, ec, _, _ = _crypto()
    key = ec.generate_private_key(ec.SECP256R1())
    public = _public_jwk(key)
    return IdJagDpopKey(key, public, jwk_thumbprint(public))


def _htu(url: str) -> str:
    # htu (RFC 9449), not a full WHATWG URL normalization: scheme and host lowercased, user info and
    # the default port dropped, '/' for an empty path, the path kept as given (no dot-segment removal,
    # no re-encoding), no query or fragment. urllib.parse.urlsplit splits the URL.
    if not isinstance(url, str):
        raise TouchqueConfigException(f'{url!r} is not an absolute http(s) URL')
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:  # urlsplit refuses it (such as an unbalanced [) or cannot read its port (such as 99999)
        raise TouchqueConfigException(f'{url} is not an absolute http(s) URL') from None
    if u.scheme not in _DEFAULT_PORTS or not u.hostname:
        raise TouchqueConfigException(f'{url} is not an absolute http(s) URL')
    host = f'[{u.hostname}]' if ':' in u.hostname else u.hostname
    if port is not None and port != _DEFAULT_PORTS[u.scheme]:
        host = f'{host}:{port}'
    return f'{u.scheme}://{host}{u.path or "/"}'


def _htm(method: Optional[str]) -> str:
    # htm: the method trimmed and uppercased, POST when empty. RFC 9110 token characters only, checked
    # before uppercasing (str.upper() turns some non-ASCII letters into ASCII ones: U+017F into 'S').
    text = '' if method is None else method.strip() if isinstance(method, str) else None
    if text == '':
        return 'POST'
    if text is None or not _METHOD.fullmatch(text):
        raise TouchqueConfigException(f'{method!r} is not an HTTP method: RFC 9110 token characters only')
    return text.upper()


def id_jag_dpop_proof(key: IdJagDpopKey, url: str, *, method: str = 'POST', access_token: Optional[str] = None,
                      nonce: Optional[str] = None) -> str:
    """A DPoP proof (RFC 9449) for one request to ``url``: by default the POST to a token endpoint.

    For a request with the DPoP-bound access token, give its ``method`` and the ``access_token``
    (``ath``) and send ``Authorization: DPoP <access_token>`` with the proof. ``nonce``: the
    server's ``DPoP-Nonce``.

    ``htm`` is ``method`` trimmed and uppercased, POST when empty; a method with a character that is
    not an RFC 9110 token character raises TouchqueConfigException. ``htu`` is ``url`` with the scheme
    and host lowercased, user info and the default port dropped, ``/`` for an empty path, the path
    kept as given and no query or fragment; a URL without an http or https scheme or without a host,
    or one ``urllib.parse.urlsplit`` refuses or whose port it cannot read, raises
    TouchqueConfigException. The header's ``jwk`` is the key's ``kty``, ``crv``, ``x`` and ``y`` only."""
    hashes, _, ec, _, decode_dss_signature = _crypto()
    jwk = key.public_jwk
    header = {'typ': 'dpop+jwt', 'alg': 'ES256', 'jwk': {'kty': jwk['kty'], 'crv': jwk['crv'], 'x': jwk['x'], 'y': jwk['y']}}
    claims: Dict[str, Any] = {'htm': _htm(method), 'htu': _htu(url), 'iat': int(time.time()), 'jti': str(uuid.uuid4())}
    if access_token is not None:
        claims['ath'] = _b64url(hashlib.sha256(access_token.encode('ascii')).digest())
    if nonce is not None:
        claims['nonce'] = nonce
    signing_input = f'{_b64url(_json(header).encode())}.{_b64url(_json(claims).encode())}'
    r, s = decode_dss_signature(key.private_key.sign(signing_input.encode('ascii'), ec.ECDSA(hashes.SHA256())))
    return f"{signing_input}.{_b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


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
        raise TouchqueConfigException("the identity provider's metadata does not match its issuer")
    return meta


class IdJagVerifier:
    """Checks the ID-JAG an authenticated client presents at your authorization server (jwt-bearer grant)."""

    def __init__(self, issuer: str, audience: str, jwks_uri: Optional[str] = None, clock_skew: int = 60,
                 first_use: Optional[Callable[[str, int], bool]] = None):
        if not issuer or not audience:
            raise TouchqueConfigException("IdJagVerifier needs issuer (the identity provider) and audience (your authorization server's issuer)")
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
                raise TouchqueConfigException('the identity provider names no jwks_uri')
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

    def verify(self, assertion: str, client_id: str, dpop_jkt: Optional[str] = None) -> Dict[str, Any]:
        """The ID-JAG, checked and used once: its claims, or IdJagError (code invalid_grant).

        ``dpop_jkt``: the thumbprint of the DPoP proof you verified on this request, if any; an
        ID-JAG bound to a key (``cnf.jkt``) is refused without a matching one. Check the proof (and
        any nonce you require) before calling this: a call that accepts the ID-JAG uses up its jti."""
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
        # Before the jti is spent: a copy without the key cannot use the ID-JAG up.
        cnf_jkt = None
        if 'cnf' in c:
            cnf = c['cnf']
            if not isinstance(cnf, dict) or not isinstance(cnf.get('jkt'), str):
                raise bad('unsupported confirmation method (only DPoP cnf.jkt)')
            if not dpop_jkt:
                raise bad('bound to a DPoP key: a DPoP proof with that key is required')
            if dpop_jkt != cnf['jkt']:
                raise bad('the DPoP proof was made with another key')
            cnf_jkt = cnf['jkt']
        if not self.first_use(c['jti'], int(c['exp'])):
            raise bad('already used')
        scope = c.get('scope')
        return {
            'iss': c['iss'], 'sub': c['sub'], 'aud': auds[0], 'client_id': c['client_id'], 'jti': c['jti'],
            'issued_at': int(c['iat']), 'expires_at': int(c['exp']),
            'scopes': scope.split(' ') if isinstance(scope, str) and scope else [],
            'resource': c.get('resource'), 'tenant': c.get('tenant'), 'email': c.get('email'),
            'auth_time': c.get('auth_time'), 'amr': c.get('amr'), 'cnf_jkt': cnf_jkt, 'claims': c,
        }


def _dpop_nonce(r: requests.Response) -> Optional[str]:
    # The answer's DPoP-Nonce when it is one valid nonce; None when it is missing, empty, repeated
    # (requests joins repeated headers with ', ', which is not a nonce) or not nonce syntax.
    value = r.headers.get('DPoP-Nonce')
    if not isinstance(value, str):
        return None
    value = value.strip(' \t')  # spaces and tabs around a field value are not part of it (RFC 9110 OWS)
    return value if _NONCE.fullmatch(value) else None


def _wants_nonce(r: requests.Response, data: Dict[str, Any]) -> bool:
    # RFC 9449 section 8: 400 use_dpop_nonce; section 9: 401 with a DPoP challenge that says so.
    if r.status_code not in (400, 401):
        return False
    if data.get('error') == 'use_dpop_nonce':
        return True
    challenges = r.headers.get('WWW-Authenticate')
    return r.status_code == 401 and isinstance(challenges, str) and _NONCE_CHALLENGE.search(challenges) is not None


def _post_form(url: str, form: Dict[str, Optional[str]], basic: Optional[tuple] = None,
               dpop_key: Optional[IdJagDpopKey] = None) -> Dict[str, Any]:
    if not _safe_url(url):
        raise TouchqueConfigException(f'{url} must be an https URL')
    headers = {'Accept': 'application/json'}
    if basic:
        raw = f'{quote(basic[0], safe="")}:{quote(basic[1], safe="")}'
        headers['Authorization'] = 'Basic ' + base64.b64encode(raw.encode()).decode()
    body = {k: v for k, v in form.items() if v is not None}

    def send(nonce: Optional[str] = None) -> Tuple[requests.Response, Dict[str, Any]]:
        if dpop_key is not None:
            headers['DPoP'] = id_jag_dpop_proof(dpop_key, url, nonce=nonce)  # a fresh jti and iat every time
        r = requests.post(url, data=body, headers=headers, timeout=10, allow_redirects=False)
        try:
            data = r.json()
        except ValueError:
            data = None
        return r, data if isinstance(data, dict) else {}

    r, data = send()
    nonce = _dpop_nonce(r)
    if dpop_key is not None and nonce is not None and _wants_nonce(r, data):
        # The server wants its nonce in the proof: the same request once more, never again.
        r, data = send(nonce)
        nonce = _dpop_nonce(r) or nonce  # the latest valid nonce the server sent
    if r.status_code >= 400:
        raise IdJagError(str(data.get('error') or 'server_error'), str(data.get('error_description') or f'{url} answered {r.status_code}'),
                         r.status_code, nonce)
    return data


def _scope_text(scope: Union[str, List[str], None]) -> Optional[str]:
    return ' '.join(scope) if isinstance(scope, (list, tuple)) else scope


def request_id_jag(*, client_id: str, client_secret: str, id_token: str, audience: str, issuer: Optional[str] = None,
                   token_endpoint: Optional[str] = None, resource: Optional[str] = None,
                   scope: Union[str, List[str], None] = None, dpop_key: Optional[IdJagDpopKey] = None) -> Dict[str, Any]:
    """Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic):
    ``{'assertion', 'expires_in', 'scope'}``. With ``dpop_key`` the ID-JAG is bound to that key (redeem it
    with the same key) and ``dpop_bound`` says whether the returned ID-JAG carries its thumbprint."""
    if not token_endpoint:
        if not issuer:
            raise TouchqueConfigException('request_id_jag needs issuer or token_endpoint')
        token_endpoint = _discover(issuer).get('token_endpoint')
        if not isinstance(token_endpoint, str):
            raise TouchqueConfigException('the identity provider names no token_endpoint')
    data = _post_form(token_endpoint, {
        'grant_type': TOKEN_EXCHANGE_GRANT, 'requested_token_type': ID_JAG_TOKEN_TYPE,
        'subject_token': id_token, 'subject_token_type': ID_TOKEN_TYPE,
        'audience': audience, 'resource': resource, 'scope': _scope_text(scope),
    }, (client_id, client_secret), dpop_key)
    if data.get('issued_token_type') != ID_JAG_TOKEN_TYPE or not isinstance(data.get('access_token'), str):
        raise IdJagError('invalid_response', 'the identity provider did not answer with an ID-JAG')
    out = {'assertion': data['access_token'], 'expires_in': data.get('expires_in'), 'scope': data.get('scope')}
    if dpop_key is not None:
        # An identity provider without DPoP support ignores the proof: say so instead of guessing.
        parts = data['access_token'].split('.')
        try:
            cnf = _json_part(parts[1]).get('cnf') if len(parts) == 3 else None
        except ValueError:
            cnf = None
        out['dpop_bound'] = isinstance(cnf, dict) and cnf.get('jkt') == dpop_key.thumbprint
    return out


def redeem_id_jag(*, token_endpoint: str, client_id: str, assertion: str, client_secret: Optional[str] = None,
                  resource: Optional[str] = None, scope: Union[str, List[str], None] = None,
                  dpop_key: Optional[IdJagDpopKey] = None) -> Dict[str, Any]:
    """Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer).
    With ``dpop_key`` (the key the ID-JAG is bound to) a DPoP proof goes along; the access token is then
    DPoP-bound too."""
    form = {'grant_type': JWT_BEARER_GRANT, 'assertion': assertion, 'resource': resource, 'scope': _scope_text(scope)}
    if not client_secret:
        form['client_id'] = client_id
    return _post_form(token_endpoint, form, (client_id, client_secret) if client_secret else None, dpop_key)
