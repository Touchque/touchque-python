"""For an MCP server whose authorization server is Touchque SSO (Organization
→ MCP servers in the dashboard; issuer https://sso.touchque.com/mcp):

- ``protected_resource_metadata()`` is its RFC 9728 document, served at the
  paths ``metadata_paths()`` gives, so MCP clients find Touchque and ask for a
  token for exactly this server;
- ``verify(method, url, headers)`` checks a request's token: signed by
  Touchque (its JWKS), this issuer, audience = this server's URL (RFC 8707),
  not expired, and for a DPoP-bound token a fresh proof for this request;
  ``McpAuthError`` carries the status (401, 403) and the WWW-Authenticate
  header to send;
- ``require_tool(claims, tool)`` raises 403 insufficient_scope naming the
  scope a tool needs, so the client asks the member for more;
- ``verify_token(token)`` checks a bearer token alone (FastMCP's
  TokenVerifier gets only the token).

    auth = McpAuth(issuer='https://sso.touchque.com/mcp', resource='https://mcp.acme.com/mcp',
                   tools={'search_tickets': 'tickets:read', 'delete_ticket': 'tickets:delete'})

Needs the optional ``cryptography`` package: ``pip install "touchque-authenticator[agent]"``.
"""
import base64
import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlparse

import requests

from .exceptions import TouchqueConfigException

__all__ = ['McpAuth', 'McpAuthError']


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _json_part(part: str) -> Dict[str, Any]:
    value = json.loads(_b64d(part))
    if not isinstance(value, dict):
        raise ValueError('not an object')
    return value


class McpAuthError(Exception):
    """A refused request: send ``status`` with the ``www_authenticate`` header."""

    def __init__(self, status: int, code: str, message: str, www_authenticate: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.www_authenticate = www_authenticate


def _public_key(jwk: Mapping[str, Any]):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    if jwk.get('kty') == 'RSA':
        return rsa.RSAPublicNumbers(int.from_bytes(_b64d(jwk['e']), 'big'), int.from_bytes(_b64d(jwk['n']), 'big')).public_key()
    if jwk.get('kty') == 'EC' and jwk.get('crv') == 'P-256':
        return ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk['x']), 'big'), int.from_bytes(_b64d(jwk['y']), 'big'), ec.SECP256R1()).public_key()
    if jwk.get('kty') == 'OKP' and jwk.get('crv') == 'Ed25519':
        return ed25519.Ed25519PublicKey.from_public_bytes(_b64d(jwk['x']))
    raise ValueError('unsupported key')


def _verify(signing_input: bytes, sig: bytes, alg: str, key) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        if alg == 'RS256':
            key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        elif alg == 'ES256':
            if len(sig) != 64:
                return False
            key.verify(encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), signing_input, ec.ECDSA(hashes.SHA256()))
        elif alg == 'EdDSA':
            key.verify(sig, signing_input)
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _thumbprint(jwk: Mapping[str, Any]) -> str:
    if jwk.get('kty') == 'EC':
        members = {'crv': jwk['crv'], 'kty': 'EC', 'x': jwk['x'], 'y': jwk['y']}
    elif jwk.get('kty') == 'RSA':
        members = {'e': jwk['e'], 'kty': 'RSA', 'n': jwk['n']}
    else:
        members = {'crv': jwk['crv'], 'kty': jwk['kty'], 'x': jwk['x']}
    return _b64e(hashlib.sha256(json.dumps(members, separators=(',', ':')).encode()).digest())


class McpAuth:
    """See the module docstring."""

    def __init__(self, issuer: str, resource: str, tools: Optional[Dict[str, str]] = None,
                 resource_name: Optional[str] = None, clock_skew: int = 60):
        if not issuer or not resource:
            raise TouchqueConfigException("McpAuth needs issuer (Touchque SSO's MCP issuer) and resource (this server's URL)")
        self.issuer = issuer.rstrip('/')
        self.resource = resource
        self.tools = dict(tools or {})
        self.resource_name = resource_name
        self.skew = clock_skew
        self._keys: Dict[str, Any] = {}
        self._keys_at = 0.0
        self._tried_at = 0.0
        self._proofs: Dict[str, float] = {}
        self._lock = threading.Lock()

    def metadata_paths(self) -> List[str]:
        path = urlparse(self.resource).path.rstrip('/')
        return ['/.well-known/oauth-protected-resource'] + ([f'/.well-known/oauth-protected-resource{path}'] if path else [])

    def metadata_url(self) -> str:
        u = urlparse(self.resource)
        return f'{u.scheme}://{u.netloc}{self.metadata_paths()[-1]}'

    def protected_resource_metadata(self) -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            'resource': self.resource, 'authorization_servers': [self.issuer], 'bearer_methods_supported': ['header'],
            'scopes_supported': list(dict.fromkeys(self.tools.values())), 'dpop_signing_alg_values_supported': ['ES256', 'EdDSA'],
        }
        if self.resource_name:
            doc['resource_name'] = self.resource_name
        return doc

    def _fail(self, status: int, code: str, message: str, scope: Optional[str] = None) -> McpAuthError:
        parts = [f'resource_metadata="{self.metadata_url()}"']
        if code != 'missing_token':
            parts.append(f'error="{code}"')
            parts.append('error_description="{}"'.format(message.replace('"', "'")))
            if scope:
                parts.append(f'scope="{scope}"')
        return McpAuthError(status, code, message, 'Bearer ' + ', '.join(parts))

    def _load_keys(self) -> None:
        u = urlparse(self.issuer)
        meta = requests.get(f'{u.scheme}://{u.netloc}/.well-known/oauth-authorization-server{u.path.rstrip("/")}', timeout=5).json()
        if str(meta.get('issuer', '')).rstrip('/') != self.issuer or not meta.get('jwks_uri'):
            raise ValueError('the authorization server metadata does not match the issuer')
        jwks = requests.get(meta['jwks_uri'], timeout=5).json()
        self._keys = {k['kid']: _public_key(k) for k in jwks.get('keys', []) if k.get('kid')}
        self._keys_at = time.time()

    def _key_for(self, kid: str):
        with self._lock:
            if not self._keys_at or time.time() - self._keys_at > 600:
                self._load_keys()
            if kid not in self._keys and time.time() - self._tried_at > 60:
                self._tried_at = time.time()
                self._load_keys()
            return self._keys.get(kid)

    def _claims(self, token: str) -> Dict[str, Any]:
        try:
            h, p, s = token.split('.')
            head, claims, sig = _json_part(h), _json_part(p), _b64d(s)
        except ValueError:
            raise self._fail(401, 'invalid_token', 'The token is malformed')
        if head.get('typ') != 'at+jwt' or head.get('alg') not in ('RS256', 'ES256'):
            raise self._fail(401, 'invalid_token', 'Not a Touchque access token')
        try:
            key = self._key_for(str(head.get('kid', '')))
        except Exception:
            raise self._fail(401, 'invalid_token', "The authorization server's keys could not be read")
        if key is None or not _verify(f'{h}.{p}'.encode('ascii'), sig, head['alg'], key):
            raise self._fail(401, 'invalid_token', 'The token signature does not verify')
        if str(claims.get('iss', '')).rstrip('/') != self.issuer:
            raise self._fail(401, 'invalid_token', 'The token is from another issuer')
        aud = claims.get('aud')
        if self.resource not in (aud if isinstance(aud, list) else [aud]):
            raise self._fail(401, 'invalid_token', 'The token is for another server')
        if not isinstance(claims.get('exp'), (int, float)) or claims['exp'] + self.skew <= time.time():
            raise self._fail(401, 'invalid_token', 'The token expired')
        return claims

    @staticmethod
    def _view(claims: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'sub': str(claims.get('sub')), 'email': claims.get('email'), 'client_id': claims.get('client_id', ''),
            'scopes': [x for x in str(claims.get('scope', '')).split(' ') if x], 'org_id': claims.get('org_id'),
            'expires_at': claims['exp'], 'dpop_bound': bool((claims.get('cnf') or {}).get('jkt')), 'claims': claims,
        }

    def verify_token(self, token: str) -> Dict[str, Any]:
        """A bearer token alone (FastMCP's TokenVerifier): a DPoP-bound one is refused here."""
        claims = self._claims(token)
        if (claims.get('cnf') or {}).get('jkt'):
            raise self._fail(401, 'invalid_token', 'This token is bound to a DPoP key: use verify() with the request')
        return self._view(claims)

    def verify(self, method: str, url: str, headers: Mapping[str, str]) -> Dict[str, Any]:
        """A request's token, checked: ``{'sub', 'email', 'client_id', 'scopes', 'org_id', 'expires_at', 'dpop_bound', 'claims'}``."""
        lower = {k.lower(): v for k, v in headers.items()}
        scheme, _, token = str(lower.get('authorization', '')).strip().partition(' ')
        if scheme.lower() not in ('bearer', 'dpop') or token.count('.') != 2:
            raise self._fail(401, 'missing_token', 'A Touchque access token is required')
        claims = self._claims(token.strip())
        jkt = (claims.get('cnf') or {}).get('jkt')
        if jkt:
            if scheme.lower() != 'dpop':
                raise self._fail(401, 'invalid_token', 'This token is bound to a DPoP key: send it as DPoP with a proof')
            self._check_proof(lower.get('dpop'), method, url, token.strip(), jkt)
        return self._view(claims)

    def _check_proof(self, proof: Optional[str], method: str, url: str, token: str, jkt: str) -> None:
        try:
            if not proof:
                raise ValueError('missing')
            h, p, s = proof.split('.')
            head, claims = _json_part(h), _json_part(p)
            jwk = head.get('jwk') or {}
            if head.get('typ') != 'dpop+jwt' or 'd' in jwk or _thumbprint(jwk) != jkt:
                raise ValueError('not the bound key')
            if not _verify(f'{h}.{p}'.encode('ascii'), _b64d(s), head.get('alg', ''), _public_key(jwk)):
                raise ValueError('signature')
            u = urlparse(url)
            if claims.get('htm') != method.upper() or claims.get('htu') != f'{u.scheme}://{u.netloc}{u.path}':
                raise ValueError('htm/htu')
            if abs(claims.get('iat', 0) - time.time()) > self.skew:
                raise ValueError('iat')
            if claims.get('ath') != _b64e(hashlib.sha256(token.encode('ascii')).digest()):
                raise ValueError('ath')
            now = time.time()
            with self._lock:
                for k in [k for k, until in self._proofs.items() if until < now]:
                    del self._proofs[k]
                if not claims.get('jti') or claims['jti'] in self._proofs:
                    raise ValueError('jti used')
                self._proofs[claims['jti']] = now + 2 * self.skew
        except McpAuthError:
            raise
        except Exception as e:
            raise self._fail(401, 'invalid_dpop_proof', f'DPoP proof: {e}')

    def require_scope(self, claims: Mapping[str, Any], scope: str) -> None:
        if scope not in claims.get('scopes', []):
            raise self._fail(403, 'insufficient_scope', f'This needs the {scope} scope', scope)

    def require_tool(self, claims: Mapping[str, Any], tool: str) -> None:
        scope = self.tools.get(tool)
        if not scope:
            raise self._fail(403, 'insufficient_scope', f'No scope is set for the tool {tool}')
        self.require_scope(claims, scope)
