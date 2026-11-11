"""McpAuth (an MCP server whose authorization server is Touchque SSO) against
the shared fake API's MCP issuer: metadata, audience, issuer, expiry, scopes
per tool, DPoP-bound tokens and their proofs."""
import base64
import hashlib
import json
import time
import urllib.request
import uuid

import pytest

from touchque import McpAuth, McpAuthError
from .fake_api import fake_api  # noqa: F401 (fixture)

RESOURCE = 'https://mcp.acme.example/mcp'


def _post(api, path, body):
    req = urllib.request.Request(api.base_url + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    return json.loads(urllib.request.urlopen(req).read() or b'{}')


def _token(api, **claims):
    return _post(api, '/__test/mcp-token', {'aud': RESOURCE, 'scope': 'tickets:read', **claims})['token']


def _auth(api):
    return McpAuth(issuer=api.base_url + '/mcp-as', resource=RESOURCE, tools={'search_tickets': 'tickets:read', 'delete_ticket': 'tickets:delete'})


def test_metadata(fake_api):
    a = _auth(fake_api)
    assert a.metadata_paths() == ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']
    assert a.protected_resource_metadata()['authorization_servers'] == [fake_api.base_url + '/mcp-as']


def test_tokens_and_scopes(fake_api):
    a = _auth(fake_api)
    claims = a.verify('POST', RESOURCE, {'Authorization': 'Bearer ' + _token(fake_api)})
    assert claims['sub'] == 'user-1' and claims['scopes'] == ['tickets:read'] and claims['dpop_bound'] is False
    a.require_tool(claims, 'search_tickets')
    with pytest.raises(McpAuthError) as e:
        a.require_tool(claims, 'delete_ticket')
    assert e.value.status == 403 and 'scope="tickets:delete"' in e.value.www_authenticate
    with pytest.raises(McpAuthError) as e:
        a.verify('POST', RESOURCE, {})
    assert e.value.status == 401 and e.value.www_authenticate == 'Bearer resource_metadata="https://mcp.acme.example/.well-known/oauth-protected-resource/mcp"'
    for bad in (_token(fake_api, aud='https://other.example/mcp'), _token(fake_api, iss='https://evil.example/mcp'), _token(fake_api, expiresIn=-120), _token(fake_api, typ='JWT')):
        with pytest.raises(McpAuthError):
            a.verify('POST', RESOURCE, {'Authorization': 'Bearer ' + bad})
    assert a.verify_token(_token(fake_api))['client_id'] == 'https://tool.example/client.json'
    # A signature segment that is not base64url (the kid is real: kids are public) is a 401, never a ValueError.
    head_and_body = _token(fake_api).rsplit('.', 1)[0]
    for sig in ('é', 'a'):
        with pytest.raises(McpAuthError) as e:
            a.verify('POST', RESOURCE, {'Authorization': f'Bearer {head_and_body}.{sig}'})
        assert e.value.status == 401 and e.value.code == 'invalid_token'


def test_dpop_bound(fake_api):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    a = _auth(fake_api)
    key = ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()  # noqa: E731
    jwk = {'kty': 'EC', 'crv': 'P-256', 'x': b64(n.x.to_bytes(32, 'big')), 'y': b64(n.y.to_bytes(32, 'big'))}
    jkt = b64(hashlib.sha256(json.dumps({'crv': 'P-256', 'kty': 'EC', 'x': jwk['x'], 'y': jwk['y']}, separators=(',', ':')).encode()).digest())
    token = _token(fake_api, jkt=jkt)

    def proof(htu=RESOURCE):
        h = b64(json.dumps({'typ': 'dpop+jwt', 'alg': 'ES256', 'jwk': jwk}).encode())
        p = b64(json.dumps({'htm': 'POST', 'htu': htu, 'iat': int(time.time()), 'jti': str(uuid.uuid4()), 'ath': b64(hashlib.sha256(token.encode()).digest())}).encode())
        r, s = decode_dss_signature(key.sign(f'{h}.{p}'.encode(), ec.ECDSA(hashes.SHA256())))
        return f'{h}.{p}.{b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}'

    with pytest.raises(McpAuthError):
        a.verify('POST', RESOURCE, {'Authorization': 'Bearer ' + token})
    good = proof()
    assert a.verify('POST', RESOURCE, {'Authorization': 'DPoP ' + token, 'DPoP': good})['dpop_bound'] is True
    with pytest.raises(McpAuthError) as e:
        a.verify('POST', RESOURCE, {'Authorization': 'DPoP ' + token, 'DPoP': good})
    assert e.value.code == 'invalid_dpop_proof'
    with pytest.raises(McpAuthError):
        a.verify('POST', RESOURCE, {'Authorization': 'DPoP ' + token, 'DPoP': proof('https://other.example/mcp')})
