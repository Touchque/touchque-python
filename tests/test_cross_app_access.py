"""Cross App Access (ID-JAG) and A2A agent card signatures against the shared fake API: an app
trades a member's ID token for an ID-JAG at the identity provider and redeems it; an
authorization server checks one (issuer, audience, client, expiry, typ, once); DPoP proofs (the
method, ath, nonce and htu options, the jwk members) and the one retry with a server's nonce
against a local token endpoint (nonce syntax, repeated nonces, WWW-Authenticate challenges, the
latest nonce on every error, 64 KB headers); the token endpoint's statuses and bodies (only a 2xx
with a JSON object is an answer, the OAuth error code) and, on a raw socket, what requests cannot
read or reach (temporarily_unavailable) and the path it sends (the proofs' htu); a card signed in
RFC 8785 form by the fake (JavaScript) verifies here with keys from its own host and fails when
changed or pointed elsewhere."""
import base64
import hashlib
import io
import json
import socket
import struct
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests

from touchque import (
    AgentCardError, IdJagDpopKey, IdJagError, IdJagVerifier, TouchqueConfigException, canonical_json, create_id_jag_dpop_key,
    id_jag_dpop_proof, jwk_thumbprint, redeem_id_jag, request_id_jag, sign_agent_card, verify_agent_card,
)

from .fake_api import fake_api  # noqa: F401 (fixture)


def _post(api, path, body):
    req = urllib.request.Request(api.base_url + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    return json.loads(urllib.request.urlopen(req).read() or b'{}')


def _get(url):
    return json.loads(urllib.request.urlopen(url).read())


def test_request_redeem_and_verify(fake_api):
    jag = request_id_jag(issuer=fake_api.base_url + '/idp', client_id='tqapp_test', client_secret='tqs_test', id_token='idtoken:ada',
                         audience='https://rs.example', resource='https://rs.example/files')
    assert jag['scope'] == 'files:read'
    with pytest.raises(IdJagError) as e:
        request_id_jag(issuer=fake_api.base_url + '/idp', client_id='tqapp_test', client_secret='wrong', id_token='idtoken:ada', audience='https://rs.example')
    assert (e.value.code, e.value.status) == ('invalid_client', 401)
    with pytest.raises(IdJagError) as e:
        request_id_jag(issuer=fake_api.base_url + '/idp', client_id='tqapp_test', client_secret='tqs_test', id_token='idtoken:ada', audience='https://other.example')
    assert e.value.code == 'invalid_target'

    verifier = IdJagVerifier(issuer=fake_api.base_url + '/idp', audience='https://rs.example')
    claims = verifier.verify(jag['assertion'], client_id='acme-at-rs')
    assert (claims['sub'], claims['client_id'], claims['scopes'], claims['resource']) == ('ada', 'acme-at-rs', ['files:read'], 'https://rs.example/files')
    with pytest.raises(IdJagError, match='already used'):
        verifier.verify(jag['assertion'], client_id='acme-at-rs')
    tokens = redeem_id_jag(token_endpoint=fake_api.base_url + '/rs/token', client_id='acme-at-rs', assertion=jag['assertion'])
    assert tokens['token_type'] == 'Bearer'


def test_refusals(fake_api):
    verifier = IdJagVerifier(issuer=fake_api.base_url + '/idp', audience='https://rs.example')

    def mint(claims=None, typ=None):
        return _post(fake_api, '/__test/id-jag', {'claims': claims or {}, **({'typ': typ} if typ else {})})['assertion']

    def reason(assertion, client_id='acme-at-rs'):
        try:
            verifier.verify(assertion, client_id=client_id)
            return 'accepted'
        except IdJagError as err:
            return str(err)

    assert reason(mint(), 'someone-else') == 'issued to another client'
    assert reason(mint({'aud': 'https://evil.example'})) == 'not for this authorization server'
    assert reason(mint({'aud': ['https://rs.example', 'https://b.example']})) == 'not for this authorization server'
    assert reason(mint({'iss': 'https://evil.example'})) == 'another issuer'
    assert reason(mint(typ='at+jwt')) == 'not an ID-JAG (typ oauth-id-jag+jwt)'
    assert reason(mint({'exp': int(time.time()) - 600})) == 'expired'
    head, body, sig = mint().split('.')
    claims = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
    forged = base64.urlsafe_b64encode(json.dumps({**claims, 'sub': 'mallory'}).encode()).rstrip(b'=').decode()
    assert reason(f'{head}.{forged}.{sig}') == 'signature does not verify'
    # A signature segment that is not base64url is a malformed JWT, never a ValueError.
    assert reason(f'{head}.{body}.é') == 'assertion is not a JWT'
    assert reason(f'{head}.{body}.a') == 'assertion is not a JWT'


def _b64j(part):
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))


def test_dpop_bound_request_redeem_and_verify(fake_api):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    # An identity provider and an authorization server that check the proof and bind to its key.
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length') or 0))
            h, p, sig = self.headers.get('DPoP', '..').split('.')
            header, payload = _b64j(h), _b64j(p)
            jwk = header['jwk']
            pub = ec.EllipticCurvePublicNumbers(int.from_bytes(base64.urlsafe_b64decode(jwk['x'] + '=='), 'big'),
                                                int.from_bytes(base64.urlsafe_b64decode(jwk['y'] + '=='), 'big'), ec.SECP256R1()).public_key()
            raw = base64.urlsafe_b64decode(sig + '=' * (-len(sig) % 4))
            try:
                pub.verify(encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')), f'{h}.{p}'.encode(), ec.ECDSA(hashes.SHA256()))
                ok = True
            except InvalidSignature:
                ok = False
            seen.append({'path': self.path, 'header': header, 'payload': payload, 'jkt': jwk_thumbprint(jwk)})
            enc = lambda v: base64.urlsafe_b64encode(json.dumps(v).encode()).rstrip(b'=').decode()
            if not ok:
                body = {'error': 'invalid_dpop_proof'}
            elif self.path == '/idp/token?x=1':
                jag = f"{enc({'typ': 'oauth-id-jag+jwt', 'alg': 'RS256'})}.{enc({'cnf': {'jkt': jwk_thumbprint(jwk)}})}.sig"
                body = {'access_token': jag, 'issued_token_type': 'urn:ietf:params:oauth:token-type:id-jag', 'token_type': 'N_A'}
            else:
                body = {'access_token': 'at', 'token_type': 'DPoP'}
            data = json.dumps(body).encode()
            self.send_response(200 if ok else 400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    local = f'http://127.0.0.1:{srv.server_address[1]}'
    try:
        key = create_id_jag_dpop_key()
        got = request_id_jag(token_endpoint=local + '/idp/token?x=1', client_id='tqapp_test', client_secret='tqs_test',
                             id_token='idtoken:ada', audience='https://rs.example', dpop_key=key)
        assert got['dpop_bound'] is True
        tokens = redeem_id_jag(token_endpoint=local + '/rs/token', client_id='acme-at-rs', assertion=got['assertion'], dpop_key=key)
        assert tokens['token_type'] == 'DPoP'
        assert len(seen) == 2
        assert (seen[0]['header']['typ'], seen[0]['header']['alg'], seen[0]['jkt']) == ('dpop+jwt', 'ES256', key.thumbprint)
        assert 'd' not in seen[0]['header']['jwk']
        assert (seen[0]['payload']['htm'], seen[0]['payload']['htu']) == ('POST', local + '/idp/token')
        assert (seen[1]['payload']['htu'], seen[1]['jkt']) == (local + '/rs/token', key.thumbprint)
        assert seen[0]['payload']['jti'] != seen[1]['payload']['jti']
    finally:
        srv.shutdown()
        srv.server_close()
    # An identity provider that ignores DPoP answers with a bearer ID-JAG: dpop_bound False.
    plain_jag = request_id_jag(issuer=fake_api.base_url + '/idp', client_id='tqapp_test', client_secret='tqs_test',
                               id_token='idtoken:ada', audience='https://rs.example', dpop_key=create_id_jag_dpop_key())
    assert plain_jag['dpop_bound'] is False

    # The verifier: a bound ID-JAG needs the proof key's thumbprint, refused before it is used up.
    verifier = IdJagVerifier(issuer=fake_api.base_url + '/idp', audience='https://rs.example')
    bound = _post(fake_api, '/__test/id-jag', {'claims': {'cnf': {'jkt': 'right-key-thumbprint'}}})['assertion']
    with pytest.raises(IdJagError, match='bound to a DPoP key: a DPoP proof with that key is required'):
        verifier.verify(bound, client_id='acme-at-rs')
    with pytest.raises(IdJagError, match='the DPoP proof was made with another key'):
        verifier.verify(bound, client_id='acme-at-rs', dpop_jkt='other-key')
    claims = verifier.verify(bound, client_id='acme-at-rs', dpop_jkt='right-key-thumbprint')
    assert claims['cnf_jkt'] == 'right-key-thumbprint'
    odd = _post(fake_api, '/__test/id-jag', {'claims': {'cnf': {'x5t': 'abc'}}})['assertion']
    with pytest.raises(IdJagError, match='unsupported confirmation method'):
        verifier.verify(odd, client_id='acme-at-rs', dpop_jkt='x')
    # Unbound: as before, with or without a proof key.
    plain = _post(fake_api, '/__test/id-jag', {'claims': {}})['assertion']
    assert verifier.verify(plain, client_id='acme-at-rs', dpop_jkt='any')['cnf_jkt'] is None


def _checked_proof(proof):
    """A DPoP proof's header and payload, once its raw r||s ES256 signature verifies with the jwk it carries."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    assert '=' not in proof
    h, p, s = proof.split('.')
    header, payload = _b64j(h), _b64j(p)
    x, y, raw = (base64.urlsafe_b64decode(v + '=' * (-len(v) % 4)) for v in (header['jwk']['x'], header['jwk']['y'], s))
    assert (len(x), len(y), len(raw)) == (32, 32, 64)
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, 'big'), int.from_bytes(y, 'big'), ec.SECP256R1()).public_key()
    pub.verify(encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')), f'{h}.{p}'.encode(), ec.ECDSA(hashes.SHA256()))
    return header, payload


def test_dpop_proof_options():
    key = create_id_jag_dpop_key()
    header, payload = _checked_proof(id_jag_dpop_proof(key, 'https://sso.touchque.com/sso/token?x=1#f'))
    assert header == {'typ': 'dpop+jwt', 'alg': 'ES256', 'jwk': key.public_jwk}
    assert sorted(header['jwk']) == ['crv', 'kty', 'x', 'y'] and jwk_thumbprint(header['jwk']) == key.thumbprint
    assert sorted(payload) == ['htm', 'htu', 'iat', 'jti']
    assert (payload['htm'], payload['htu']) == ('POST', 'https://sso.touchque.com/sso/token')
    assert type(payload['iat']) is int and abs(payload['iat'] - time.time()) <= 5
    # A request with the DPoP-bound access token: its method (uppercased), ath and the server's nonce.
    # The token and its ath are RFC 9449's own example (section 7.1).
    _, payload = _checked_proof(id_jag_dpop_proof(key, 'https://API.Example.com:443/v1/files?x=1', method='get',
                                                  access_token='Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU', nonce='eyJ7S_zG.eyJH0-Z.HX4w-7v'))
    assert (payload['htm'], payload['htu']) == ('GET', 'https://api.example.com/v1/files')
    assert payload['ath'] == 'fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo'
    assert payload['nonce'] == 'eyJ7S_zG.eyJH0-Z.HX4w-7v'
    token = 'at-' + 'x' * 40
    _, payload = _checked_proof(id_jag_dpop_proof(key, 'https://api.example/v1/files/7', method='DELETE', access_token=token))
    assert payload['ath'] == base64.urlsafe_b64encode(hashlib.sha256(token.encode('ascii')).digest()).rstrip(b'=').decode()
    assert payload['htm'] == 'DELETE' and 'nonce' not in payload
    # A fresh jti every time; the options are keyword-only; htu needs an http(s) URL with a host.
    assert len({_b64j(id_jag_dpop_proof(key, 'https://a.example/t').split('.')[1])['jti'] for _ in range(50)}) == 50
    with pytest.raises(TypeError):
        id_jag_dpop_proof(key, 'https://a.example/t', 'GET')
    for bad in ('/v1/files', 'ftp://a.example/t', 'https:///t', 'https://a.example:99999/t', 'https://[::1/t', None, b'https://a.example/t'):
        with pytest.raises(TouchqueConfigException):
            id_jag_dpop_proof(key, bad)


def test_dpop_proof_method():
    # htm: the method trimmed of ASCII whitespace (space, \t, \r, \n, \v, \f) and uppercased, POST when empty.
    key = create_id_jag_dpop_key()
    for method, htm in ((' get\t', 'GET'), ('Patch', 'PATCH'), ('', 'POST'), (' \n', 'POST'), (None, 'POST'),
                        ('\x0bget\x0c', 'GET'), ('\r\nput\r\n', 'PUT'), (' \t\r\n\x0b\x0c', 'POST'),
                        ('m-search', 'M-SEARCH'), ("!#$%&'*+-.^_`|~09az", "!#$%&'*+-.^_`|~09AZ")):
        assert _checked_proof(id_jag_dpop_proof(key, 'https://a.example/t', method=method))[1]['htm'] == htm
    # Anything but RFC 9110 token characters is refused, also what uppercasing would make ASCII (U+017F to 'S'),
    # and what is not ASCII whitespace is not trimmed: NUL, U+00A0, U+0085, U+3000, the separators U+001C-U+001F.
    for bad in ('GET /', 'G\nET', 'GE"T', 'GET,POST', 'GET()', 'G\u00c9T', 'po\u017ft', b'GET', 7,
                '\u00a0GET', 'GET\u00a0', '\u2003GET', '\u3000', '\x85GET', '\x1cGET', 'GET\x1f', 'GET\x00', '\x00GET'):
        with pytest.raises(TouchqueConfigException):
            id_jag_dpop_proof(key, 'https://a.example/t', method=bad)


def test_dpop_proof_empty_token_and_nonce():
    # An empty access token or nonce is left out, like None: no ath of '', no "nonce": "".
    key = create_id_jag_dpop_key()
    _, payload = _checked_proof(id_jag_dpop_proof(key, 'https://a.example/t', method='GET', access_token='', nonce=''))
    assert sorted(payload) == ['htm', 'htu', 'iat', 'jti']
    # A nonce given by hand goes in as it is, nonce syntax or not.
    for nonce in ('a b', 'n"1', 'n\\1', 'caf\u00e9', ' n-1 '):
        assert _checked_proof(id_jag_dpop_proof(key, 'https://a.example/t', nonce=nonce))[1]['nonce'] == nonce


def test_dpop_proof_jwk_members():
    # The header's jwk is rebuilt from the key's kty, crv, x and y: other members (d, kid ...) never go along.
    key = create_id_jag_dpop_key()
    loose = IdJagDpopKey(key.private_key, dict(key.public_jwk, d='private', kid='k1', use='sig', alg='ES256'), key.thumbprint)
    header, _ = _checked_proof(id_jag_dpop_proof(loose, 'https://a.example/t'))
    assert header['jwk'] == {'kty': 'EC', 'crv': 'P-256', 'x': key.public_jwk['x'], 'y': key.public_jwk['y']}
    assert list(header['jwk']) == ['kty', 'crv', 'x', 'y']


@pytest.mark.parametrize('url,htu', [
    # The htu rules: scheme and host lowercased, user info and the default port dropped, '/' for an
    # empty path, the path kept as given (no dot-segment removal, no re-encoding), no query or fragment.
    ('https://sso.touchque.com/sso/token?x=1#f', 'https://sso.touchque.com/sso/token'),
    ('HTTPS://AUTH.Files.Example:443/token', 'https://auth.files.example/token'),
    ('https://auth.files.example/oauth/token;v=2', 'https://auth.files.example/oauth/token;v=2'),
    ('https://user:pw@Host.example:8443/a%7Eb/%2F;p=1/c?q', 'https://host.example:8443/a%7Eb/%2F;p=1/c'),
    ('https://auth.files.example', 'https://auth.files.example/'),
    ('https://auth.files.example?x=1#f', 'https://auth.files.example/'),
    ('http://localhost:8080/token', 'http://localhost:8080/token'),
    ('http://127.0.0.1:80/token', 'http://127.0.0.1/token'),
    ('http://host.example:443/token', 'http://host.example:443/token'),
    ('https://[::1]:8443/token', 'https://[::1]:8443/token'),
    ('https://[::1]:443/token', 'https://[::1]/token'),
    ('https://a.example/x/../token/./%7e', 'https://a.example/x/../token/./%7e'),
])
def test_dpop_proof_htu(url, htu):
    assert _b64j(id_jag_dpop_proof(create_id_jag_dpop_key(), url).split('.')[1])['htu'] == htu


class _TokenEndpoint:
    """A local token endpoint: gives its answers in turn (the last one from then on) and records each
    request's form body, Authorization and DPoP header. An answer's headers are a dict, or a list of
    (name, value) pairs to send a header more than once."""

    def __init__(self, *answers):
        self.answers = answers
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                req = {'body': self.rfile.read(int(self.headers.get('Content-Length') or 0)).decode(),
                       'authorization': self.headers.get('Authorization'), 'dpop': self.headers.get('DPoP')}
                outer.requests.append(req)
                status, headers, body = outer.answers[min(len(outer.requests), len(outer.answers)) - 1]
                body = body(req) if callable(body) else body
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                pairs = list(headers.items()) if isinstance(headers, dict) else headers
                for name, value in [('Content-Type', 'application/json'), ('Content-Length', str(len(data))), *pairs]:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

        self.srv = HTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.srv.server_address[1]}/token'

    def __enter__(self):
        # A short poll interval: shutdown() waits for one.
        threading.Thread(target=self.srv.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()

    def proof(self, i):
        return _checked_proof(self.requests[i]['dpop'])


def _bound_jag(req):
    # An identity provider that binds the ID-JAG to the proof's key.
    jwk = _b64j(req['dpop'].split('.')[0])['jwk']
    enc = lambda v: base64.urlsafe_b64encode(json.dumps(v).encode()).rstrip(b'=').decode()
    return {'access_token': f"{enc({'typ': 'oauth-id-jag+jwt', 'alg': 'RS256'})}.{enc({'cnf': {'jkt': jwk_thumbprint(jwk)}})}.sig",
            'issued_token_type': 'urn:ietf:params:oauth:token-type:id-jag', 'token_type': 'N_A'}


def _call(which, url, key=None):
    if which == 'request':
        return request_id_jag(token_endpoint=url, client_id='tqapp_test', client_secret='tqs_test', id_token='idtoken:ada',
                              audience='https://rs.example', dpop_key=key)
    return redeem_id_jag(token_endpoint=url, client_id='acme-at-rs', client_secret='rs-secret', assertion='the-id-jag', dpop_key=key)


_NONCE_REFUSALS = {
    'json 400': (400, {'DPoP-Nonce': 'n-1'}, {'error': 'use_dpop_nonce', 'error_description': 'Authorization server requires nonce in DPoP proof'}),
    'json 401': (401, {'DPoP-Nonce': 'n-1'}, {'error': 'use_dpop_nonce'}),
    'challenge 401': (401, {'DPoP-Nonce': 'n-1', 'WWW-Authenticate': 'Bearer realm="rs", DPoP algs="ES256", error="use_dpop_nonce"'}, b''),
}


@pytest.mark.parametrize('which', ['request', 'redeem'])
@pytest.mark.parametrize('refusal', sorted(_NONCE_REFUSALS))
def test_dpop_nonce_retry(which, refusal):
    key = create_id_jag_dpop_key()
    answer = _bound_jag if which == 'request' else {'access_token': 'at', 'token_type': 'DPoP'}
    with _TokenEndpoint(_NONCE_REFUSALS[refusal], (200, {'DPoP-Nonce': 'n-2'}, answer)) as srv:
        got = _call(which, srv.url, key)
    if which == 'request':
        assert got['dpop_bound'] is True
    else:
        assert got == {'access_token': 'at', 'token_type': 'DPoP'}
    assert len(srv.requests) == 2
    (_, first), (header, second) = srv.proof(0), srv.proof(1)
    assert 'nonce' not in first and second['nonce'] == 'n-1'
    assert first['jti'] != second['jti'] and type(second['iat']) is int
    assert (second['htm'], second['htu'], jwk_thumbprint(header['jwk'])) == ('POST', srv.url, key.thumbprint)
    # The same request again: the same form, the same client authentication.
    assert srv.requests[0]['body'] == srv.requests[1]['body'] and 'grant_type=' in srv.requests[1]['body']
    assert srv.requests[0]['authorization'] == srv.requests[1]['authorization'] and srv.requests[1]['authorization'].startswith('Basic ')


def test_dpop_nonce_retry_once_only():
    key = create_id_jag_dpop_key()
    with _TokenEndpoint((400, {'DPoP-Nonce': 'n-1'}, {'error': 'use_dpop_nonce'}), (400, {'DPoP-Nonce': 'n-2'}, {'error': 'use_dpop_nonce'})) as srv:
        with pytest.raises(IdJagError) as e:
            redeem_id_jag(token_endpoint=srv.url, client_id='acme-public', assertion='the-id-jag', dpop_key=key)
    assert len(srv.requests) == 2 and srv.proof(1)[1]['nonce'] == 'n-1'
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('use_dpop_nonce', 400, 'n-2')
    # A public client: client_id in the form both times, no Authorization.
    assert srv.requests[0]['body'] == srv.requests[1]['body'] and 'client_id=acme-public' in srv.requests[1]['body']
    assert srv.requests[0]['authorization'] is None and srv.requests[1]['authorization'] is None


@pytest.mark.parametrize('which', ['request', 'redeem'])
def test_dpop_nonce_without_a_key(which):
    # No key: no proof and no retry, as before; the refusal still says which nonce the server wants.
    with _TokenEndpoint((400, {'DPoP-Nonce': 'n-1'}, {'error': 'use_dpop_nonce'})) as srv:
        with pytest.raises(IdJagError) as e:
            _call(which, srv.url)
    assert len(srv.requests) == 1 and srv.requests[0]['dpop'] is None
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('use_dpop_nonce', 400, 'n-1')


@pytest.mark.parametrize('status,headers,body,code', [
    (400, {}, {'error': 'use_dpop_nonce'}, 'use_dpop_nonce'),
    (400, {'DPoP-Nonce': 'n-1'}, {'error': 'invalid_grant'}, 'invalid_grant'),
    (403, {'DPoP-Nonce': 'n-1'}, {'error': 'use_dpop_nonce'}, 'use_dpop_nonce'),
    (500, {'DPoP-Nonce': 'n-1'}, {'error': 'use_dpop_nonce'}, 'use_dpop_nonce'),
    (401, {'DPoP-Nonce': 'n-1', 'WWW-Authenticate': 'Bearer error="use_dpop_nonce"'}, b'', 'server_error'),
    (400, {'DPoP-Nonce': 'n-1', 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"'}, b'', 'server_error'),
])
def test_dpop_nonce_no_retry(status, headers, body, code):
    # Retried only for use_dpop_nonce on a 400 or 401 that carries a DPoP-Nonce (a DPoP challenge counts on a 401).
    with _TokenEndpoint((status, headers, body)) as srv:
        with pytest.raises(IdJagError) as e:
            _call('redeem', srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 1
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == (code, status, headers.get('DPoP-Nonce'))


@pytest.mark.parametrize('second,latest', [({'DPoP-Nonce': 'n-2'}, 'n-2'), ({}, 'n-1'), ({'DPoP-Nonce': 'not a nonce'}, 'n-1')])
def test_dpop_nonce_on_the_error_is_the_latest(second, latest):
    # The error keeps the latest valid nonce the server sent: the retry's answer's, else the first answer's.
    with _TokenEndpoint((400, {'DPoP-Nonce': 'n-1'}, {'error': 'use_dpop_nonce'}), (400, second, {'error': 'invalid_grant'})) as srv:
        with pytest.raises(IdJagError) as e:
            _call('redeem', srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 2 and srv.proof(1)[1]['nonce'] == 'n-1'
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('invalid_grant', 400, latest)


# Every NQCHAR (RFC 9449: printable ASCII except space, double quote and backslash).
_NQCHARS = ''.join(chr(c) for c in range(0x21, 0x7f) if chr(c) not in '"\\')


@pytest.mark.parametrize('which', ['request', 'redeem'])
@pytest.mark.parametrize('sent,used', [(_NQCHARS, _NQCHARS), ('  n-1\t', 'n-1')])
def test_dpop_nonce_syntax(which, sent, used):
    # A valid nonce is retried with exactly its value; spaces and tabs around a header value are not part of it.
    answer = _bound_jag if which == 'request' else {'access_token': 'at', 'token_type': 'DPoP'}
    with _TokenEndpoint((400, {'DPoP-Nonce': sent}, {'error': 'use_dpop_nonce'}), (200, {}, answer)) as srv:
        _call(which, srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 2 and srv.proof(1)[1]['nonce'] == used


@pytest.mark.parametrize('nonce_headers', [
    [],  # missing
    [('DPoP-Nonce', '')],
    [('DPoP-Nonce', ' \t ')],
    [('DPoP-Nonce', 'n-1'), ('DPoP-Nonce', 'n-2')],  # repeated with different values
    [('DPoP-Nonce', 'n-1'), ('DPoP-Nonce', 'n-1'), ('DPoP-Nonce', 'n-2')],
    [('DPoP-Nonce', 'n-1'), ('DPoP-Nonce', '')],
    [('DPoP-Nonce', 'n 1'), ('DPoP-Nonce', 'n 1')],  # repeated, the same value, but not nonce syntax
    [('DPoP-Nonce', 'n-1, n-1')],  # one line whose value has a space
    [('DPoP-Nonce', 'n 1')], [('DPoP-Nonce', 'n"1')], [('DPoP-Nonce', 'n\\1')],
    [('DPoP-Nonce', 'n\x00')], [('DPoP-Nonce', 'n\x1b')], [('DPoP-Nonce', 'n\x7f')], [('DPoP-Nonce', 'n\xe9')], [('DPoP-Nonce', 'n\xff')],
], ids=lambda headers: repr(headers))
@pytest.mark.parametrize('challenge', [False, True])
def test_dpop_nonce_not_valid(nonce_headers, challenge):
    # A DPoP-Nonce that is missing, empty, not nonce syntax or repeated with different values: no retry, the usual
    # IdJagError, no nonce on it.
    refusal = (401, [('WWW-Authenticate', 'DPoP error="use_dpop_nonce"'), *nonce_headers], b'') if challenge else \
        (400, nonce_headers, {'error': 'use_dpop_nonce'})
    with _TokenEndpoint(refusal, (200, {}, {'access_token': 'at'})) as srv:
        with pytest.raises(IdJagError) as e:
            _call('redeem', srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 1
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == (('server_error', 401) if challenge else ('use_dpop_nonce', 400)) + (None,)


@pytest.mark.parametrize('which', ['request', 'redeem'])
@pytest.mark.parametrize('nonce_headers', [
    [('DPoP-Nonce', 'n-1'), ('DPoP-Nonce', 'n-1')],
    [('DPoP-Nonce', 'n-1'), ('DPoP-Nonce', ' n-1\t'), ('DPoP-Nonce', 'n-1')],  # blanks around a value are not part of it
    [('DPoP-Nonce', 'a,b'), ('DPoP-Nonce', 'a,b')],  # a comma is a nonce character
], ids=lambda headers: repr(headers))
@pytest.mark.parametrize('challenge', [False, True])
def test_dpop_nonce_repeated_with_one_value(which, nonce_headers, challenge):
    # A DPoP-Nonce on several lines that all carry the same valid nonce is that nonce: the retry carries it.
    used = nonce_headers[0][1]
    refusal = (401, [('WWW-Authenticate', 'DPoP error="use_dpop_nonce"'), *nonce_headers], b'') if challenge else \
        (400, nonce_headers, {'error': 'use_dpop_nonce'})
    answer = _bound_jag if which == 'request' else {'access_token': 'at', 'token_type': 'DPoP'}
    with _TokenEndpoint(refusal, (200, {}, answer)) as srv:
        _call(which, srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 2 and srv.proof(1)[1]['nonce'] == used
    # It is also the nonce on an error.
    with _TokenEndpoint(refusal, (400, nonce_headers, {'error': 'invalid_dpop_proof'})) as srv:
        with pytest.raises(IdJagError) as e:
            _call(which, srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 2 and (e.value.code, e.value.status, e.value.dpop_nonce) == ('invalid_dpop_proof', 400, used)


@pytest.mark.parametrize('joined,used', [
    ('n-1, n-1', 'n-1'), ('a,b, a,b', 'a,b'), ('a,b', 'a,b'), (' n-1 , n-1', 'n-1'),
    ('n-1, n-2', None), ('n-1, ', None), ('a b, a b', None),
])
def test_dpop_nonce_joined(monkeypatch, joined, used):
    # A response without urllib3's list of header lines (a stub here): requests' value, where lines of one name are
    # joined with ', ', is split there again.
    proofs = _stub_post(monkeypatch, 400, {'DPoP-Nonce': joined}, {'error': 'use_dpop_nonce'})
    with pytest.raises(IdJagError) as e:
        _call('redeem', 'https://as.example/token', create_id_jag_dpop_key())
    assert e.value.dpop_nonce == used
    assert len(proofs) == (1 if used is None else 2)


@pytest.mark.parametrize('lines,retried', [
    (['DPoP error="use_dpop_nonce"'], True),
    (['DPoP error=use_dpop_nonce'], True),
    (['dpop ERROR=use_dpop_nonce'], True),  # scheme and parameter names in any case
    (['DPOP Error="use_dpop_nonce"'], True),
    (['DPoP error = "use_dpop_nonce"'], True),
    (['DPoP error="use\\_dpop\\_nonce"'], True),  # quoted-pairs undone
    (['DPoP algs="ES256 PS256", error="use_dpop_nonce"'], True),
    (['Bearer realm="a, b", DPoP algs="ES256", error="use_dpop_nonce"'], True),
    (['Basic realm="x", Bearer, DPoP error="use_dpop_nonce"'], True),
    (['Basic dXNlcjpwYXNz==, DPoP error="use_dpop_nonce"'], True),  # after a token68 challenge
    ([', , DPoP error="use_dpop_nonce" , ,'], True),  # empty list elements
    (['Bearer realm="x"', 'DPoP error="use_dpop_nonce"'], True),  # on a second line
    (['Bearer realm="x', 'DPoP error="use_dpop_nonce"'], True),  # each line read on its own
    (['Bearer realm=", DPoP error=use_dpop_nonce,"'], False),  # inside a quoted string
    (['Bearer realm="a\\", DPoP error=use_dpop_nonce"'], False),  # an escaped quote does not end it
    (['DPoP error="use_dpop_nonce'], False),  # an unclosed quoted string has no value
    (['DPoP error="use_dpop_nonce" x'], False),
    (['DPoP error="USE_DPOP_NONCE"'], False),  # the value exactly
    (['DPoP error="use_dpop_nonce "'], False),
    (['DPoP error=use_dpop_nonce_x'], False),
    (['DPoP error=use_dpop_nonce\x01'], False),
    (['DPoP error="invalid_dpop_proof"'], False),
    (['Bearer error="use_dpop_nonce"'], False),  # only the DPoP challenge's own error parameter
    (['Bearer error="use_dpop_nonce", DPoP algs="ES256"'], False),
    (['DPoP algs="ES256", Bearer error="use_dpop_nonce"'], False),
    (['DPoPx error="use_dpop_nonce"'], False),
    (['error="use_dpop_nonce"'], False),
    (['DPoP realm="use_dpop_nonce"', 'DPoP error_description="use_dpop_nonce"'], False),
], ids=lambda value: repr(value))
def test_www_authenticate_challenges(lines, retried):
    # A 401's WWW-Authenticate (RFC 9110 section 11.6.1) asks for the nonce only in a DPoP challenge's own error parameter.
    refusal = (401, [('DPoP-Nonce', 'n-1')] + [('WWW-Authenticate', line) for line in lines], b'')
    with _TokenEndpoint(refusal, (401, [], b'')) as srv:
        with pytest.raises(IdJagError) as e:
            _call('redeem', srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == (2 if retried else 1)
    if retried:
        assert srv.proof(1)[1]['nonce'] == 'n-1'
    # The code never comes from WWW-Authenticate.
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('server_error', 401, 'n-1')


def _stub_post(monkeypatch, status, headers, body):
    """Stands in for requests.post with the same answer every time; returns the DPoP proofs sent.
    (http.client refuses a header line over 64 KB, so a local server's such answer is temporarily_unavailable:
    see test_transport_failure. The stub's answer has no urllib3 list of header lines.)"""
    proofs = []

    def post(url, **kwargs):
        proofs.append(kwargs['headers'].get('DPoP'))
        r = requests.Response()
        r.status_code, r.url = status, url
        r.raw = io.BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode())
        r.headers.update(headers)
        return r

    monkeypatch.setattr(requests, 'post', post)
    return proofs


_64_KB_CHALLENGES = {
    'quoted param': 'DPoP realm="' + 'a' * 65536 + '"',
    'unclosed quoted param': 'DPoP realm="' + 'a' * 65536,
    'escapes': 'DPoP realm="' + '\\"' * 32768,
    'commas': 'DPoP ' + 'a,' * 30000,
    'params': 'DPoP ' + 'a=b, ' * 13107,
    'quotes': '"' * 65536,
    'backslashes': 'DPoP realm="' + '\\' * 65536 + '"',
    'challenges': 'DPoP, ' * 13107,
    'error with quoted-pairs': 'DPoP error="' + '\\a' * 32768 + '"',
    'unclosed error': 'DPoP error="' + 'a' * 65536,
    'errors': 'DPoP ' + 'error="x", ' * 6000,
    'use_dpop_nonce after a quoted param': 'DPoP realm="' + 'a' * 65536 + '", error="use_dpop_nonce"',
    'use_dpop_nonce after empty elements': 'DPoP ' + ', ' * 30000 + 'error="use_dpop_nonce"',
}


@pytest.mark.parametrize('name', sorted(_64_KB_CHALLENGES))
def test_64_kb_www_authenticate(monkeypatch, name):
    # Reading WWW-Authenticate takes time linear in its length: a 64 KB one answers at once.
    challenge = _64_KB_CHALLENGES[name]
    token = {'access_token': 'a.b.c', 'issued_token_type': 'urn:ietf:params:oauth:token-type:id-jag', 'token_type': 'N_A'}
    started = time.perf_counter()
    # A 200 without a key: the normal result.
    _stub_post(monkeypatch, 200, {'WWW-Authenticate': challenge}, token)
    assert _call('redeem', 'https://as.example/token') == token
    assert _call('request', 'https://idp.example/token')['assertion'] == 'a.b.c'
    # A 401 with a key and a DPoP-Nonce: the usual IdJagError, after the one retry when the challenge asks for the nonce.
    proofs = _stub_post(monkeypatch, 401, {'WWW-Authenticate': challenge, 'DPoP-Nonce': 'n-1'}, b'')
    for which in ('request', 'redeem'):
        with pytest.raises(IdJagError) as e:
            _call(which, 'https://as.example/token', create_id_jag_dpop_key())
        assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('server_error', 401, 'n-1')
    assert time.perf_counter() - started < 0.5
    assert len(proofs) == (4 if 'use_dpop_nonce' in name else 2)


def test_64_kb_dpop_nonce(monkeypatch):
    # Reading DPoP-Nonce takes time linear in its length too: a valid 64 KB nonce is used, one with a space is not.
    big = (_NQCHARS * (65536 // len(_NQCHARS) + 1))[:65536]
    started = time.perf_counter()
    proofs = _stub_post(monkeypatch, 400, {'DPoP-Nonce': big}, {'error': 'use_dpop_nonce'})
    with pytest.raises(IdJagError) as e:
        _call('redeem', 'https://as.example/token', create_id_jag_dpop_key())
    assert len(proofs) == 2 and _checked_proof(proofs[1])[1]['nonce'] == big and e.value.dpop_nonce == big
    spaced = big[:32768] + ' ' + big[32769:]
    proofs = _stub_post(monkeypatch, 401, {'DPoP-Nonce': spaced, 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"'}, b'')
    with pytest.raises(IdJagError) as e:
        _call('redeem', 'https://as.example/token', create_id_jag_dpop_key())
    assert len(proofs) == 1 and e.value.dpop_nonce is None
    assert time.perf_counter() - started < 0.5


def test_answer_that_is_not_a_json_object():
    # A refusal without a JSON object is server_error with its status; a 2xx without one is invalid_response with its status.
    with _TokenEndpoint((400, {}, b'["not", "an", "object"]')) as srv:
        with pytest.raises(IdJagError) as e:
            _call('redeem', srv.url)
    assert (e.value.code, e.value.status, str(e.value)) == ('server_error', 400, f'{srv.url} answered 400')
    with _TokenEndpoint((200, {}, b'["not", "an", "object"]')) as srv:
        for which in ('request', 'redeem'):
            with pytest.raises(IdJagError) as e:
                _call(which, srv.url)
            assert (e.value.code, e.value.status, str(e.value)) == ('invalid_response', 200, f'{srv.url} answered 200 without a JSON object')


_TOO_DEEP = b'{"a":' * 100000 + b'1' + b'}' * 100000  # more nesting than the json module reads (RecursionError)


@pytest.mark.parametrize('which', ['request', 'redeem'])
@pytest.mark.parametrize('status,body', [
    *((status, body) for status in (200, 201, 299)
      for body in (b'null', b'[]', b'["a"]', b'"text"', b'5', b'true', b'false', b'', b'<html>hi</html>', b'{"a": 1} x', b'{', _TOO_DEEP)),
    (204, b''),
], ids=lambda value: repr(value)[:24])
def test_2xx_without_a_json_object(which, status, body):
    # Only a JSON object is an answer, in both calls; the error keeps the status and the call's nonce.
    with _TokenEndpoint((status, {'DPoP-Nonce': 'n-1'}, body)) as srv:
        with pytest.raises(IdJagError) as e:
            _call(which, srv.url)
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('invalid_response', status, 'n-1')
    # A refusal with such a body: server_error with its status.
    with _TokenEndpoint((400, {'DPoP-Nonce': 'n-1'}, body)) as srv:
        with pytest.raises(IdJagError) as e:
            _call(which, srv.url)
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('server_error', 400, 'n-1')


@pytest.mark.parametrize('which', ['request', 'redeem'])
def test_2xx_with_a_json_object(which):
    answer = _bound_jag if which == 'request' else {'access_token': 'at', 'token_type': 'DPoP'}
    for status in (200, 201, 299):
        with _TokenEndpoint((status, {}, answer)) as srv:
            got = _call(which, srv.url, create_id_jag_dpop_key())
        if which == 'request':
            assert got['dpop_bound'] is True
        else:
            assert got == answer


@pytest.mark.parametrize('which', ['request', 'redeem'])
@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_redirect_is_an_error(which, status):
    # Only a 2xx is a success: a redirect is not followed and is an IdJagError with its status, whatever its body.
    answer = _bound_jag if which == 'request' else {'access_token': 'at', 'token_type': 'DPoP'}
    with _TokenEndpoint((status, {'Location': 'https://elsewhere.example/token', 'DPoP-Nonce': 'n-1'}, answer)) as srv:
        with pytest.raises(IdJagError) as e:
            _call(which, srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 1
    assert (e.value.code, e.value.status, e.value.dpop_nonce, str(e.value)) == ('server_error', status, 'n-1', f'{srv.url} answered {status}')
    with _TokenEndpoint((status, {'Location': 'https://elsewhere.example/token'}, {'error': 'invalid_grant', 'error_description': 'moved'})) as srv:
        with pytest.raises(IdJagError) as e:
            _call(which, srv.url)
    assert (e.value.code, e.value.status, str(e.value)) == ('invalid_grant', status, 'moved')


@pytest.mark.parametrize('error,code', [
    ('invalid_grant', 'invalid_grant'), ('invalid grant', 'invalid grant'), ("!#[]~'", "!#[]~'"), ('x' * 128, 'x' * 128),
    ('x' * 129, 'server_error'), ('', 'server_error'), ('bad"quote', 'server_error'), ('back\\slash', 'server_error'),
    ('tab\there', 'server_error'), ('new\nline', 'server_error'), ('\x7f', 'server_error'), ('café', 'server_error'),
    (5, 'server_error'), (True, 'server_error'), (None, 'server_error'), (['invalid_grant'], 'server_error'), ({'code': 'x'}, 'server_error'),
], ids=lambda value: repr(value)[:40])
def test_error_code(error, code):
    # The code is the body's error when it is an OAuth error code (RFC 6749 error characters, at most 128), else server_error.
    with _TokenEndpoint((400, {'DPoP-Nonce': 'n-1'}, {'error': error, 'error_description': 'why'})) as srv:
        for which in ('request', 'redeem'):
            with pytest.raises(IdJagError) as e:
                _call(which, srv.url)
            assert (e.value.code, e.value.status, e.value.dpop_nonce, str(e.value)) == (code, 400, 'n-1', 'why')


@pytest.mark.parametrize('which', ['request', 'redeem'])
@pytest.mark.parametrize('second,latest', [({'DPoP-Nonce': 'n-2'}, 'n-2'), ({}, 'n-1'), ({'DPoP-Nonce': 'not a nonce'}, 'n-1')])
def test_nonce_on_invalid_response(which, second, latest):
    # invalid_response after the retry keeps the latest valid nonce too.
    with _TokenEndpoint((400, {'DPoP-Nonce': 'n-1'}, {'error': 'use_dpop_nonce'}), (200, second, b'null')) as srv:
        with pytest.raises(IdJagError) as e:
            _call(which, srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 2
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('invalid_response', 200, latest)


def test_request_without_an_id_jag_keeps_the_nonce():
    # A JSON object that holds no ID-JAG: request_id_jag's invalid_response (no status) with the call's latest nonce.
    with _TokenEndpoint((400, {'DPoP-Nonce': 'n-1'}, {'error': 'use_dpop_nonce'}), (200, {}, {'foo': 1})) as srv:
        with pytest.raises(IdJagError) as e:
            _call('request', srv.url, create_id_jag_dpop_key())
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('invalid_response', None, 'n-1')
    with _TokenEndpoint((200, {'DPoP-Nonce': 'n-3'}, {'access_token': 'at', 'token_type': 'Bearer'})) as srv:
        with pytest.raises(IdJagError) as e:
            _call('request', srv.url)
    assert (e.value.code, e.value.status, e.value.dpop_nonce, str(e.value)) == \
        ('invalid_response', None, 'n-3', 'the identity provider did not answer with an ID-JAG')


class _RawEndpoint:
    """A token endpoint on a raw socket, for what http.server cannot send and requests refuses or
    cannot read: after each request it sends its answers in turn (the last one from then on) and
    records the request line's target, the DPoP header and the body. An answer is the bytes to
    send, CLOSE (close the connection without answering), RESET (a TCP reset) or HANG (no answer
    until the test ends)."""

    CLOSE, RESET, HANG = 'close', 'reset', 'hang'

    def __init__(self, *answers):
        self.answers = answers
        self.requests = []
        self.done = threading.Event()
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.sock.settimeout(0.05)
        self.base = f'http://127.0.0.1:{self.sock.getsockname()[1]}'
        self.url = self.base + '/token'

    def _serve(self):
        while not self.done.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:  # closed
                return
            threading.Thread(target=self._answer, args=(conn,), daemon=True).start()

    def _answer(self, conn):
        try:
            conn.settimeout(5)
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, _, body = data.partition(b'\r\n\r\n')
            lines = head.decode('latin-1').split('\r\n')
            fields = {name.strip().lower(): value.strip() for name, _, value in (line.partition(':') for line in lines[1:])}
            while len(body) < int(fields.get('content-length', 0)):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                body += chunk
            self.requests.append({'target': lines[0].split(' ')[1], 'dpop': fields.get('dpop'), 'body': body.decode()})
            answer = self.answers[min(len(self.requests), len(self.answers)) - 1]
            if answer == self.RESET:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            elif answer == self.HANG:
                self.done.wait(10)
            elif answer != self.CLOSE:
                conn.sendall(answer)
        finally:
            conn.close()

    def __enter__(self):
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.done.set()
        self.sock.close()

    def proof(self, i):
        return _checked_proof(self.requests[i]['dpop'])


def _raw(status, headers=(), body=b''):
    """An HTTP/1.1 answer's bytes: the status line, (name, value) headers, Content-Length and Connection: close."""
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    lines = [b'HTTP/1.1 %d X' % status] + [f'{name}: {value}'.encode('latin-1') for name, value in headers]
    return b'\r\n'.join(lines + [b'Content-Length: %d' % len(data), b'Connection: close']) + b'\r\n\r\n' + data


# A header line over 64 KB: http.client refuses the answer (LineTooLong).
_BIG_LINE = ('X-Padding', 'a' * 65536)
_UNREADABLE = {
    'header line over 64 KB': _raw(200, [_BIG_LINE], {'access_token': 'at'}),
    '64 KB WWW-Authenticate': _raw(401, [('WWW-Authenticate', 'DPoP error="' + 'a' * 65536 + '"'), ('DPoP-Nonce', 'n-1')]),
    '64 KB DPoP-Nonce': _raw(400, [('DPoP-Nonce', 'n' * 65536)], {'error': 'use_dpop_nonce'}),
    'over 100 header lines': _raw(200, [(f'X-{i}', 'a') for i in range(101)], {'access_token': 'at'}),
    'broken status line': b'HTTP/1.1 abc OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}',
    'not HTTP': b'hello\r\n\r\n',
    'Content-Length with two values': b'HTTP/1.1 200 OK\r\nContent-Length: 1, 2\r\nConnection: close\r\n\r\n{}',
    'body cut off': b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{"access_token": "at"}',
    'broken chunk': b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\n{}\r\n0\r\n\r\n',
    'body that does not decode': b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd',
    'closed without an answer': _RawEndpoint.CLOSE,
    'reset': _RawEndpoint.RESET,
}


@pytest.mark.parametrize('which', ['request', 'redeem'])
@pytest.mark.parametrize('key', [False, True])
@pytest.mark.parametrize('name', sorted(_UNREADABLE))
def test_transport_failure(which, key, name):
    # An answer requests refuses or cannot read, or none: temporarily_unavailable with no status, its exception as the cause.
    with _RawEndpoint(_UNREADABLE[name]) as srv:
        with pytest.raises(IdJagError) as e:
            _call(which, srv.url, create_id_jag_dpop_key() if key else None)
    assert len(srv.requests) == 1
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('temporarily_unavailable', None, None)
    assert isinstance(e.value.__cause__, requests.exceptions.RequestException)
    assert str(e.value).startswith(f'{srv.url} could not be reached or read: ')


@pytest.mark.parametrize('which', ['request', 'redeem'])
@pytest.mark.parametrize('name', ['header line over 64 KB', 'broken status line', 'body cut off', 'closed without an answer', 'reset'])
def test_transport_failure_on_the_retry(which, name):
    # The nonce retry fails: temporarily_unavailable, with the nonce the first answer sent.
    with _RawEndpoint(_raw(400, [('DPoP-Nonce', 'n-1')], {'error': 'use_dpop_nonce'}), _UNREADABLE[name]) as srv:
        with pytest.raises(IdJagError) as e:
            _call(which, srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 2 and srv.proof(1)[1]['nonce'] == 'n-1'
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('temporarily_unavailable', None, 'n-1')
    assert isinstance(e.value.__cause__, requests.exceptions.RequestException)


@pytest.mark.parametrize('which', ['request', 'redeem'])
def test_connection_refused(which):
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    url = f'http://127.0.0.1:{sock.getsockname()[1]}/token'
    sock.close()  # nothing listens there now
    with pytest.raises(IdJagError) as e:
        _call(which, url, create_id_jag_dpop_key())
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('temporarily_unavailable', None, None)
    assert isinstance(e.value.__cause__, requests.exceptions.ConnectionError)


def test_host_not_found(monkeypatch):
    def not_found(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, 'nodename nor servname provided, or not known')
    monkeypatch.setattr(socket, 'getaddrinfo', not_found)
    monkeypatch.setattr(socket, 'gethostbyname', not_found)  # macOS proxy settings look hosts up as well
    for which in ('request', 'redeem'):
        with pytest.raises(IdJagError) as e:
            _call(which, 'https://idp.invalid/token', create_id_jag_dpop_key())
        assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('temporarily_unavailable', None, None)
        assert isinstance(e.value.__cause__, requests.exceptions.ConnectionError)


def test_timeout(monkeypatch):
    # requests' timeout (10 seconds in the SDK, 0.2 here) is temporarily_unavailable too.
    real_post = requests.post
    monkeypatch.setattr(requests, 'post', lambda url, **kwargs: real_post(url, **dict(kwargs, timeout=0.2)))
    with _RawEndpoint(_RawEndpoint.HANG) as srv:
        with pytest.raises(IdJagError) as e:
            _call('redeem', srv.url, create_id_jag_dpop_key())
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == ('temporarily_unavailable', None, None)
    assert isinstance(e.value.__cause__, requests.exceptions.Timeout)


def test_interrupt_stays_an_interrupt(monkeypatch):
    # Only requests' own exceptions become IdJagError: the caller stopping the call (Ctrl-C) stays a KeyboardInterrupt.
    def interrupted(url, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(requests, 'post', interrupted)
    with pytest.raises(KeyboardInterrupt):
        _call('redeem', 'https://as.example/token', create_id_jag_dpop_key())


@pytest.mark.parametrize('key', [False, True])
def test_token_endpoint_url_requests_cannot_use(monkeypatch, key):
    # Refused before anything is sent, as a configuration error.
    proofs = _stub_post(monkeypatch, 200, {}, {'access_token': 'at'})
    for url in ('https://as.example:99999/token', 'https://as.example:x/token', 'https://as.example:-1/token', 'ftp://as.example/token'):
        with pytest.raises(TouchqueConfigException):
            _call('redeem', url, create_id_jag_dpop_key() if key else None)
    assert proofs == []


@pytest.mark.parametrize('which', ['request', 'redeem'])
@pytest.mark.parametrize('path', ['/token', '/a/../token', '/x/./token', '/a/b/..', '/t/%7e', '/t/%7E', '/a/%2e%2e/token', '/t/a%20b',
                                  '/t/a b', '/t/a~b', '/t/a|b', '/t/a%2fb', '/t/%zz', '/t/é', '/t;p=1/x', '//token', '///a//token', '/t?x=1#f'])
def test_htu_is_the_path_requests_sends(which, path):
    # The SDK's own proofs carry the URL requests puts on the wire (requests removes dot segments and re-encodes), on the retry too.
    with _RawEndpoint(_raw(400, [('DPoP-Nonce', 'n-1')], {'error': 'use_dpop_nonce'}), _raw(400, [], {'error': 'invalid_grant'})) as srv:
        with pytest.raises(IdJagError):
            _call(which, srv.base + path, create_id_jag_dpop_key())
    assert len(srv.requests) == 2
    for i, sent in enumerate(srv.requests):
        assert srv.proof(i)[1]['htu'] == srv.base + sent['target'].split('?')[0]


def test_htu_of_a_unicode_host(monkeypatch):
    # requests sends a Unicode host IDNA-encoded: so does the proof's htu.
    proofs = _stub_post(monkeypatch, 200, {}, {'access_token': 'at'})
    _call('redeem', 'https://Bücher.example/a/../token', create_id_jag_dpop_key())
    assert _checked_proof(proofs[0])[1]['htu'] == 'https://xn--bcher-kva.example/token'
    # id_jag_dpop_proof keeps what it is given.
    assert _b64j(id_jag_dpop_proof(create_id_jag_dpop_key(), 'https://Bücher.example/a/../token').split('.')[1])['htu'] == \
        'https://bücher.example/a/../token'


def test_agent_card_from_the_fake(fake_api):
    url = fake_api.base_url + '/.well-known/agent-card.json'
    card = _get(url)
    assert verify_agent_card(card, card_url=url) == {'kid': 'a2a-1', 'alg': 'ES256', 'key_source': 'jku'}
    with pytest.raises(AgentCardError) as e:
        verify_agent_card(_get(url + '?tamper=1'), card_url=url)
    assert e.value.code == 'invalid_signature'
    with pytest.raises(AgentCardError) as e:
        verify_agent_card(card, card_url='https://agent.example/.well-known/agent-card.json')
    assert e.value.code == 'untrusted_key'
    with pytest.raises(AgentCardError) as e:
        verify_agent_card({'name': 'x'})
    assert e.value.code == 'unsigned'


def test_sign_and_canonical_form():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    signed = sign_agent_card({'name': 'Mine', 'url': 'https://mine.example/a2a', 'skills': []}, key, kid='k1')
    raw = key.public_key().public_bytes_raw() if hasattr(key.public_key(), 'public_bytes_raw') else None
    if raw is None:
        from cryptography.hazmat.primitives import serialization
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = {'kty': 'OKP', 'crv': 'Ed25519', 'x': base64.urlsafe_b64encode(raw).rstrip(b'=').decode(), 'kid': 'k1'}
    assert verify_agent_card(signed, keys=[jwk]) == {'kid': 'k1', 'alg': 'EdDSA', 'key_source': 'keys'}
    with pytest.raises(AgentCardError):
        verify_agent_card({**signed, 'url': 'https://evil.example/a2a'}, keys=[jwk])
    with pytest.raises(AgentCardError) as e:
        verify_agent_card({**signed, 'signatures': [{**signed['signatures'][0], 'signature': 'é'}]}, keys=[jwk])
    assert e.value.code == 'invalid_signature'
    assert canonical_json({'€': 'Euro', '\r': 'CR', '\U0001F600': 'smile', '1': 'one', 'a': [1e21, 1e-7, 0.5, -0.0, 'tab\there', 1e-5, 100.0]}) == \
        '{"\\r":"CR","1":"one","a":[1e+21,1e-7,0.5,0,"tab\\there",0.00001,100],"€":"Euro","😀":"smile"}'
