"""Cross App Access (ID-JAG) and A2A agent card signatures against the shared fake API: an app
trades a member's ID token for an ID-JAG at the identity provider and redeems it; an
authorization server checks one (issuer, audience, client, expiry, typ, once); DPoP proofs (the
method, ath, nonce and htu options, the jwk members) and the one retry with a server's nonce
against a local token endpoint (nonce syntax, the latest nonce on the error, 64 KB headers); a card
signed in RFC 8785 form by the fake (JavaScript) verifies here with keys from its own host and fails
when changed or pointed elsewhere."""
import base64
import hashlib
import io
import json
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
    # htm: the method trimmed and uppercased, POST when empty.
    key = create_id_jag_dpop_key()
    for method, htm in ((' get\t', 'GET'), ('Patch', 'PATCH'), ('', 'POST'), (' \n', 'POST'), (None, 'POST'),
                        ('m-search', 'M-SEARCH'), ("!#$%&'*+-.^_`|~09az", "!#$%&'*+-.^_`|~09AZ")):
        assert _checked_proof(id_jag_dpop_proof(key, 'https://a.example/t', method=method))[1]['htm'] == htm
    # Anything but RFC 9110 token characters is refused, also what uppercasing would make ASCII (U+017F to 'S').
    for bad in ('GET /', 'G\nET', 'GE"T', 'GET,POST', 'GET()', 'G\u00c9T', 'po\u017ft', b'GET', 7):
        with pytest.raises(TouchqueConfigException):
            id_jag_dpop_proof(key, 'https://a.example/t', method=bad)


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
    [('DPoP-Nonce', 'n-1'), ('DPoP-Nonce', 'n-1')],  # repeated: requests joins them as 'n-1, n-1'
    [('DPoP-Nonce', 'n 1')], [('DPoP-Nonce', 'n"1')], [('DPoP-Nonce', 'n\\1')],
    [('DPoP-Nonce', 'n\x00')], [('DPoP-Nonce', 'n\x1b')], [('DPoP-Nonce', 'n\x7f')], [('DPoP-Nonce', 'n\xe9')], [('DPoP-Nonce', 'n\xff')],
], ids=lambda headers: repr(headers))
@pytest.mark.parametrize('challenge', [False, True])
def test_dpop_nonce_not_valid(nonce_headers, challenge):
    # A DPoP-Nonce that is missing, empty, repeated or not nonce syntax: no retry, the usual IdJagError, no nonce on it.
    refusal = (401, [('WWW-Authenticate', 'DPoP error="use_dpop_nonce"'), *nonce_headers], b'') if challenge else \
        (400, nonce_headers, {'error': 'use_dpop_nonce'})
    with _TokenEndpoint(refusal, (200, {}, {'access_token': 'at'})) as srv:
        with pytest.raises(IdJagError) as e:
            _call('redeem', srv.url, create_id_jag_dpop_key())
    assert len(srv.requests) == 1
    assert (e.value.code, e.value.status, e.value.dpop_nonce) == (('server_error', 401) if challenge else ('use_dpop_nonce', 400)) + (None,)


def _stub_post(monkeypatch, status, headers, body):
    """Stands in for requests.post with the same answer every time; returns the DPoP proofs sent.
    (http.client refuses a header line over 64 KB, so a local server cannot send these answers.)"""
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
    'use_dpop_nonce after a quoted param': 'DPoP realm="' + 'a' * 65536 + '", error="use_dpop_nonce"',
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
    with _TokenEndpoint((400, {}, b'["not", "an", "object"]')) as srv:
        with pytest.raises(IdJagError) as e:
            _call('redeem', srv.url)
    assert (e.value.code, e.value.status, str(e.value)) == ('server_error', 400, f'{srv.url} answered 400')
    with _TokenEndpoint((200, {}, b'["not", "an", "object"]')) as srv:
        with pytest.raises(IdJagError) as e:
            _call('request', srv.url)
        assert e.value.code == 'invalid_response'
        assert _call('redeem', srv.url) == {}


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
