"""Shared Signals SETs: the cross-SDK vectors (fixtures/security-event-vectors.json),
discovery through /.well-known/ssf-configuration, and a poll (RFC 8936).
Same cases as the Node SDK's securityEvents tests."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from touchque import SecurityEventError, SecurityEventVerifier, SECURITY_EVENT_TYPES, poll_security_events
from touchque.exceptions import TouchQueConfigException

pytest.importorskip('cryptography')

with open(os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'security-event-vectors.json')) as f:
    V = json.load(f)


def verifier():
    return SecurityEventVerifier(issuer=V['issuer'], audience=V['audience'], jwks=V['jwks'])


@pytest.mark.parametrize('v', V['valid'], ids=[v['name'] for v in V['valid']])
def test_reads(v):
    e = verifier().verify(v['token'])
    x = v['expect']
    assert (e.jti, e.issuer, e.audience, e.issued_at, e.txn, e.subject, e.type, e.name, e.claims) == (
        x['jti'], x['issuer'], x['audience'], x['issuedAt'], x['txn'], x['subject'], x['type'], x['name'], x['claims'])


@pytest.mark.parametrize('v', V['invalid'], ids=[v['name'] for v in V['invalid']])
def test_refuses(v):
    with pytest.raises(SecurityEventError) as e:
        verifier().verify(v['token'])
    assert e.value.code == v['error']


def test_short_names():
    assert SECURITY_EVENT_TYPES['session-revoked'].endswith('/caep/event-type/session-revoked')


POLLED = []


class _Transmitter(BaseHTTPRequestHandler):
    """The transmitter's metadata, its JWKS and a poll endpoint, like Touchque SSO serves them."""

    def _send(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        base = f'http://127.0.0.1:{self.server.server_port}'
        if self.path.endswith('/.well-known/ssf-configuration'):
            return self._send(200, {'issuer': base, 'jwks_uri': f'{base}/jwks'})
        if self.path == '/jwks':
            return self._send(200, V['jwks'])
        return self._send(404, {})

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        POLLED.append({'auth': self.headers.get('Authorization'), 'body': json.loads(self.rfile.read(n) or b'{}')})
        if self.path == '/ssf/poll/denied':
            return self._send(401, {'error': 'invalid_token'})
        return self._send(200, {'sets': {V['valid'][0]['expect']['jti']: V['valid'][0]['token']}, 'moreAvailable': False})

    def log_message(self, *args):
        pass


@pytest.fixture
def transmitter():
    server = HTTPServer(('127.0.0.1', 0), _Transmitter)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    POLLED.clear()
    yield f'http://127.0.0.1:{server.server_port}'
    server.shutdown()
    server.server_close()


def test_discovers_the_jwks_and_checks_the_issuer_the_set_names(transmitter):
    v = SecurityEventVerifier(issuer=transmitter, audience=V['audience'])
    # The vectors' issuer is not this one: the signature verifies, the issuer does not.
    with pytest.raises(SecurityEventError) as e:
        v.verify(V['valid'][0]['token'])
    assert e.value.code == 'invalid_issuer'
    assert v.jwks_uri == f'{transmitter}/jwks'
    out = poll_security_events(url=f'{transmitter}/ssf/poll/s1', token='tqssf_x', ack=['a'], max_events=5)
    assert out == {'sets': {V['valid'][0]['expect']['jti']: V['valid'][0]['token']}, 'more_available': False}
    assert POLLED == [{'auth': 'Bearer tqssf_x', 'body': {'ack': ['a'], 'maxEvents': 5}}]


def test_metadata_naming_another_issuer_is_not_trusted(transmitter):
    v = SecurityEventVerifier(issuer=f'{transmitter}/other', audience=V['audience'])
    with pytest.raises(SecurityEventError) as e:
        v.verify(V['valid'][0]['token'])
    assert e.value.code == 'temporarily_unavailable'


def test_a_refused_poll_raises_with_the_transmitters_error(transmitter):
    with pytest.raises(SecurityEventError) as e:
        poll_security_events(url=f'{transmitter}/ssf/poll/denied', token='tqssf_wrong')
    assert e.value.code == 'invalid_token'
    assert POLLED == [{'auth': 'Bearer tqssf_wrong', 'body': {}}]
    for call in (lambda: poll_security_events(url='http://sso.example.com/ssf/poll/s1', token='tqssf_x'),
                 lambda: poll_security_events(url=f'{transmitter}/ssf/poll/s1', token='')):
        with pytest.raises(TouchQueConfigException):
            call()
