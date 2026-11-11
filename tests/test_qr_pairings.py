"""QR pairing against the shared fake Touchque API: register, the QR's text and
hash, the phone's scan, a request for the phone that scanned, and refusals.
Same scenarios as the Node SDK's QrPairings tests."""
import base64
import hashlib
import json
import re
import urllib.request

import pytest

from touchque import Config, Touchque, TouchqueAPIException, qr_pairing_uri
from touchque.exceptions import TouchqueConfigException
from .fake_api import fake_api  # noqa: F401 (fixture)

THUMB = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'


def _tq(fake_api):
    return Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))


def _stored(fake_api):
    with urllib.request.urlopen(fake_api.base_url + '/__test/qr-pairings') as resp:
        return json.loads(resp.read())[-1]


def test_create_scan_then_ask_the_phone_that_scanned(fake_api):
    fake_api.link('ayse@acme.com')
    tq = _tq(fake_api)
    p = tq.qr_pairings.create(THUMB, client_ip='203.0.113.7', user_agent='Mozilla/5.0', browser='Chrome 155', os_name='macOS 15')
    assert p['uri'] == qr_pairing_uri(p['pairingId'], p['nonce'], THUMB)
    assert re.fullmatch(r'touchque://pair-browser\?v=1&p=[\w-]{22}&n=[\w-]{43}&k=[\w-]{43}', p['uri'])
    digest = base64.urlsafe_b64encode(hashlib.sha256(p['nonce'].encode()).digest()).rstrip(b'=').decode()
    assert _stored(fake_api)['nonceHash'] == digest
    assert tq.qr_pairings.get(p['pairingId'])['state'] == 'waiting'
    with pytest.raises(TouchqueAPIException) as e:
        tq.login.request('ayse@acme.com', qr_pairing=p['pairingId'])
    assert e.value.code == 'pairing_not_confirmed'

    fake_api._call('/__test/qr-scan', {'id': p['pairingId'], 'user': 'ayse@acme.com'})
    seen = tq.qr_pairings.get(p['pairingId'])
    assert seen['state'] == 'confirmed' and seen['externalUsername'] == 'ayse@acme.com' and seen['proximity']['warnings'] == []
    req = tq.login.request('ayse@acme.com', qr_pairing=p['pairingId'])
    after = tq.qr_pairings.get(p['pairingId'])
    assert after['state'] == 'requested' and after['requestId'] == req['requestId']


def test_refuse_after_the_scan_and_checks_before_the_call(fake_api):
    fake_api.link('ayse@acme.com')
    tq = _tq(fake_api)
    p = tq.qr_pairings.create(THUMB, ttl_seconds=60)
    with pytest.raises(TouchqueAPIException) as e:
        tq.qr_pairings.refuse(p['pairingId'], 'policy', 'Not yet')
    assert e.value.status == 409 and e.value.code == 'not_open'
    fake_api._call('/__test/qr-scan', {'id': p['pairingId'], 'user': 'ayse@acme.com', 'confirm': False})
    refused = tq.qr_pairings.refuse(p['pairingId'], 'device_not_approved', 'Ask IT to approve this computer.', device_code='ABC-123')
    assert refused['state'] == 'refused'
    assert refused['outcome']['reason'] == 'device_not_approved' and refused['outcome']['deviceCode'] == 'ABC-123'
    for call in (lambda: tq.qr_pairings.create('short'), lambda: tq.qr_pairings.create(THUMB, ttl_seconds=10),
                 lambda: tq.qr_pairings.refuse(p['pairingId'], 'nope', 'x'), lambda: tq.qr_pairings.refuse(p['pairingId'], 'other', ' ')):
        with pytest.raises(TouchqueConfigException):
            call()


def test_os_is_an_alias_of_os_name(fake_api):
    tq = _tq(fake_api)
    tq.qr_pairings.create(THUMB, browser='Firefox 140', os='Windows 11')
    assert _stored(fake_api)['os'] == 'Windows 11'
    tq.qr_pairings.create(THUMB, os_name='macOS 15')
    assert _stored(fake_api)['os'] == 'macOS 15'
