"""Safe Guard: the verifier against the shared vectors (fixtures/safe-guard-vectors.json, derived
from the reference project and shared with every server SDK), and request / status / wait
against the shared fake TouchQue API."""
import json
import os
import urllib.request

import pytest

from touchque import (
    Config, TouchQue, TouchQueConfigException, TouchQueRejectedException, safe_approval_message, safe_display_digest,
    safe_governance_hash, safe_schedule_call, safe_tx_hash, verify_safe_approval, with_safe_approvals,
)
from .fake_api import fake_api  # noqa: F401 (fixture)

_VECTORS = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'safe-guard-vectors.json')
with open(_VECTORS, encoding='utf-8') as fh:
    VECTORS = json.load(fh)
BY_NAME = {v['name']: v for v in VECTORS['vectors']}
OPTIONS = {'purpose': 'purpose', 'approverIndex': 'approver_index', 'displayDigest': 'display_digest', 'now': 'now'}


@pytest.mark.parametrize('v', VECTORS['vectors'], ids=lambda v: v['name'])
def test_vector(v):
    t = v['safeTx']
    assert safe_tx_hash(t) == v['safeTxHash']
    assert safe_governance_hash(t) == v['governanceHash']
    assert safe_approval_message(v['purpose'], t['chainId'], t['guard'], t['safe'], v['subject'], v['expiresAt'], v['displayDigest']) == v['message']
    if 'rows' in v:
        assert safe_display_digest(v['rows']) == v['rowsDigest']
    assert verify_safe_approval(t, v['approval'], VECTORS['approverKey'], purpose=v['purpose'], now=VECTORS['now'], approver_index=t['approverIndex']) == {
        'valid': True, 'reason': None, 'purpose': v['purpose'], 'approverIndex': t['approverIndex'], 'expiresAt': v['expiresAt'],
        'displayDigest': v['displayDigest'], 'safeTxHash': v['safeTxHash'], 'governanceHash': v['governanceHash'],
    }


@pytest.mark.parametrize('c', VECTORS['checks'], ids=lambda c: c['name'])
def test_check(c):
    options = {'now': VECTORS['now'], **{OPTIONS[k]: val for k, val in c['options'].items()}}
    key = c.get('keyXY') or c.get('key') or VECTORS['approverKey']
    got = verify_safe_approval(BY_NAME[c['vector']]['safeTx'], c['approval'], key, **options)
    assert got['reason'] == c['reason']
    assert got['valid'] is (c['reason'] is None)
    if 'purpose' in c:
        assert got['purpose'] == c['purpose']


def test_trailer_and_schedule_call():
    w = VECTORS['withApprovals']
    assert with_safe_approvals(w['ownerSignatures'], w['approvals']) == w['expected']
    s = VECTORS['scheduleCall']
    assert safe_schedule_call(s['safe'], s['governanceHash'], s['approvals']) == s['expected']


def test_a_transaction_that_is_not_one_raises():
    t = VECTORS['vectors'][0]['safeTx']
    with pytest.raises(TouchQueConfigException):
        safe_tx_hash({**t, 'tx': {**t['tx'], 'to': '0x1234'}})
    with pytest.raises(TouchQueConfigException):
        safe_tx_hash({**t, 'tx': {**t['tx'], 'operation': 2}})
    with pytest.raises(TouchQueConfigException):
        with_safe_approvals('0x', [])


def _post(fake_api, path, body):
    req = urllib.request.Request(fake_api.base_url + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def test_request_wait_and_check_the_approval_here(fake_api):
    fake_api.link('treasurer@acme.com')
    v = BY_NAME['bybit_pattern']
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    _post(fake_api, '/__test/opts', {'safeTxView': {'class': v['class'], 'flags': ['delegatecall'], 'safeTxHash': v['safeTxHash'], 'governanceHash': v['governanceHash'], 'purpose': v['purpose']}})
    safe_tx = {**v['safeTx'], 'chainId': 1, 'tx': {**v['safeTx']['tx'], 'safeTxGas': 45746, 'nonce': 42}}
    sent = tq.safe_guard.request('treasurer@acme.com', 'safe_payment', safe_tx, reference_id='tx-1')
    assert sent['safeTx']['governanceHash'] == v['governanceHash']
    with urllib.request.urlopen(fake_api.base_url + '/__test/calls') as resp:
        call = json.loads(resp.read())[-1]
    assert call['path'] == '/safe-guard/approvals'
    assert call['body']['safeTx']['chainId'] == '1' and call['body']['safeTx']['tx']['nonce'] == '42' and call['body']['referenceId'] == 'tx-1'
    assert 'approval' not in tq.safe_guard.status(sent['requestId'])['safeTx']

    _post(fake_api, '/__test/approve', {'id': sent['requestId'], 'safeTx': {'approval': v['approval'], 'expiresAt': v['expiresAt']}})
    done = tq.safe_guard.wait_for_approval(sent['requestId'], poll_interval_ms=10)
    assert done['status'] == 'CONFIRMED' and done['safeTx']['approval'] == v['approval']
    assert done['safeTx']['purpose'] == 'schedule'
    check = verify_safe_approval(safe_tx, done['safeTx']['approval'], VECTORS['approverKey'], purpose=done['safeTx']['purpose'],
                                 now=VECTORS['now'], approver_index=done['safeTx']['approverIndex'])
    assert check['valid'] and check['purpose'] == 'schedule'
    # Not named, only an approval to execute counts: this one schedules a change.
    unnamed = verify_safe_approval(safe_tx, done['safeTx']['approval'], VECTORS['approverKey'], now=VECTORS['now'])
    assert unnamed['valid'] is False and unnamed['reason'] == 'signature_invalid'

    again = tq.safe_guard.request('treasurer@acme.com', 'safe_payment', v['safeTx'])
    _post(fake_api, '/__test/reject', {'id': again['requestId']})
    with pytest.raises(TouchQueRejectedException):
        tq.safe_guard.wait_for_approval(again['requestId'], poll_interval_ms=10)
