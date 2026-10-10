"""verify_approval_proof against the cross-SDK golden vectors
(fixtures/approval-proof-vectors.json, shared with Node, PHP and Go)."""
import json
import os

import pytest

from touchque import details_digest, verify_approval_proof

_VECTORS = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'approval-proof-vectors.json')
with open(_VECTORS, encoding='utf-8') as fh:
    VECTORS = json.load(fh)

_OPTION_NAMES = {
    'requestId': 'request_id',
    'type': 'type',
    'details': 'details',
    'challengeCode': 'challenge_code',
    'expectedPublicKey': 'expected_public_key',
    'allowUnpinnedKey': 'allow_unpinned_key',
}


@pytest.mark.parametrize('case', VECTORS['digest_cases'], ids=lambda c: c['digest'][:12] or 'empty')
def test_details_digest(case):
    details = case.get('details_object', case.get('details'))
    assert details_digest(details) == case['digest']


@pytest.mark.parametrize('case', VECTORS['cases'], ids=lambda c: c['name'])
def test_verify_approval_proof(case):
    kwargs = {_OPTION_NAMES[k]: v for k, v in case['options'].items()}
    assert verify_approval_proof(case['proof'], **kwargs) is case['expected']


def test_garbage_never_raises():
    for proof in ({}, {'version': 'v2'}, 'not a dict', 42,
                  {'version': 'v2', 'algorithm': 'ECDSA-P256-SHA256', 'message': 1, 'signature': None, 'publicKey': []},
                  {'version': 'v2', 'algorithm': 'ECDSA-P256-SHA256', 'message': 'm', 'signature': '%%%', 'publicKey': '%%%'}):
        assert verify_approval_proof(proof, request_id='r', type='t', allow_unpinned_key=True) is False
