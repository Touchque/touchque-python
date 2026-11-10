"""AI agents in the Python SDK: management calls send what the shared vectors
(fixtures/agent-vectors.json) say, and TouchQueAgent signs in with its own key
against the shared fake API, which checks the private_key_jwt assertion and
the DPoP proofs like the real API."""
import hashlib
import base64
import json
import os
from urllib.parse import quote

import pytest

from touchque import Config, TouchQue, TouchQueAgent, generate_agent_key, jwk_thumbprint
from touchque.exceptions import TouchQueAPIException, TouchQueConfigException
from .fake_api import fake_api  # noqa: F401 (fixture)

with open(os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'agent-vectors.json'), encoding='utf-8') as f:
    VECTORS = json.load(f)


def client_for(api) -> TouchQue:
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))


@pytest.mark.parametrize('v', VECTORS['thumbprints'], ids=lambda v: v['jwk']['crv'])
def test_thumbprint_vectors(v):
    assert jwk_thumbprint(v['jwk']) == v['thumbprint']


def test_ath_vectors():
    for v in VECTORS['ath']:
        assert base64.urlsafe_b64encode(hashlib.sha256(v['accessToken'].encode()).digest()).rstrip(b'=').decode() == v['ath']


def test_generate_agent_key():
    ec = generate_agent_key()
    assert ec['public_jwk']['kty'] == 'EC' and ec['public_jwk']['alg'] == 'ES256'
    assert ec['public_jwk']['kid'] == jwk_thumbprint(ec['public_jwk'])
    assert 'd' not in ec['public_jwk'] and ec['private_jwk']['d']
    assert generate_agent_key('EdDSA')['public_jwk']['crv'] == 'Ed25519'


def test_management_call_vectors(fake_api):
    tq = client_for(fake_api)
    k1, k2 = generate_agent_key(), generate_agent_key('EdDSA')
    state = {'id': ''}

    def fill(v):
        text = json.dumps(v).replace('"{publicKey}"', json.dumps(k1['public_jwk'])).replace('"{publicKey2}"', json.dumps(k2['public_jwk']))
        return json.loads(text.replace('{id}', state['id']).replace('{kid}', quote(k2['public_jwk']['kid'], safe='')))

    ag = tq.agents
    runs = {
        'create': lambda a: ag.create(a['name'], a['allowedTypes'], public_key=k1['public_jwk'], owner_email=a['ownerEmail'], platform=a['platform'], review_in_days=a['reviewInDays']),
        'list': lambda a: ag.list(status=a['status']),
        'get': lambda a: ag.get(state['id']),
        'update': lambda a: ag.update(state['id'], review_in_days=a['reviewInDays'], description=a['description']),
        'addKey': lambda a: ag.add_key(state['id'], k2['public_jwk']),
        'removeKey': lambda a: ag.remove_key(state['id'], k2['public_jwk']['kid']),
        'suspend': lambda a: ag.suspend(state['id'], a['reason']),
        'resume': lambda a: ag.resume(state['id']),
        'setPolicy': lambda a: ag.set_policy(state['id'], a['policy']),
        'getWorkspacePolicy': lambda a: ag.get_workspace_policy(),
        'listEvents': lambda a: ag.list_events(after=a['after'], limit=a['limit']),
        'setWorkspacePolicy': lambda a: ag.set_workspace_policy(a['policy']),
        'listBlocks': lambda a: ag.list_blocks(state['id']),
        'killSwitch': lambda a: ag.set_kill_switch(a['engaged'], a['reason']),
        'killSwitchOff': lambda a: ag.set_kill_switch(a['engaged']),
        'revoke': lambda a: ag.revoke(state['id']),
    }
    for v in VECTORS['calls']:
        result = runs[v['name']](v['args'])
        if v['name'] == 'create':
            state['id'] = result['id']
        call = fake_api.calls()[-1]
        want = fill(v)
        assert call['method'] == want['method'], v['name']
        assert call['path'] == want['path'], v['name']
        if 'query' in want:
            assert call['url'] == f"{want['path']}?{want['query']}"
        if 'body' in want:
            assert call['body'] == want['body'], v['name']

    with pytest.raises(TouchQueConfigException):
        ag.create('x', ['LOGIN'], public_key=k1['private_jwk'])


def test_agent_signs_in_with_its_own_key(fake_api):
    tq = client_for(fake_api)
    for alg in ('ES256', 'EdDSA'):
        keys = generate_agent_key(alg)
        created = tq.agents.create(f'agent {alg}', ['LOGIN'], public_key=keys['public_jwk'])
        for private_key in (keys['private_jwk'], json.dumps(keys['private_jwk'])):
            me = TouchQueAgent(agent_id=created['id'], private_key=private_key, base_url=fake_api.base_url).me()
            assert me['agent']['id'] == created['id']
            assert me['scope'] == 'agent:read approvals:request approvals:read vault:read'
    token_calls = [c for c in fake_api.calls() if c['path'] == '/agents/token']
    assert token_calls[-1]['body']['grant_type'] == 'client_credentials'


def test_token_vault(fake_api):
    tq = client_for(fake_api)
    keys = generate_agent_key()
    created = tq.agents.create('calendar', ['LOGIN'], public_key=keys['public_jwk'])
    agent = TouchQueAgent(agent_id=created['id'], private_key=keys['private_jwk'], base_url=fake_api.base_url)
    conn = tq.agents.vault.put_connection('google', 'google', 'acme.apps.googleusercontent.com', client_secret='g-secret', agent_ids=[created['id']])
    assert conn['hasClientSecret'] and conn['agentIds'] == [created['id']]
    tq.agents.vault.deposit('google', 'jane@example.com', 'ya29.jane', refresh_token='1//jane', expires_in=3599, scope='calendar.readonly')
    assert 'ya29' not in str(tq.agents.vault.list_accounts('jane@example.com'))
    got = agent.get_connection_token('jane@example.com', 'google')
    assert got == {'access_token': 'ya29.jane', 'token_type': 'Bearer', 'expires_in': 3599, 'scope': 'calendar.readonly', 'connection': 'google'}
    with pytest.raises(TouchQueAPIException) as e:
        agent.get_connection_token('john@example.com', 'google')
    assert e.value.code == 'not_connected'
    tq.agents.vault.remove_account('google', 'jane@example.com')
    assert tq.agents.vault.remove_connection('google') == {'removed': True, 'tokensDeleted': 0}


def test_token_is_reused(fake_api):
    tq = client_for(fake_api)
    keys = generate_agent_key()
    created = tq.agents.create('reuse', ['LOGIN'], public_key=keys['public_jwk'])
    agent = TouchQueAgent(agent_id=created['id'], private_key=keys['private_jwk'], base_url=fake_api.base_url)
    agent.me()
    agent.me()
    assert len([c for c in fake_api.calls() if c['path'] == '/agents/token']) == 1


def test_refusals_carry_the_reason(fake_api):
    tq = client_for(fake_api)
    keys = generate_agent_key()
    created = tq.agents.create('refused', ['LOGIN'], public_key=keys['public_jwk'])
    agent = TouchQueAgent(agent_id=created['id'], private_key=keys['private_jwk'], base_url=fake_api.base_url)
    agent.me()
    tq.agents.suspend(created['id'], 'looping')
    with pytest.raises(TouchQueAPIException) as blocked:
        agent.me()
    assert blocked.value.status == 403 and blocked.value.code == 'agent_blocked' and blocked.value.reason == 'suspended'
    with pytest.raises(TouchQueAPIException) as fresh:
        TouchQueAgent(agent_id=created['id'], private_key=keys['private_jwk'], base_url=fake_api.base_url).me()
    assert fresh.value.code == 'unauthorized_client' and fresh.value.reason == 'suspended'
    tq.agents.resume(created['id'])

    stranger = generate_agent_key()
    with pytest.raises(TouchQueAPIException) as spoof:
        TouchQueAgent(agent_id=created['id'], private_key=stranger['private_jwk'], kid=keys['public_jwk']['kid'], base_url=fake_api.base_url).me()
    assert spoof.value.status == 401 and spoof.value.code == 'invalid_client'

    tq.agents.set_kill_switch(True, 'incident')
    with pytest.raises(TouchQueAPIException) as paused:
        agent.me()
    assert paused.value.reason == 'workspace_paused'
    tq.agents.set_kill_switch(False)
    assert agent.me()['agent']['id'] == created['id']


def test_configuration_errors():
    key = generate_agent_key()['private_jwk']
    with pytest.raises(TouchQueConfigException):
        TouchQueAgent(agent_id='nope', private_key=key)
    with pytest.raises(TouchQueConfigException):
        TouchQueAgent(agent_id='agt_abcdefghijkmnpqrstuv', private_key='not a key')
    with pytest.raises(TouchQueConfigException):
        TouchQueAgent(agent_id='agt_abcdefghijkmnpqrstuv', private_key=key, base_url='http://api.example.com')


# ── approvals ─────────────────────────────────────────────────────────────────

from touchque import (  # noqa: E402
    TouchQueApprovalError, TouchQueApprovalMismatchError, matches_authorization_details, verify_approval_token_with,
)

TOKEN = VECTORS['approvalToken']
PAYMENT = TOKEN['claims']['authorization_details'][0]


def test_approval_token_vectors():
    at = TOKEN['verifyAt']
    claims = verify_approval_token_with(TOKEN['token'], TOKEN['jwks'], audience=TOKEN['audience'], now=at)
    assert claims['sub'] == TOKEN['claims']['sub']
    head_and_body = TOKEN['token'].rsplit('.', 1)[0]
    own = {'audience': TOKEN['audience']}
    for bad, kwargs in ((TOKEN['tampered'], own), (TOKEN['wrongType'], own), (TOKEN['token'], {'audience': 'touchque:workspace:other'}),
                        (head_and_body + '.é', own), (head_and_body + '.a', own)):
        with pytest.raises(TouchQueApprovalMismatchError):
            verify_approval_token_with(bad, TOKEN['jwks'], now=at, **kwargs)
    with pytest.raises(TouchQueApprovalMismatchError, match='expired'):
        verify_approval_token_with(TOKEN['token'], TOKEN['jwks'], now=TOKEN['claims']['exp'] + 60, **own)
    with pytest.raises(TouchQueApprovalMismatchError, match='another workspace'):
        verify_approval_token_with(TOKEN['token'], TOKEN['jwks'], audience='touchque:workspace:other', now=at)


def test_approval_token_audience_is_required():
    at = TOKEN['verifyAt']
    for audience in (None, ''):
        with pytest.raises(TouchQueApprovalMismatchError, match='audience is required'):
            verify_approval_token_with(TOKEN['token'], TOKEN['jwks'], audience=audience, now=at)
    with pytest.raises(TouchQueApprovalMismatchError, match='names no workspace'):
        verify_approval_token_with(TOKEN['noAudience']['token'], TOKEN['noAudience']['jwks'], audience=TOKEN['audience'], now=at)


@pytest.mark.parametrize('m', VECTORS['matching'], ids=lambda m: m['name'])
def test_matching_vectors(m):
    assert matches_authorization_details(TOKEN['claims']['authorization_details'], m['expect']) is m['matches']


def _post(api, path, body):
    import urllib.request
    req = urllib.request.Request(api.base_url + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    urllib.request.urlopen(req).read()


def test_ask_wait_redeem(fake_api):
    tq = client_for(fake_api)
    user = 'agent-approvals@example.com'
    fake_api.link(user)
    tq.action_types.define('PAY_INVOICE', critical=False)
    keys = generate_agent_key()
    created = tq.agents.create('Invoice bot', ['PAY_INVOICE'], public_key=keys['public_jwk'])
    agent = TouchQueAgent(agent_id=created['id'], private_key=keys['private_jwk'], base_url=fake_api.base_url)

    ask = agent.request_approval(user, 'PAY_INVOICE', [PAYMENT], reason='October rent')
    assert ask['status'] == 'pending' and ask['challengeCode'] == '47'
    assert fake_api.calls()[-1]['body'] == {'externalUsername': user, 'type': 'PAY_INVOICE', 'authorizationDetails': [PAYMENT], 'reason': 'October rent'}
    _post(fake_api, '/__test/approve', {'id': ask['approvalId']})
    token = agent.wait_for_approval(ask['approvalId'], interval=0.5)['approvalToken']

    assert tq.agents.approval_audience() == 'touchque:workspace:fake-workspace'
    claims = tq.agents.verify_approval_token(token, user=user, authorization_details=PAYMENT)
    assert claims['act']['sub'] == created['id']
    with pytest.raises(TouchQueApprovalMismatchError, match='another workspace'):
        tq.agents.verify_approval_token(token, audience='touchque:workspace:other')
    with pytest.raises(TouchQueApprovalMismatchError):
        tq.agents.redeem_approval(token, authorization_details=dict(PAYMENT, instructedAmount={'currency': 'TRY', 'amount': '5000.00'}))
    approval = tq.agents.redeem_approval(token, user=user, type='PAY_INVOICE',
                                         authorization_details={'type': 'payment_initiation', 'instructedAmount': {'currency': 'try', 'amount': '500'}})
    assert approval['id'] == ask['approvalId'] and approval['agent']['id'] == created['id']
    with pytest.raises(TouchQueAPIException) as again:
        tq.agents.redeem_approval(token)
    assert again.value.code == 'already_redeemed'

    ask2 = agent.request_approval(user, 'PAY_INVOICE', [PAYMENT], presence='background')
    assert 'challengeCode' not in ask2
    _post(fake_api, '/__test/reject', {'id': ask2['approvalId']})
    with pytest.raises(TouchQueApprovalError) as rejected:
        agent.wait_for_approval(ask2['approvalId'], interval=0.5)
    assert rejected.value.status == 'rejected'
    with pytest.raises(TouchQueAPIException) as refused:
        agent.request_approval(user, 'SEND_MONEY', [PAYMENT])
    assert refused.value.code == 'type_not_allowed'


def test_blocks_listed_and_lifted(fake_api):
    tq = client_for(fake_api)
    keys = generate_agent_key()
    a = tq.agents.create('blocked', ['LOGIN'], public_key=keys['public_jwk'])
    _post(fake_api, '/__test/agent-block', {'agentId': a['id'], 'user': 'jane@example.com'})
    assert tq.agents.list_blocks(a['id'])[0]['reason'] == 'not_me'
    tq.agents.lift_block(a['id'], 'jane@example.com')
    assert fake_api.calls()[-1]['path'] == f"/agents/{a['id']}/blocks/jane%40example.com"
    assert tq.agents.list_blocks(a['id']) == []


def test_mandates(fake_api):
    import urllib.request
    tq = client_for(fake_api)
    user = 'agent-mandates@example.com'
    fake_api.link(user)
    tq.action_types.define('PAY_INVOICE', critical=False)
    keys = generate_agent_key()
    created = tq.agents.create('Mandate bot', ['PAY_INVOICE'], public_key=keys['public_jwk'])
    agent = TouchQueAgent(agent_id=created['id'], private_key=keys['private_jwk'], base_url=fake_api.base_url)
    mandate = agent.request_mandate(user, 'PAY_INVOICE', 2, {'currency': 'TRY', 'amount': '1000'}, recipients=[PAYMENT['creditorAccount']['iban']], valid_for=3600)
    assert mandate['status'] == 'pending' and mandate['challengeCode'] == '47'
    with urllib.request.urlopen(fake_api.base_url + '/__test/requests') as resp:
        last = json.loads(resp.read())[-1]
    _post(fake_api, '/__test/approve', {'id': last['id']})
    assert agent.get_mandate(mandate['mandateId'])['status'] == 'active'
    used = agent.request_approval(user, 'PAY_INVOICE', [PAYMENT], mandate_id=mandate['mandateId'])
    assert used['status'] == 'approved' and used['mandate']['usedCount'] == 1
    assert [m['mandateId'] for m in tq.agents.list_mandates(created['id'], user=user)] == [mandate['mandateId']]
    assert tq.agents.revoke_mandate(created['id'], mandate['mandateId'])['status'] == 'revoked'
    with pytest.raises(TouchQueAPIException) as refused:
        agent.request_approval(user, 'PAY_INVOICE', [PAYMENT], mandate_id=mandate['mandateId'])
    assert refused.value.code == 'mandate_revoked'
    assert agent.revoke_mandate(mandate['mandateId'])['status'] == 'revoked'
