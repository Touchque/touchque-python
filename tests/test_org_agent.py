"""An organization's AI agent on TouchQue SSO against the shared fake API's
/sso/token: its own key or its platform's token, a DPoP proof, and calls to an
app that checks the proof against the token's key."""
import json
import urllib.request

import pytest
import requests

from touchque import TouchQueOrgAgent, generate_agent_key
from touchque.exceptions import TouchQueAPIException, TouchQueConfigException
from .fake_api import fake_api  # noqa: F401 (fixture)

APP = 'tqapp_paymentsapi0000000000'


def _post(api, path, body):
    req = urllib.request.Request(api.base_url + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    return json.loads(urllib.request.urlopen(req).read() or b'{}')


def test_own_key_token_and_calls(fake_api):
    keys = generate_agent_key()
    agent_id = 'oagt_abcdefghijkmnpqrstuv'
    _post(fake_api, '/__test/org-agent', {'agentId': agent_id, 'publicKey': keys['public_jwk'], 'audiences': [APP], 'scopes': ['invoices:read', 'payments:create']})
    agent = TouchQueOrgAgent(agent_id=agent_id, private_key=keys['private_jwk'], issuer=fake_api.base_url)
    token = agent.get_token(scope='invoices:read')
    assert token['token_type'] == 'DPoP' and token['expires_in'] == 300 and token['scope'] == 'invoices:read'
    assert agent.get_token(scope='invoices:read') is token
    response = agent.request('GET', fake_api.base_url + '/__test/resource', scope='invoices:read')
    assert response.json() == {'ok': True, 'sub': agent_id, 'aud': APP, 'via': 'key'}
    headers = agent.authorization('GET', fake_api.base_url + '/__test/resource', scope='invoices:read')
    assert requests.get(fake_api.base_url + '/__test/resource', headers=headers).status_code == 200
    assert requests.get(fake_api.base_url + '/__test/resource', headers=headers).status_code == 401  # a proof is for one request
    with pytest.raises(TouchQueAPIException) as refused:
        agent.get_token(scope='payments:refund')
    assert refused.value.code == 'invalid_scope'


def test_platform_token(fake_api):
    agent_id = 'oagt_bbbbbbbbbbbbbbbbbbbb'
    _post(fake_api, '/__test/org-agent', {'agentId': agent_id, 'workload': {'subject': 'repo:acme/payments:ref:refs/heads/main', 'audience': 'touchque'}, 'audiences': [APP], 'scopes': ['invoices:read']})
    agent = TouchQueOrgAgent(agent_id=agent_id, issuer=fake_api.base_url,
                             assertion=lambda: _post(fake_api, '/__test/workload-token', {'sub': 'repo:acme/payments:ref:refs/heads/main', 'aud': 'touchque'})['token'])
    assert agent.request('GET', fake_api.base_url + '/__test/resource').json()['via'] == 'workload'
    wrong = TouchQueOrgAgent(agent_id=agent_id, issuer=fake_api.base_url,
                             assertion=lambda: _post(fake_api, '/__test/workload-token', {'sub': 'repo:evil/x', 'aud': 'touchque'})['token'])
    with pytest.raises(TouchQueAPIException):
        wrong.get_token()


def test_configuration_mistakes():
    with pytest.raises(TouchQueConfigException):
        TouchQueOrgAgent(agent_id='agt_abcdefghijkmnpqrstuv', private_key=generate_agent_key()['private_jwk'])
    with pytest.raises(TouchQueConfigException):
        TouchQueOrgAgent(agent_id='oagt_abcdefghijkmnpqrstuv', issuer='http://sso.example.com', assertion=lambda: 'x')


def test_for_a_member(fake_api):
    import threading
    keys = generate_agent_key()
    agent_id = 'oagt_cccccccccccccccccccc'
    _post(fake_api, '/__test/org-agent', {'agentId': agent_id, 'publicKey': keys['public_jwk'], 'audiences': [APP], 'scopes': ['payments:create'], 'delegation': ['token_exchange', 'ciba'], 'sharedAccounts': ['k3JInstagramAcme01']})
    agent = TouchQueOrgAgent(agent_id=agent_id, private_key=keys['private_jwk'], issuer=fake_api.base_url)

    def call(token):
        url = fake_api.base_url + '/__test/resource'
        return requests.get(url, headers={'Authorization': f'DPoP {token}', 'DPoP': agent.dpop_proof('GET', url, token)}).json()

    exchanged = agent.exchange_token('member:ada@acme.com')
    assert call(exchanged['access_token'])['sub'] == 'ada@acme.com'
    google = agent.get_connection_token('member:ada@acme.com', 'google', scope='email')
    assert google == {'access_token': 'ya29.ada@acme.com', 'token_type': 'Bearer', 'expires_in': 3599, 'scope': 'email', 'connection': 'google'}
    with pytest.raises(TouchQueAPIException) as e:
        agent.get_connection_token('member:ada@acme.com', 'github')
    assert e.value.code == 'invalid_grant'
    # A shared account: the member's extension opens it; the agent learns only how it ended.
    with pytest.raises(TouchQueAPIException) as e:
        agent.ask_to_open_shared_account('other', 'ada@acme.com')
    assert e.value.code == 'invalid_target'
    shared = agent.ask_to_open_shared_account('k3JInstagramAcme01', 'ada@acme.com', message='Post the launch photo')
    assert shared['status'] == 'waiting_member' and f"/agent-ask?ask={shared['ask_id']}" in shared['open_url']
    _post(fake_api, '/__test/shared-ask-answer', {'askId': shared['ask_id'], 'status': 'opened'})
    assert agent.wait_for_shared_account(shared, interval=0.05) == {'status': 'opened'}
    payment = {'type': 'payment_initiation', 'instructedAmount': {'currency': 'TRY', 'amount': '500.00'}}
    ask = agent.ask_member('ada@acme.com', binding_message='Pay invoice 42', authorization_details=[payment])
    assert ask['binding_code'] == '42' and ask['interval'] == 1
    threading.Timer(1.5, lambda: _post(fake_api, '/__test/ciba-answer', {'authReqId': ask['auth_req_id'], 'approve': True})).start()
    approved = agent.wait_for_member(ask)
    assert approved['authorization_details'] == [payment]
    assert call(approved['access_token'])['act'] == agent_id
    no = agent.ask_member('ada@acme.com')
    _post(fake_api, '/__test/ciba-answer', {'authReqId': no['auth_req_id'], 'approve': False})
    with pytest.raises(TouchQueAPIException) as refused:
        agent.wait_for_member(no)
    assert refused.value.code == 'access_denied'
