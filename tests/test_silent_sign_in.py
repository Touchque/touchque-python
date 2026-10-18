"""Silent sign-ins against the shared fake TouchQue API: the risk resource,
browser_proof on login requests, the guard's silent_sign_in option and the
relay's POST /login. Same scenarios as the Node SDK's silentSignIn tests."""
from unittest.mock import Mock

import pytest

from touchque import (
    BROWSER_HEADER, Config, RelayHandler, TouchQue, TouchQueAPIException, TouchQueNetworkException,
    silent_input_from_headers,
)
from touchque.exceptions import TouchQueConfigException
from touchque.guard import run_guard
from .fake_api import fake_api  # noqa: F401 (fixture)
from .silent_vectors import PROOF, THUMBPRINT
SILENT_CODES = ['known_browser', 'recent_approval', 'same_phone', 'familiar_network', 'no_risk_signal']


def client_for(api) -> TouchQue:
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))


@pytest.fixture
def api(fake_api):
    fake_api.link('jane@acme.com')
    return fake_api


GUARD = dict(user='jane@acme.com', action='LOGIN', ip='203.0.113.7', user_agent='UA', browser_proof=PROOF,
             silent_sign_in=True)


def guard(tq, **overrides):
    kwargs = {**GUARD, **overrides}
    return run_guard(tq, kwargs.pop('user'), kwargs.pop('action'), **kwargs)


# ── risk resource ────────────────────────────────────────────────────────

def test_check_a_browser_without_a_key_then_a_new_browser_asks_and_nothing_goes_to_the_phone(api):
    tq = client_for(api)
    res = tq.risk.check('jane@acme.com')
    assert res['prompt'] is True
    assert res['assurance'] == 'normal'
    assert res['silentMode'] == 'enforce'
    assert [r['code'] for r in res['reasons']] == ['no_browser_key']

    res = tq.risk.check('jane@acme.com', type='LOGIN', client_ip='203.0.113.7', user_agent='UA',
                        browser_proof=PROOF, max_age_seconds=3600)
    assert res['prompt'] is True
    assert res['reasons'] == [{'code': 'new_browser',
                               'text': 'This browser has not been approved on the phone for this account'}]
    assert api.last_check() == {'externalUsername': 'jane@acme.com', 'type': 'LOGIN', 'clientIp': '203.0.113.7',
                                'userAgent': 'UA', 'browserProof': PROOF, 'maxAgeSeconds': 3600}
    assert '/login/request' not in api.paths()


def test_check_silent_answers_prompt_false_a_critical_action_and_an_unlinked_user_still_ask(api):
    api.opts(silent=True)
    tq = client_for(api)
    res = tq.risk.check('jane@acme.com', browser_proof=PROOF)
    assert res['prompt'] is False
    assert res['assurance'] == 'high'
    assert [r['code'] for r in res['reasons']] == SILENT_CODES

    critical = tq.risk.check('jane@acme.com', type='SEND_MONEY', browser_proof=PROOF)
    assert critical['prompt'] is True
    assert critical['reasons'] == [{'code': 'critical_action', 'text': 'The action is critical'}]
    unlinked = tq.risk.check('nobody@acme.com', browser_proof=PROOF)
    assert unlinked['prompt'] is True
    assert [r['code'] for r in unlinked['reasons']] == ['phone_not_linked']


def test_check_max_age_zero_is_sent(api):
    client_for(api).risk.check('jane@acme.com', browser_proof=PROOF, max_age_seconds=0)
    assert api.last_check()['maxAgeSeconds'] == 0


def test_login_request_carries_the_proof_and_the_approval_makes_the_browser_known_until_forgotten(api):
    tq = client_for(api)
    request_id = tq.login.request('jane@acme.com', type='LOGIN', browser_proof=PROOF)['requestId']
    sent = [c for c in api.calls() if c['path'] == '/login/request'][0]['body']
    assert sent['browserProof'] == PROOF
    assert tq.risk.browsers('jane@acme.com') == {'browsers': []}

    api.approve(request_id)
    browsers = tq.risk.browsers('jane@acme.com')['browsers']
    assert len(browsers) == 1
    assert browsers[0]['thumbprint'] == THUMBPRINT
    assert browsers[0]['lastMfaMethod'] == 'push'
    assert browsers[0]['lastSilentAt'] is None
    assert 'user' not in browsers[0]

    assert tq.risk.forget_browsers('jane@acme.com', thumbprint='other') == {'forgotten': 0}
    assert tq.risk.forget_browsers('jane@acme.com', thumbprint=THUMBPRINT) == {'forgotten': 1}
    assert tq.risk.browsers('jane@acme.com') == {'browsers': []}


def test_forget_all_browsers_of_a_user(api):
    tq = client_for(api)
    tq.login.request('jane@acme.com', browser_proof=PROOF)
    api.approve()
    assert tq.risk.forget_browsers('jane@acme.com') == {'forgotten': 1}
    forget = [c for c in api.calls() if c['path'] == '/risk/browsers/forget'][0]['body']
    assert forget == {'externalUsername': 'jane@acme.com'}


def test_a_provisional_approval_during_a_call_does_not_make_the_browser_known(api):
    tq = client_for(api)
    tq.login.request('jane@acme.com', browser_proof=PROOF)
    api.approve(provisional=True)
    assert tq.risk.browsers('jane@acme.com') == {'browsers': []}


def test_risk_methods_need_the_user():
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url='http://127.0.0.1:9'))
    for call in (lambda: tq.risk.check(''), lambda: tq.risk.browsers(''), lambda: tq.risk.forget_browsers('')):
        with pytest.raises(TouchQueConfigException):
            call()


def test_browsers_reads_a_malformed_answer_as_no_browsers():
    from touchque.resources.risk import Risk
    http = Mock()
    for raw in ({}, {'browsers': 'x'}, [], None):
        http.get.return_value = raw
        assert Risk(http).browsers('a@b.com') == {'browsers': []}
    http.get.assert_called_with('/risk/browsers', {'externalUsername': 'a@b.com'})


# ── guard: silent_sign_in ────────────────────────────────────────────────

def test_guard_a_known_browser_with_nothing_new_is_approved_at_once_with_no_push(api):
    api.opts(silent=True)
    res = guard(client_for(api))
    assert res['status'] == 200
    approved = res['approved']
    assert approved['requestId'] == 'silent'
    assert approved['user'] == 'jane@acme.com'
    assert approved['action'] == 'LOGIN'
    assert approved['confirmedVia'] == 'SILENT'
    assert approved['assurance'] == {'phishingResistant': False, 'method': 'silent'}
    assert approved['approvalProof'] is None
    assert [r['code'] for r in approved['reasons']] == SILENT_CODES
    assert api.last_check() == {'externalUsername': 'jane@acme.com', 'type': 'LOGIN', 'clientIp': '203.0.113.7',
                                'userAgent': 'UA', 'browserProof': PROOF}
    assert api.paths() == ['/risk/check']


def test_guard_otherwise_the_usual_push_starts_carrying_the_proof_and_polls_never_check_again(api):
    tq = client_for(api)
    first = guard(tq)
    assert first['status'] == 202
    assert first['body']['touchque']['state'] == 'waiting'
    assert api.paths() == ['/risk/check', '/login/request']
    assert api.calls()[1]['body']['browserProof'] == PROOF

    # Polling with the token never asks again, even if the answer would now be silent.
    api.opts(silent=True)
    poll = guard(tq, token=first['body']['token'])
    assert poll['body']['touchque']['state'] == 'waiting'
    assert api.paths().count('/risk/check') == 1

    api.approve()
    done = guard(tq, token=first['body']['token'])
    assert done['status'] == 200
    assert done['approved']['confirmedVia'] == 'DEVICE'
    assert done['approved']['assurance']['method'] == 'push'
    assert [b['thumbprint'] for b in tq.risk.browsers('jane@acme.com')['browsers']] == [THUMBPRINT]


def test_guard_a_critical_action_always_asks_with_number_matching(api):
    api.opts(silent=True)
    res = guard(client_for(api), action='SEND_MONEY')
    assert res['status'] == 202
    assert res['body']['touchque']['state'] == 'waiting'
    assert res['body']['touchque']['number'] == '47'
    assert api.last_check()['type'] == 'SEND_MONEY'


@pytest.mark.parametrize('failure', [
    TouchQueNetworkException('network down'),
    TouchQueAPIException('not found', status=404, code='not_found'),
    TouchQueAPIException('boom', status=500),
    ValueError('unexpected'),
])
def test_guard_fails_closed_any_error_in_the_check_starts_the_usual_push(api, failure):
    api.opts(silent=True)
    tq = client_for(api)
    tq.risk.check = Mock(side_effect=failure)
    res = guard(tq)
    assert res['status'] == 202
    assert res['body']['touchque']['state'] == 'waiting'
    assert api.calls()[-1]['body']['browserProof'] == PROOF


@pytest.mark.parametrize('answer', [
    {'prompt': 'false', 'reasons': [], 'assurance': 'high', 'silentMode': 'enforce'},
    {'prompt': 0, 'reasons': []},
    {'prompt': None},
    {},
    None,
    'false',
])
def test_guard_an_answer_that_is_not_exactly_prompt_false_asks(api, answer):
    tq = client_for(api)
    tq.risk.check = Mock(return_value=answer)
    assert guard(tq)['body']['touchque']['state'] == 'waiting'


def test_guard_off_by_default_without_a_proof_or_with_a_proof_too_large_no_check(api):
    api.opts(silent=True)
    tq = client_for(api)
    assert guard(tq, silent_sign_in=False)['status'] == 202
    # Still attached: an approval makes the browser known.
    assert api.calls()[-1]['body']['browserProof'] == PROOF
    assert guard(tq, browser_proof=None)['status'] == 202
    assert guard(tq, browser_proof='x' * 5000)['status'] == 202
    assert 'browserProof' not in api.calls()[-1]['body']
    assert '/risk/check' not in api.paths()


def test_guard_max_age_seconds_is_sent_and_an_empty_dict_turns_it_on(api):
    tq = client_for(api)
    guard(tq, silent_sign_in={'max_age_seconds': 0})
    assert api.last_check()['maxAgeSeconds'] == 0
    guard(tq, silent_sign_in={})
    assert 'maxAgeSeconds' not in api.last_check()
    assert api.paths().count('/risk/check') == 2


def test_silent_input_from_headers_reads_the_header_only_when_on():
    headers = {BROWSER_HEADER: PROOF}
    assert silent_input_from_headers(False, headers.get) == {}
    assert silent_input_from_headers(None, headers.get) == {}
    assert silent_input_from_headers(True, headers.get) == {'silent_sign_in': True, 'browser_proof': PROOF}
    assert silent_input_from_headers({'max_age_seconds': 60}, {}.get) == {
        'silent_sign_in': {'max_age_seconds': 60}, 'browser_proof': None}


# ── relay: POST /login ───────────────────────────────────────────────────

def relay_login(handler, headers=None):
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    return handler.handle('POST', '/login', body={}, ip='203.0.113.7', user_agent='UA',
                          get_header=lambda name: hdrs.get(name.lower()))


def test_relay_login_silent_success_with_via_silent_a_new_browser_gets_the_push_with_the_proof(api):
    seen = []
    handler = RelayHandler(client_for(api), get_user_id=lambda req: None, get_login_user=lambda req: 'jane@acme.com',
                           rate_limit=False, silent_sign_in=True,
                           on_authenticated=lambda req, resp, info: seen.append(info))
    pushed = relay_login(handler, {'X-TouchQue-Browser': PROOF})
    assert pushed.status == 202
    assert api.calls()[-1]['path'] == '/login/request'
    assert api.calls()[-1]['body']['browserProof'] == PROOF
    assert seen == []

    api.opts(silent=True)
    silent = relay_login(handler, {'X-TouchQue-Browser': PROOF})
    assert silent.status == 200
    assert silent.body == {'status': 'success', 'requestId': 'silent',
                           'assurance': {'phishingResistant': False, 'method': 'silent'}}
    assert seen == [{'externalUsername': 'jane@acme.com', 'requestId': 'silent', 'via': 'silent'}]
    assert api.paths().count('/login/request') == 1


def test_relay_login_without_silent_sign_in_ignores_the_header(api):
    api.opts(silent=True)
    handler = RelayHandler(client_for(api), get_user_id=lambda req: None, get_login_user=lambda req: 'jane@acme.com',
                           rate_limit=False)
    res = relay_login(handler, {'X-TouchQue-Browser': PROOF})
    assert res.status == 202
    assert '/risk/check' not in api.paths()
    assert 'browserProof' not in api.calls()[-1]['body']
