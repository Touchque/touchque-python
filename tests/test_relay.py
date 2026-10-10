"""Framework-agnostic relay (touchque.relay.RelayHandler) - mirrors the Node
SDK's router tests."""
import logging
from unittest.mock import Mock

import pytest

from touchque import (
    FixedWindowLimiter, RelayHandler, TouchQueAPIException, TouchQueNetworkException, TouchQueRejectedException,
)
from touchque import relay as relay_module
from .fake_api import fake_api  # noqa: F401
from .relay_helpers import fake_tq, real_tq


def make(tq, **options):
    options.setdefault('get_user_id', lambda req: 'user@example.com')
    return RelayHandler(tq, **options)


def call(handler, method, path, body=None, headers=None, ip='203.0.113.1', user_agent=None, request=None,
         response=None):
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    return handler.handle(method, path, body=body, ip=ip, user_agent=user_agent,
                          get_header=lambda name: hdrs.get(name.lower()), request=request, response=response)


AUTH_REQUIRED = [
    ('POST', '/enroll/start'),
    ('GET', '/enroll/status'),
    ('POST', '/passkey/register/options'),
    ('POST', '/passkey/register/verify'),
    ('GET', '/passkey/credentials'),
    ('DELETE', '/passkey/credentials/abc'),
]


# ── auth-required routes ─────────────────────────────────────────────────

@pytest.mark.parametrize('method,path', AUTH_REQUIRED)
def test_auth_required_routes_401_without_user(method, path):
    tq = fake_tq()
    res = call(make(tq, get_user_id=lambda req: None), method, path, body={})
    assert res.status == 401
    assert res.body['error'] == 'UNAUTHORIZED_FOR_2FA'
    tq.auth.generate_secret.assert_not_called()
    tq.webauthn.delete_credential.assert_not_called()


def test_get_user_id_receives_the_native_request():
    seen = []
    native = object()
    call(make(fake_tq(), get_user_id=lambda req: seen.append(req)), 'GET', '/enroll/status', request=native)
    assert seen == [native]


def test_get_user_id_is_required():
    with pytest.raises(TypeError):
        RelayHandler(fake_tq())


def test_unknown_route_or_method_returns_none():
    h = make(fake_tq())
    assert call(h, 'GET', '/nope') is None
    assert call(h, 'GET', '/login') is None
    assert call(h, 'POST', '/passkey/credentials/x') is None
    assert call(h, 'GET', '/enroll/status/').status == 200  # trailing slash tolerated, like Express


# ── enrollment ───────────────────────────────────────────────────────────

def test_enroll_start_returns_secret():
    res = call(make(fake_tq()), 'POST', '/enroll/start')
    assert res.status == 200
    assert res.body['secret'] == 'S3CR3T'


def test_enroll_start_retries_via_reset_on_409_when_nothing_linked():
    tq = fake_tq()
    tq.auth.generate_secret.side_effect = TouchQueAPIException('pending', status=409)
    res = call(make(tq), 'POST', '/enroll/start')
    assert res.status == 200
    assert res.body['secret'] == 'NEWSECRET'
    tq.auth.reset_secret.assert_called_once_with('user@example.com')


def test_enroll_start_never_replaces_a_linked_phone():
    tq = fake_tq()
    tq.auth.generate_secret.side_effect = TouchQueAPIException('linked', status=409)
    tq.auth.get_user.return_value = {'used': True, 'deviceId': 'victim-phone'}
    res = call(make(tq), 'POST', '/enroll/start')
    assert res.status == 409
    assert res.body['error'] == 'already_linked'
    tq.auth.reset_secret.assert_not_called()


def test_enroll_start_already_linked_against_fake_api(fake_api):
    fake_api.link('user@example.com')
    res = call(make(real_tq(fake_api)), 'POST', '/enroll/start')
    assert res.status == 409
    assert res.body['error'] == 'already_linked'
    assert not [c for c in fake_api.calls() if c['path'] == '/auth/secret/reset']


def test_enroll_status_maps_404_to_not_linked():
    tq = fake_tq()
    tq.auth.get_user.side_effect = TouchQueAPIException('nope', status=404)
    res = call(make(tq), 'GET', '/enroll/status')
    assert (res.status, res.body) == (200, {'linked': False, 'used': False, 'deviceId': None})


def test_enroll_status_reports_linked():
    tq = fake_tq()
    tq.auth.get_user.return_value = {'used': True, 'deviceId': 'dev_1'}
    res = call(make(tq), 'GET', '/enroll/status')
    assert res.body == {'linked': True, 'used': True, 'deviceId': 'dev_1'}


# ── classic login (two-phase guard) ──────────────────────────────────────

def test_login_400_without_username(fake_api):
    res = call(make(real_tq(fake_api), rate_limit=False), 'POST', '/login', body={})
    assert res.status == 400
    assert res.body == {'error': 'externalUsername_required'}


def test_login_202_then_approved_calls_on_authenticated_once(fake_api):
    fake_api.link('user@example.com')
    fake_api.opts(numberMatch=True)
    on_auth = Mock()
    native_req, native_resp = object(), object()
    h = make(real_tq(fake_api), rate_limit=False, on_authenticated=on_auth,
             get_details=lambda req: {'Action': 'Sign in'})

    first = call(h, 'POST', '/login', body={'externalUsername': 'user@example.com'},
                 user_agent='Mozilla/5.0 (Macintosh)', request=native_req, response=native_resp)
    assert first.status == 202
    assert first.headers['Cache-Control'] == 'no-store'
    step = first.body['touchque']
    assert step['state'] == 'waiting' and step['number'] == '47'
    assert step['details'] == [{'label': 'Action', 'value': 'Sign in'}]
    sent = [c for c in fake_api.calls() if c['path'] == '/login/request'][0]['body']
    assert sent['externalUsername'] == 'user@example.com' and sent['type'] == 'LOGIN'
    assert sent['userAgent'] == 'Mozilla/5.0 (Macintosh)'
    on_auth.assert_not_called()

    fake_api.approve()
    token = first.body['token']
    done = call(h, 'POST', '/login', body={'externalUsername': 'user@example.com'},
                headers={'X-TouchQue-Token': token}, request=native_req, response=native_resp)
    assert done.status == 200
    assert done.body['status'] == 'success'
    assert done.body['requestId'] == step['requestId']
    assert done.body['assurance']['method'] == 'push'
    on_auth.assert_called_once_with(native_req, native_resp, {
        'externalUsername': 'user@example.com', 'requestId': step['requestId'], 'via': 'login'})

    replay = call(h, 'POST', '/login', body={'externalUsername': 'user@example.com'},
                  headers={'X-TouchQue-Token': token})
    assert replay.status != 200
    assert on_auth.call_count == 1


def test_login_rejected_and_unknown_user(fake_api):
    fake_api.link('user@example.com')
    h = make(real_tq(fake_api), rate_limit=False)
    first = call(h, 'POST', '/login', body={'externalUsername': 'user@example.com'})
    fake_api.reject()
    rej = call(h, 'POST', '/login', body={'externalUsername': 'user@example.com'},
               headers={'X-TouchQue-Token': first.body['token']})
    assert rej.status == 403 and rej.body['touchque']['state'] == 'rejected'
    fresh = call(h, 'POST', '/login', body={'externalUsername': 'new@example.com'})
    assert fresh.status == 202 and fresh.body['touchque']['state'] == 'enroll'


def test_login_guard_retry_after_is_forwarded(fake_api):
    fake_api.link('user@example.com')
    fake_api.opts(rateLimited=True)
    res = call(make(real_tq(fake_api), rate_limit=False), 'POST', '/login', body={'externalUsername': 'user@example.com'})
    assert res.status == 429
    assert res.headers['Retry-After'] == '60'
    assert res.headers['Cache-Control'] == 'no-store'


def test_login_passkey_required(fake_api):
    fake_api.link('a@example.com')
    fake_api.opts(passkeyOnly=True)
    res = call(make(real_tq(fake_api), rate_limit=False), 'POST', '/login', body={'externalUsername': 'a@example.com'})
    assert res.status == 202
    assert res.body['touchque']['state'] == 'passkey_required'


def test_login_on_authenticated_error_mapping(fake_api):
    """onAuthenticated failures use the auth-result mapping (sendAuthResultError)."""
    fake_api.link('user@example.com')
    cases = [
        (TouchQueRejectedException('no'), 403, '2FA_REJECTED'),
        (TouchQueAPIException('Thing not found', status=404, data={'error': 'thing_missing'}), 404, 'thing_missing'),
        (RuntimeError('boom'), 503, '2FA_UNAVAILABLE'),
    ]
    for exc, status, code in cases:
        fake_api.reset()
        fake_api.link('user@example.com')
        h = make(real_tq(fake_api), rate_limit=False, on_authenticated=Mock(side_effect=exc))
        first = call(h, 'POST', '/login', body={'externalUsername': 'user@example.com'})
        fake_api.approve()
        res = call(h, 'POST', '/login', body={'externalUsername': 'user@example.com'},
                   headers={'X-TouchQue-Token': first.body['token']})
        assert res.status == status
        assert res.body['error'] == code


# ── first-factor binding ─────────────────────────────────────────────────

def test_login_with_get_login_user_pushes_only_to_first_factor_user(fake_api):
    fake_api.link('alice@example.com')
    h = make(real_tq(fake_api), get_login_user=lambda req: 'Alice@Example.com', rate_limit=False)
    res = call(h, 'POST', '/login', body={'externalUsername': 'victim@example.com'})
    assert res.status == 202
    pushes = [c['body']['externalUsername'] for c in fake_api.calls() if c['path'] == '/login/request']
    assert pushes == ['alice@example.com']


@pytest.mark.parametrize('path,body', [
    ('/login', {'externalUsername': 'victim@example.com'}),
    ('/offline/challenge', {'externalUsername': 'victim@example.com'}),
    ('/offline/totp', {'externalUsername': 'victim@example.com', 'code': 'AAAAAAA'}),
])
def test_first_factor_required_when_get_login_user_returns_nothing(path, body):
    tq = fake_tq()
    res = call(make(tq, get_login_user=lambda req: None, rate_limit=False), 'POST', path, body=body)
    assert res.status == 401
    assert res.body['error'] == 'FIRST_FACTOR_REQUIRED'
    tq.login.request.assert_not_called()
    tq.offline.challenge.assert_not_called()
    tq.offline.verify_totp.assert_not_called()


def test_offline_challenge_uses_first_factor_user_not_body():
    tq = fake_tq()
    h = make(tq, get_login_user=lambda req: 'Alice@Example.com', rate_limit=False)
    res = call(h, 'POST', '/offline/challenge', body={'externalUsername': 'victim@example.com'})
    assert res.status == 200
    assert tq.offline.challenge.call_args[0][0] == 'alice@example.com'


def test_offline_code_for_a_different_user_does_not_open_a_session():
    tq = fake_tq()
    tq.offline.verify.return_value = {'approved': True, 'challengeId': 'c1',
                                      'externalUsername': 'someone.else@example.com', 'type': 'LOGIN'}
    on_auth = Mock()
    h = make(tq, get_login_user=lambda req: 'alice@example.com', on_authenticated=on_auth, rate_limit=False)
    res = call(h, 'POST', '/offline/verify', body={'challengeId': 'c1', 'code': 'AAAAAAA'})
    assert res.status == 401
    assert res.body == {'approved': False, 'reason': 'invalid_code'}
    on_auth.assert_not_called()


# ── offline sign ─────────────────────────────────────────────────────────

@pytest.mark.parametrize('path,body', [
    ('/offline/challenge', {'externalUsername': 'victim@example.com'}),
    ('/offline/verify', {'challengeId': 'c1', 'code': 'AAAAAAA'}),
    ('/offline/totp', {'externalUsername': 'victim@example.com', 'code': 'AAAAAAA'}),
])
def test_offline_routes_off_without_first_factor(path, body):
    tq = fake_tq()
    res = call(make(tq, rate_limit=False), 'POST', path, body=body)
    assert res.status == 403
    assert res.body['error'] == 'OFFLINE_REQUIRES_FIRST_FACTOR'
    tq.offline.challenge.assert_not_called()
    tq.offline.verify.assert_not_called()
    tq.offline.verify_totp.assert_not_called()


UNBOUND = {'allow_offline_without_first_factor': True}


def test_offline_challenge_passes_ip_ua_details_and_request_id():
    tq = fake_tq()
    h = make(tq, get_details=lambda req: {'Action': 'Sign in'}, **UNBOUND)
    res = call(h, 'POST', '/offline/challenge', body={'externalUsername': 'User@Example.com', 'requestId': 'r1'},
               user_agent='Mozilla/5.0 (Macintosh)')
    assert res.status == 200
    assert res.body == {'challengeId': 'c1', 'qr': 'TQ1.a.b', 'qrDataUrl': 'data:image/png;base64,q',
                        'expiresAt': 't', 'expiresInSeconds': 120, 'totpAvailable': True}
    tq.offline.challenge.assert_called_once_with(
        'user@example.com', type='LOGIN', client_ip='203.0.113.1', user_agent='Mozilla/5.0 (Macintosh)',
        details={'Action': 'Sign in'}, request_id='r1')


def test_offline_challenge_400_without_username():
    res = call(make(fake_tq(), **UNBOUND), 'POST', '/offline/challenge', body={})
    assert res.status == 400


def test_offline_verify_uses_username_from_touchque_not_body():
    on_auth = Mock()
    res = call(make(fake_tq(), on_authenticated=on_auth, **UNBOUND), 'POST', '/offline/verify',
               body={'challengeId': 'c1', 'code': 'ABC-DEFG', 'externalUsername': 'victim@example.com'})
    assert res.status == 200
    assert res.body == {'status': 'success', 'approved': True, 'requestId': 'c1'}
    assert on_auth.call_args[0][2] == {'externalUsername': 'user@example.com', 'requestId': 'c1', 'via': 'offline'}


def test_offline_verify_wrong_code_401_and_expired_400():
    on_auth = Mock()
    tq = fake_tq()
    tq.offline.verify.return_value = {'approved': False, 'reason': 'invalid_code', 'attemptsLeft': 4}
    res = call(make(tq, on_authenticated=on_auth, **UNBOUND), 'POST', '/offline/verify',
               body={'challengeId': 'c1', 'code': 'AAAAAAA'})
    assert (res.status, res.body) == (401, {'approved': False, 'reason': 'invalid_code', 'attemptsLeft': 4})
    tq.offline.verify.return_value = {'approved': False, 'reason': 'expired', 'attemptsLeft': None}
    res = call(make(tq, on_authenticated=on_auth, **UNBOUND), 'POST', '/offline/verify',
               body={'challengeId': 'c1', 'code': 'AAAAAAA'})
    assert (res.status, res.body) == (400, {'approved': False, 'reason': 'expired'})
    on_auth.assert_not_called()


def test_offline_totp_verifies_with_action_type_and_authenticates():
    on_auth = Mock()
    tq = fake_tq()
    res = call(make(tq, on_authenticated=on_auth, action_type='LOGIN', **UNBOUND), 'POST', '/offline/totp',
               body={'externalUsername': 'User@Example.com', 'code': 'ABCDEFG'})
    assert res.status == 200 and res.body == {'status': 'success', 'approved': True}
    tq.offline.verify_totp.assert_called_once_with('user@example.com', 'ABCDEFG', type='LOGIN',
                                                   client_ip='203.0.113.1', request_id=None)
    assert on_auth.call_args[0][2] == {'externalUsername': 'user@example.com', 'via': 'offline-totp'}


# ── passkeys ─────────────────────────────────────────────────────────────

def test_passkey_authenticate_options_relays():
    tq = fake_tq()
    res = call(make(tq), 'POST', '/passkey/authenticate/options', body={'email': 'User@example.com'})
    assert res.status == 200 and res.body['attemptId'] == 'att_1'
    tq.webauthn.primary_options.assert_called_once_with('user@example.com')


def test_passkey_authenticate_verify_success_and_step_up():
    on_auth = Mock()
    res = call(make(fake_tq(), on_authenticated=on_auth), 'POST', '/passkey/authenticate/verify',
               body={'attemptId': 'att_1', 'response': {}})
    assert res.body == {'status': 'success', 'requestId': 'req_2'}
    assert on_auth.call_args[0][2] == {'externalUsername': 'user@example.com', 'requestId': 'req_2', 'via': 'passkey'}

    on_auth.reset_mock()
    tq = fake_tq()
    tq.webauthn.primary_verify.return_value = {'success': False, 'requiresStepUp': True}
    res = call(make(tq, on_authenticated=on_auth), 'POST', '/passkey/authenticate/verify', body={})
    assert res.body == {'requiresStepUp': True}
    tq.webauthn.primary_verify.return_value = {'success': False}
    res = call(make(tq, on_authenticated=on_auth), 'POST', '/passkey/authenticate/verify', body={})
    assert (res.status, res.body) == (401, {'error': 'verification_failed'})
    on_auth.assert_not_called()


def test_passkey_login_options_relays():
    tq = fake_tq()
    res = call(make(tq), 'POST', '/passkey/login/options', body={'requestId': 'req_9'})
    assert res.status == 200
    tq.webauthn.authenticate_options.assert_called_once_with('req_9')


def test_passkey_login_verify_opens_session_for_touchque_user_not_browser_name():
    on_auth = Mock()
    tq = fake_tq()
    tq.webauthn.authenticate_verify.return_value = {'success': True, 'message': 'approved',
                                                    'externalUsername': 'attacker@example.com', 'requestId': 'req_9'}
    res = call(make(tq, on_authenticated=on_auth), 'POST', '/passkey/login/verify',
               body={'requestId': 'req_9', 'response': {}, 'externalUsername': 'victim@example.com'})
    assert res.status == 200
    on_auth.assert_called_once()
    assert on_auth.call_args[0][2] == {'externalUsername': 'attacker@example.com', 'requestId': 'req_9',
                                       'via': 'passkey'}


def test_passkey_login_verify_no_session_when_touchque_names_no_user():
    on_auth = Mock()
    call(make(fake_tq(), on_authenticated=on_auth), 'POST', '/passkey/login/verify',
         body={'requestId': 'req_9', 'response': {}, 'externalUsername': 'victim@example.com'})
    on_auth.assert_not_called()


def test_passkey_login_verify_user_mismatch_is_401():
    on_auth = Mock()
    tq = fake_tq()
    tq.webauthn.authenticate_verify.return_value = {'success': True, 'message': 'ok',
                                                    'externalUsername': 'other@example.com', 'requestId': 'r'}
    h = make(tq, get_login_user=lambda req: 'alice@example.com', on_authenticated=on_auth, rate_limit=False)
    res = call(h, 'POST', '/passkey/login/verify', body={'requestId': 'r', 'response': {}})
    assert (res.status, res.body) == (401, {'error': 'verification_failed'})
    on_auth.assert_not_called()


def test_passkey_login_verify_matching_first_factor_user_opens_session():
    on_auth = Mock()
    tq = fake_tq()
    tq.webauthn.authenticate_verify.return_value = {'success': True, 'externalUsername': 'Alice@example.com'}
    h = make(tq, get_login_user=lambda req: 'alice@example.com', on_authenticated=on_auth, rate_limit=False)
    res = call(h, 'POST', '/passkey/login/verify', body={'requestId': 'r', 'response': {}})
    assert res.status == 200
    assert on_auth.call_args[0][2] == {'externalUsername': 'Alice@example.com', 'requestId': 'r', 'via': 'passkey'}


def test_passkey_management_routes():
    tq = fake_tq()
    h = make(tq)
    assert call(h, 'POST', '/passkey/register/options').status == 200
    tq.webauthn.register_options.assert_called_once_with('user@example.com', discoverable=True)
    assert call(h, 'POST', '/passkey/register/verify', body={'response': {'id': 'x'}, 'label': 'Mac'}).body == {
        'verified': True, 'credentialId': 'cred_1'}
    tq.webauthn.register_verify.assert_called_once_with('user@example.com', {'id': 'x'}, label='Mac')
    assert call(h, 'GET', '/passkey/credentials').body == {'credentials': []}
    res = call(h, 'DELETE', '/passkey/credentials/cred_1')
    assert (res.status, res.body) == (200, {'deleted': True})
    tq.webauthn.delete_credential.assert_called_once_with('cred_1', external_username='user@example.com')


# ── relay error mapping ──────────────────────────────────────────────────

def test_relay_4xx_forwards_code_only_never_message():
    tq = fake_tq()
    tq.webauthn.primary_options.side_effect = TouchQueAPIException(
        'Internal detail: tenant 42 has no passkey', status=404, code='no_passkey_registered',
        data={'error': 'Internal detail', 'code': 'no_passkey_registered'})
    res = call(make(tq), 'POST', '/passkey/authenticate/options', body={'email': 'a@b.c'})
    assert (res.status, res.body) == (404, {'error': 'no_passkey_registered'})


def test_relay_4xx_without_code_uses_data_error_or_default():
    tq = fake_tq()
    tq.webauthn.list_credentials.side_effect = TouchQueAPIException('x', status=400, data={'error': 'bad_input'})
    assert call(make(tq), 'GET', '/passkey/credentials').body == {'error': 'bad_input'}
    tq.webauthn.list_credentials.side_effect = TouchQueAPIException('x', status=400)
    assert call(make(tq), 'GET', '/passkey/credentials').body == {'error': 'request_failed'}


@pytest.mark.parametrize('exc', [
    TouchQueAPIException('db down', status=500, code='internal'),
    TouchQueNetworkException('Network Error: refused'),
    RuntimeError('unexpected'),
])
def test_relay_5xx_network_and_unexpected_become_502(exc):
    tq = fake_tq()
    tq.webauthn.register_options.side_effect = exc
    res = call(make(tq), 'POST', '/passkey/register/options')
    assert (res.status, res.body) == (502, {'error': 'relay_error'})


def test_login_touchque_unreachable_is_503_without_details(fake_api):
    h = make(real_tq(fake_api), rate_limit=False)
    fake_api.close()
    res = call(h, 'POST', '/login', body={'externalUsername': 'user@example.com'})
    assert res.status == 503
    assert res.body['error']['code'] == 'unavailable'


# ── rate limiting ────────────────────────────────────────────────────────

def test_login_capped_per_username_across_ips(fake_api):
    fake_api.link('victim@example.com')
    h = make(real_tq(fake_api), rate_limit={'per_user': 3, 'per_ip': 100})
    statuses = []
    for i in range(5):
        r = call(h, 'POST', '/login', body={'externalUsername': 'victim@example.com'}, ip='198.51.100.%d' % i)
        statuses.append(r.status)
        if r.status == 429:
            assert r.body['error'] == 'RATE_LIMITED'
            assert int(r.headers['Retry-After']) > 0
            assert r.body['retryAfter'] == int(r.headers['Retry-After'])
    assert statuses == [202, 202, 202, 429, 429]
    assert len([c for c in fake_api.calls() if c['path'] == '/login/request']) == 3


def test_one_ip_spraying_usernames_is_capped_per_ip():
    tq = fake_tq()
    h = make(tq, rate_limit={'per_ip': 4, 'per_user': 100}, **UNBOUND)
    statuses = [call(h, 'POST', '/offline/challenge', body={'externalUsername': 'u%d@example.com' % i},
                     ip='203.0.113.7').status for i in range(6)]
    assert statuses.count(429) == 2
    assert tq.offline.challenge.call_count == 4


def test_offline_code_guessing_is_capped_per_ip():
    tq = fake_tq()
    tq.offline.verify.return_value = {'approved': False, 'reason': 'invalid_code', 'attemptsLeft': 3}
    h = make(tq, rate_limit={'per_ip': 3}, **UNBOUND)
    statuses = [call(h, 'POST', '/offline/verify', body={'challengeId': 'c1', 'code': 'AAAAAAA'},
                     ip='203.0.113.7').status for _ in range(5)]
    assert statuses == [401, 401, 401, 429, 429]


def test_passkey_login_options_and_verify_share_one_budget():
    h = make(fake_tq(), rate_limit={'per_ip': 2})
    assert call(h, 'POST', '/passkey/login/options', body={'requestId': 'r'}).status == 200
    assert call(h, 'POST', '/passkey/login/verify', body={'requestId': 'r'}).status == 200
    assert call(h, 'POST', '/passkey/login/options', body={'requestId': 'r'}).status == 429


def test_rate_limit_false_turns_limiter_off():
    tq = fake_tq()
    h = make(tq, rate_limit=False, **UNBOUND)
    for _ in range(30):
        assert call(h, 'POST', '/offline/challenge', body={'externalUsername': 'a@example.com'}).status == 200


def test_default_limits_are_20_per_ip_and_5_per_user():
    h = make(fake_tq(), **UNBOUND)
    assert (h.limiter.window_ms, h.limiter.per_ip, h.limiter.per_user) == (60000, 20, 5)
    statuses = [call(h, 'POST', '/offline/challenge', body={'externalUsername': 'a@example.com'}).status
                for _ in range(6)]
    assert statuses == [200] * 5 + [429]


# ── limiter ──────────────────────────────────────────────────────────────

def test_fixed_window_limiter_semantics():
    lim = FixedWindowLimiter(window_ms=10000)
    assert [lim.hit('k', 2, now=0) for _ in range(3)] == [0, 0, 10]
    assert lim.hit('k', 2, now=9500) == 1
    assert lim.hit('k', 2, now=10000) == 0  # new window


def test_fixed_window_limiter_prunes_at_max_keys(monkeypatch):
    from touchque import rate_limiter
    monkeypatch.setattr(rate_limiter, 'MAX_KEYS', 10)
    lim = FixedWindowLimiter(window_ms=1000)
    for i in range(10):
        lim.hit('old%d' % i, 5, now=0)
    lim.hit('new', 5, now=5000)  # everything expired -> pruned
    assert list(lim._entries) == ['new']
    for i in range(9):
        lim.hit('live%d' % i, 5, now=5000)
    lim.hit('one-more', 5, now=5000)  # still full: drop the oldest half (+1)
    assert len(lim._entries) == 10 - (10 // 2 + 1) + 1


# ── warning ──────────────────────────────────────────────────────────────

def test_warns_once_without_get_login_user(monkeypatch, caplog):
    monkeypatch.setattr(relay_module, '_warned_pre_auth', False)
    with caplog.at_level(logging.WARNING, logger='touchque'):
        make(fake_tq())
        make(fake_tq())
    warnings = [r for r in caplog.records if 'get_login_user' in r.getMessage()]
    assert len(warnings) == 1
    assert 'offline routes are disabled' in warnings[0].getMessage()


def test_no_warning_with_get_login_user(monkeypatch, caplog):
    monkeypatch.setattr(relay_module, '_warned_pre_auth', False)
    with caplog.at_level(logging.WARNING, logger='touchque'):
        make(fake_tq(), get_login_user=lambda req: 'a@b.c')
    assert not [r for r in caplog.records if 'get_login_user' in r.getMessage()]


def test_async_callback_without_async_adapter_is_a_clear_error():
    async def get_user(req):
        return 'a@b.c'

    with pytest.raises(TypeError):
        call(make(fake_tq(), get_user_id=get_user), 'GET', '/enroll/status')
