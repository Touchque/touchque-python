"""2FA setup context: where a first-time linking QR was asked for.

``generate_secret`` / ``reset_secret`` send the browser's IP address and
User-Agent (each only when given, as it is, like ``login.request``), the guard
and the relay pass the request's, and ``validate_secret`` answers
``setupContext``, read leniently (fixtures/setup-context.json, shared by every
SDK)."""
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

import touchque
from touchque import (
    Config, RelayHandler, SetupContext, SetupDevice, SetupLocation, Touchque, TouchqueAPIException,
    parse_setup_context, run_guard,
)
from touchque.resources.auth import Auth
from touchque.resources.login import Login
from touchque.steps import _iso_ms, start
from .fake_api import fake_api  # noqa: F401

with open(os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'setup-context.json'),
          encoding='utf-8') as f:
    FIXTURE = json.load(f)

CASES = ('full', 'allNull', 'missing', 'null', 'wrongTypes', 'extraFields')
SECRET_CALLS = [('generate_secret', '/auth/generate-secret'), ('reset_secret', '/auth/secret/reset')]
SAFARI_IPHONE = ('Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 '
                 '(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1')
FIREFOX_WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0'
BERLIN_SAFARI = {'ip': '203.0.113.7', 'location': {'city': 'Berlin', 'country': 'Germany', 'countryCode': 'DE'},
                 'device': {'browser': 'Safari', 'os': 'iOS', 'model': 'iPhone'}, 'farFromPhone': None}
NEW_YORK_FIREFOX = {'ip': '198.51.100.23',
                    'location': {'city': 'New York', 'country': 'United States', 'countryCode': 'US'},
                    'device': {'browser': 'Firefox', 'os': 'Windows', 'model': None}, 'farFromPhone': None}
ALL_NONE = {'ip': None, 'location': None, 'device': None, 'requestedAt': None, 'farFromPhone': None}


def _auth():
    http = MagicMock()
    http.post.return_value = {'secret': 's'}
    return Auth(http), http


# ── what generate_secret / reset_secret send ─────────────────────────────

@pytest.mark.parametrize('method,path', SECRET_CALLS)
def test_the_secret_request_carries_the_browser(method, path):
    auth, http = _auth()
    getattr(auth, method)('a@b.com', client_ip='203.0.113.7', user_agent=SAFARI_IPHONE)
    http.post.assert_called_once_with(path, {'externalUsername': 'a@b.com', 'clientIp': '203.0.113.7',
                                             'userAgent': SAFARI_IPHONE})


@pytest.mark.parametrize('method,path', SECRET_CALLS)
@pytest.mark.parametrize('client_ip,user_agent,sent', [
    (None, None, {}),
    ('', '', {}),
    ('203.0.113.7', None, {'clientIp': '203.0.113.7'}),
    ('203.0.113.7', '', {'clientIp': '203.0.113.7'}),
    (None, 'UA/1', {'userAgent': 'UA/1'}),
    ('', 'UA/1', {'userAgent': 'UA/1'}),
])
def test_each_is_left_out_when_none_or_empty(method, path, client_ip, user_agent, sent):
    auth, http = _auth()
    getattr(auth, method)('a@b.com', client_ip=client_ip, user_agent=user_agent)
    http.post.assert_called_once_with(path, {'externalUsername': 'a@b.com', **sent})


@pytest.mark.parametrize('client_ip,user_agent', [
    (' 203.0.113.7 ', '  Mozilla/5.0 (Macintosh)  '),  # not trimmed
    ('203.0.113.7:51234', 'Mozilla/5.0 ' + 'x' * 5000),  # no format check, no length cap
    ('not an address', 'Mozilla/5.0 \u00e9\u4e2d \U0001F600\n'),  # nor any other check
])
def test_they_are_sent_as_given_like_the_login_request(client_ip, user_agent):
    """The login request's rules: no trimming, no length cap, no check of the value."""
    http = MagicMock()
    http.post.return_value = {'requestId': 'r', 'secret': 's'}
    Login(http).request('a@b.com', client_ip=client_ip, user_agent=user_agent)
    Auth(http).generate_secret('a@b.com', client_ip=client_ip, user_agent=user_agent)
    Auth(http).reset_secret('a@b.com', client_ip=client_ip, user_agent=user_agent)
    login, generate, reset = (c[0][1] for c in http.post.call_args_list)
    for body in (generate, reset):
        assert (body['clientIp'], body['userAgent']) == (login['clientIp'], login['userAgent']) \
            == (client_ip, user_agent)


def test_they_are_keyword_only():
    auth, http = _auth()
    for method, _ in SECRET_CALLS:
        with pytest.raises(TypeError):
            getattr(auth, method)('a@b.com', '203.0.113.7')
    http.post.assert_not_called()


# ── validate_secret: setupContext, read leniently ────────────────────────

@pytest.mark.parametrize('case', CASES)
def test_validate_secret_reads_the_setup_context_of_every_shared_case(case):
    answer = FIXTURE[case]
    http = MagicMock()
    http.post.return_value = json.loads(json.dumps(answer))
    res = Auth(http).validate_secret('S')
    http.post.assert_called_once_with('/auth/secret/validate', {'secret': 'S'})
    assert res['setupContext'] == FIXTURE['expected'][case]
    # The rest of the answer as the API sent it (an unknown top-level key included), and that answer untouched.
    assert {k: v for k, v in res.items() if k != 'setupContext'} == \
        {k: v for k, v in answer.items() if k != 'setupContext'}
    assert http.post.return_value == answer
    assert parse_setup_context(answer.get('setupContext')) == FIXTURE['expected'][case]


@pytest.mark.parametrize('raw', ['203.0.113.7', 42, 1.5, True, False, ['203.0.113.7'], None])
def test_a_setup_context_that_is_not_an_object_is_none(raw):
    assert parse_setup_context(raw) is None
    http = MagicMock()
    http.post.return_value = {'valid': True, 'setupContext': raw}
    assert Auth(http).validate_secret('S') == {'valid': True, 'setupContext': None}


def test_every_value_of_the_wrong_type_is_none_never_an_error():
    assert parse_setup_context({}) == ALL_NONE
    assert parse_setup_context({'ip': ['203.0.113.7'], 'location': ['Berlin'], 'device': 'Safari on iOS',
                                'requestedAt': 1763285400000, 'farFromPhone': 1}) == ALL_NONE
    assert parse_setup_context({'ip': True, 'location': None, 'device': None, 'requestedAt': {'at': 'now'},
                                'farFromPhone': 'false'}) == ALL_NONE
    assert parse_setup_context({'location': {'city': 7, 'country': None, 'countryCode': {'iso': 'DE'}},
                                'device': {'browser': False, 'os': 10.5, 'model': ['iPhone']},
                                'farFromPhone': 0}) == {
        'ip': None, 'location': {'city': None, 'country': None, 'countryCode': None},
        'device': {'browser': None, 'os': None, 'model': None}, 'requestedAt': None, 'farFromPhone': None}
    assert parse_setup_context({'location': {}, 'device': {}, 'farFromPhone': False}) == {
        'ip': None, 'location': {'city': None, 'country': None, 'countryCode': None},
        'device': {'browser': None, 'os': None, 'model': None}, 'requestedAt': None, 'farFromPhone': False}


def test_requested_at_stays_the_string_the_api_sent():
    assert parse_setup_context({'requestedAt': 'not a date'})['requestedAt'] == 'not a date'
    assert parse_setup_context({'requestedAt': '2026-11-16T09:30:00.000Z'})['requestedAt'] == \
        '2026-11-16T09:30:00.000Z'


def test_an_answer_that_is_not_an_object_is_returned_as_it_is():
    http = MagicMock()
    http.post.return_value = ['odd']
    assert Auth(http).validate_secret('S') == ['odd']


def test_the_types_are_exported_with_the_other_response_types():
    for name in ('SetupContext', 'SetupLocation', 'SetupDevice', 'parse_setup_context'):
        assert name in touchque.__all__ and getattr(touchque, name)
    assert set(SetupContext.__annotations__) == {'ip', 'location', 'device', 'requestedAt', 'farFromPhone'}
    assert set(SetupLocation.__annotations__) == {'city', 'country', 'countryCode'}
    assert set(SetupDevice.__annotations__) == {'browser', 'os', 'model'}
    full = parse_setup_context(FIXTURE['full']['setupContext'])
    assert set(full) == set(SetupContext.__annotations__)
    assert set(full['location']) == set(SetupLocation.__annotations__)
    assert set(full['device']) == set(SetupDevice.__annotations__)
    json.dumps(full)  # plain JSON data, like the rest of the answer


# ── the guard's first-time QR (steps.start) ──────────────────────────────

def _no_phone(generate=None, linked=False):
    """A client whose user has no phone: the push answers 404, then the first-time QR."""
    return SimpleNamespace(
        login=SimpleNamespace(request=Mock(side_effect=TouchqueAPIException(
            'No linked device found for this user', status=404, code='device_not_linked'))),
        auth=SimpleNamespace(
            generate_secret=Mock(side_effect=generate) if generate else Mock(
                return_value={'qrCodeDataUrl': 'qr1', 'recoveryCodes': ['r1']}),
            reset_secret=Mock(return_value={'qrCodeDataUrl': 'qr2', 'recoveryCodes': ['r2']}),
            get_user=Mock(return_value={'used': linked, 'deviceId': 'dev-1' if linked else None}),
        ),
    )


def test_the_first_time_qr_gets_the_browser_the_push_got():
    tq = _no_phone()
    step = start(tq, 'LOGIN', 'new@acme.com', ip='203.0.113.7', user_agent=SAFARI_IPHONE)
    assert step['state'] == 'enroll' and step['enroll']['qrCodeDataUrl'] == 'qr1'
    push = tq.login.request.call_args[1]
    assert (push['client_ip'], push['user_agent']) == ('203.0.113.7', SAFARI_IPHONE)
    tq.auth.generate_secret.assert_called_once_with('new@acme.com', client_ip='203.0.113.7', user_agent=SAFARI_IPHONE)


def test_a_new_qr_after_a_409_gets_it_too_and_a_linked_phone_is_never_replaced():
    tq = _no_phone(generate=TouchqueAPIException('Secret already generated', status=409))
    step = start(tq, 'LOGIN', 'new@acme.com', ip='198.51.100.23', user_agent=FIREFOX_WINDOWS)
    assert step['enroll']['qrCodeDataUrl'] == 'qr2'
    tq.auth.reset_secret.assert_called_once_with('new@acme.com', client_ip='198.51.100.23',
                                                 user_agent=FIREFOX_WINDOWS)

    linked = _no_phone(generate=TouchqueAPIException('already linked', status=409), linked=True)
    assert start(linked, 'LOGIN', 'new@acme.com', ip='198.51.100.23') == {'state': 'enroll',
                                                                          'reason': 'already_linked'}
    linked.auth.reset_secret.assert_not_called()


def test_without_an_address_or_user_agent_none_goes_like_for_the_push():
    tq = _no_phone()
    start(tq, 'LOGIN', 'new@acme.com')
    push = tq.login.request.call_args[1]
    assert (push['client_ip'], push['user_agent']) == (None, None)
    tq.auth.generate_secret.assert_called_once_with('new@acme.com', client_ip=None, user_agent=None)


def test_enrollment_off_makes_no_qr_at_all():
    tq = _no_phone()
    assert start(tq, 'LOGIN', 'new@acme.com', ip='203.0.113.7', enroll=False) == {
        'state': 'enroll', 'reason': 'enrollment_off'}
    tq.auth.generate_secret.assert_not_called()


# ── end to end, against the shared fake API ──────────────────────────────

def client_for(api) -> Touchque:
    return Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))


def bodies(api, path):
    return [c['body'] for c in api.calls() if c['path'] == path]


def context(res):
    """A validate answer's setupContext without requestedAt (checked to be an ISO 8601 string)."""
    ctx = dict(res['setupContext'])
    assert isinstance(ctx['requestedAt'], str) and _iso_ms(ctx.pop('requestedAt')) is not None
    return ctx


def test_generate_with_the_browser_then_validate_shows_it(fake_api):
    tq = client_for(fake_api)
    qr = tq.auth.generate_secret('new@acme.com', client_ip='203.0.113.7', user_agent=SAFARI_IPHONE)
    assert bodies(fake_api, '/auth/generate-secret') == [
        {'externalUsername': 'new@acme.com', 'clientIp': '203.0.113.7', 'userAgent': SAFARI_IPHONE}]
    res = tq.auth.validate_secret(qr['secret'])
    assert res['valid'] is True and res['externalUsername'] == 'new@acme.com'
    assert res['integration']['companyName'] == 'Fake workspace'
    assert context(res) == BERLIN_SAFARI

    again = tq.auth.reset_secret('new@acme.com', client_ip='198.51.100.23', user_agent=FIREFOX_WINDOWS)
    assert bodies(fake_api, '/auth/secret/reset') == [
        {'externalUsername': 'new@acme.com', 'clientIp': '198.51.100.23', 'userAgent': FIREFOX_WINDOWS}]
    assert context(tq.auth.validate_secret(again['secret'])) == NEW_YORK_FIREFOX
    with pytest.raises(TouchqueAPIException) as err:
        tq.auth.validate_secret(qr['secret'])  # replaced by the reset
    assert (err.value.status, err.value.reason) == (404, 'not_found')
    # A reset without them: the new QR has no setup context, not the old QR's.
    assert tq.auth.validate_secret(tq.auth.reset_secret('new@acme.com')['secret'])['setupContext'] is None


def test_no_browser_or_an_older_qr_is_no_setup_context(fake_api):
    tq = client_for(fake_api)
    qr = tq.auth.generate_secret('new@acme.com', client_ip='', user_agent=None)
    assert bodies(fake_api, '/auth/generate-secret') == [{'externalUsername': 'new@acme.com'}]
    assert tq.auth.validate_secret(qr['secret'])['setupContext'] is None

    again = tq.auth.reset_secret('new@acme.com', client_ip='203.0.113.7', user_agent=SAFARI_IPHONE)
    fake_api.opts(setupContextNull=True)  # an API that answers null
    assert tq.auth.validate_secret(again['secret'])['setupContext'] is None


def test_the_guards_qr_and_its_renewal_carry_the_browser_of_the_request_that_made_them(fake_api):
    api = fake_api
    api.opts(secretTtlMs=10000)  # inside the 15 s margin: the next poll makes a new QR
    tq = client_for(api)
    first = run_guard(tq, 'new@acme.com', 'LOGIN', ip='203.0.113.7', user_agent=SAFARI_IPHONE)
    assert first['body']['touchque']['enroll']['qrCodeDataUrl'] == 'data:image/png;base64,QR-new@acme.com'
    assert context(tq.auth.validate_secret('S')) == BERLIN_SAFARI

    poll = run_guard(tq, 'new@acme.com', 'LOGIN', token=first['body']['token'], ip='198.51.100.23',
                     user_agent=FIREFOX_WINDOWS)
    assert poll['body']['touchque']['enroll']['qrCodeDataUrl'] == 'data:image/png;base64,QR2-new@acme.com'
    # Each secret request carries what that request's push carried.
    pushes = [(b['clientIp'], b['userAgent']) for b in bodies(api, '/login/request')]
    assert pushes == [('203.0.113.7', SAFARI_IPHONE), ('198.51.100.23', FIREFOX_WINDOWS)]
    assert [(b['clientIp'], b['userAgent']) for b in bodies(api, '/auth/generate-secret')] == pushes
    assert [(b['clientIp'], b['userAgent']) for b in bodies(api, '/auth/secret/reset')] == pushes[1:]
    assert context(tq.auth.validate_secret('S2')) == NEW_YORK_FIREFOX


def test_the_relay_sends_the_browser_for_enrollment_and_for_a_qr_behind_the_password(fake_api):
    tq = client_for(fake_api)
    h = RelayHandler(tq, get_user_id=lambda req: 'new@acme.com', get_login_user=lambda req: 'late@acme.com',
                     rate_limit=False)
    first = h.handle('POST', '/enroll/start', ip='203.0.113.7', user_agent=SAFARI_IPHONE)
    assert first.status == 200
    assert context(tq.auth.validate_secret(first.body['secret'])) == BERLIN_SAFARI
    renewed = h.handle('POST', '/enroll/start', ip='198.51.100.23', user_agent=FIREFOX_WINDOWS)  # 409: reset
    assert renewed.status == 200 and renewed.body['secret'] == 'S2'
    assert context(tq.auth.validate_secret('S2')) == NEW_YORK_FIREFOX

    login = h.handle('POST', '/login', body={}, ip='198.51.100.23', user_agent=FIREFOX_WINDOWS)
    assert login.status == 202 and login.body['touchque']['enroll']['qrCodeDataUrl']
    assert [(b['externalUsername'], b['clientIp'], b['userAgent'])
            for b in bodies(fake_api, '/auth/generate-secret')] == [
        ('new@acme.com', '203.0.113.7', SAFARI_IPHONE),
        ('new@acme.com', '198.51.100.23', FIREFOX_WINDOWS),  # a QR is out: 409, then the reset
        ('late@acme.com', '198.51.100.23', FIREFOX_WINDOWS)]
    assert bodies(fake_api, '/auth/secret/reset') == [
        {'externalUsername': 'new@acme.com', 'clientIp': '198.51.100.23', 'userAgent': FIREFOX_WINDOWS}]
    push = bodies(fake_api, '/login/request')[-1]
    assert (push['externalUsername'], push['clientIp'], push['userAgent']) == (
        'late@acme.com', '198.51.100.23', FIREFOX_WINDOWS)


# ── touchque.testing.FakeTouchque ────────────────────────────────────────

def test_the_fake_records_the_browser_and_validate_answers_like_the_api(monkeypatch):
    from touchque import testing
    from touchque.testing import FakeTouchque
    tq = FakeTouchque(linked=False)
    for secret, status, reason in (('', 400, None), ('S404', 404, 'not_found')):
        with pytest.raises(TouchqueAPIException) as err:
            tq.auth.validate_secret(secret)
        assert (err.value.status, err.value.reason) == (status, reason)

    first = tq.auth.generate_secret('new@acme.com', client_ip='203.0.113.7', user_agent=SAFARI_IPHONE)
    setup = tq.setups[-1]
    assert setup == {'user': 'new@acme.com', 'secret': first['secret'], 'clientIp': '203.0.113.7',
                     'userAgent': SAFARI_IPHONE, 'requestedAt': setup['requestedAt'], 'expiresAt': first['expiresAt']}
    assert tq.auth.validate_secret(first['secret']) == {
        'valid': True, 'externalUsername': 'new@acme.com', 'integrationId': 'int-1',
        'integration': {'companyName': 'Fake workspace', 'icon': 'key-outline', 'color': '#007AFF', 'logo': None,
                        'logoDark': None, 'logoVersion': None},
        'setupContext': dict(BERLIN_SAFARI, requestedAt=setup['requestedAt'])}

    # A reset replaces the QR (the old secret is not found) and keeps its own request's browser.
    second = tq.auth.reset_secret('new@acme.com', client_ip='198.51.100.23', user_agent=FIREFOX_WINDOWS)
    assert [(s['secret'], s['clientIp']) for s in tq.setups] == [(first['secret'], '203.0.113.7'),
                                                                (second['secret'], '198.51.100.23')]
    with pytest.raises(TouchqueAPIException) as err:
        tq.auth.validate_secret(first['secret'])
    assert err.value.reason == 'not_found'
    assert context(tq.auth.validate_secret(second['secret'])) == NEW_YORK_FIREFOX

    # Nothing named: no setup context; the API's rules for what it keeps and shows.
    assert tq.auth.validate_secret(tq.auth.reset_secret('new@acme.com')['secret'])['setupContext'] is None
    assert tq.setups[-1]['clientIp'] is None and tq.setups[-1]['userAgent'] is None
    for client_ip, user_agent, expected in (
            # A port, brackets and ::ffff: are dropped; not a browser: no device.
            ('[::ffff:203.0.113.7]:443', 'curl/8.7.1', dict(BERLIN_SAFARI, device=None)),
            ('198.51.100.23:8443', 'Mozilla/5.0 (Linux; Android 15) Chrome/131.0 Mobile Safari/537.36',
             dict(NEW_YORK_FIREFOX, device={'browser': 'Chrome', 'os': 'Android', 'model': None})),
            # A loopback address is not kept, a private one is not shown.
            ('127.0.0.1', 'Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) Version/18.1 Safari/604.1',
             dict(ALL_NONE, device={'browser': 'Safari', 'os': 'iPadOS', 'model': 'iPad'})),
            ('10.1.2.3', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) Edg/131.0',
             dict(ALL_NONE, device={'browser': 'Edge', 'os': 'macOS', 'model': None})),
            ('fe80::1', None, ALL_NONE),
            # Neither kept (no IP address, a User-Agent of control characters only): no setup context.
            ('not an address', ' \x00\t ', None)):
        secret = tq.auth.reset_secret('new@acme.com', client_ip=client_ip, user_agent=user_agent)['secret']
        assert tq.auth.validate_secret(secret)['setupContext'] == (
            expected and dict(expected, requestedAt=tq.setups[-1]['requestedAt']))

    # Expired: 410; linked since: 409 with when it was first seen used.
    latest = tq.setups[-1]['secret']
    real_now = testing._now_ms
    monkeypatch.setattr(testing, '_now_ms', lambda: real_now() + tq.secret_ttl_ms + 1000)
    with pytest.raises(TouchqueAPIException) as err:
        tq.auth.validate_secret(latest)
    assert (err.value.status, err.value.reason, err.value.data['expiredAt']) == (
        410, 'expired', tq.setups[-1]['expiresAt'])
    monkeypatch.setattr(testing, '_now_ms', real_now)
    tq.link('new@acme.com')
    used = []
    for _ in range(2):
        with pytest.raises(TouchqueAPIException) as err:
            tq.auth.validate_secret(latest)
        assert (err.value.status, err.value.reason) == (409, 'already_used')
        used.append(err.value.data['usedAt'])
    assert used[0] == used[1] and _iso_ms(used[0]) is not None


def test_the_fake_keeps_its_secret_answers():
    from touchque.testing import FakeTouchque
    tq = FakeTouchque(linked=False)
    first = tq.auth.generate_secret('new@acme.com', client_ip='203.0.113.7', user_agent=SAFARI_IPHONE)
    assert set(first) == {'secret', 'qrCodeDataUrl', 'externalUsername', 'expiresAt', 'ttlMs', 'recoveryCodes'}
    with pytest.raises(TouchqueAPIException) as err:
        tq.auth.generate_secret('new@acme.com')
    assert (err.value.status, str(err.value)) == (409, 'Secret already generated')
    again = tq.auth.reset_secret('new@acme.com')
    assert again['success'] is True and set(again) == set(first) | {'success'}
    assert [c['body'] for c in tq.calls] == [
        {'externalUsername': 'new@acme.com', 'clientIp': '203.0.113.7', 'userAgent': SAFARI_IPHONE},
        {'externalUsername': 'new@acme.com'}, {'externalUsername': 'new@acme.com'}]
