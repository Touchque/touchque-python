"""Contract tests against the shared fake TouchQue API — a real HTTP round
trip, so request signing is verified too (not just mocked). Same scenarios
as the Node SDK's step-up tests."""
import pytest

from touchque import Config, TouchQue
from touchque.exceptions import TouchQueConfigException
from touchque.guard import run_guard
from .fake_api import fake_api  # noqa: F401 (fixture)


def client_for(api) -> TouchQue:
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))


def test_start_check_complete_full_flow(fake_api):
    api = fake_api
    api.link('jane@acme.com')
    tq = client_for(api)

    step = tq.start('SEND_MONEY', 'jane@acme.com', details={'Amount': '250 EUR'}, reference_id='tx-9')
    assert step['state'] == 'waiting'
    assert step['number'] == '47'  # SEND_MONEY is critical in the fake API
    assert step['details'] == [{'label': 'Amount', 'value': '250 EUR'}]

    assert tq.check(step['requestId'])['state'] == 'waiting'
    api.approve()
    assert tq.check(step['requestId'])['state'] == 'approved'

    approval = tq.complete(step['requestId'], 'jane@acme.com', 'SEND_MONEY', details={'Amount': '250 EUR'}, reference_id='tx-9')
    assert approval['assurance'] == {'phishingResistant': False, 'method': 'push'}

    with pytest.raises(Exception):
        tq.complete(step['requestId'], 'jane@acme.com', 'SEND_MONEY', details={'Amount': '250 EUR'}, reference_id='tx-9')


def test_complete_refuses_a_different_amount(fake_api):
    api = fake_api
    api.link('jane@acme.com')
    tq = client_for(api)
    step = tq.start('SEND_MONEY', 'jane@acme.com', details={'Amount': '250 EUR'})
    api.approve()
    with pytest.raises(Exception):
        tq.complete(step['requestId'], 'jane@acme.com', 'SEND_MONEY', details={'Amount': '9999 EUR'})


def test_unknown_action_is_a_clear_config_error(fake_api):
    api = fake_api
    api.link('jane@acme.com')
    tq = client_for(api)
    with pytest.raises(TouchQueConfigException, match='NOT_DEFINED'):
        tq.start('NOT_DEFINED', 'jane@acme.com')


def test_actions_define_creates_and_updates(fake_api):
    api = fake_api
    tq = client_for(api)
    tq.actions.define('EXPORT', name='Export data', critical=True)
    calls = api.calls()
    body = next(c['body'] for c in calls if c['path'] == '/action-types')
    assert body == {'type': 'EXPORT', 'name': 'Export data', 'critical': True}


def test_guard_full_flow_via_run_guard(fake_api):
    """The same two-phase contract the framework adapters expose."""
    api = fake_api
    api.link('jane@acme.com')
    api.opts(numberMatch=True)
    tq = client_for(api)

    first = run_guard(tq, 'jane@acme.com', 'LOGIN')
    assert first['status'] == 202
    step = first['body']['touchque']
    assert step['state'] == 'waiting'
    assert step['number'] == '47'
    token = first['body']['token']

    still = run_guard(tq, 'jane@acme.com', 'LOGIN', token=token)
    assert still['status'] == 202

    api.approve()
    done = run_guard(tq, 'jane@acme.com', 'LOGIN', token=token)
    assert done['status'] == 200
    assert done['approved']['assurance']['method'] == 'push'

    replay = run_guard(tq, 'jane@acme.com', 'LOGIN', token=token)
    assert 'approved' not in replay
    assert replay['status'] in (403, 408, 409)


def test_guard_enroll_then_offline_code(fake_api):
    api = fake_api
    tq = client_for(api)

    first = run_guard(tq, 'new@acme.com', 'LOGIN')
    assert first['status'] == 202
    assert first['body']['touchque']['state'] == 'enroll'
    assert first['body']['touchque']['enroll']['qrCodeDataUrl'].startswith('data:image/png;base64,')

    api.link('new@acme.com')
    token = first['body']['token']
    waiting = run_guard(tq, 'new@acme.com', 'LOGIN', token=token)
    assert waiting['body']['touchque']['state'] == 'waiting'

    off = run_guard(tq, 'new@acme.com', 'LOGIN', token=waiting['body']['token'], offline=True)
    assert off['body']['touchque']['state'] == 'offline'
    assert off['body']['touchque']['offline']['qrDataUrl'] == 'data:image/png;base64,OFFLINE'

    wrong = run_guard(tq, 'new@acme.com', 'LOGIN', token=off['body']['token'], code='ZZZZ999')
    assert wrong['body']['touchque']['offline']['attemptsLeft'] == 4

    ok = run_guard(tq, 'new@acme.com', 'LOGIN', token=wrong['body']['token'], code='ABCD123')
    assert ok['status'] == 200
    assert ok['approved']['assurance'] == {'phishingResistant': False, 'method': 'offline_code'}


def test_guard_frozen_rate_limited_blocked(fake_api):
    api = fake_api
    api.link('jane@acme.com')
    tq = client_for(api)

    api.opts(frozen=True)
    frozen = run_guard(tq, 'jane@acme.com', 'LOGIN')
    assert frozen['status'] == 423
    assert frozen['body']['touchque']['retryAfter'] == 900

    api.opts(frozen=False, rateLimited=True)
    limited = run_guard(tq, 'jane@acme.com', 'LOGIN')
    assert limited['status'] == 429

    api.opts(rateLimited=False, blocked='geo_policy')
    blocked = run_guard(tq, 'jane@acme.com', 'LOGIN')
    assert blocked['status'] == 403
    assert blocked['body']['touchque'] == {'state': 'blocked', 'reason': 'geo_policy'}
