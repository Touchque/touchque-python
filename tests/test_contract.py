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


def test_action_types_define_creates_and_updates(fake_api):
    api = fake_api
    tq = client_for(api)
    tq.action_types.define('EXPORT', name='Export data', critical=True)
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


def test_guard_phone_reject_kills_the_offline_qr(fake_api):
    api = fake_api
    api.link('jane@acme.com')
    tq = client_for(api)

    start = run_guard(tq, 'jane@acme.com', 'LOGIN')
    off = run_guard(tq, 'jane@acme.com', 'LOGIN', token=start['body']['token'], offline=True)
    assert off['body']['touchque']['state'] == 'offline'
    # The QR is linked to the push the user started.
    qr_call = [c for c in api.calls() if c['path'] == '/offline/challenge'][-1]
    assert qr_call['body']['requestId'] == start['body']['touchque']['requestId']

    # While the QR is up the page keeps polling; nothing changes until the phone answers.
    poll = run_guard(tq, 'jane@acme.com', 'LOGIN', token=off['body']['token'])
    assert poll['status'] == 202
    assert poll['body']['touchque']['state'] == 'offline'
    assert poll['body']['touchque']['offline']['challengeId'] == off['body']['touchque']['offline']['challengeId']

    api.reject()  # the user taps Reject on the phone

    rejected = run_guard(tq, 'jane@acme.com', 'LOGIN', token=poll['body']['token'])
    assert rejected['status'] == 403 and rejected['body']['touchque']['state'] == 'rejected'
    # Even the right code from the QR already on screen does not finish it...
    late = run_guard(tq, 'jane@acme.com', 'LOGIN', token=off['body']['token'], code='ABCD123')
    assert late['body']['touchque'] == {'state': 'rejected', 'requestId': start['body']['touchque']['requestId'], 'reason': 'request_rejected'}
    # ...nor the time-based code...
    totp = run_guard(tq, 'jane@acme.com', 'LOGIN', token=off['body']['token'], code='123456', code_type='totp')
    assert totp['body']['touchque']['state'] == 'rejected'
    # ...and pressing offline mode again gets no QR for that sign-in.
    again = run_guard(tq, 'jane@acme.com', 'LOGIN', token=start['body']['token'], offline=True)
    assert again['body']['touchque']['state'] == 'rejected'


def test_guard_offline_qr_carries_the_number_for_matching(fake_api):
    api = fake_api
    api.link('jane@acme.com')
    api.opts(numberMatch=True)
    tq = client_for(api)
    start = run_guard(tq, 'jane@acme.com', 'LOGIN')
    assert start['body']['touchque']['number'] == '47'
    off = run_guard(tq, 'jane@acme.com', 'LOGIN', token=start['body']['token'], offline=True)
    assert off['body']['touchque']['offline']['challengeCode'] == '47'


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
    assert blocked['body']['touchque'] == {'state': 'blocked', 'reason': 'geo_policy', 'caseCode': 'REF-USE'}


def test_waiting_step_carries_the_telemetry_token(fake_api):
    # R1-04: the browser can only post behavioural signals with this token.
    fake_api.link('tel@acme.com')
    tq = client_for(fake_api)
    assert 'telemetryToken' not in tq.start('LOGIN', 'tel@acme.com')
    fake_api.opts(telemetry=True)
    assert tq.start('LOGIN', 'tel@acme.com')['telemetryToken'] == 'tt_test'


# ── Vishing Shield ──────────────────────────────────────────────────────

def test_first_waiting_step_carries_the_mirror_canary_polls_do_not(fake_api):
    fake_api.link('jane@acme.com')
    tq = client_for(fake_api)
    assert 'canary' not in tq.start('LOGIN', 'jane@acme.com')
    fake_api.opts(canary=True)
    first = run_guard(tq, 'jane@acme.com', 'LOGIN')
    assert first['body']['touchque']['canary']['url'].endswith('.gif')
    poll = run_guard(tq, 'jane@acme.com', 'LOGIN', token=first['body']['token'])
    assert poll['body']['touchque']['state'] == 'waiting'
    assert 'canary' not in poll['body']['touchque']


def test_push_tapped_during_a_call_becomes_passkey_required_also_from_the_offline_qr(fake_api):
    fake_api.link('jane@acme.com')
    tq = client_for(fake_api)
    first = run_guard(tq, 'jane@acme.com', 'LOGIN')
    rid = first['body']['touchque']['requestId']
    offline = run_guard(tq, 'jane@acme.com', 'LOGIN', token=first['body']['token'], offline=True)
    assert offline['body']['touchque']['state'] == 'offline'
    fake_api.escalate()
    poll = run_guard(tq, 'jane@acme.com', 'LOGIN', token=offline['body']['token'])
    assert poll['status'] == 202
    assert poll['body']['touchque']['state'] == 'passkey_required'
    assert poll['body']['touchque']['requestId'] == rid
    typed = run_guard(tq, 'jane@acme.com', 'LOGIN', token=offline['body']['token'], code='ABCD123')
    assert typed['body']['touchque']['state'] == 'passkey_required'


def test_provisional_approval_and_the_critical_action_lock(fake_api):
    fake_api.link('jane@acme.com')
    tq = client_for(fake_api)
    step = tq.start('LOGIN', 'jane@acme.com')
    fake_api.approve(provisional=True)
    approval = tq.complete(step['requestId'], 'jane@acme.com', 'LOGIN')
    assert approval['provisional'] is True
    assert approval['revoked'] is False
    assert tq.start('SEND_MONEY', 'jane@acme.com') == {'state': 'blocked', 'reason': 'provisional', 'caseCode': 'REF-USE'}
    fake_api.reconfirm(step['requestId'])
    assert tq.start('SEND_MONEY', 'jane@acme.com')['state'] == 'waiting'


def test_an_approval_taken_back_is_never_used(fake_api):
    fake_api.link('jane@acme.com')
    tq = client_for(fake_api)
    first = run_guard(tq, 'jane@acme.com', 'LOGIN')
    fake_api.approve()
    fake_api.revoke(reason='COACHED')
    done = run_guard(tq, 'jane@acme.com', 'LOGIN', token=first['body']['token'])
    assert done['status'] == 408
    assert done['body']['touchque'] == {'state': 'expired', 'reason': 'revoked'}
