"""Contract tests against the shared fake Touchque API — a real HTTP round
trip, so request signing is verified too (not just mocked). Same scenarios
as the Node SDK's step-up tests."""
import time

import pytest

from touchque import Config, Touchque
from touchque.exceptions import TouchqueConfigException
from touchque.guard import is_status_poll, run_guard
from touchque.steps import _iso_ms, verify_guard_token
from .fake_api import fake_api  # noqa: F401 (fixture)


def client_for(api) -> Touchque:
    return Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))


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
    with pytest.raises(TouchqueConfigException, match='NOT_DEFINED') as exc:
        tq.start('NOT_DEFINED', 'jane@acme.com')
    assert 'client.action_types.define("NOT_DEFINED")' in str(exc.value)


def test_a_non_ascii_guard_token_is_just_not_valid(fake_api):
    """WSGI/ASGI decode headers as latin-1: such a token is refused, never a 500."""
    api = fake_api
    api.link('jane@acme.com')
    tq = client_for(api)
    for token in ('v1.abc.\xe9', 'v1.\xe9.abc'):
        assert is_status_poll(tq, 'jane@acme.com', 'LOGIN', token=token) is False
        assert run_guard(tq, 'jane@acme.com', 'LOGIN', token=token)['status'] == 202


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


# ── first-time QR: one QR per enrollment, not one per poll ──────────────

def test_enroll_polls_keep_the_qr_until_the_phone_is_linked(fake_api):
    api = fake_api
    tq = client_for(api)
    first = run_guard(tq, 'new@acme.com', 'LOGIN', details={'Device': 'Mac'})
    qr = first['body']['touchque']['enroll']
    assert qr['qrCodeDataUrl'] == 'data:image/png;base64,QR-new@acme.com' and qr['recoveryCodes'] == ['r1']
    ee = _iso_ms(qr['expiresAt'])
    assert 290000 < ee - time.time() * 1000 <= 300000  # the API's own expiresAt (5 minutes)
    claims = verify_guard_token('test_secret', first['body']['token'])
    assert claims['st'] == 'enroll' and claims['ee'] == ee

    before = len(api.calls())
    poll = run_guard(tq, 'new@acme.com', 'LOGIN', details={'Device': 'Mac'}, token=first['body']['token'])
    assert poll['status'] == 202
    assert poll['body']['touchque'] == {'state': 'enroll', 'expiresAt': qr['expiresAt'],
                                        'details': [{'label': 'Device', 'value': 'Mac'}]}
    assert [c['path'] for c in api.calls()[before:]] == ['/users/new%40acme.com']  # no generate or reset
    again = verify_guard_token('test_secret', poll['body']['token'])
    assert again['st'] == 'enroll' and again['ee'] == ee

    api.link('new@acme.com')  # the phone scanned the QR
    waiting = run_guard(tq, 'new@acme.com', 'LOGIN', details={'Device': 'Mac'}, token=poll['body']['token'])
    assert waiting['status'] == 202 and waiting['body']['touchque']['state'] == 'waiting'


def test_an_enroll_qr_about_to_expire_is_replaced(fake_api):
    api = fake_api
    api.opts(secretTtlMs=1000)
    tq = client_for(api)
    first = run_guard(tq, 'new@acme.com', 'LOGIN')
    assert first['body']['touchque']['enroll']['qrCodeDataUrl'] == 'data:image/png;base64,QR-new@acme.com'
    poll = run_guard(tq, 'new@acme.com', 'LOGIN', token=first['body']['token'])
    assert poll['status'] == 202
    assert poll['body']['touchque']['enroll']['qrCodeDataUrl'] == 'data:image/png;base64,QR2-new@acme.com'
    assert '/auth/secret/reset' in api.paths()


def test_an_enroll_token_without_an_expiry_starts_again(fake_api):
    """No "ee" (an enroll step without a QR, or a 5.0 token): every poll starts again, as before."""
    api = fake_api
    tq = client_for(api)
    old = run_guard(tq, 'new@acme.com', 'LOGIN', enroll=False)
    assert old['body']['touchque'] == {'state': 'enroll'}
    assert 'ee' not in verify_guard_token('test_secret', old['body']['token'])
    assert is_status_poll(tq, 'new@acme.com', 'LOGIN', token=old['body']['token']) is False
    again = run_guard(tq, 'new@acme.com', 'LOGIN', token=old['body']['token'])
    assert again['body']['touchque']['enroll']['qrCodeDataUrl']
    assert '/users/new%40acme.com' not in api.paths()


def test_is_status_poll_counts_a_bound_enroll_token(fake_api):
    tq = client_for(fake_api)
    token = run_guard(tq, 'new@acme.com', 'LOGIN')['body']['token']
    assert is_status_poll(tq, 'new@acme.com', 'LOGIN', token=token) is True
    assert is_status_poll(tq, 'other@acme.com', 'LOGIN', token=token) is False
    assert is_status_poll(tq, 'new@acme.com', 'SEND_MONEY', token=token) is False
    assert is_status_poll(tq, 'new@acme.com', 'LOGIN', token=token, offline=True) is False

    # The poll that renews an expiring QR (or replays an old token) still counts against the limit.
    fake_api.opts(secretTtlMs=1000)
    expiring = run_guard(tq, 'late@acme.com', 'LOGIN')['body']['token']
    assert verify_guard_token('test_secret', expiring)['ee']
    assert is_status_poll(tq, 'late@acme.com', 'LOGIN', token=expiring) is False


def test_enroll_qr_expiry_is_the_apis_or_now_plus_ttl():
    from touchque.steps import _enroll_qr, _iso_from_ms
    assert _enroll_qr({'qrCodeDataUrl': 'qr', 'expiresAt': '2026-11-12T10:05:00.000Z', 'ttlMs': 1000})['enroll'][
        'expiresAt'] == '2026-11-12T10:05:00.000Z'
    before = int(time.time() * 1000)
    step = _enroll_qr({'qrCodeDataUrl': 'qr', 'expiresAt': 'soon', 'ttlMs': 60000})
    assert before + 60000 <= _iso_ms(step['enroll']['expiresAt']) <= time.time() * 1000 + 60000
    assert 'expiresAt' not in _enroll_qr({'qrCodeDataUrl': 'qr', 'expiresAt': 'soon'})['enroll']
    assert _iso_from_ms(_iso_ms('2026-11-12T12:05:00+02:00')) == '2026-11-12T10:05:00.000Z'
    assert _iso_ms('2026-13-12T10:05:00Z') is None and _iso_ms(1700000000000) is None


def test_before_start_runs_once_only_when_an_enroll_token_starts(fake_api):
    api = fake_api
    tq = client_for(api)
    seen = []

    def hook():
        seen.append(api.paths()[-1])
        return None

    token = run_guard(tq, 'new@acme.com', 'LOGIN', before_start=hook)['body']['token']  # a fresh attempt
    keep = run_guard(tq, 'new@acme.com', 'LOGIN', token=token, before_start=hook)  # keeps the QR
    assert keep['body']['touchque']['state'] == 'enroll' and seen == []

    api.link('new@acme.com')
    before = len(api.calls())
    refused = run_guard(tq, 'new@acme.com', 'LOGIN', token=token,
                        before_start=lambda: {'status': 429, 'body': {'error': 'RATE_LIMITED'}})
    assert refused == {'status': 429, 'body': {'error': 'RATE_LIMITED'}}
    assert api.paths()[before:] == ['/users/new%40acme.com']  # nothing started
    went = run_guard(tq, 'new@acme.com', 'LOGIN', token=token, before_start=hook)
    assert went['body']['touchque']['state'] == 'waiting' and seen == ['/users/new%40acme.com']

    api.opts(secretTtlMs=1000)  # a QR within 15 s of its expiry: the hook runs before the new QR
    late = run_guard(tq, 'late@acme.com', 'LOGIN')['body']['token']
    renewed = run_guard(tq, 'late@acme.com', 'LOGIN', token=late, before_start=hook)
    assert renewed['body']['touchque']['enroll']['qrCodeDataUrl'] and len(seen) == 2

    api.reset()
    fresh = run_guard(tq, 'gone@acme.com', 'LOGIN')['body']['token']
    api.reset()  # the QR is gone: GET /users answers 404, and the hook runs before the new QR
    gone = run_guard(tq, 'gone@acme.com', 'LOGIN', token=fresh, before_start=hook)
    assert gone['body']['touchque']['enroll']['qrCodeDataUrl'] and len(seen) == 3
    assert run_guard(tq, 'gone@acme.com', 'LOGIN', before_start=hook)['status'] == 202 and len(seen) == 3
