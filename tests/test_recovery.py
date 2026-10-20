"""Never Locked Out against the shared fake TouchQue API: vouchers, start,
status, list and veto. Same scenarios as the Node SDK's Recovery tests."""
import pytest

from touchque import Config, TouchQue, TouchQueAPIException, is_recovery_open
from touchque.exceptions import TouchQueConfigException
from .fake_api import fake_api  # noqa: F401 (fixture)


def client_for(api) -> TouchQue:
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))


@pytest.fixture
def api(fake_api):
    for user in ('ada@acme.com', 'bo@acme.com', 'cy@acme.com'):
        fake_api.link(user)
    return fake_api


def test_vouchers_are_named_and_say_who_can_vouch(api):
    tq = client_for(api)
    out = tq.recovery.set_vouchers('ada@acme.com', ['bo@acme.com', 'zed@acme.com', 'ada@acme.com'])
    assert out['vouchers'] == [{'externalUsername': 'bo@acme.com', 'eligible': True},
                               {'externalUsername': 'zed@acme.com', 'eligible': False, 'reason': 'no_phone'}]
    assert tq.recovery.vouchers('ada@acme.com')['vouchers'][0]['externalUsername'] == 'bo@acme.com'


def test_a_recovery_starts_with_a_qr_for_the_new_phone_and_moves_on(api):
    tq = client_for(api)
    tq.recovery.set_vouchers('ada@acme.com', ['bo@acme.com', 'cy@acme.com'])
    r = tq.recovery.start('ada@acme.com', client_ip='203.0.113.7', user_agent='UA', display_name='Ada',
                          cool_off_minutes=90)
    assert r['status'] == 'AWAITING_DEVICE'
    assert r['bindUri'].startswith('touchque://recover?id=')
    assert api.calls()[-1]['body'] == {'externalUsername': 'ada@acme.com', 'clientIp': '203.0.113.7', 'userAgent': 'UA',
                                       'displayName': 'Ada', 'coolOffMinutes': 90}
    api.recovery('VOUCHING')
    now = tq.recovery.status(r['recoveryId'])
    assert [v['code'] for v in now['vouchers']] == ['11', '12']
    assert is_recovery_open(now)
    api.recovery('COMPLETED')
    assert tq.recovery.status(r['recoveryId'])['status'] == 'COMPLETED'
    assert [x['recoveryId'] for x in tq.recovery.list(external_username='ada@acme.com')] == [r['recoveryId']]


def test_an_admin_vetoes_a_running_recovery_and_too_few_vouchers_is_a_clear_error(api):
    tq = client_for(api)
    with pytest.raises(TouchQueAPIException) as e:
        tq.recovery.start('ada@acme.com')
    assert e.value.status == 409
    r = tq.recovery.start('ada@acme.com', fallback_vouchers=['bo@acme.com', 'cy@acme.com'])
    assert [x['recoveryId'] for x in tq.recovery.list(open=True)] == [r['recoveryId']]
    vetoed = tq.recovery.veto(r['recoveryId'], by='admin@acme.com')
    assert (vetoed['status'], vetoed['endedBy']) == ('VETOED', 'admin@acme.com')
    with pytest.raises(TouchQueAPIException):
        tq.recovery.veto(r['recoveryId'])
    assert tq.recovery.list(open=True) == []


def test_missing_arguments_fail_before_any_request(api):
    tq = client_for(api)
    for call in (lambda: tq.recovery.start(''), lambda: tq.recovery.status(''), lambda: tq.recovery.list(),
                 lambda: tq.recovery.set_vouchers('ada@acme.com', 'bo@acme.com')):
        with pytest.raises(TouchQueConfigException):
            call()
    assert api.calls() == []
