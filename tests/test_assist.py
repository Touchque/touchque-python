"""The help desk against the shared fake TouchQue API: a passed check used once
for its own action, a wrong number, "this isn't me" and unfreeze, and no phone.
Same scenarios as the Node SDK's Assist tests."""
import pytest

from touchque import Config, TouchQue, TouchQueAPIException, is_assist_check_passed
from touchque.exceptions import TouchQueConfigException
from .fake_api import fake_api  # noqa: F401 (fixture)


def _tq(fake_api):
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))


def test_a_passed_check_is_used_once_for_its_action(fake_api):
    fake_api.link('ayse@acme.com')
    tq = _tq(fake_api)
    s = tq.assist.open('ayse@acme.com', {'name': 'Deniz Kaya', 'title': 'IT help desk'}, reason='Ticket 4411')
    assert s['status'] == 'OPEN' and s['notified'] and s['phone']
    check = tq.assist.verify(s['id'], 'reset_2fa', 'reset your two-step verification')
    assert len(check['challengeCode']) == 2
    fake_api._call('/__test/assist', {'requestId': check['requestId'], 'action': 'approve'})
    assert is_assist_check_passed(tq.assist.get(s['id']), check['requestId'])
    with pytest.raises(TouchQueAPIException) as e:
        tq.assist.spend(s['id'], check['requestId'], 'reset_password')
    assert e.value.status == 428
    assert not is_assist_check_passed(tq.assist.spend(s['id'], check['requestId'], 'reset_2fa'), check['requestId'])
    assert tq.assist.list('ayse@acme.com')[0]['id'] == s['id']
    assert tq.assist.end(s['id'])['status'] == 'ENDED'
    with pytest.raises(TouchQueAPIException) as e:
        tq.assist.verify(s['id'], 'unlock')
    assert e.value.code == 'assist_not_open'


def test_wrong_number_not_me_and_unfreeze(fake_api):
    fake_api.link('ayse@acme.com')
    tq = _tq(fake_api)
    s = tq.assist.open('ayse@acme.com', {'name': 'Deniz Kaya'}, notify=False)
    bad = tq.assist.verify(s['id'], 'activation_link')
    fake_api._call('/__test/assist', {'requestId': bad['requestId'], 'action': 'wrong_number'})
    with pytest.raises(TouchQueAPIException) as e:
        tq.assist.spend(s['id'], bad['requestId'], 'activation_link')
    assert e.value.code == 'check_required'
    not_me = tq.assist.verify(s['id'], 'activation_link')
    fake_api._call('/__test/assist', {'requestId': not_me['requestId'], 'action': 'not_me'})
    now = tq.assist.get(s['id'])
    assert now['frozen'] and now['checks'][1]['outcome'] == 'not_me' and not now['notified']
    unlock = tq.assist.verify(s['id'], 'unlock')
    fake_api._call('/__test/assist', {'requestId': unlock['requestId'], 'action': 'approve'})
    out = tq.assist.unfreeze(s['id'], unlock['requestId'])
    assert out['unfrozen'] and not out['session']['frozen']


def test_no_phone_routes_to_never_locked_out(fake_api):
    tq = _tq(fake_api)
    tq.auth.generate_secret('can@acme.com')
    s = tq.assist.open('can@acme.com', {'name': 'Deniz Kaya'})
    assert s['phone'] is False
    with pytest.raises(TouchQueAPIException) as e:
        tq.assist.verify(s['id'], 'new_phone')
    assert e.value.code == 'no_phone' and e.value.data['route'] == 'never_locked_out'


def test_missing_arguments_never_reach_the_api(fake_api):
    tq = _tq(fake_api)
    for call in (lambda: tq.assist.open('a@b.com', {}), lambda: tq.assist.get(''), lambda: tq.assist.list(),
                 lambda: tq.assist.verify('id', '')):
        with pytest.raises(TouchQueConfigException):
            call()


def test_open_is_an_alias_of_open_only(fake_api):
    fake_api.link('ayse@acme.com')
    tq = _tq(fake_api)
    s = tq.assist.open('ayse@acme.com', {'name': 'Deniz Kaya'}, notify=False)
    assert [x['id'] for x in tq.assist.list(open=True)] == [s['id']]
    assert [x['id'] for x in tq.assist.list(open_only=True)] == [s['id']]
    tq.assist.end(s['id'])
    assert tq.assist.list(open=True) == []
    with pytest.raises(TouchQueConfigException):
        tq.assist.list(open=False)
