""""Why?" case codes against the shared fake TouchQue API: every decision names
one, the step shows it with plain reasons, a refusal and the raw API error
carry it, and the silent check returns it. Same scenarios as the Node SDK."""
import pytest

from touchque import Config, TouchQue, TouchQueAPIException
from touchque.guard import run_guard
from touchque.steps import start
from .fake_api import fake_api  # noqa: F401 (fixture)


@pytest.fixture
def tq(fake_api):
    fake_api.link('jane@acme.com')
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))


def test_a_number_matched_step_names_its_case_and_plain_reasons(tq, fake_api):
    fake_api.opts(numberMatch=True)
    step = start(tq, 'LOGIN', 'jane@acme.com')
    assert step['state'] == 'waiting' and step['number'] == '47'
    assert step['caseCode'] == 'K7P-2QX'
    assert step['reasons'] == [{'code': 'number_match_requested', 'text': 'The risk check asked for number matching'}]


def test_a_refusal_names_its_case_in_the_step_and_on_the_exception(tq, fake_api):
    fake_api.opts(blocked='access_policy')
    assert start(tq, 'LOGIN', 'jane@acme.com') == {'state': 'blocked', 'reason': 'access_policy', 'caseCode': 'REF-USE'}
    with pytest.raises(TouchQueAPIException) as e:
        tq.login.request('jane@acme.com', type='LOGIN')
    assert e.value.status == 403 and e.value.case_code == 'REF-USE'
    fake_api.opts(blocked=None, frozen=True)
    assert start(tq, 'LOGIN', 'jane@acme.com')['caseCode'] == 'REF-USE'


def test_the_silent_check_returns_its_case(tq):
    assert tq.risk.check('jane@acme.com')['caseCode'] == 'CHK-2QX'


def test_the_guard_keeps_showing_the_case_while_it_waits(tq, fake_api):
    fake_api.opts(numberMatch=True)
    first = run_guard(tq, 'jane@acme.com', 'LOGIN')
    again = run_guard(tq, 'jane@acme.com', 'LOGIN', token=first['body']['token'])
    assert first['body']['touchque']['caseCode'] == 'K7P-2QX'
    assert again['body']['touchque']['state'] == 'waiting' and again['body']['touchque']['caseCode'] == 'K7P-2QX'
