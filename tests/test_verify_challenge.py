"""verify(on_challenge=...) against the shared fake TouchQue API: the number
reaches the caller before the wait (the callback approves, so verify() could
not finish otherwise), and a callback that raises is logged while verify()
keeps waiting."""
import logging

from touchque import Config, TouchQue
from .fake_api import fake_api  # noqa: F401 (fixture)

USER = 'jane@acme.com'


def client_for(api) -> TouchQue:
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))


def test_on_challenge_gets_the_number_before_the_wait(fake_api):
    fake_api.link(USER)
    fake_api.opts(numberMatch=True)
    seen = []

    def show(challenge):
        seen.append(challenge)
        fake_api.approve(challenge['requestId'])

    result = client_for(fake_api).login.verify(USER, 'LOGIN', timeout_ms=5000, on_challenge=show)
    assert result['approved'] is True
    assert len(seen) == 1
    assert seen[0]['requestId'] == result['requestId']
    assert seen[0]['challengeCode'] == '47' and seen[0]['caseCode'] == 'K7P-2QX'
    assert seen[0]['reasons'][0]['code'] == 'number_match_requested'
    assert seen[0]['expiresAt']


def test_a_raising_on_challenge_is_logged_and_verify_keeps_waiting(fake_api, caplog):
    fake_api.link(USER)

    def broken(challenge):
        fake_api.approve(challenge['requestId'])
        raise RuntimeError('screen gone')

    with caplog.at_level(logging.WARNING, logger='touchque'):
        result = client_for(fake_api).login.verify(USER, 'SEND_MONEY', timeout_ms=5000, on_challenge=broken)
    assert result['approved'] is True and result['challengeCode'] == '47'
    assert 'screen gone' in caplog.text
