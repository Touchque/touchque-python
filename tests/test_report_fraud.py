"""login.report_fraud() against the shared fake TouchQue API."""
from unittest.mock import MagicMock

import pytest

from touchque import Config, TouchQue, TouchQueAPIException, TouchQueConfigException
from touchque.resources.login import Login
from tests.fake_api import fake_api  # noqa: F401  (fixture)


def test_report_fraud_flow(fake_api):  # noqa: F811
    fake_api.link('jane@acme.com')
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    req = tq.login.request('jane@acme.com', type='LOGIN')

    first = tq.login.report_fraud(req['requestId'], reason='chargeback', note='Disputed by card holder')
    assert first == {'reported': True, 'alreadyReported': False, 'requestId': req['requestId']}
    assert tq.login.report_fraud(req['requestId'])['alreadyReported'] is True

    with pytest.raises(TouchQueAPIException) as bad:
        tq.login.report_fraud(req['requestId'], reason='because')
    assert bad.value.status == 400
    with pytest.raises(TouchQueAPIException) as missing:
        tq.login.report_fraud('unknown-id')
    assert missing.value.status == 404


def test_report_fraud_quotes_the_id_and_needs_one():
    http = MagicMock()
    http.post.return_value = {'reported': True, 'alreadyReported': False, 'requestId': 'a/b'}
    Login(http).report_fraud('a/b')
    http.post.assert_called_once_with('/login/a%2Fb/report-fraud', {})
    with pytest.raises(TouchQueConfigException):
        Login(http).report_fraud('')
