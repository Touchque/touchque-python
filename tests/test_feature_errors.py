"""A feature the workspace's organization cannot use comes back as a typed
exception with the feature's id, still a TouchQueAPIException. Same scenarios
as the Node SDK, against the shared fake TouchQue API."""
import pytest

from touchque import (
    Config, TouchQue, TouchQueAPIException, TouchQueFeatureException, TouchQueFeatureNotInPlanException,
    TouchQueFeatureOffException, TouchQueFeatureReadOnlyException,
)
from .fake_api import fake_api  # noqa: F401 (fixture)


@pytest.fixture
def tq(fake_api):
    fake_api.link('jane@acme.com')
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))


@pytest.mark.parametrize('code,cls,reason', [
    ('feature_not_in_plan', TouchQueFeatureNotInPlanException, 'not_in_plan'),
    ('feature_read_only', TouchQueFeatureReadOnlyException, 'read_only'),
    ('feature_off', TouchQueFeatureOffException, 'off'),
])
def test_each_feature_refusal_has_its_own_exception(tq, fake_api, code, cls, reason):
    fake_api.opts(featureRefused=code, feature='device_risk')
    with pytest.raises(cls) as e:
        tq.login.request('jane@acme.com', type='LOGIN')
    assert isinstance(e.value, TouchQueFeatureException) and isinstance(e.value, TouchQueAPIException)
    assert e.value.status == 403 and e.value.feature == 'device_risk' and e.value.feature_reason == reason


def test_other_refusals_stay_plain_api_exceptions(tq, fake_api):
    fake_api.opts(featureRefused=None, blocked='access_policy')
    with pytest.raises(TouchQueAPIException) as e:
        tq.login.request('jane@acme.com', type='LOGIN')
    assert not isinstance(e.value, TouchQueFeatureException)
