"""Device risk against the shared fake Touchque API: the report goes through
untouched, the answer fails toward asking, and login.request / risk.check
carry device_risk. Same scenarios as the Node SDK's DeviceRisk tests."""
import pytest

from touchque import Config, Touchque, parse_device_risk_check
from touchque.exceptions import TouchqueConfigException
from .fake_api import fake_api  # noqa: F401 (fixture)


def _tq(fake_api):
    return Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))


def test_check_sends_the_report_and_reads_the_answer(fake_api):
    tq = _tq(fake_api)
    r = tq.device_risk.check('dre_flaggedaaaaaaaaaaaaaaa', event='sign_up', external_username='ayse@acme.com', client_ip='203.0.113.7')
    assert r['report'] == 'ok'
    assert r['visitorId'] == 'tqv_fakeVisitor00000001' and r['caseCode'] == 'DRK-2QX'
    assert r['signals'][0]['enforced'] is False
    assert [s['code'] for s in r['signals']] == ['device_many_accounts']
    assert r['stepUp'] is False and r['wouldStepUp'] is True and r['mode'] == 'shadow'
    calm = tq.device_risk.check(device_risk='REPORT')
    assert calm['signals'] == [] and calm['wouldStepUp'] is False
    event = tq.device_risk.get_event('dre_aaaaaaaaaaaaaaaaaaaaaa')
    assert event['visitorId'] == 'tqv_fakeVisitor00000001' and event['verdict']['stepUp'] is False


def test_the_form_field_as_it_came_is_answered_never_raised(fake_api):
    tq = _tq(fake_api)
    for value in (None, '', ['x']):
        r = tq.device_risk.check(value, event='sign_in', external_username='ayse@acme.com')
        assert r['report'] == 'missing' and r['visitorId'] is None
        assert [s['code'] for s in r['signals']] == ['device_identification_missing']
        assert r['stepUp'] is False and r['wouldStepUp'] is True
    assert tq.device_risk.check('nope')['report'] == 'unknown'
    assert parse_device_risk_check({'report': 'expired'})['report'] == 'expired'


def test_bad_input_fails_before_any_request(fake_api):
    tq = _tq(fake_api)
    with pytest.raises(TouchqueConfigException):
        tq.device_risk.check(device_risk='r', event='tracking')
    with pytest.raises(TouchqueConfigException):
        tq.device_risk.get_event('../users')


def test_the_answer_fails_toward_asking():
    assert parse_device_risk_check({})['stepUp'] is True
    assert parse_device_risk_check({'stepUp': False})['stepUp'] is False
    r = parse_device_risk_check({'signals': [{'code': 'device_tampered', 'text': 't'}, None, {'text': 'x'}], 'requires': 'passkey'})
    assert r['signals'] == [{'code': 'device_tampered', 'text': 't', 'strength': 'number_match'}]
    assert r['requires'] == 'passkey' and r['report'] == 'invalid'


def test_engine_unavailable_comes_through_and_a_normal_answer_has_none():
    down = parse_device_risk_check({'report': 'ok', 'signals': [], 'stepUp': True, 'wouldStepUp': True,
                                    'requires': 'number_match', 'mode': 'enforce', 'engine': 'unavailable'})
    assert down['engine'] == 'unavailable' and down['stepUp'] is True and down['requires'] == 'number_match'
    normal = parse_device_risk_check({'report': 'ok', 'signals': [], 'stepUp': False, 'requires': 'none', 'mode': 'shadow'})
    assert normal['engine'] is None and normal['stepUp'] is False
    assert parse_device_risk_check({'engine': 42})['engine'] is None


def test_risk_check_carries_device_risk(fake_api):
    tq = _tq(fake_api)
    sent = {}
    original = tq.risk._http.post

    def capture(path, payload):
        sent[path] = payload
        return original(path, payload)
    tq.risk._http.post = capture
    tq.risk.check('ayse@acme.com', device_risk_request_id='dre_aaaaaaaaaaaaaaaaaaaaaa')
    assert sent['/risk/check']['deviceRiskRequestId'] == 'dre_aaaaaaaaaaaaaaaaaaaaaa'


def test_the_address_the_counts_and_a_bot_answer_come_through():
    r = parse_device_risk_check({'report': 'ok', 'network': {'type': 'hosting', 'hosting': True}, 'velocity': {'identifications1h': 2},
                                 'bot': {'result': 'suspected', 'reasons': ['pointer_synthetic']}})
    assert r['network']['type'] == 'hosting' and r['velocity']['identifications1h'] == 2 and r['bot']['result'] == 'suspected'
    assert parse_device_risk_check({'network': 'x'})['network'] is None


def test_search_events_pages_with_the_opaque_cursor_and_sends_the_filters(fake_api):
    tq = _tq(fake_api)
    first = tq.device_risk.search_events(account='ada@example.com', step_up=False, ip='203.0.113.0/24', limit=1)
    assert fake_api.last_device_risk_search() == {'account': 'ada@example.com', 'stepUp': 'false', 'ip': '203.0.113.0/24', 'limit': '1'}
    assert [e['requestId'] for e in first['events']] == ['dre_fakeEvent00000000002'] and first['nextCursor'] is None
    seen, cursor = [], None
    while True:
        page = tq.device_risk.search_events(limit=1, cursor=cursor)
        seen += [e['requestId'] for e in page['events']]
        cursor = page['nextCursor']
        if not cursor:
            break
    assert seen == ['dre_fakeEvent00000000003', 'dre_fakeEvent00000000002', 'dre_fakeEvent00000000001']
    with pytest.raises(TouchqueConfigException):
        tq.device_risk.search_events(limit=101)

