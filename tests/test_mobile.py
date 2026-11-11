"""Mobile SDK (the partner's own app as the approver) against the shared fake Touchque API:
an enrollment token the app spends once, replace for a second phone, the devices, the
settings, and the push a MOBILE_PUSH webhook becomes. Same scenarios as the Node SDK's tests."""
from datetime import datetime, timezone

import pytest

from touchque import Config, Touchque, TouchqueAPIException, is_mobile_push_expired, mobile_push_from_webhook
from .fake_api import fake_api  # noqa: F401 (fixture)


def client_for(api) -> Touchque:
    return Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))


def test_an_enrollment_token_is_spent_once_and_a_second_phone_needs_replace(fake_api):
    tq = client_for(fake_api)
    first = tq.mobile.create_enrollment('ada@shop.example')
    assert first['enrollmentToken'].startswith('tqe_') and first['replace'] is False
    assert fake_api.calls()[-1]['body'] == {'externalUsername': 'ada@shop.example'}
    device = fake_api._call('/__test/mobile-enroll', {'enrollmentToken': first['enrollmentToken'], 'platform': 'android'})
    with pytest.raises(TouchqueAPIException) as e:
        tq.mobile.create_enrollment('ada@shop.example')
    assert e.value.code == 'already_enrolled'
    second = tq.mobile.create_enrollment('ada@shop.example', replace=True, ttl_seconds=300)
    assert second['replacesDeviceId'] == device['deviceId']
    fake_api._call('/__test/mobile-enroll', {'enrollmentToken': second['enrollmentToken']})
    active = tq.mobile.list_devices(external_username='ada@shop.example')['devices']
    assert [d['platform'] for d in active] == ['ios']
    every = tq.mobile.list_devices(external_username='ada@shop.example', status='all')['devices']
    assert {d['status'] for d in every} == {'active', 'revoked'}
    assert tq.mobile.get_device(device['deviceId'])['revokedReason'] == 'replaced'
    assert tq.mobile.test_push(active[0]['deviceId']) == {'via': 'webhook', 'ok': True}
    assert tq.mobile.remove_device(active[0]['deviceId']) == {'removed': True, 'wasLinked': True}


def test_settings_change_only_what_is_given(fake_api):
    tq = client_for(fake_api)
    assert tq.mobile.settings()['attestation'] == 'optional'
    s = tq.mobile.update_settings(ios_app_ids=['ABCDE12345.com.shop.app'], attestation='required')
    assert s['iosAppIds'] == ['ABCDE12345.com.shop.app'] and s['attestation'] == 'required' and s['enrollTtlSeconds'] == 600
    with pytest.raises(Exception):
        tq.mobile.update_settings(colour='blue')


def test_your_own_push_keys(fake_api):
    tq = client_for(fake_api)
    s = tq.mobile.update_settings(apns={'keyId': 'ABC123DEFG', 'teamId': 'TEAM123456', 'topic': 'com.shop.app', 'key': '-----BEGIN PRIVATE KEY-----'},
                                  fcm={'serviceAccount': {'project_id': 'shop', 'client_email': 'push@shop.iam.gserviceaccount.com', 'private_key': 'x'}})
    assert s['push']['ios'] == 'touchque' and s['push']['android'] == 'touchque'
    assert s['push']['apns'] == {'keyId': 'ABC123DEFG', 'teamId': 'TEAM123456', 'topic': 'com.shop.app', 'production': False}
    assert tq.mobile.update_settings(apns=None)['push']['ios'] == 'webhook'


def test_a_mobile_push_webhook_becomes_the_apns_payload_and_fcm_data():
    event = {
        'event': 'MOBILE_PUSH', 'externalUsername': 'ada@shop.example', 'deviceId': 'd1', 'platform': 'ios', 'pushToken': 'apns-token',
        'kind': 'approval', 'requestId': 'r1', 'expiresAt': '2026-10-26T10:00:30.000Z',
        'alert': {'title': 'Change delivery address', 'body': 'Demo Shop is waiting for your approval.'},
        'data': {'touchque': '{"v":1,"k":"approval","did":"d1","rid":"r1"}'},
    }
    push = mobile_push_from_webhook(event)
    assert push['apns'] == {'aps': {'sound': 'default', 'interruption-level': 'time-sensitive', 'alert': event['alert']},
                            'touchque': event['data']['touchque']}
    assert push['fcmData'] == {'touchque': event['data']['touchque']}
    assert mobile_push_from_webhook({**event, 'event': 'DEVICE_LINKED'}) is None
    assert is_mobile_push_expired(push, now=datetime(2026, 10, 26, 10, 1, tzinfo=timezone.utc)) is True
    assert is_mobile_push_expired(push, now=datetime(2026, 10, 26, 10, 0, tzinfo=timezone.utc)) is False
    assert is_mobile_push_expired({'expiresAt': None}) is False
