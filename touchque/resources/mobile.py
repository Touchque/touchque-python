"""
TouchQue Mobile SDK, your backend's side: your own iOS/Android app is the
approver of your users (white-label); they never install the TouchQue app.

1. A user signed in to your app turns approvals on: ``create_enrollment``
   gives a one-time token; your app hands it to the SDK (``TouchQue.enroll``).
2. Ask for approvals as always (``login.request``, ``start``, guards...):
   they reach your app over the SDK's encrypted connection.
3. TouchQue holds no push key of your app. For each request it sends you a
   signed MOBILE_PUSH webhook: verify it (``webhook.verify``), then
   ``mobile_push_from_webhook(event)`` gives the APNs payload / FCM data to
   send with your own credentials.
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import quote

from ..exceptions import TouchQueConfigException
from ..http_client import HttpClient


def mobile_push_from_webhook(event: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The push to send for a verified MOBILE_PUSH webhook, or None for any other event.

    Returns ``deviceId``, ``externalUsername``, ``platform``, ``pushToken`` (None: send by your
    own user -> device mapping), ``requestId``, ``expiresAt``, ``kind``, ``alert`` (English,
    translate it), ``apns`` (the APNs payload: alert + the custom key ``touchque``) and
    ``fcmData`` (the FCM data map). The data carries no secret, no details and no number.
    """
    if not isinstance(event, dict) or event.get('event') != 'MOBILE_PUSH':
        return None
    data = event.get('data') or {}
    touchque = data.get('touchque') if isinstance(data.get('touchque'), str) else json.dumps(data.get('touchque') or {})
    alert = event.get('alert') or None
    aps: Dict[str, Any] = {'sound': 'default', 'interruption-level': 'time-sensitive'}
    if alert:
        aps['alert'] = alert
    return {
        'deviceId': event.get('deviceId'),
        'externalUsername': event.get('externalUsername'),
        'platform': 'android' if event.get('platform') == 'android' else 'ios',
        'pushToken': event.get('pushToken') if isinstance(event.get('pushToken'), str) else None,
        'requestId': event.get('requestId'),
        'expiresAt': event.get('expiresAt'),
        'kind': event['kind'] if event.get('kind') in ('notice', 'test') else 'approval',  # test: a test push from the dashboard
        'alert': alert,
        'apns': {'aps': aps, 'touchque': touchque},
        'fcmData': {'touchque': touchque},
    }


def is_mobile_push_expired(push: Dict[str, Any], now: Optional[datetime] = None) -> bool:
    """True once a push is past its request's expiry (don't send it any more)."""
    expires = push.get('expiresAt') if isinstance(push, dict) else None
    if not expires:
        return False
    at = datetime.fromisoformat(str(expires).replace('Z', '+00:00'))
    return at <= (now or datetime.now(timezone.utc))


class Mobile:
    """Enrollment tokens, the devices inside your app and your Mobile SDK settings."""

    def __init__(self, http: HttpClient):
        self._http = http

    def create_enrollment(self, external_username: str, replace: bool = False,
                          ttl_seconds: Optional[int] = None) -> Dict[str, Any]:
        """A one-time enrollment token for a user you signed in. Whoever spends it becomes the
        user's approver, so authenticate the user first. Raises TouchQueAPIException
        ``already_enrolled`` (pass ``replace=True``) or ``account_frozen``."""
        if not external_username:
            raise TouchQueConfigException('mobile.create_enrollment() needs the user (external_username)')
        body: Dict[str, Any] = {'externalUsername': external_username}
        if replace:
            body['replace'] = True
        if ttl_seconds is not None:
            body['ttlSeconds'] = ttl_seconds
        return self._http.post('/mobile/enrollments', body)

    def list_devices(self, external_username: Optional[str] = None, status: Optional[str] = None,
                     limit: Optional[int] = None, cursor: Optional[str] = None) -> Dict[str, Any]:
        """The devices inside your app (default: active ones), newest first: ``{devices, nextCursor}``."""
        params: Dict[str, Any] = {}
        if external_username:
            params['externalUsername'] = external_username
        if status:
            params['status'] = status
        if limit is not None:
            params['limit'] = limit
        if cursor:
            params['cursor'] = cursor
        return self._http.get('/mobile/devices', params)

    def get_device(self, device_id: str) -> Dict[str, Any]:
        if not device_id:
            raise TouchQueConfigException('mobile.get_device() needs the device id')
        return self._http.get('/mobile/devices/' + quote(device_id, safe=''))['device']

    def remove_device(self, device_id: str) -> Dict[str, Any]:
        """Stops a device from approving (the user has no approver until you enrol again)."""
        if not device_id:
            raise TouchQueConfigException('mobile.remove_device() needs the device id')
        return self._http.delete('/mobile/devices/' + quote(device_id, safe=''))

    def test_push(self, device_id: str) -> Dict[str, Any]:
        """A harmless push to the device, the way a request would reach it: ``via`` 'touchque' (your key for
        its platform) or 'webhook' (MOBILE_PUSH, kind 'test'); ``ok``: APNs / FCM accepted it."""
        if not device_id:
            raise TouchQueConfigException('mobile.test_push() needs the device id')
        return self._http.post('/mobile/devices/' + quote(device_id, safe='') + '/test-push', {})

    def settings(self) -> Dict[str, Any]:
        return self._http.get('/mobile/settings')['settings']

    def update_settings(self, **changes: Any) -> Dict[str, Any]:
        """Which apps may enrol, whether they must prove themselves, and your push keys: ``ios_app_ids``,
        ``android_packages``, ``android_certs`` ({package: [SHA-256 of its signing certificate]}),
        ``attestation`` ('off' | 'optional' | 'required'), ``enroll_ttl_seconds``,
        ``apns`` ({keyId, teamId, topic, key: the .p8 text, production}; TouchQue then sends the iOS push
        itself) and ``fcm`` ({serviceAccount: the JSON}; the Android push). None removes a key; the keys
        are never shown back (``settings()['push']``)."""
        names = {'ios_app_ids': 'iosAppIds', 'android_packages': 'androidPackages', 'android_certs': 'androidCerts',
                 'attestation': 'attestation', 'enroll_ttl_seconds': 'enrollTtlSeconds',
                 'apns': 'apns', 'fcm': 'fcm'}
        unknown = set(changes) - set(names)
        if unknown:
            raise TouchQueConfigException('mobile.update_settings(): unknown setting ' + ', '.join(sorted(unknown)))
        return self._http.put('/mobile/settings', {names[k]: v for k, v in changes.items()})['settings']
