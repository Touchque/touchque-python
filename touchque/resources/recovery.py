"""
Never Locked Out: move a user whose phone is lost, dead or replaced to a new
phone without a help desk.

1. Let users name colleagues who can vouch for them (``set_vouchers``), behind
   an approval on their phone.
2. When the phone is gone, after the password (or your IdP): ``start``. Show
   ``bindUri`` as a QR for the TouchQue app on the new phone, then poll
   ``status`` and show each voucher's ``code``: the user reads it to the
   colleague on a call, who types it on their own phone.
3. After the cooling-off nobody vetoed, the account is on the new phone
   (``status == 'COMPLETED'``); critical actions wait 24 h (probation).

Admins can stop a running recovery with ``veto``.
"""
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from ..exceptions import TouchQueConfigException
from ..http_client import HttpClient

OPEN_STATUSES = ('AWAITING_DEVICE', 'VOUCHING', 'COOLING')


def is_recovery_open(recovery: Dict[str, Any]) -> bool:
    """A recovery still waiting for the new phone, the vouchers or the cooling-off."""
    return isinstance(recovery, dict) and recovery.get('status') in OPEN_STATUSES


class Recovery:
    """Never Locked Out: vouchers, start, status, list and veto."""

    def __init__(self, http: HttpClient):
        self._http = http

    def vouchers(self, external_username: str) -> Dict[str, Any]:
        """The colleagues a user named, and whether each can vouch today."""
        if not external_username:
            raise TouchQueConfigException('recovery.vouchers() needs the user (external_username)')
        return self._http.get('/recovery/vouchers', {'externalUsername': external_username})

    def set_vouchers(self, external_username: str, vouchers: List[str]) -> Dict[str, Any]:
        """Replaces the user's vouchers (at most 5 are kept). Ask for the
        user's phone first: whoever sets them chooses who may move the account."""
        if not external_username:
            raise TouchQueConfigException('recovery.set_vouchers() needs the user (external_username)')
        if not isinstance(vouchers, list):
            raise TouchQueConfigException('recovery.set_vouchers() needs a list of vouchers')
        return self._http.post('/recovery/vouchers', {'externalUsername': external_username, 'vouchers': vouchers})

    def start(
        self,
        external_username: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        display_name: Optional[str] = None,
        fallback_vouchers: Optional[List[str]] = None,
        required: Optional[int] = None,
        cool_off_minutes: Optional[int] = None,
        details: Optional[List[Dict[str, str]]] = None,
        notice_details: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Starts moving the user to a new phone. Call it only after the first
        factor. Raises TouchQueAPIException with ``code`` ``not_enough_vouchers``,
        ``recovery_in_progress``, ``blocked``, ``frozen`` or ``rate_limited``::

            r = tq.recovery.start(user, client_ip=ip, display_name='Ada')
            show_qr(r['bindUri'])  # the new phone scans it
        """
        if not external_username:
            raise TouchQueConfigException('recovery.start() needs the user (external_username)')
        payload: Dict[str, Any] = {'externalUsername': external_username}
        if client_ip:
            payload['clientIp'] = client_ip
        if user_agent:
            payload['userAgent'] = user_agent
        if display_name:
            payload['displayName'] = display_name
        if fallback_vouchers:
            payload['fallbackVouchers'] = list(fallback_vouchers)
        if required is not None:
            payload['required'] = required
        if cool_off_minutes is not None:
            payload['coolOffMinutes'] = cool_off_minutes
        if details:
            payload['details'] = details
        if notice_details:
            payload['noticeDetails'] = notice_details
        return self._http.post('/recovery/start', payload)

    def status(self, recovery_id: str) -> Dict[str, Any]:
        """The recovery now, with its receipt chain. Poll it while the user waits."""
        if not recovery_id:
            raise TouchQueConfigException('recovery.status() needs the recovery id')
        return self._http.get(f'/recovery/{quote(recovery_id, safe="")}')

    def list(self, external_username: Optional[str] = None, open: bool = False) -> List[Dict[str, Any]]:
        """A user's recoveries, or (``open=True``) every running one of your workspace."""
        if not external_username and not open:
            raise TouchQueConfigException('recovery.list() needs external_username or open=True')
        params: Dict[str, Any] = {}
        if external_username:
            params['externalUsername'] = external_username
        if open:
            params['open'] = 'true'
        res = self._http.get('/recovery', params)
        return res.get('recoveries', []) if isinstance(res, dict) else []

    def veto(self, recovery_id: str, by: Optional[str] = None, reason: Optional[str] = None) -> Dict[str, Any]:
        """Stops a running recovery (e.g. an admin who does not believe it). Does not freeze the user."""
        if not recovery_id:
            raise TouchQueConfigException('recovery.veto() needs the recovery id')
        payload: Dict[str, Any] = {}
        if by:
            payload['by'] = by
        if reason:
            payload['reason'] = reason
        return self._http.post(f'/recovery/{quote(recovery_id, safe="")}/veto', payload)
