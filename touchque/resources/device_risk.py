"""Device risk (a paid add-on, off until your workspace turns it on): a visitor
ID for every browser on your sign-up, password-reset, sign-in or approval page.

The page identifies with ``@touchque/web`` (``deviceRisk.identify({ siteKey,
purpose })`` gives ``{ visitorId, requestId, confidence }``) and sends you the
requestId. Never trust the page's copy: read the identification here
(``get_event``) or check it for an account (``check``). Touchque keeps keyed
hashes only, with a key of your workspace alone, and its risk engine decides.

Every signal only ever asks for more: ``stepUp`` means an extra check on this
page (an emailed code, a passkey, a number-matched approval), never a refusal.
For sign-ins, pass the requestId to ``login.request`` / ``risk.check`` as
``device_risk_request_id`` instead. Collect it only on these pages and name it
in your privacy notice.

With the script tag (device.js), the form arrives with ``touchque_request_id``::

    r = tq.device_risk.check(request.form.get('touchque_request_id'), event='sign_in', external_username=email)

Pass it as it came. Missing, empty, made up or expired, it is still a verdict
(``report``: ``missing``, ``unknown``, ``expired``; the signal
``device_identification_missing``), never an exception: a page without the
tag, or with it blocked, only gets the visitor a step-up.
"""
import re
from typing import Any, Dict, Optional

from ..exceptions import TouchqueConfigException
from ..http_client import HttpClient

#: The pages a device report may come from.
DEVICE_RISK_EVENTS = ('sign_in', 'sign_up', 'password_reset', 'approval')
#: What the page had sent: ``ok``, ``replayed``, or no usable identification.
DEVICE_RISK_REPORTS = ('ok', 'replayed', 'missing', 'unknown', 'expired', 'invalid')

_REQUEST_ID = re.compile(r'^dre_[A-Za-z0-9_-]{22}$')


def parse_device_risk_check(raw: Any) -> Dict[str, Any]:
    """Reads a ``POST /device-risk/check`` answer, failing toward asking:
    ``stepUp`` is True unless it says exactly False; junk signals are dropped."""
    body = raw if isinstance(raw, dict) else {}
    signals = []
    for s in body.get('signals') or []:
        if isinstance(s, dict) and isinstance(s.get('code'), str):
            item = {
                'code': s['code'],
                'text': s['text'] if isinstance(s.get('text'), str) else '',
                'strength': s['strength'] if s.get('strength') in ('passkey', 'none') else 'number_match',
            }
            if isinstance(s.get('enforced'), bool):
                item['enforced'] = s['enforced']
            if isinstance(s.get('evidence'), dict):
                item['evidence'] = s['evidence']
            signals.append(item)
    out = {
        'report': body.get('report') if body.get('report') in DEVICE_RISK_REPORTS else 'invalid',
        'requestId': body.get('requestId') if isinstance(body.get('requestId'), str) else None,
        'visitorId': body.get('visitorId') if isinstance(body.get('visitorId'), str) else None,
        'confidence': body.get('confidence') if isinstance(body.get('confidence'), (int, float)) and not isinstance(body.get('confidence'), bool) else None,
        'visitor': body.get('visitor') if isinstance(body.get('visitor'), dict) else None,
        'counts': body.get('counts') if isinstance(body.get('counts'), dict) else None,
        # The address (never coordinates), the visitor's counts, one answer to "a bot?" (detected | suspected | not_detected).
        'network': body.get('network') if isinstance(body.get('network'), dict) else None,
        'velocity': body.get('velocity') if isinstance(body.get('velocity'), dict) else None,
        'bot': body.get('bot') if isinstance(body.get('bot'), dict) else None,
        'signals': signals,
        'stepUp': body.get('stepUp') is not False,
        'wouldStepUp': body.get('wouldStepUp') is True,
        'requires': body.get('requires') if body.get('requires') in ('number_match', 'passkey') else 'none',
        'mode': 'enforce' if body.get('mode') == 'enforce' else 'shadow',
        # The engine's state for this check; 'unavailable' when the risk engine could not be reached and the verdict is a safe default.
        'engine': body.get('engine') if isinstance(body.get('engine'), str) else None,
    }
    if isinstance(body.get('caseCode'), str):
        out['caseCode'] = body['caseCode']
    return out


class DeviceRisk:
    def __init__(self, http: HttpClient):
        self._http = http

    def check(
        self,
        request_id: Any = None,
        event: str = 'sign_in',
        external_username: Optional[str] = None,
        client_ip: Optional[str] = None,
        device_risk: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Checks the page's identification for an account: binds it (one
        account per identification, 15 minutes) and asks the risk engine. Pass
        the form field as it came: None, empty or made up is still a verdict
        (``report``: ``missing``, ``unknown``), never an exception. 409
        ``device_risk_off`` until your workspace turns Device risk on.

        :param request_id: the ``touchque_request_id`` form field (the script tag), or ``deviceRisk.identify()``'s requestId.
        :param event: ``sign_in``, ``sign_up``, ``password_reset`` or ``approval``.
        :param external_username: the account the page is for, when there is one.
        :param client_ip: the end user's address (default: where the browser identified from).
        :param device_risk: instead of request_id, the page's report (``deviceRisk.collect()``).

        Example::

            r = tq.device_risk.check(request.form.get('touchque_request_id'), event='sign_up', external_username=email, client_ip=ip)
            if r['stepUp']:
                ask_for_email_code()   # never refuse on it alone
        """
        if event not in DEVICE_RISK_EVENTS:
            raise TouchqueConfigException(f"device_risk.check() event must be one of {', '.join(DEVICE_RISK_EVENTS)}")
        payload: Dict[str, Any] = {}
        if isinstance(request_id, str) and request_id:
            payload['requestId'] = request_id[:64]
        elif isinstance(device_risk, str) and device_risk:
            payload['deviceRisk'] = device_risk
        payload['event'] = event
        if external_username:
            payload['externalUsername'] = external_username
        if client_ip:
            payload['clientIp'] = client_ip
        return parse_device_risk_check(self._http.post('/device-risk/check', payload))

    def search_events(self, from_: Optional[str] = None, to: Optional[str] = None, signal: Optional[str] = None,
                      step_up: Optional[bool] = None, kind: Optional[str] = None, origin: Optional[str] = None,
                      ip: Optional[str] = None, account: Optional[str] = None, visitor_id: Optional[str] = None,
                      request_id: Optional[str] = None, cursor: Optional[str] = None, limit: Optional[int] = None) -> Dict[str, Any]:
        """Your workspace's identifications, newest first, one page at a time:
        a date range (``from_``/``to``: ``YYYY-MM-DD`` or ISO times; 7 days by
        default, at most 90, within your retention) and any of the filters.
        ``ip`` is an address or a CIDR range and is never returned. Pass
        ``nextCursor`` back as ``cursor`` until it is ``None``; do not page by
        moving the dates. A search that would read too much is a 422
        ``search_too_broad``: narrow the range or add a filter.

        Returns ``{ events, nextCursor, from, to }``.

        Example::

            cursor = None
            while True:
                page = tq.device_risk.search_events(signal='device_tampered', cursor=cursor)
                for e in page['events']:
                    print(e['at'], e['visitorId'], e['caseCode'])
                cursor = page['nextCursor']
                if not cursor:
                    break
        """
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100):
            raise TouchqueConfigException('device_risk.search_events() limit must be 1 to 100')
        params: Dict[str, Any] = {}
        for key, value in (('from', from_), ('to', to), ('signal', signal), ('kind', kind), ('origin', origin), ('ip', ip),
                           ('account', account), ('visitorId', visitor_id), ('requestId', request_id), ('cursor', cursor)):
            if isinstance(value, str) and value:
                params[key] = value
        if isinstance(step_up, bool):
            params['stepUp'] = 'true' if step_up else 'false'
        if limit is not None:
            params['limit'] = limit
        raw = self._http.get('/device-risk/events', params) or {}
        cursor_out = raw.get('nextCursor')
        return {
            'events': raw.get('events') if isinstance(raw.get('events'), list) else [],
            'nextCursor': cursor_out if isinstance(cursor_out, str) and cursor_out else None,
            'from': raw.get('from') or '',
            'to': raw.get('to') or '',
        }

    def get_event(self, request_id: str) -> Dict[str, Any]:
        """The trusted identification behind a request_id: the visitor, how sure,
        what the page showed, the risk engine's verdict. Read-only."""
        if not isinstance(request_id, str) or not _REQUEST_ID.match(request_id):
            raise TouchqueConfigException('device_risk.get_event() needs a request_id (dre_...)')
        return self._http.get(f'/device-risk/events/{request_id}')
