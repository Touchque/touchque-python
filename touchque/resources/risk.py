"""
Silent sign-ins: ask TouchQue's risk engine whether a sign-in needs the phone
at all, and manage the browsers it knows for a user.

A browser becomes known when the user approves a request on the phone (or
with a passkey) that carried the browser's device-bound key proof
(``login.request(..., browser_proof=...)``). Later, ``risk.check`` with a
fresh proof from the same browser answers ``prompt: False`` when nothing about
the sign-in is new. ``risk.check`` sends nothing to the phone.
"""
from typing import Any, Dict, List, Optional

from ..exceptions import TouchQueConfigException
from ..http_client import HttpClient

_ASSURANCE = ('high', 'normal', 'low')


def parse_risk_check(raw: Any) -> Dict[str, Any]:
    """Reads a ``POST /risk/check`` answer, failing closed.

    ``prompt`` is ``False`` ONLY when the answer says exactly ``prompt: false``
    (a JSON boolean). Anything else, including a missing, ``null``, ``0`` or
    ``"false"`` value or an answer that is not a JSON object, asks. Malformed
    ``reasons`` become ``[]`` (entries without a string ``code`` are dropped, a
    missing ``text`` is ``''``), an unknown or missing ``assurance`` is
    ``'normal'``, and ``silentMode`` is ``'shadow'`` or ``'enforce'``.
    """
    body = raw if isinstance(raw, dict) else {}
    reasons: List[Dict[str, str]] = []
    if isinstance(body.get('reasons'), list):
        for r in body['reasons']:
            if isinstance(r, dict) and isinstance(r.get('code'), str):
                text = r.get('text')
                reasons.append({'code': r['code'], 'text': text if isinstance(text, str) else ''})
    assurance = body.get('assurance')
    out = {
        # `is not False`: only the boolean False skips the push (0, None, 'false' ask).
        'prompt': body.get('prompt') is not False,
        'reasons': reasons,
        'assurance': assurance if isinstance(assurance, str) and assurance in _ASSURANCE else 'normal',
        'silentMode': 'shadow' if body.get('silentMode') == 'shadow' else 'enforce',
    }
    # "Why?": the check's case code (K7P-2QX), to show the user.
    if isinstance(body.get('caseCode'), str):
        out['caseCode'] = body['caseCode']
    return out


class Risk:
    """Silent sign-ins: should this sign-in ask the phone, and which browsers
    TouchQue knows for a user."""

    def __init__(self, http: HttpClient):
        self._http = http

    def check(
        self,
        external_username: str,
        type: str = 'LOGIN',
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        browser_proof: Optional[str] = None,
        max_age_seconds: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Should this sign-in ask the phone? Sends nothing to the phone.

        Returns ``{'prompt', 'reasons', 'assurance', 'silentMode'}``. Skip the
        push only when ``prompt`` is ``False``; on any error, ask as usual::

            browser_proof = request.headers.get('X-TouchQue-Browser')
            risk = tq.risk.check(user, client_ip=ip, browser_proof=browser_proof)
            if risk['prompt'] is False:
                return sign_in(user)  # known browser, nothing new
            tq.login.request(user, type='LOGIN', browser_proof=browser_proof)

        :param type: the action the user is about to do (default ``'LOGIN'``).
            A critical action always asks.
        :param client_ip: the end user's IP address, compared with the networks
            of the user's earlier approved sign-ins.
        :param browser_proof: the browser's device-bound key proof
            (``X-TouchQue-Browser``), passed through untouched.
        :param max_age_seconds: your own limit on how long ago the last phone
            approval in this browser may be (integer, ``0`` = always ask).
            TouchQue never goes beyond its own limit (7 days).
        :param context: for your TouchQue Actions only (``event.context``).
        """
        if not external_username:
            raise TouchQueConfigException('risk.check() needs the user (external_username)')
        payload: Dict[str, Any] = {'externalUsername': external_username}
        if type:
            payload['type'] = type
        if client_ip:
            payload['clientIp'] = client_ip
        if user_agent:
            payload['userAgent'] = user_agent
        if browser_proof:
            payload['browserProof'] = browser_proof
        if max_age_seconds is not None:
            payload['maxAgeSeconds'] = max_age_seconds
        if context:
            payload['context'] = context
        return parse_risk_check(self._http.post('/risk/check', payload))

    def browsers(self, external_username: str) -> Dict[str, Any]:
        """The browsers TouchQue knows for a user, for an "approved browsers"
        list in your settings page: ``{'browsers': [{'thumbprint', 'label',
        'createdAt', 'lastMfaAt', 'lastMfaMethod', 'lastSeenAt',
        'lastSilentAt'}]}``. Pass a ``thumbprint`` to ``forget_browsers`` to
        forget that one."""
        if not external_username:
            raise TouchQueConfigException('risk.browsers() needs the user (external_username)')
        res = self._http.get('/risk/browsers', {'externalUsername': external_username})
        browsers = res.get('browsers') if isinstance(res, dict) else None
        return {'browsers': browsers if isinstance(browsers, list) else []}

    def forget_browsers(self, external_username: str, thumbprint: Optional[str] = None) -> Dict[str, Any]:
        """Forgets one browser (``thumbprint``) or all of a user's browsers:
        their next sign-in asks the phone again. Call it after a password reset
        or when the user signs out everywhere. Returns ``{'forgotten': n}``."""
        if not external_username:
            raise TouchQueConfigException('risk.forget_browsers() needs the user (external_username)')
        payload: Dict[str, Any] = {'externalUsername': external_username}
        if thumbprint:
            payload['thumbprint'] = thumbprint
        return self._http.post('/risk/browsers/forget', payload)
