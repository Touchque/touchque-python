"""Help desk: IT working on a person's account in the open.

1. Before your help desk acts on someone's account: ``open`` with the person
   and the signed-in agent. The person's phone gets a calm notice ("<agent>
   from IT is working on your account now"); while the session is open, their
   "someone says they're from IT" button shows this agent, and with none open
   it tells them to hang up (webhook ``ASSIST_CLAIM_UNVERIFIED``).
2. Before a sensitive action (a factor or password reset, an activation or
   recovery link, an unlock, a new phone, removing a passkey): ``verify``. Show
   ``challengeCode`` to the agent only; they read it to the person, who types
   it on their phone and approves with Face ID. Default deny.
3. Right before the action: ``spend`` (a passed check, for that action, at most
   ten minutes old, once). ``unfreeze`` lifts a freeze the same way.

No phone (``code`` ``no_phone``, ``data['route']`` ``never_locked_out``): the
person moves to a new phone with Never Locked Out; the help desk cannot.
"""
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from ..exceptions import TouchQueConfigException
from ..http_client import HttpClient


def _path(id: str, rest: str = '') -> str:
    return f'/assist/{quote(id, safe="")}{rest}'


def is_assist_check_passed(session: Dict[str, Any], request_id: str) -> bool:
    """The check of ``request_id`` passed on the person's phone and was not used yet."""
    for check in session.get('checks') or []:
        if check.get('requestId') == request_id:
            return check.get('outcome') == 'verified' and not check.get('spentAt')
    return False


class Assist:
    """IT working on a person's account, and checks on their phone before sensitive actions."""

    def __init__(self, http: HttpClient):
        self._http = http

    def open(self, external_username: str, agent: Dict[str, str], reason: Optional[str] = None,
             ttl_minutes: Optional[int] = None, notify: Optional[bool] = None) -> Dict[str, Any]:
        """Starts helping a person. ``agent``: ``{'name', 'title', 'ref'}`` (``ref`` is your id for them).
        A session of the same agent for the same person is replaced."""
        if not external_username or not (agent or {}).get('name'):
            raise TouchQueConfigException('assist.open() needs external_username and agent["name"]')
        payload: Dict[str, Any] = {'externalUsername': external_username, 'agent': {k: v for k, v in agent.items() if v}}
        if reason:
            payload['reason'] = reason
        if ttl_minutes is not None:
            payload['ttlMinutes'] = ttl_minutes
        if notify is not None:
            payload['notify'] = notify
        return self._http.post('/assist', payload)

    def get(self, id: str) -> Dict[str, Any]:
        """The session and its checks. Poll it while a check is ``pending``."""
        if not id:
            raise TouchQueConfigException('assist.get() needs the session id')
        return self._http.get(_path(id))

    def list(self, external_username: Optional[str] = None, open_only: bool = False,
             open: Optional[bool] = None) -> List[Dict[str, Any]]:
        """A person's sessions, or every open one, newest first.
        ``open=True`` is the same as ``open_only=True`` (the name ``recovery.list`` and the other SDKs use)."""
        open_only = open_only or bool(open)
        if not external_username and not open_only:
            raise TouchQueConfigException('assist.list() needs external_username or open_only=True')
        params: Dict[str, Any] = {}
        if external_username:
            params['externalUsername'] = external_username
        if open_only:
            params['open'] = 'true'
        res = self._http.get('/assist', params)
        return list((res or {}).get('sessions') or [])

    def verify(self, id: str, action: str, action_text: Optional[str] = None,
               details: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """Asks the person's phone to confirm ``action`` (``reset_2fa``, ``reset_password``, ``activation_link``,
        ``recovery_link``, ``unlock``, ``new_phone``, ``remove_passkey`` or your own). Returns ``requestId`` and
        ``challengeCode`` (for the agent only). Raises TouchQueAPIException ``no_phone``, ``assist_not_open`` or
        ``rate_limited``."""
        if not id or not action:
            raise TouchQueConfigException('assist.verify() needs the session id and an action')
        payload: Dict[str, Any] = {'action': action}
        if action_text:
            payload['actionText'] = action_text
        if details:
            payload['details'] = details
        return self._http.post(_path(id, '/verify'), payload)

    def spend(self, id: str, request_id: str, action: str) -> Dict[str, Any]:
        """Uses a passed check for its action, right before you take it; ``check_required`` (428) otherwise."""
        if not id or not request_id or not action:
            raise TouchQueConfigException('assist.spend() needs the session id, request_id and action')
        return self._http.post(_path(id, '/spend'), {'requestId': request_id, 'action': action})

    def unfreeze(self, id: str, request_id: str) -> Dict[str, Any]:
        """Lifts the person's approval freeze with a passed check for ``unlock``: ``{'unfrozen', 'session'}``."""
        if not id or not request_id:
            raise TouchQueConfigException('assist.unfreeze() needs the session id and request_id')
        return self._http.post(_path(id, '/unfreeze'), {'requestId': request_id})

    def end(self, id: str, by: Optional[str] = None, reason: Optional[str] = None) -> Dict[str, Any]:
        """Stops helping; checks still waiting on the phone expire."""
        if not id:
            raise TouchQueConfigException('assist.end() needs the session id')
        payload: Dict[str, Any] = {}
        if by:
            payload['by'] = by
        if reason:
            payload['reason'] = reason
        return self._http.post(_path(id, '/end'), payload)
