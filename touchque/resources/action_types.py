from typing import Any, Dict, List, Optional

from ..http_client import HttpClient

# The Second Thought questions an action type can ask (at most two).
SECOND_THOUGHT_QUESTIONS = (
    'someone_guiding',
    'safe_account',
    'remote_access',
    'asked_for_code',
    'support_call',
    'met_online',
    'promised_return',
    'know_recipient',
    'sim_in_hand',
)

_KEEP: Any = object()


class ActionTypes:
    """Action types ("LOGIN", "SEND_MONEY", …) — what a user is asked to
    approve. Define them from code at start-up instead of clicking them
    into the Dashboard. (Before 4.0 this was ``tq.actions``; ``tq.actions``
    is Touchque Actions now.)"""

    def __init__(self, http: HttpClient):
        self._http = http

    def define(self, type: str, name: Optional[str] = None, description: Optional[str] = None,
               critical: Optional[bool] = None, second_thought: Optional[Dict[str, Any]] = _KEEP) -> Dict[str, Any]:
        """Creates the action type, or updates its name, description,
        critical flag and Second Thought questions. Safe to call on every
        start-up: it never re-enables a type an admin disabled.

        ``second_thought``: ``{'questions': [...], 'locale': 'tr'|'en'}``, at
        most two of ``SECOND_THOUGHT_QUESTIONS``, asked on the phone before
        Approve. A risky answer never refuses: the approval comes back
        ``provisional`` and the phone asks "Was this you?" later. ``None``
        turns them off; leave it out to keep what the Dashboard has.
        """
        body: Dict[str, Any] = {'type': type, 'name': name or type}
        if description is not None:
            body['description'] = description
        if critical is not None:
            body['critical'] = critical
        if second_thought is not _KEEP:
            body['secondThought'] = second_thought
        return self._http.post('/action-types', body)

    def list(self) -> List[Dict[str, Any]]:
        return self._http.get('/action-types')
