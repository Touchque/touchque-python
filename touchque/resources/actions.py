from typing import Any, Dict, List, Optional

from ..http_client import HttpClient


class Actions:
    """Action types ("LOGIN", "SEND_MONEY", …) — what a user is asked to
    approve. Define them from code at start-up instead of clicking them
    into the Dashboard."""

    def __init__(self, http: HttpClient):
        self._http = http

    def define(self, type: str, name: Optional[str] = None, description: Optional[str] = None,
               critical: Optional[bool] = None) -> Dict[str, Any]:
        """Creates the action type, or updates its name/description/critical
        flag. Safe to call on every start-up: it never re-enables a type an
        admin disabled.
        """
        body: Dict[str, Any] = {'type': type, 'name': name or type}
        if description is not None:
            body['description'] = description
        if critical is not None:
            body['critical'] = critical
        return self._http.post('/action-types', body)

    def list(self) -> List[Dict[str, Any]]:
        return self._http.get('/action-types')
