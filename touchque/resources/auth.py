from typing import Dict, Any
from urllib.parse import quote
from ..http_client import HttpClient

class Auth:
    def __init__(self, http: HttpClient):
        self._http = http

    def generate_secret(self, external_username: str) -> Dict[str, Any]:
        """Generate a new setup secret for a user."""
        return self._http.post('/auth/generate-secret', {
            'externalUsername': external_username
        })





    def reset_secret(self, external_username: str) -> Dict[str, Any]:
        """Reset (regenerate) a user's secret."""
        return self._http.post('/auth/secret/reset', {
            'externalUsername': external_username
        })

    def validate_secret(self, secret: str) -> Dict[str, Any]:
        """Validate a setup secret code."""
        return self._http.post('/auth/secret/validate', {
            'secret': secret
        })

    def get_user(self, external_username: str) -> Dict[str, Any]:
        """
        Look up a user's link status without sending a push. Useful while
        polling during enrollment: ``used`` flips true and ``deviceId`` is set
        once the mobile app scans the setup secret.

        Returns ``{ externalUsername, deviceId, used, frozen, createdAt, expireAt }``.
        Raises ``TouchQueAPIException`` (404) if the user is unknown.
        """
        return self._http.get(f"/users/{quote(external_username, safe='')}")
