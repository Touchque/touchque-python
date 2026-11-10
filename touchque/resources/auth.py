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

        Returns ``{ externalUsername, deviceId, used, frozen, createdAt, expireAt, device }``.
        Raises ``TouchQueAPIException`` (404) if the user is unknown.

        ``device`` is the linked phone's posture for device trust, or ``None`` before a
        phone is linked. It is self-reported by the TouchQue app::

            {
              "platform": "ios" | "android" | None,
              "model": str | None,             # e.g. "iPhone15,3"
              "osVersion": str | None,         # e.g. "18.1"
              "securityPatch": str | None,     # Android "YYYY-MM-DD", None on iOS
              "appVersion": str | None,
              "screenLock": bool | None,
              "biometrics": "face" | "touch" | "fingerprint" | "iris" | "none" | None,
              "jailbroken": bool,              # jailbroken or rooted, by the app's checks
              "compromised": bool,             # jailbroken/rooted or tampered (sticky for a cool-down)
              "hardwareKey": bool,             # approvals are signed by a Secure Enclave / Keystore key
              "attestation": "apple-appattest" | "android-key" | None,
              "signed": bool,                  # the latest report was signed by the hardware key
              "reportedAt": str | None,        # ISO date-time of the latest report
              "lastSeenAt": str | None,
              "linkedAt": str | None,
              "state": "healthy" | "at_risk" | "compromised" | "unknown",
              "issues": [str],                 # jailbroken, tampered, integrity_failed, no_report,
                                               # stale_report, no_screen_lock, keys_lost,
                                               # no_hardware_key, debugger, developer_mode
            }
        """
        return self._http.get(f"/users/{quote(external_username, safe='')}")
