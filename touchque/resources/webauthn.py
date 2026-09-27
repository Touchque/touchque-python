from typing import Dict, Any, Optional
from urllib.parse import quote
from ..http_client import HttpClient


class WebAuthn:
    """
    WebAuthn / FIDO2 (passkey) — a phishing-resistant approval path alongside
    the push + device flow (``login.verify``).

    Server-to-server, like every other resource here: the passkey ceremony runs
    in the browser (``navigator.credentials.create()`` / ``.get()``, or
    ``@touchque/web``), your backend collects that JSON and relays it through
    these methods. There is no client-side ceremony in this SDK.
    """

    def __init__(self, http: HttpClient):
        self._http = http

    # ── registration ────────────────────────────────────────────────────────
    def register_options(self, external_username: str, discoverable: bool = False) -> Dict[str, Any]:
        """Step 1: options for ``navigator.credentials.create()``.

        ``discoverable=True`` registers a resident credential with forced user
        verification — the shape a passwordless-primary login authenticates
        against. Omit for a classic second-factor credential.
        """
        body: Dict[str, Any] = {'externalUsername': external_username}
        if discoverable:
            body['discoverable'] = True
        return self._http.post('/webauthn/register/options', body)

    def register_verify(self, external_username: str, response: Dict[str, Any], label: Optional[str] = None) -> Dict[str, Any]:
        """Step 2: verify the browser's registration response and store the credential.

        Returns ``{ verified, credentialId }``.
        """
        body: Dict[str, Any] = {'externalUsername': external_username, 'response': response}
        if label:
            body['label'] = label
        return self._http.post('/webauthn/register/verify', body)

    # ── second-factor authentication (against a pending LoginRequest) ────────
    def authenticate_options(self, request_id: str) -> Dict[str, Any]:
        """Step 1: options for ``navigator.credentials.get()``, scoped to a
        pending ``request_id`` from ``login.request()``."""
        return self._http.post('/webauthn/login/options', {'requestId': request_id})

    def authenticate_verify(self, request_id: str, response: Dict[str, Any]) -> Dict[str, Any]:
        """Step 2: verify the assertion — approves the LoginRequest on success.

        Returns ``{ success, message }``.
        """
        return self._http.post('/webauthn/login/verify', {'requestId': request_id, 'response': response})

    # ── passwordless-primary login (no password, no prior login.request) ────
    def primary_options(self, external_username: str) -> Dict[str, Any]:
        """Step 1 of a passwordless-primary login. Requires
        ``TenantPolicy.passwordlessLoginEnabled``. A 404 ``no_passkey_registered``
        means the user has no passkey — fall back to password login.

        Returns ``{ attemptId, options }``.
        """
        return self._http.post('/webauthn/authenticate/primary/options', {'externalUsername': external_username})

    def primary_verify(self, attempt_id: str, response: Dict[str, Any]) -> Dict[str, Any]:
        """Step 2 of a passwordless-primary login.

        On ``success=True`` the returned ``requestId`` is a CONFIRMED
        LoginRequest. On ``success=False`` with ``requiresStepUp=True``, start
        the normal ``login.request()`` / number-match flow instead.
        """
        return self._http.post('/webauthn/authenticate/primary/verify', {'attemptId': attempt_id, 'response': response})

    # ── credential management ──────────────────────────────────────────────
    def list_credentials(self, external_username: str) -> Dict[str, Any]:
        """List a user's registered credentials (metadata only, no key material)."""
        return self._http.get('/webauthn/credentials', params={'externalUsername': external_username})

    def delete_credential(self, credential_record_id: str, external_username: Optional[str] = None) -> Dict[str, Any]:
        """Remove a registered credential. Pass ``external_username`` to scope
        the deletion to that user (recommended: without it, any credential id
        your API key can reach is deletable). Returns ``{ deleted: bool }``."""
        path = f"/webauthn/credentials/{quote(credential_record_id, safe='')}"
        if external_username:
            path += f"?externalUsername={quote(external_username, safe='')}"
        return self._http.delete(path)
