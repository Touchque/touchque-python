"""TouchQue Login My Account API (/me/v1) from your server: the signed-in
customer's own profile, sign-in methods, devices, apps and data, called with
their access token for audience https://<domain>/me/.

    me = login.my_account_token(session["refresh_token"], scope="read:me update:me")  # keep me.refresh_token
    account = login.my_account(me.access_token)
    account.get()["profile"]

Security changes, the data export and deletion need a recent sign-in; when it
is too old a MyAccountError with step_up True is raised: send the person
through authorization_url(max_age=0) again.
"""

import re
from typing import Any, Dict, Optional
from urllib.parse import quote, urlsplit

import requests

from .config import _LOCAL_HOSTS
from .exceptions import TouchQueException


class MyAccountError(TouchQueException):
    def __init__(self, code: str, status: int, description: Optional[str] = None, max_age: Optional[int] = None):
        super().__init__(f"{code}: {description}" if description else code)
        self.code = code
        self.status = status
        self.description = description
        # True when the sign-in is too old for this change (RFC 9470).
        self.step_up = code == "insufficient_user_authentication"
        self.max_age = max_age


def _seg(value: str) -> str:
    return quote(value, safe="")


def _issuer_of(domain: str) -> str:
    """https://<domain>. Plaintext http only on this machine (localhost, 127.0.0.1, ::1,
    *.localhost), as for the API base_url: codes, tokens and secrets would travel in the clear."""
    raw = domain.rstrip("/")
    issuer = raw if raw.startswith(("http://", "https://")) else f"https://{raw}"
    host = (urlsplit(issuer).hostname or "").lower()
    if issuer.startswith("http://") and host not in _LOCAL_HOSTS and not host.endswith(".localhost"):
        raise ValueError(f'refusing a plaintext http:// issuer for "{host}": use https://')
    return issuer


class MyAccount:
    def __init__(self, domain: str, access_token: str, session: Optional[requests.Session] = None, timeout: float = 10.0):
        if not domain or not access_token:
            raise MyAccountError("config", 0, "domain and access_token are required")
        try:
            self.issuer = _issuer_of(domain)
        except ValueError as err:
            raise MyAccountError("config", 0, str(err))
        self._token = access_token
        self._http = session or requests.Session()
        self.timeout = timeout

    def account_page_url(self, section: Optional[str] = None) -> str:
        """The hosted account page, optionally at 'security', 'devices' or 'privacy'."""
        return f"{self.issuer}/account" + (f"/{section}" if section else "")

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        res = self._http.request(method, f"{self.issuer}/me/v1{path}", headers=headers, json=body, timeout=self.timeout)
        if res.status_code == 204:
            return None
        try:
            data = res.json()
        except ValueError:
            data = {}
        if res.status_code >= 400:
            challenge = res.headers.get("WWW-Authenticate", "") if getattr(res, "headers", None) else ""
            m = re.search(r'max_age="?(\d+)"?', challenge)
            raise MyAccountError(data.get("error") or f"http_{res.status_code}", res.status_code, data.get("error_description"), int(m.group(1)) if m else None)
        return data

    def get(self) -> Dict[str, Any]:
        return self._call("GET", "")

    def get_profile(self) -> Dict[str, Any]:
        return self._call("GET", "/profile")

    def update_profile(self, **changes: Any) -> Dict[str, Any]:
        """name, given_name, family_name, nickname, locale, user_metadata (merged; None removes a key)."""
        names = {"given_name": "givenName", "family_name": "familyName", "user_metadata": "userMetadata"}
        return self._call("PATCH", "/profile", {names.get(k, k): v for k, v in changes.items()})

    def authentication_methods(self) -> Dict[str, Any]:
        return self._call("GET", "/authentication-methods")

    def rename_passkey(self, passkey_id: str, label: str) -> None:
        self._call("PATCH", f"/authentication-methods/passkeys/{_seg(passkey_id)}", {"label": label})

    def remove_passkey(self, passkey_id: str) -> None:
        """Needs a recent sign-in."""
        self._call("DELETE", f"/authentication-methods/passkeys/{_seg(passkey_id)}")

    def unlink_touchque_app(self) -> None:
        """Needs a recent sign-in."""
        self._call("DELETE", "/authentication-methods/touchque")

    def set_email_codes(self, enabled: bool) -> Dict[str, Any]:
        """Email codes as a second step. Needs a recent sign-in."""
        return self._call("PUT", "/authentication-methods/email", {"enabled": enabled})

    def start_sms_enrollment(self, phone: str) -> Dict[str, Any]:
        """Texts a code to a new number for text-message codes. Needs a recent sign-in."""
        return self._call("POST", "/authentication-methods/sms", {"phone": phone})

    def verify_sms_enrollment(self, code: str) -> Dict[str, Any]:
        """The code from that text: text-message codes are on. Needs a recent sign-in."""
        return self._call("POST", "/authentication-methods/sms/verify", {"code": code})

    def remove_sms_codes(self) -> None:
        """Needs a recent sign-in."""
        self._call("DELETE", "/authentication-methods/sms")

    def unlink_identity(self, identity_id: str) -> None:
        """Needs a recent sign-in."""
        self._call("DELETE", f"/identities/{_seg(identity_id)}")

    def stop_app_access(self, access_id: str) -> None:
        """Apps stop using a linked account for the person (token vault: the identity's appAccess id);
        signing in with it stays."""
        self._call("DELETE", f"/app-access/{_seg(access_id)}")

    def set_password(self, password: str) -> Dict[str, Any]:
        """Sets or changes the password; other sessions end. Needs a recent sign-in."""
        return self._call("PUT", "/password", {"password": password})

    def remove_password(self) -> None:
        """Needs a recent sign-in and another way to sign in."""
        self._call("DELETE", "/password")

    def change_email(self, email: str) -> Dict[str, Any]:
        """A confirmation link goes to the new address. Needs a recent sign-in."""
        return self._call("POST", "/email", {"email": email})

    def send_verification_email(self) -> Dict[str, Any]:
        return self._call("POST", "/email/verification")

    def sessions(self) -> Dict[str, Any]:
        return self._call("GET", "/sessions")

    def end_session(self, session_id: str) -> None:
        self._call("DELETE", f"/sessions/{_seg(session_id)}")

    def end_other_sessions(self) -> Dict[str, Any]:
        return self._call("DELETE", "/sessions")

    def apps(self) -> Dict[str, Any]:
        return self._call("GET", "/apps")

    def revoke_app(self, client_id: str) -> Dict[str, Any]:
        return self._call("DELETE", f"/apps/{_seg(client_id)}")

    def consents(self) -> Dict[str, Any]:
        return self._call("GET", "/consents")

    def set_marketing(self, granted: bool) -> Dict[str, Any]:
        return self._call("PUT", "/consents/marketing", {"granted": granted})

    def export_data(self) -> Dict[str, Any]:
        """Everything about the person (KVKK/GDPR). Needs a recent sign-in."""
        return self._call("GET", "/export")

    def delete_account(self) -> Dict[str, Any]:
        """Erases the account at once. Needs delete:me and a recent sign-in."""
        return self._call("DELETE", "")
