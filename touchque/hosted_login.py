"""Touchque Login (hosted sign-in) for your app: an OpenID Connect client for
your tenant (acme.login.touchque.com or your own domain).

    login = HostedLogin(domain="acme.login.touchque.com", client_id=..., client_secret=..., redirect_uri=...)
    req = login.authorization_url()            # keep req.state, req.nonce, req.code_verifier; redirect to req.url
    tokens = login.handle_callback(request_url, state=..., nonce=..., code_verifier=...)
    tokens.claims["sub"], tokens.access_token, tokens.refresh_token

PKCE (S256) is always used. ID tokens are checked against the tenant's JWKS
(RS256 signature, issuer, audience, expiry, nonce, at_hash). RS256 is
verified in pure Python, so the core needs only ``requests``. Your API checks
access tokens with ``verify_access_token(token, audience=...)``.

An app acting for a user (an AI agent; a confidential app whose grantTypes
list the grant, and an API that grants it scopes)::

    for_ada = login.exchange_token(adas_access_token, audience="https://api.acme.com")   # RFC 8693
    ask = login.ask_user(login_hint="ada@acme.com", scope="openid payments:create", binding_message="Pay invoice 42")
    reply(f"Type {ask.binding_code} in the Touchque app")
    approved = login.wait_for_user(ask)                                                 # CIBA, poll mode
"""

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, quote

import requests

from .exceptions import TouchqueException
from .my_account import MyAccount, _issuer_of

__all__ = ["HostedLogin", "HostedLoginError", "AuthorizationRequest", "TokenSet", "UserApprovalRequest"]


class HostedLoginError(TouchqueException):
    """A sign-in or token check failed. ``code`` is machine-readable."""

    def __init__(self, code: str, description: Optional[str] = None, status: Optional[int] = None):
        super().__init__(f"{code}: {description}" if description else code)
        self.code = code
        self.description = description
        self.status = status


@dataclass
class AuthorizationRequest:
    url: str
    state: str
    nonce: str
    code_verifier: str


# requested_token_type for the token vault (get_connection_token).
CONNECTION_TOKEN_TYPE = "urn:touchque:params:oauth:token-type:connection-access-token"


@dataclass
class TokenSet:
    access_token: str
    token_type: str
    expires_at: int
    scope: str
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict)
    # What the user approved on the phone (CIBA with authorization_details).
    authorization_details: Optional[list] = None
    # Token exchange: always the access token type.
    issued_token_type: Optional[str] = None
    # get_connection_token: the connection the provider token is for.
    connection: Optional[str] = None


@dataclass
class UserApprovalRequest:
    """A CIBA request: show ``binding_code`` (the number the user picks on the phone), then ``wait_for_user``."""
    auth_req_id: str
    expires_at: int
    interval: int
    binding_code: Optional[str] = None


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _random(n: int = 32) -> str:
    return _b64u(os.urandom(n))


# DER prefix of DigestInfo for SHA-256 (RFC 8017 9.2, note 1).
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _rs256_verify(n: int, e: int, signing_input: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 with SHA-256, public-key operation only."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_PREFIX + hashlib.sha256(signing_input).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


class HostedLogin:
    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: str = "openid profile email",
        audience: Optional[str] = None,
        clock_tolerance: int = 60,
        session: Optional[requests.Session] = None,
        timeout: float = 10.0,
    ):
        if not domain:
            raise HostedLoginError("config", "domain is required")
        if not client_id:
            raise HostedLoginError("config", "client_id is required")
        try:
            self.issuer = _issuer_of(domain)
        except ValueError as err:
            raise HostedLoginError("config", str(err))
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.audience = audience
        self.clock_tolerance = clock_tolerance
        self.timeout = timeout
        self._http = session or requests.Session()
        self._keys: Dict[str, tuple] = {}
        self._keys_at = 0.0
        self._lock = threading.Lock()

    # ── Sign-in ──────────────────────────────────────────────────────────

    def authorization_url(
        self,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        code_verifier: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        audience: Optional[str] = None,
        prompt: Optional[str] = None,
        login_hint: Optional[str] = None,
        screen_hint: Optional[str] = None,
        ui_locales: Optional[str] = None,
        max_age: Optional[int] = None,
        connection: Optional[str] = None,
        organization: Optional[str] = None,
        invitation: Optional[str] = None,
        acr_values: Optional[str] = None,
        response_mode: Optional[str] = None,
        extra_params: Optional[Mapping[str, str]] = None,
    ) -> AuthorizationRequest:
        """The URL to send the browser to, and the values to keep until the callback."""
        redirect = redirect_uri or self.redirect_uri
        if not redirect:
            raise HostedLoginError("config", "redirect_uri is required")
        state = state or _random()
        nonce = nonce or _random()
        verifier = code_verifier or _random(48)
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect,
            "scope": scope or self.scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": _b64u(hashlib.sha256(verifier.encode("ascii")).digest()),
            "code_challenge_method": "S256",
        }
        optional = {
            "audience": audience if audience is not None else self.audience,
            "prompt": prompt, "login_hint": login_hint, "screen_hint": screen_hint, "ui_locales": ui_locales,
            "max_age": max_age, "connection": connection, "organization": organization, "invitation": invitation,
            "acr_values": acr_values, "response_mode": response_mode,
        }
        params.update({k: str(v) for k, v in optional.items() if v not in (None, "")})
        params.update(dict(extra_params or {}))
        return AuthorizationRequest(f"{self.issuer}/authorize?{urlencode(params, quote_via=quote)}", state, nonce, verifier)

    def handle_callback(
        self,
        callback: Union[str, Mapping[str, str]],
        state: str,
        nonce: str,
        code_verifier: str,
        redirect_uri: Optional[str] = None,
        max_age: Optional[int] = None,
    ) -> TokenSet:
        """Checks state (and iss), exchanges the code, verifies the ID token.

        ``callback`` is the full callback URL or its query/form fields.
        """
        params = self._params(callback)
        got_state = params.get("state")
        if not got_state or not state or not hmac.compare_digest(got_state, state):
            raise HostedLoginError("state_mismatch", "The state does not match this sign-in")
        # RFC 9207: a response that carries iss (even an empty one) must name this issuer,
        # the one the ID token is checked against. Servers that do not send iss yet are accepted.
        if "iss" in params and params["iss"] != self.issuer:
            iss = params["iss"]
            raise HostedLoginError("issuer_mismatch", f"The response came from {iss}" if iss else "The response has an empty iss")
        if params.get("error"):
            raise HostedLoginError(params["error"], params.get("error_description"))
        code = params.get("code")
        if not code:
            raise HostedLoginError("invalid_request", "The callback has no code")
        redirect = redirect_uri or self.redirect_uri
        if not redirect:
            raise HostedLoginError("config", "redirect_uri is required")
        tokens = self._token({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "code_verifier": code_verifier})
        if not tokens.id_token:
            raise HostedLoginError("invalid_token", "No ID token: ask for the openid scope")
        tokens.claims = self.verify_id_token(tokens.id_token, nonce=nonce, access_token=tokens.access_token, max_age=max_age)
        return tokens

    def refresh(self, refresh_token: str, scope: Optional[str] = None) -> TokenSet:
        """A new access token and a rotated refresh token: keep the new one."""
        fields = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        if scope:
            fields["scope"] = scope
        tokens = self._token(fields)
        if tokens.id_token:
            tokens.claims = self.verify_id_token(tokens.id_token, access_token=tokens.access_token)
        return tokens

    def my_account_token(self, refresh_token: str, scope: str = "read:me update:me") -> TokenSet:
        """A token for the My Account API (audience https://<domain>/me/) from the
        refresh token a first-party app holds. The refresh token rotates: keep the
        returned one. Scopes: read:me, update:me, manage:me:security, delete:me."""
        return self._token({"grant_type": "refresh_token", "refresh_token": refresh_token, "audience": f"{self.issuer}/me/", "scope": scope})

    def my_account(self, access_token: str) -> "MyAccount":
        """The My Account API for the person holding access_token."""
        return MyAccount(self.issuer, access_token, session=self._http, timeout=self.timeout)

    def account_url(self, section: Optional[str] = None) -> str:
        """The hosted account page (profile; 'security', 'devices' or 'privacy')."""
        return f"{self.issuer}/account" + (f"/{section}" if section else "")

    def client_credentials(self, audience: str, scope: Optional[str] = None) -> TokenSet:
        """Machine to machine: an access token for your API with the app's own credentials."""
        fields = {"grant_type": "client_credentials", "audience": audience}
        if scope:
            fields["scope"] = scope
        return self._token(fields)

    def exchange_token(self, subject_token: str, audience: str, scope: Optional[str] = None) -> TokenSet:
        """RFC 8693: a signed-in user's access token, traded for one to call ``audience`` on their
        behalf (sub = the user, act.sub = this app). For a confidential app the API grants scopes to;
        never longer than the user's token."""
        fields = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token", "audience": audience,
        }
        if scope:
            fields["scope"] = scope
        return self._token(fields)

    def get_connection_token(self, user_access_token: str, connection: str, scope: Optional[str] = None) -> TokenSet:
        """Token vault: the provider's own access token (Google, Microsoft, GitHub...) for the signed-in
        user, from a connection that stores tokens. Touchque refreshes it; the refresh token never
        leaves. ``user_access_token`` is the user's token for this app (or for an app the connection
        lists). HostedLoginError invalid_grant: the user has not signed in with the connection since it
        started storing tokens, or they stopped app access."""
        fields = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": user_access_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": CONNECTION_TOKEN_TYPE, "connection": connection,
        }
        if scope:
            fields["scope"] = scope
        return self._token(fields)

    def ask_user(self, login_hint: str, scope: str, audience: Optional[str] = None, binding_message: Optional[str] = None,
                 authorization_details: Optional[list] = None, requested_expiry: Optional[int] = None) -> UserApprovalRequest:
        """CIBA: asks the user (e-mail or usr_ id) to approve on their phone. At least one of
        ``binding_message`` (<= 64 characters) or ``authorization_details`` (RFC 9396) is needed."""
        fields = {"login_hint": login_hint, "scope": scope}
        if audience:
            fields["audience"] = audience
        if binding_message:
            fields["binding_message"] = binding_message
        if authorization_details:
            fields["authorization_details"] = json.dumps(authorization_details)
        if requested_expiry:
            fields["requested_expiry"] = str(requested_expiry)
        res = self._post("/bc-authorize", fields)
        if res.status_code >= 400:
            raise self._error(res)
        d = res.json()
        return UserApprovalRequest(auth_req_id=str(d["auth_req_id"]), expires_at=int(time.time()) + int(d.get("expires_in") or 0),
                                   interval=int(d.get("interval", 5)), binding_code=d.get("binding_code"))

    def wait_for_user(self, request: UserApprovalRequest) -> TokenSet:
        """Polls until the user answers: the tokens, or HostedLoginError access_denied / expired_token."""
        interval = request.interval
        while True:
            if time.time() > request.expires_at:
                raise HostedLoginError("expired_token", "The user did not answer in time")
            time.sleep(interval)
            try:
                return self._token({"grant_type": "urn:openid:params:grant-type:ciba", "auth_req_id": request.auth_req_id})
            except HostedLoginError as e:
                if e.code == "slow_down":
                    interval += 5
                elif e.code != "authorization_pending":
                    raise

    def revoke(self, token: str) -> None:
        res = self._post("/oauth/revoke", {"token": token})
        if res.status_code >= 400:
            raise self._error(res)

    def userinfo(self, access_token: str) -> Dict[str, Any]:
        res = self._http.get(f"{self.issuer}/userinfo", headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}, timeout=self.timeout)
        if res.status_code >= 400:
            raise self._error(res)
        return res.json()

    def logout_url(self, id_token_hint: Optional[str] = None, post_logout_redirect_uri: Optional[str] = None, state: Optional[str] = None) -> str:
        params = {"client_id": self.client_id}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state:
            params["state"] = state
        return f"{self.issuer}/oidc/logout?{urlencode(params, quote_via=quote)}"

    # ── Token checks ─────────────────────────────────────────────────────

    def verify_access_token(self, token: str, audience: str, required_scopes: Iterable[str] = ()) -> Dict[str, Any]:
        """For your API: signature, issuer, audience, expiry, typ at+jwt, scopes."""
        payload = self._verify_jwt(token, typ="at+jwt")
        auds = payload.get("aud") if isinstance(payload.get("aud"), list) else [payload.get("aud")]
        if audience not in auds:
            raise HostedLoginError("invalid_token", "The token is for another audience")
        scopes = str(payload.get("scope") or "").split(" ")
        missing = [s for s in required_scopes if s not in scopes]
        if missing:
            raise HostedLoginError("insufficient_scope", "Missing scope: " + " ".join(missing), 403)
        return payload

    def verify_id_token(self, id_token: str, nonce: Optional[str] = None, access_token: Optional[str] = None, max_age: Optional[int] = None) -> Dict[str, Any]:
        payload = self._verify_jwt(id_token)
        auds = payload.get("aud") if isinstance(payload.get("aud"), list) else [payload.get("aud")]
        if self.client_id not in auds:
            raise HostedLoginError("invalid_token", "The ID token is for another app")
        if len(auds) > 1 and payload.get("azp") != self.client_id:
            raise HostedLoginError("invalid_token", "azp does not name this app")
        if nonce is not None and not (isinstance(payload.get("nonce"), str) and hmac.compare_digest(payload["nonce"], nonce)):
            raise HostedLoginError("nonce_mismatch", "The nonce does not match this sign-in")
        if access_token and isinstance(payload.get("at_hash"), str):
            expected = _b64u(hashlib.sha256(access_token.encode("ascii")).digest()[:16])
            if not hmac.compare_digest(payload["at_hash"], expected):
                raise HostedLoginError("invalid_token", "at_hash does not match the access token")
        if max_age is not None and isinstance(payload.get("auth_time"), int) and time.time() - payload["auth_time"] > max_age + self.clock_tolerance:
            raise HostedLoginError("login_required", "The sign-in is older than max_age")
        return payload

    # ── Internals ────────────────────────────────────────────────────────

    @staticmethod
    def _params(callback: Union[str, Mapping[str, str]]) -> Dict[str, str]:
        if isinstance(callback, str):
            query = urlsplit(callback).query if "?" in callback or "://" in callback else callback
            return dict(parse_qsl(query, keep_blank_values=True))
        return {k: v for k, v in dict(callback).items() if isinstance(v, str)}

    def _post(self, path: str, fields: Dict[str, str]) -> requests.Response:
        headers = {"Accept": "application/json"}
        auth = None
        data = dict(fields)
        if self.client_secret:
            auth = (quote(self.client_id, safe=""), quote(self.client_secret, safe=""))
        else:
            data["client_id"] = self.client_id
        return self._http.post(f"{self.issuer}{path}", data=data, headers=headers, auth=auth, timeout=self.timeout)

    @staticmethod
    def _error(res: requests.Response) -> HostedLoginError:
        try:
            data = res.json()
        except ValueError:
            data = {}
        return HostedLoginError(data.get("error") or f"http_{res.status_code}", data.get("error_description"), res.status_code)

    def _token(self, fields: Dict[str, str]) -> TokenSet:
        res = self._post("/oauth/token", fields)
        if res.status_code >= 400:
            raise self._error(res)
        d = res.json()
        return TokenSet(
            access_token=str(d.get("access_token")),
            token_type=str(d.get("token_type") or "Bearer"),
            expires_at=int(time.time()) + int(d.get("expires_in") or 0),
            scope=str(d.get("scope") or ""),
            id_token=d.get("id_token"),
            refresh_token=d.get("refresh_token"),
            authorization_details=d.get("authorization_details") if isinstance(d.get("authorization_details"), list) else None,
            issued_token_type=d.get("issued_token_type"),
            connection=d.get("connection") if isinstance(d.get("connection"), str) else None,
        )

    def _load_keys(self, force: bool = False) -> None:
        with self._lock:
            age = time.time() - self._keys_at
            if not force and self._keys and age < 3600:
                return
            if force and age < 30:
                return
            res = self._http.get(f"{self.issuer}/.well-known/jwks.json", headers={"Accept": "application/json"}, timeout=self.timeout)
            if res.status_code >= 400:
                raise HostedLoginError("jwks_unavailable", f"JWKS answered {res.status_code}")
            keys = {}
            for k in res.json().get("keys", []):
                if k.get("kty") == "RSA" and k.get("kid") and k.get("n") and k.get("e") and k.get("use", "sig") == "sig":
                    keys[k["kid"]] = (int.from_bytes(_b64u_decode(k["n"]), "big"), int.from_bytes(_b64u_decode(k["e"]), "big"))
            self._keys = keys
            self._keys_at = time.time()

    def _verify_jwt(self, token: str, typ: Optional[str] = None) -> Dict[str, Any]:
        parts = str(token).split(".")
        if len(parts) != 3:
            raise HostedLoginError("invalid_token", "not a JWT")
        try:
            header = json.loads(_b64u_decode(parts[0]))
            payload = json.loads(_b64u_decode(parts[1]))
            signature = _b64u_decode(parts[2])
        except (ValueError, TypeError):
            raise HostedLoginError("invalid_token", "malformed JWT")
        if header.get("alg") != "RS256":
            raise HostedLoginError("invalid_token", f"Unexpected alg {header.get('alg')}")
        if typ and str(header.get("typ") or "").lower() != typ:
            raise HostedLoginError("invalid_token", "Wrong token type")
        kid = str(header.get("kid") or "")
        self._load_keys()
        if kid not in self._keys:
            self._load_keys(force=True)
        if kid not in self._keys:
            raise HostedLoginError("invalid_token", "Unknown signing key")
        n, e = self._keys[kid]
        if not _rs256_verify(n, e, f"{parts[0]}.{parts[1]}".encode("ascii"), signature):
            raise HostedLoginError("invalid_token", "Bad signature")
        now = time.time()
        if payload.get("iss") != self.issuer:
            raise HostedLoginError("invalid_token", "Wrong issuer")
        if not isinstance(payload.get("exp"), (int, float)) or now > payload["exp"] + self.clock_tolerance:
            raise HostedLoginError("invalid_token", "The token expired")
        if isinstance(payload.get("iat"), (int, float)) and payload["iat"] > now + self.clock_tolerance:
            raise HostedLoginError("invalid_token", "The token is from the future")
        return payload
