"""TouchQue Login client: authorization URL, callback with a verified ID
token, refresh, access-token checks, and the refusals (state, issuer, nonce,
forged signature), against an in-process fake tenant."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from touchque import HostedLogin, HostedLoginError, CONNECTION_TOKEN_TYPE

ISSUER = "https://acme.login.touchque.com"
CLIENT = "client-123"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt(payload, typ="JWT", key=KEY):
    head = b64u(json.dumps({"alg": "RS256", "typ": typ, "kid": "k1"}).encode())
    body = b64u(json.dumps(payload).encode())
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64u(sig)}"


def jwk():
    nums = KEY.public_key().public_numbers()
    to = lambda i: b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))
    return {"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256", "n": to(nums.n), "e": to(nums.e)}


class Res:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class FakeTenant:
    def __init__(self, nonce_override=None, sign_with=KEY):
        self.codes = {}
        self.posts = []
        self.nonce_override = nonce_override
        self.sign_with = sign_with

    def authorize(self, url):
        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        code = f"code-{len(self.codes)}"
        self.codes[code] = (q["code_challenge"], q["nonce"])
        return {"code": code, "state": q["state"]}

    def get(self, url, headers=None, timeout=None):
        if url.endswith("/.well-known/jwks.json"):
            return Res(200, {"keys": [jwk()]})
        return Res(404, {})

    def post(self, url, data=None, headers=None, auth=None, timeout=None):
        self.posts.append({"url": url, "data": data, "auth": auth})
        now = int(time.time())
        if data["grant_type"] == "authorization_code":
            challenge, nonce = self.codes.get(data["code"], (None, None))
            if challenge != b64u(hashlib.sha256(data["code_verifier"].encode()).digest()):
                return Res(400, {"error": "invalid_grant"})
            at = jwt({"iss": ISSUER, "sub": "usr_1", "aud": ["https://api.acme.test"], "exp": now + 300, "iat": now, "client_id": CLIENT, "scope": "openid read:orders"}, typ="at+jwt")
            at_hash = b64u(hashlib.sha256(at.encode()).digest()[:16])
            idt = jwt({"iss": ISSUER, "sub": "usr_1", "aud": CLIENT, "exp": now + 300, "iat": now, "nonce": self.nonce_override or nonce, "email": "a@acme.test", "at_hash": at_hash}, key=self.sign_with)
            return Res(200, {"access_token": at, "token_type": "Bearer", "expires_in": 300, "scope": "openid", "id_token": idt, "refresh_token": "tqr_1"})
        if data["grant_type"] == "refresh_token":
            return Res(200, {"access_token": "x", "token_type": "Bearer", "expires_in": 300, "scope": "openid", "refresh_token": "tqr_2"})
        return Res(400, {"error": "unsupported_grant_type"})


def make(fake, **kw):
    return HostedLogin(domain=ISSUER, client_id=CLIENT, redirect_uri="https://app/cb", session=fake, **kw)


def test_authorization_url_has_pkce_state_nonce():
    login = HostedLogin(domain="acme.login.touchque.com", client_id=CLIENT, redirect_uri="https://app/cb", audience="https://api.acme.test")
    req = login.authorization_url(screen_hint="signup", ui_locales="tr")
    q = {k: v[0] for k, v in parse_qs(urlsplit(req.url).query).items()}
    assert req.url.startswith(f"{ISSUER}/authorize?")
    assert q["code_challenge"] == b64u(hashlib.sha256(req.code_verifier.encode()).digest())
    assert q["code_challenge_method"] == "S256"
    assert q["state"] == req.state and q["nonce"] == req.nonce
    assert q["audience"] == "https://api.acme.test" and q["screen_hint"] == "signup" and q["ui_locales"] == "tr"


def test_callback_refresh_and_access_token():
    fake = FakeTenant()
    login = make(fake, client_secret="s3cret")
    req = login.authorization_url()
    got = fake.authorize(req.url)
    tokens = login.handle_callback(f"https://app/cb?code={got['code']}&state={got['state']}&iss={ISSUER}", req.state, req.nonce, req.code_verifier)
    assert tokens.claims["sub"] == "usr_1" and tokens.claims["email"] == "a@acme.test"
    assert tokens.refresh_token == "tqr_1"
    assert fake.posts[0]["auth"] == (CLIENT, "s3cret")
    assert login.refresh("tqr_1").refresh_token == "tqr_2"
    claims = login.verify_access_token(tokens.access_token, audience="https://api.acme.test", required_scopes=["read:orders"])
    assert claims["sub"] == "usr_1"
    with pytest.raises(HostedLoginError):
        login.verify_access_token(tokens.access_token, audience="https://other")
    with pytest.raises(HostedLoginError) as e:
        login.verify_access_token(tokens.access_token, audience="https://api.acme.test", required_scopes=["write:orders"])
    assert e.value.code == "insufficient_scope"
    with pytest.raises(HostedLoginError):
        login.verify_access_token(tokens.id_token, audience=CLIENT)


def test_refusals():
    fake = FakeTenant()
    login = make(fake)
    req = login.authorization_url()
    got = fake.authorize(req.url)
    for params, code in [
        ({"code": got["code"], "state": "other"}, "state_mismatch"),
        ({"error": "access_denied", "state": req.state}, "access_denied"),
        ({"code": got["code"], "state": req.state, "iss": "https://evil"}, "issuer_mismatch"),
    ]:
        with pytest.raises(HostedLoginError) as e:
            login.handle_callback(params, req.state, req.nonce, req.code_verifier)
        assert e.value.code == code
    bad = FakeTenant(nonce_override="replayed")
    l2 = make(bad)
    r2 = l2.authorization_url()
    with pytest.raises(HostedLoginError) as e:
        l2.handle_callback(bad.authorize(r2.url), r2.state, r2.nonce, r2.code_verifier)
    assert e.value.code == "nonce_mismatch"
    forged = FakeTenant(sign_with=OTHER)
    l3 = make(forged)
    r3 = l3.authorization_url()
    with pytest.raises(HostedLoginError, match="signature"):
        l3.handle_callback(forged.authorize(r3.url), r3.state, r3.nonce, r3.code_verifier)


def test_iss_this_issuer_or_none_accepted_foreign_or_empty_refused_before_the_exchange():
    fake = FakeTenant()
    login = make(fake)
    req = login.authorization_url()
    got = fake.authorize(req.url)
    for iss in ["https://evil", "https://acme.login.touchque.com.evil", ISSUER + "/", ""]:
        with pytest.raises(HostedLoginError) as e:
            login.handle_callback({"code": got["code"], "state": req.state, "iss": iss}, req.state, req.nonce, req.code_verifier)
        assert e.value.code == "issuer_mismatch"
    with pytest.raises(HostedLoginError) as e:
        login.handle_callback("https://app/cb?code=c&iss=&state=" + req.state, req.state, req.nonce, req.code_verifier)
    assert e.value.code == "issuer_mismatch"
    # A foreign error answer is reported as the issuer mismatch, not as its own error.
    with pytest.raises(HostedLoginError) as e:
        login.handle_callback({"error": "access_denied", "state": req.state, "iss": "https://evil"}, req.state, req.nonce, req.code_verifier)
    assert e.value.code == "issuer_mismatch"
    assert fake.posts == []
    assert login.handle_callback({"code": got["code"], "state": req.state, "iss": ISSUER}, req.state, req.nonce, req.code_verifier).claims["sub"] == "usr_1"
    older = login.authorization_url()
    got = fake.authorize(older.url)
    tokens = login.handle_callback(f"https://app/cb?code={got['code']}&state={got['state']}", older.state, older.nonce, older.code_verifier)
    assert tokens.claims["sub"] == "usr_1"


def test_a_plaintext_issuer_only_on_this_machine():
    from touchque import MyAccount, MyAccountError
    for domain in ("http://acme.login.touchque.com", "http://10.0.0.5:8080", "http://localhost.evil.com"):
        with pytest.raises(HostedLoginError) as e:
            HostedLogin(domain=domain, client_id=CLIENT)
        assert e.value.code == "config"
        with pytest.raises(MyAccountError):
            MyAccount(domain, "at")
    for domain in ("http://localhost:3000", "http://127.0.0.1:5000", "http://[::1]:5000", "http://acme.login.localhost:8080/"):
        assert HostedLogin(domain=domain, client_id=CLIENT).issuer == domain.rstrip("/")
    assert HostedLogin(domain="acme.login.touchque.com", client_id=CLIENT).issuer == ISSUER


def test_logout_url():
    login = HostedLogin(domain=ISSUER, client_id=CLIENT)
    q = parse_qs(urlsplit(login.logout_url(id_token_hint="h", post_logout_redirect_uri="https://app/")).query)
    assert q["id_token_hint"] == ["h"] and q["post_logout_redirect_uri"] == ["https://app/"]


class FakeAgentTenant:
    def __init__(self):
        self.posts = []
        self.polls = 0

    def post(self, url, data=None, headers=None, auth=None, timeout=None):
        self.posts.append({"url": url, "data": data, "auth": auth})
        if url.endswith("/bc-authorize"):
            return Res(200, {"auth_req_id": "req-1", "expires_in": 300, "interval": 0, "binding_code": "42"})
        if data.get("requested_token_type") == "urn:touchque:params:oauth:token-type:connection-access-token":
            return Res(200, {"access_token": "ya29.g", "token_type": "Bearer", "expires_in": 3500, "scope": "openid email", "connection": data["connection"]})
        if data["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange":
            return Res(200, {"access_token": "at-x", "token_type": "Bearer", "expires_in": 120, "scope": "payments:create", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"})
        if data["grant_type"] == "urn:openid:params:grant-type:ciba":
            self.polls += 1
            if self.polls == 1:
                return Res(400, {"error": "authorization_pending"})
            if data["auth_req_id"] == "denied":
                return Res(400, {"error": "access_denied"})
            return Res(200, {"access_token": "at-c", "token_type": "Bearer", "expires_in": 300, "scope": "payments:create", "authorization_details": [{"type": "payment_initiation"}]})
        return Res(400, {"error": "unsupported_grant_type"})


def test_exchange_token_and_ciba():
    fake = FakeAgentTenant()
    login = make(fake, client_secret="s3cret")
    ex = login.exchange_token("user-at", audience="https://api.acme.test", scope="payments:create")
    assert ex.access_token == "at-x" and ex.issued_token_type.endswith(":access_token")
    assert fake.posts[0]["data"]["subject_token"] == "user-at" and fake.posts[0]["auth"] == (CLIENT, "s3cret")
    ask = login.ask_user("ada@acme.test", "openid payments:create", binding_message="Pay invoice 42", authorization_details=[{"type": "payment_initiation"}])
    assert ask.auth_req_id == "req-1" and ask.binding_code == "42"
    assert json.loads(fake.posts[1]["data"]["authorization_details"]) == [{"type": "payment_initiation"}]
    approved = login.wait_for_user(ask)
    assert approved.access_token == "at-c" and approved.authorization_details == [{"type": "payment_initiation"}]
    fake.polls = 0
    ask.auth_req_id = "denied"
    with pytest.raises(HostedLoginError) as e:
        login.wait_for_user(ask)
    assert e.value.code == "access_denied"
    vaulted = login.get_connection_token("user-at", "google", scope="email")
    assert vaulted.access_token == "ya29.g" and vaulted.connection == "google"
    assert fake.posts[-1]["data"]["requested_token_type"] == CONNECTION_TOKEN_TYPE and "audience" not in fake.posts[-1]["data"]
