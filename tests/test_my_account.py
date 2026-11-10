"""My Account API client: the refresh-token trade for a /me/ token, calls with
it, and the RFC 9470 step-up answer, against an in-process fake tenant."""

import json

import pytest

from touchque import HostedLogin, MyAccountError

ISSUER = "https://acme.login.touchque.com"


class Res:
    def __init__(self, status, body, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class Fake:
    def __init__(self):
        self.calls = []

    def post(self, url, data=None, headers=None, auth=None, timeout=None):
        self.calls.append(("POST", url, data, headers))
        return Res(200, {"access_token": "me-at", "token_type": "Bearer", "expires_in": 600, "scope": data["scope"], "refresh_token": "tqr_2"})

    def request(self, method, url, headers=None, json=None, timeout=None):
        self.calls.append((method, url, json, headers))
        if url.endswith("/me/v1/profile") and method == "PATCH":
            return Res(200, {"id": "usr_1", **json})
        if url.endswith("/me/v1/sessions/s%201"):
            return Res(204, None)
        if url.endswith("/me/v1") and method == "DELETE":
            return Res(401, {"error": "insufficient_user_authentication", "error_description": "A more recent sign-in is required"},
                       {"WWW-Authenticate": 'Bearer error="insufficient_user_authentication", max_age="600"'})
        return Res(404, {"error": "not_found"})


def test_trade_and_calls():
    fake = Fake()
    login = HostedLogin(domain="acme.login.touchque.com", client_id="c1", session=fake)
    me = login.my_account_token("tqr_1", scope="read:me update:me")
    assert me.access_token == "me-at" and me.refresh_token == "tqr_2"
    assert fake.calls[0][2]["audience"] == f"{ISSUER}/me/"
    account = login.my_account(me.access_token)
    assert account.update_profile(name="Zoë", user_metadata={"theme": "dark"}) == {"id": "usr_1", "name": "Zoë", "userMetadata": {"theme": "dark"}}
    assert fake.calls[1][3]["Authorization"] == "Bearer me-at"
    assert account.end_session("s 1") is None
    assert login.account_url("devices") == f"{ISSUER}/account/devices"


def test_step_up_error():
    account = HostedLogin(domain=ISSUER, client_id="c1", session=Fake()).my_account("old")
    with pytest.raises(MyAccountError) as e:
        account.delete_account()
    assert e.value.step_up and e.value.max_age == 600 and e.value.status == 401
