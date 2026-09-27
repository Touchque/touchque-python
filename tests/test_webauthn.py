from unittest.mock import MagicMock

from touchque.resources.webauthn import WebAuthn


def make():
    http = MagicMock()
    return http, WebAuthn(http)


def test_register_options_sends_discoverable_only_when_true():
    http, wa = make()
    http.post.return_value = {"challenge": "c"}
    wa.register_options("a@b.com")
    http.post.assert_called_once_with("/webauthn/register/options", {"externalUsername": "a@b.com"})

    http.post.reset_mock()
    wa.register_options("a@b.com", discoverable=True)
    http.post.assert_called_once_with("/webauthn/register/options", {"externalUsername": "a@b.com", "discoverable": True})


def test_register_verify_sends_label_only_when_present():
    http, wa = make()
    http.post.return_value = {"verified": True, "credentialId": "cred_1"}
    r = wa.register_verify("a@b.com", {"id": "x"}, label="MacBook")
    http.post.assert_called_once_with(
        "/webauthn/register/verify",
        {"externalUsername": "a@b.com", "response": {"id": "x"}, "label": "MacBook"},
    )
    assert r["credentialId"] == "cred_1"


def test_authenticate_options_and_verify():
    http, wa = make()
    http.post.return_value = {"challenge": "c"}
    wa.authenticate_options("req_1")
    http.post.assert_called_once_with("/webauthn/login/options", {"requestId": "req_1"})

    http.post.reset_mock()
    http.post.return_value = {"success": True, "message": "ok"}
    wa.authenticate_verify("req_1", {"id": "a"})
    http.post.assert_called_once_with("/webauthn/login/verify", {"requestId": "req_1", "response": {"id": "a"}})


def test_primary_options_and_verify():
    http, wa = make()
    http.post.return_value = {"attemptId": "att_1", "options": {}}
    r = wa.primary_options("a@b.com")
    http.post.assert_called_once_with("/webauthn/authenticate/primary/options", {"externalUsername": "a@b.com"})
    assert r["attemptId"] == "att_1"

    http.post.reset_mock()
    http.post.return_value = {"success": False, "requiresStepUp": True, "externalUsername": "a@b.com", "riskScore": 0.95}
    r = wa.primary_verify("att_1", {"id": "a"})
    http.post.assert_called_once_with("/webauthn/authenticate/primary/verify", {"attemptId": "att_1", "response": {"id": "a"}})
    assert r["requiresStepUp"] is True


def test_list_credentials_passes_query_param():
    http, wa = make()
    http.get.return_value = {"credentials": [{"id": "c1"}]}
    r = wa.list_credentials("a@b.com")
    http.get.assert_called_once_with("/webauthn/credentials", params={"externalUsername": "a@b.com"})
    assert r["credentials"][0]["id"] == "c1"


def test_delete_credential_url_encodes_id():
    http, wa = make()
    http.delete.return_value = {"deleted": True}
    r = wa.delete_credential("cred/1 2")
    http.delete.assert_called_once_with("/webauthn/credentials/cred%2F1%202")
    assert r["deleted"] is True
