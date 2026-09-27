from unittest.mock import MagicMock

from touchque.resources.auth import Auth


def test_generate_secret_posts_expected_payload():
    http = MagicMock()
    http.post.return_value = {"secret": "s", "externalUsername": "a@b.com"}
    auth = Auth(http)

    result = auth.generate_secret("a@b.com")

    http.post.assert_called_once_with("/auth/generate-secret", {"externalUsername": "a@b.com"})
    assert result["secret"] == "s"


def test_reset_secret_posts_expected_payload():
    http = MagicMock()
    http.post.return_value = {"secret": "new"}
    auth = Auth(http)

    auth.reset_secret("a@b.com")

    http.post.assert_called_once_with("/auth/secret/reset", {"externalUsername": "a@b.com"})


def test_validate_secret_posts_expected_payload():
    http = MagicMock()
    http.post.return_value = {"valid": True}
    auth = Auth(http)

    result = auth.validate_secret("123456")

    http.post.assert_called_once_with("/auth/secret/validate", {"secret": "123456"})
    assert result["valid"] is True


def test_get_user_gets_expected_path():
    http = MagicMock()
    http.get.return_value = {"externalUsername": "a@b.com", "used": False, "deviceId": None}
    auth = Auth(http)

    result = auth.get_user("a+x@b.com")

    http.get.assert_called_once_with("/users/a%2Bx%40b.com")
    assert result["used"] is False
