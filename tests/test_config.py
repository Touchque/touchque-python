import pytest
from touchque.config import Config
from touchque.exceptions import TouchQueConfigException


def test_valid_config_is_accepted():
    config = Config(api_key="tq_auth_test123", api_secret="shh")
    assert config.api_key == "tq_auth_test123"
    assert config.base_url == "https://api.touchque.com"
    assert config.timeout == 10000


def test_apikey_not_starting_with_tq_raises():
    with pytest.raises(TouchQueConfigException):
        Config(api_key="wrong_prefix", api_secret="shh")


def test_custom_base_url_and_timeout_are_honored_and_trailing_slash_stripped():
    config = Config(api_key="tq_auth_x", api_secret="shh", base_url="http://localhost:9999/", timeout=5000)
    assert config.base_url == "http://localhost:9999"
    assert config.timeout == 5000


def test_refuses_plaintext_http_to_a_non_localhost_host():
    with pytest.raises(TouchQueConfigException):
        Config(api_key="tq_auth_x", api_secret="shh", base_url="http://api.example.com")


def test_allows_plaintext_http_only_for_loopback():
    assert Config(api_key="tq_auth_x", api_secret="shh", base_url="http://127.0.0.1:9999").base_url
    assert Config(api_key="tq_auth_x", api_secret="shh", base_url="https://api.example.com").base_url


def test_rejects_a_non_http_scheme():
    with pytest.raises(TouchQueConfigException):
        Config(api_key="tq_auth_x", api_secret="shh", base_url="ftp://api.touchque.com")
