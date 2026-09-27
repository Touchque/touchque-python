import os
from urllib.parse import urlparse

from .exceptions import TouchQueConfigException

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_BASE_URL = "https://api.touchque.com"


def _assert_safe_base_url(base_url: str) -> None:
    """Allow plaintext http only for localhost / loopback (local development)."""
    parsed = urlparse(base_url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and (parsed.hostname or "").lower() in _LOCAL_HOSTS:
        return
    if parsed.scheme == "http":
        raise TouchQueConfigException(
            f'Refusing a plaintext http:// base_url for "{parsed.hostname}". '
            "The API key and request signature would be sent in the clear — use https://."
        )
    raise TouchQueConfigException(f"base_url must be http(s): {base_url}")


class Config:
    def __init__(
        self,
        api_key: str = None,
        api_secret: str = None,
        base_url: str = None,
        timeout: int = 10000,
    ):
        """
        Falls back to the environment when an argument is omitted:
        ``TQ_API_KEY``, ``TQ_API_SECRET``, ``TQ_API_URL`` (default
        ``https://api.touchque.com``).
        """
        api_key = api_key if api_key is not None else os.environ.get("TQ_API_KEY")
        api_secret = api_secret if api_secret is not None else os.environ.get("TQ_API_SECRET")
        base_url = base_url if base_url is not None else os.environ.get("TQ_API_URL", DEFAULT_BASE_URL)

        if not api_key or not api_secret:
            raise TouchQueConfigException(
                "Set TQ_API_KEY and TQ_API_SECRET (or pass api_key=/api_secret=)."
            )
        if not api_key.startswith('tq_'):
            raise TouchQueConfigException(
                'api_key must start with "tq_". Did you accidentally swap api_key and api_secret?'
            )

        _assert_safe_base_url(base_url)

        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
