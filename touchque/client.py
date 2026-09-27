from typing import Any, Dict, Optional

from .config import Config
from .http_client import HttpClient
from .resources.actions import Actions
from .resources.auth import Auth
from .resources.login import Login
from .resources.offline import Offline
from .resources.webauthn import WebAuthn
from .resources.webhook import Webhook
from .steps import LoginDetails, check as _check, complete as _complete, start as _start


class TouchQue:
    """
    TouchQue SDK client.

        # .env: TQ_API_KEY=tq_...  TQ_API_SECRET=...
        client = TouchQue()                                   # from the environment
        client = TouchQue(Config(api_key=..., api_secret=...))  # explicit

    One line per protected route (see ``touchque.contrib`` for Django /
    FastAPI / Flask adapters, or call ``client.start`` / ``client.check`` /
    ``client.complete`` yourself for any framework).
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._api_secret = self.config.api_secret
        http = HttpClient(self.config)

        self.auth = Auth(http)
        self.login = Login(http)
        self.webauthn = WebAuthn(http)
        self.webhook = Webhook(self.config)
        self.offline = Offline(http)
        self.actions = Actions(http)

    # ── headless step-up (see touchque.steps / touchque.guard) ─────────────

    def start(self, action: str, user: str, details: Optional[LoginDetails] = None,
              reference_id: Optional[str] = None, ip: Optional[str] = None,
              user_agent: Optional[str] = None) -> Dict[str, Any]:
        """Starts an approval and returns immediately — show the step in your
        UI. ``waiting`` + ``number``: show the number, the user picks it on
        the phone. ``enroll``: show ``enroll['qrCodeDataUrl']`` so the user
        links the TouchQue app first."""
        return _start(self, action, user, details=details, reference_id=reference_id, ip=ip, user_agent=user_agent)

    def check(self, request_id: str) -> Dict[str, Any]:
        """Where a started approval is now: waiting, approved, rejected, expired…"""
        return _check(self, request_id)

    def complete(self, request_id: str, user: str, action: str, details: Optional[LoginDetails] = None,
                 reference_id: Optional[str] = None) -> Dict[str, Any]:
        """Uses an approved request exactly once, after checking it is for
        this user, action and transaction. Call it right before doing the
        protected thing."""
        return _complete(self, request_id, user, action, details=details, reference_id=reference_id)


_default_client: Optional[TouchQue] = None


def get_default_client() -> TouchQue:
    """The client built from TQ_API_KEY / TQ_API_SECRET, created on first use."""
    global _default_client
    if _default_client is None:
        _default_client = TouchQue()
    return _default_client
