from typing import Any, Dict, Optional

from .config import Config
from .http_client import HttpClient
from .resources.action_types import ActionTypes
from .resources.actions import Actions
from .resources.agents import Agents
from .resources.identity import Identity
from .resources.auth import Auth
from .resources.login import Login
from .resources.offline import Offline
from .resources.risk import Risk
from .resources.recovery import Recovery
from .resources.mobile import Mobile
from .resources.qr_pairings import QrPairings
from .resources.device_risk import DeviceRisk
from .resources.safe_guard import SafeGuard
from .resources.assist import Assist
from .resources.webauthn import WebAuthn
from .resources.webhook import Webhook
from .steps import LoginDetails, check as _check, complete as _complete, start as _start


class Touchque:
    """
    Touchque SDK client.

        # .env: TQ_API_KEY=tq_...  TQ_API_SECRET=...
        client = Touchque()                                   # from the environment
        client = Touchque(Config(api_key=..., api_secret=...))  # explicit

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
        #: Action types: what users approve (LOGIN, SEND_MONEY…). Was ``actions`` before 4.0.
        self.action_types = ActionTypes(http)
        #: Touchque Actions: your own code in the approval pipeline.
        self.actions = Actions(http)
        #: Silent sign-ins: should this sign-in ask the phone, and which browsers Touchque knows.
        self.risk = Risk(http)
        #: Never Locked Out: move a user whose phone is gone to a new phone, with colleagues vouching.
        self.recovery = Recovery(http)
        #: Help desk: IT working on a person's account in the open, and checks on their phone before sensitive actions.
        self.assist = Assist(http)
        #: AI agents as identities of their own: register (public key), suspend, revoke, kill switch.
        #: The agent itself uses ``touchque.TouchqueAgent``.
        self.agents = Agents(http)
        # Touchque Login Management API: customers' accounts, roles, organizations, apps
        self.identity = Identity(http)
        #: Mobile SDK: your own iOS/Android app approves for your users (enrollment tokens, devices, settings).
        self.mobile = Mobile(http)
        #: Pairing a browser by QR code: the phone that scans it is the one asked to approve.
        self.qr_pairings = QrPairings(http)
        #: Device risk: the device on your sign-up, reset, sign-in or approval page (a paid add-on).
        self.device_risk = DeviceRisk(http)
        #: Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard.
        self.safe_guard = SafeGuard(http)

    # ── headless step-up (see touchque.steps / touchque.guard) ─────────────

    def start(self, action: str, user: str, details: Optional[LoginDetails] = None,
              reference_id: Optional[str] = None, ip: Optional[str] = None,
              user_agent: Optional[str] = None, browser_proof: Optional[str] = None) -> Dict[str, Any]:
        """Starts an approval and returns immediately — show the step in your
        UI. ``waiting`` + ``number``: show the number, the user picks it on
        the phone. ``enroll``: show ``enroll['qrCodeDataUrl']`` so the user
        links the Touchque app first. ``browser_proof``: the browser's
        ``X-Touchque-Browser`` proof, so the approval makes the browser known
        (silent sign-ins, see ``risk.check``)."""
        return _start(self, action, user, details=details, reference_id=reference_id, ip=ip, user_agent=user_agent,
                      browser_proof=browser_proof)

    def check(self, request_id: str) -> Dict[str, Any]:
        """Where a started approval is now: waiting, approved, rejected, expired…"""
        return _check(self, request_id)

    def complete(self, request_id: str, user: str, action: str, details: Optional[LoginDetails] = None,
                 reference_id: Optional[str] = None) -> Dict[str, Any]:
        """Uses an approved request exactly once, after checking it is for
        this user, action and transaction. Call it right before doing the
        protected thing."""
        return _complete(self, request_id, user, action, details=details, reference_id=reference_id)


_default_client: Optional[Touchque] = None


def get_default_client() -> Touchque:
    """The client built from TQ_API_KEY / TQ_API_SECRET, created on first use."""
    global _default_client
    if _default_client is None:
        _default_client = Touchque()
    return _default_client
