import sys
from typing import Dict, Any, Optional
from urllib.parse import quote
from ..http_client import HttpClient

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:  # pragma: no cover - Python 3.7 has no typing.TypedDict: the same names, as dict subclasses
    TypedDict = dict


class SetupLocation(TypedDict):
    """Where a first-time linking QR was asked for, from its IP address
    (GeoIP). Each is ``None`` when unknown."""
    city: Optional[str]
    country: Optional[str]
    #: ISO 3166-1 alpha-2, e.g. ``'DE'``.
    countryCode: Optional[str]


class SetupDevice(TypedDict):
    """The browser that asked for a first-time linking QR, from its
    User-Agent. Each is ``None`` when unknown."""
    browser: Optional[str]  # e.g. 'Safari', 'Chrome'
    os: Optional[str]  # e.g. 'iOS', 'Windows'
    model: Optional[str]  # e.g. 'iPhone'


class SetupContext(TypedDict):
    """2FA setup context: where a first-time linking QR was asked for, as the
    phone shows it before it links (``validate_secret``'s ``setupContext``).
    The Touchque API records it from the request that made the QR
    (``generate_secret``, or ``reset_secret`` for a new one), never in the
    QR. Every key is there; any value may be ``None``."""
    #: The browser's IP address as the phone shows it.
    ip: Optional[str]
    location: Optional[SetupLocation]
    device: Optional[SetupDevice]
    #: When the QR was asked for: ISO 8601, as the API sent it (not parsed).
    requestedAt: Optional[str]
    #: Whether that place is far from the address that checks the QR (``POST /auth/secret/validate``): the
    #: phone's when the phone checks it, your server's when your server calls ``validate_secret``. ``None``
    #: when Touchque cannot tell.
    farFromPhone: Optional[bool]


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def parse_setup_context(raw: Any) -> Optional[SetupContext]:
    """Reads the ``setupContext`` of a ``POST /auth/secret/validate`` answer,
    leniently, never raising: ``None`` when it is missing, ``None`` or not a
    JSON object. Otherwise all five keys, each ``None`` when it is missing,
    ``None`` or of the wrong type: ``ip`` and ``requestedAt`` only strings,
    ``farFromPhone`` only a boolean, ``location`` and ``device`` only objects
    (with their three keys, strings or ``None``, the same way). Unknown keys
    are dropped."""
    if not isinstance(raw, dict):
        return None
    location, device, far = raw.get('location'), raw.get('device'), raw.get('farFromPhone')
    return {
        'ip': _text(raw.get('ip')),
        'location': {
            'city': _text(location.get('city')),
            'country': _text(location.get('country')),
            'countryCode': _text(location.get('countryCode')),
        } if isinstance(location, dict) else None,
        'device': {
            'browser': _text(device.get('browser')),
            'os': _text(device.get('os')),
            'model': _text(device.get('model')),
        } if isinstance(device, dict) else None,
        'requestedAt': _text(raw.get('requestedAt')),
        'farFromPhone': far if isinstance(far, bool) else None,
    }


def _with_browser(body: Dict[str, Any], client_ip: Optional[str], user_agent: Optional[str]) -> Dict[str, Any]:
    """Adds the browser's IP address and User-Agent, each only when given (not None or empty), as it is."""
    if client_ip:
        body['clientIp'] = client_ip
    if user_agent:
        body['userAgent'] = user_agent
    return body


class Auth:
    def __init__(self, http: HttpClient):
        self._http = http

    def generate_secret(self, external_username: str, *, client_ip: Optional[str] = None,
                        user_agent: Optional[str] = None) -> Dict[str, Any]:
        """Generate a new setup secret for a user: the first-time linking QR
        (``qrCodeDataUrl``) and its recovery codes.

        ``client_ip`` / ``user_agent``: the IP address and User-Agent of the
        browser asking for the QR, as you pass them to ``login.request``; each
        is sent only when given (not ``None`` or empty), as it is. The
        Touchque API records where the QR was asked for (never in the QR) and
        the phone shows it before it links (``validate_secret``'s
        ``setupContext``), so a person tricked into scanning someone else's QR
        sees that place and device. The API keeps what it can use (a port is
        dropped, a loopback address or one that is not an IP address is
        ignored, the User-Agent loses its control characters and is cut at 512
        characters) and never refuses the request for them; with neither kept,
        the QR has no setup context. ``reset_secret`` records its new QR's the
        same way. The relay and the guard send them for you::

            tq.auth.generate_secret(user, client_ip=request.remote_addr,
                                    user_agent=request.headers.get('User-Agent'))
        """
        return self._http.post('/auth/generate-secret', _with_browser(
            {'externalUsername': external_username}, client_ip, user_agent))

    def reset_secret(self, external_username: str, *, client_ip: Optional[str] = None,
                     user_agent: Optional[str] = None) -> Dict[str, Any]:
        """Reset (regenerate) a user's secret.

        ``client_ip`` / ``user_agent``: the browser asking for the new QR,
        sent like ``generate_secret``'s (each only when given). The Touchque
        API records them with the new QR as ``generate_secret`` does; a reset
        without them leaves the new QR with no setup context
        (``validate_secret``'s ``setupContext`` is ``None``), not the old
        QR's."""
        return self._http.post('/auth/secret/reset', _with_browser(
            {'externalUsername': external_username}, client_ip, user_agent))

    def validate_secret(self, secret: str) -> Dict[str, Any]:
        """Validate a setup secret code: ``POST /auth/secret/validate``, the
        phone's public call after scanning the QR. The phone makes it itself;
        your server does not need it for the phone to show where the QR was
        asked for.

        The answer's ``setupContext`` (a ``SetupContext``) is where the QR was
        asked for, as the phone shows it before it links, or ``None``: the
        request that made the QR (``generate_secret``, or ``reset_secret`` for
        a new one) named neither a usable IP address nor a User-Agent, the QR
        is older, or the API predates it. As the phone gets it::

            {'ip': '203.0.113.7',
             'location': {'city': 'Berlin', 'country': 'Germany', 'countryCode': 'DE'},
             'device': {'browser': 'Safari', 'os': 'iOS', 'model': 'iPhone'},
             'requestedAt': '2026-11-16T09:30:00.000Z',
             'farFromPhone': True}

        ``farFromPhone`` compares that place with the address that makes this
        call: called from your server, it compares with your server, not the
        phone. Any value in ``setupContext`` may be ``None`` (``location`` and
        ``device`` too); one of the wrong type is read as ``None``
        (``parse_setup_context``), never an error. The rest of the answer is
        as the API sent it."""
        res = self._http.post('/auth/secret/validate', {
            'secret': secret
        })
        if not isinstance(res, dict):
            return res
        return {**res, 'setupContext': parse_setup_context(res.get('setupContext'))}

    def get_user(self, external_username: str) -> Dict[str, Any]:
        """
        Look up a user's link status without sending a push. Useful while
        polling during enrollment: ``used`` flips true and ``deviceId`` is set
        once the mobile app scans the setup secret.

        Returns ``{ externalUsername, deviceId, used, frozen, createdAt, expireAt, device }``.
        Raises ``TouchqueAPIException`` (404) if the user is unknown.

        ``device`` is the linked phone's posture for device trust, or ``None`` before a
        phone is linked. It is self-reported by the Touchque app::

            {
              "platform": "ios" | "android" | None,
              "model": str | None,             # e.g. "iPhone15,3"
              "osVersion": str | None,         # e.g. "18.1"
              "securityPatch": str | None,     # Android "YYYY-MM-DD", None on iOS
              "appVersion": str | None,
              "screenLock": bool | None,
              "biometrics": "face" | "touch" | "fingerprint" | "iris" | "none" | None,
              "jailbroken": bool,              # jailbroken or rooted, by the app's checks
              "compromised": bool,             # jailbroken/rooted or tampered (sticky for a cool-down)
              "hardwareKey": bool,             # approvals are signed by a Secure Enclave / Keystore key
              "attestation": "apple-appattest" | "android-key" | None,
              "signed": bool,                  # the latest report was signed by the hardware key
              "reportedAt": str | None,        # ISO date-time of the latest report
              "lastSeenAt": str | None,
              "linkedAt": str | None,
              "state": "healthy" | "at_risk" | "compromised" | "unknown",
              "issues": [str],                 # jailbroken, tampered, integrity_failed, no_report,
                                               # stale_report, no_screen_lock, keys_lost,
                                               # no_hardware_key, debugger, developer_mode
            }
        """
        return self._http.get(f"/users/{quote(external_username, safe='')}")
