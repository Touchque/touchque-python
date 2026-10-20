from typing import Optional, Dict, Any


class TouchQueException(Exception):
    def __init__(self, message: str, data: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.data = data


class TouchQueAPIException(TouchQueException):
    """Raised when the API returns an error response (status >= 400)."""

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        code: Optional[str] = None,
        reason: Optional[str] = None,
        attempts_left: Optional[int] = None,
        retry_after: Optional[int] = None,
        data: Optional[Dict[str, Any]] = None,
        case_code: Optional[str] = None,
    ):
        super().__init__(message, data=data)
        #: HTTP status code (e.g. 404, 429, 423).
        self.status = status
        #: Machine-readable error code (e.g. "device_not_linked", "unknown_action").
        self.code = code
        #: Offline sign: why a code was not approved.
        self.reason = reason
        #: Offline sign: wrong codes left before the challenge locks.
        self.attempts_left = attempts_left
        #: Seconds to wait before retrying (429 / 423).
        self.retry_after = retry_after
        #: "Why?" case code of a refusal (``K7P-2QX``): show it to the user
        #: ("Tell your support team: K7P-2QX"); your team opens the decision by it
        #: in the dashboard. ``None`` for other errors.
        self.case_code = case_code


class TouchQueNetworkException(TouchQueException):
    """Raised when the request never reached the API (DNS, connection, timeout)."""
    pass


class TouchQueTimeoutException(TouchQueException):
    """Raised when a polling operation (like login.verify) times out."""
    pass


class TouchQueRejectedException(TouchQueException):
    """Raised when a request is explicitly rejected by the user."""
    pass


class TouchQueWebhookSignatureException(TouchQueException):
    """Raised when an incoming webhook signature is invalid."""
    pass


class TouchQueWebhookReplayException(TouchQueWebhookSignatureException):
    """
    Raised when a correctly signed webhook with this ``jti`` was already
    accepted. Usually a TouchQue retry of a delivery you processed: answer
    200 so it stops, but don't run your side effects again.
    """

    def __init__(self, jti: str):
        super().__init__("Webhook was already accepted (replayed jti)")
        self.jti = jti


class TouchQueConfigException(TouchQueException):
    """Raised when configuration is invalid or incomplete."""
    pass


class TouchQuePasskeyRequiredError(TouchQueException):
    """Raised when the request must be approved with a passkey.

    ``reason`` is ``'policy'`` when a phishing-resistant policy requires it (no
    push was sent), or ``'step_up'`` when the user tapped Approve on the phone
    during a call (Vishing Shield) and the request, still open, now waits for
    a passkey in the browser."""

    def __init__(self, request_id: str, reason: str = 'policy'):
        if reason == 'step_up':
            message = (f"TouchQue: request '{request_id}' must now be approved with a passkey: "
                       "the user approved on the phone during a call.")
        else:
            message = (f"TouchQue: request '{request_id}' must be approved with a passkey "
                       "(phishing-resistant policy); no push was sent.")
        super().__init__(message)
        self.request_id = request_id
        self.reason = reason
