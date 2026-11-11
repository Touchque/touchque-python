from typing import Optional, Dict, Any


class TouchqueException(Exception):
    def __init__(self, message: str, data: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.data = data


class TouchqueAPIException(TouchqueException):
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


class TouchqueFeatureException(TouchqueAPIException):
    """The organization behind your workspace cannot use this feature here (HTTP 403).

    ``reason``:

    - ``not_in_plan`` -- not in its plan (``feature_not_in_plan``): an owner or
      admin adds it in the Touchque dashboard;
    - ``read_only`` -- being turned off (``feature_read_only``): reads still work
      for 14 days, changes are refused;
    - ``off`` -- switched off on this Touchque deployment (``feature_off``).

    ``feature`` is the catalog id (``device_risk``, ``ai_agents``, ``mobile_sdk``,
    ``ciam``...). A subclass of TouchqueAPIException, so existing ``except``
    blocks still catch it; catch one of the three subclasses to tell them apart.
    """

    reason_code = ''

    def __init__(self, message: str, **kwargs: Any):
        super().__init__(message, **kwargs)
        data = self.data or {}
        #: The catalog id of the feature (``device_risk``...), or None.
        self.feature: Optional[str] = data.get('feature') if isinstance(data.get('feature'), str) else None
        #: ``not_in_plan``, ``read_only`` or ``off``.
        self.feature_reason = self.reason_code


class TouchqueFeatureNotInPlanException(TouchqueFeatureException):
    """``feature_not_in_plan``: the feature is not in the organization's plan."""
    reason_code = 'not_in_plan'


class TouchqueFeatureReadOnlyException(TouchqueFeatureException):
    """``feature_read_only``: the feature is being turned off; reads work, changes are refused."""
    reason_code = 'read_only'


class TouchqueFeatureOffException(TouchqueFeatureException):
    """``feature_off``: the feature is switched off on this Touchque deployment."""
    reason_code = 'off'


_FEATURE_ERRORS = {
    'feature_not_in_plan': TouchqueFeatureNotInPlanException,
    'feature_read_only': TouchqueFeatureReadOnlyException,
    'feature_off': TouchqueFeatureOffException,
}


def api_exception(message: str, **kwargs: Any) -> TouchqueAPIException:
    """The exception for an error answer: a feature exception for the three feature codes, else TouchqueAPIException."""
    data = kwargs.get('data') or {}
    cls = _FEATURE_ERRORS.get(data.get('error')) if isinstance(data, dict) else None
    return (cls or TouchqueAPIException)(message, **kwargs)


class TouchqueNetworkException(TouchqueException):
    """Raised when the request never reached the API (DNS, connection, timeout)."""
    pass


class TouchqueTimeoutException(TouchqueException):
    """Raised when a polling operation (like login.verify) times out."""
    pass


class TouchqueRejectedException(TouchqueException):
    """Raised when a request is explicitly rejected by the user."""
    pass


class TouchqueWebhookSignatureException(TouchqueException):
    """Raised when an incoming webhook signature is invalid."""
    pass


class TouchqueWebhookReplayException(TouchqueWebhookSignatureException):
    """
    Raised when a correctly signed webhook with this ``jti`` was already
    accepted. Usually a Touchque retry of a delivery you processed: answer
    200 so it stops, but don't run your side effects again.
    """

    def __init__(self, jti: str):
        super().__init__("Webhook was already accepted (replayed jti)")
        self.jti = jti


class TouchqueConfigException(TouchqueException):
    """Raised when configuration is invalid or incomplete."""
    pass


class TouchquePasskeyRequiredError(TouchqueException):
    """Raised when the request must be approved with a passkey.

    ``reason`` is ``'policy'`` when a phishing-resistant policy requires it (no
    push was sent), or ``'step_up'`` when the user tapped Approve on the phone
    during a call (Vishing Shield) and the request, still open, now waits for
    a passkey in the browser."""

    def __init__(self, request_id: str, reason: str = 'policy'):
        if reason == 'step_up':
            message = (f"Touchque: request '{request_id}' must now be approved with a passkey: "
                       "the user approved on the phone during a call.")
        else:
            message = (f"Touchque: request '{request_id}' must be approved with a passkey "
                       "(phishing-resistant policy); no push was sent.")
        super().__init__(message)
        self.request_id = request_id
        self.reason = reason


class TouchqueApprovalError(TouchqueException):
    """An AI agent's approval ended without a usable approval: ``status`` is
    rejected, blocked, revoked, expired, stale (approved too long ago) or
    redeemed (already used)."""

    def __init__(self, approval_id: str, status: str, reason: Optional[str] = None):
        super().__init__(f"Touchque: approval '{approval_id}' is {status}" + (f' ({reason})' if reason else ''))
        self.approval_id = approval_id
        self.status = status
        self.reason = reason


class TouchqueApprovalMismatchError(TouchqueException):
    """An approval token does not say what you are about to execute (another
    person, action type, amount, recipient...), or it is not a valid token
    from Touchque. Do not execute."""
    pass
