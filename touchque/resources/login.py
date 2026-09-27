import time
from typing import Dict, Any, List, Optional, Union

# Label -> value, or an ordered list of {'label': ..., 'value': ...}.
LoginDetails = Union[Dict[str, Union[str, int, float]], List[Dict[str, Any]]]
from urllib.parse import quote
from ..http_client import HttpClient
from ..exceptions import TouchQueTimeoutException, TouchQueRejectedException, TouchQuePasskeyRequiredError

class Login:
    def __init__(self, http: HttpClient):
        self._http = http

    def request(self, external_username: str, type: str = 'LOGIN', reference_id: Optional[str] = None, client_ip: Optional[str] = None, user_agent: Optional[str] = None, require_biometric: bool = False, require_number_match: bool = False, details: Optional[LoginDetails] = None) -> Dict[str, Any]:
        """
        Request a 2FA login/approval from the user's mobile device.

        When the integration has behavioral biometrics enabled
        (``TenantPolicy.behavioralBiometricsEnabled``), the response also
        contains ``telemetryToken`` — pass it plus ``requestId`` to your
        frontend to initialize the ``@touchque/web`` behavioral widget
        (``tq.behavioral.attach(...)``). There is no widget in this server SDK.

        ``details`` is transaction context shown on the approval screen, e.g.
        ``{'Amount': '1,250.00 USD', 'Recipient': 'Jane Doe'}`` (shown in
        order). At most 8 entries, labels <= 40 and values <= 120
        characters; the API rejects (never truncates) anything outside those
        limits. Build it from server-side state, never from browser input.
        """
        payload = {
            'externalUsername': external_username,
            'type': type
        }
        if reference_id is not None:
            payload['referenceId'] = reference_id
        if client_ip is not None:
            payload['clientIp'] = client_ip
        if user_agent is not None:
            payload['userAgent'] = user_agent
        if require_biometric:
            payload['requireBiometric'] = True
        if require_number_match:
            payload['requireNumberMatch'] = True
        if details:
            payload['details'] = details

        return self._http.post('/login/request', payload)

    def status(self, request_id: str) -> Dict[str, Any]:
        """Check the current status of a login request."""
        return self._http.get(f"/login/status/{quote(request_id, safe='')}")

    def verify(self, external_username: str, type: str = 'LOGIN', reference_id: Optional[str] = None, client_ip: Optional[str] = None, user_agent: Optional[str] = None, require_biometric: bool = False, require_number_match: bool = False, timeout_ms: int = 30000, details: Optional[LoginDetails] = None) -> Dict[str, Any]:
        """Request a login and wait (poll) until the user approves or rejects it."""
        request_result = self.request(external_username, type, reference_id, client_ip, user_agent, require_biometric, require_number_match, details)
        request_id = request_result['requestId']
        if request_result.get('requiresPasskey'):
            raise TouchQuePasskeyRequiredError(request_id)

        start_time = time.time() * 1000
        poll_interval_sec = 0.4

        while True:
            status_result = self.status(request_id)
            status = status_result.get('status')

            if status == 'CONFIRMED':
                return {
                    'approved': True,
                    'status': status,
                    'requestId': request_id,
                    'challengeCode': request_result.get('challengeCode'),
                    'assurance': status_result.get('assurance'),
                    'confirmedVia': status_result.get('confirmedVia'),
                }

            if status == 'REJECTED':
                raise TouchQueRejectedException(f"Request {request_id} was rejected by the user.")

            if status == 'EXPIRED':
                raise TouchQueTimeoutException(f"Request {request_id} expired before it was approved.")

            elapsed = (time.time() * 1000) - start_time
            if elapsed > timeout_ms:
                raise TouchQueTimeoutException(f"Login verification timed out after {timeout_ms}ms")

            time.sleep(poll_interval_sec)

    def approve_with_recovery_code(self, request_id: str, code: str) -> Dict[str, Any]:
        """Approve a pending 2FA request using a Recovery Code (bypasses mobile device)."""
        return self._http.post('/login/recovery', {
            'requestId': request_id,
            'code': code
        })

    def consume(self, request_id: str) -> Dict[str, Any]:
        """Uses an approved request exactly once. The first call on a
        CONFIRMED request wins atomically; every later call (a replayed
        token, a retried form post) raises ``TouchQueAPIException`` with
        ``code='already_used'`` (409)."""
        return self._http.post(f"/login/{quote(request_id, safe='')}/consume", {})
