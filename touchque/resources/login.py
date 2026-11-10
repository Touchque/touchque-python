import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union

# Label -> value, or an ordered list of {'label': ..., 'value': ...}.
LoginDetails = Union[Dict[str, Union[str, int, float]], List[Dict[str, Any]]]
from urllib.parse import quote
from ..http_client import HttpClient
from ..exceptions import TouchQueTimeoutException, TouchQueRejectedException, TouchQuePasskeyRequiredError, TouchQueConfigException

logger = logging.getLogger('touchque')

SECURITY_CHANGE_KINDS = ('password', 'mfa', 'device', 'email', 'phone')
DESTINATION_KINDS = ('iban', 'account', 'wallet', 'address', 'payee')


def _security_changes_body(changes: Dict[str, Any]) -> Dict[str, Any]:
    """datetimes go out as ISO 8601 (a naive one is taken as UTC); strings and epoch milliseconds as given."""
    out: Dict[str, Any] = {}
    for kind, at in changes.items():
        if at is None:
            continue
        if isinstance(at, datetime):
            out[kind] = (at if at.tzinfo else at.replace(tzinfo=timezone.utc)).isoformat()
        else:
            out[kind] = at
    return out


class Login:
    def __init__(self, http: HttpClient):
        self._http = http

    def request(self, external_username: str, type: str = 'LOGIN', reference_id: Optional[str] = None, client_ip: Optional[str] = None, user_agent: Optional[str] = None, require_biometric: bool = False, require_number_match: bool = False, details: Optional[LoginDetails] = None, browser_proof: Optional[str] = None, context: Optional[Dict[str, Any]] = None, challenge_digits: Optional[int] = None, expires_in: Optional[int] = None, client_signals: Optional[str] = None, security_changes: Optional[Dict[str, Any]] = None, destination: Optional[Dict[str, Any]] = None, locale: Optional[str] = None, qr_pairing: Optional[str] = None, device_risk: Optional[str] = None, device_risk_request_id: Optional[str] = None, reply: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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

        ``browser_proof`` (silent sign-ins): the browser's device-bound key
        proof, exactly as the browser sent it (``X-TouchQue-Browser`` header,
        made by ``@touchque/web``). When the user approves this request on the
        phone (or with a passkey), TouchQue remembers the browser, so a later
        ``risk.check`` can let the same browser in without asking. Pass it
        through untouched; an invalid proof only means "a browser TouchQue
        does not know".

        ``context``: for your TouchQue Actions only (``event.context``): roles,
        plan, amount… Any JSON object up to 4 KB. Never shown on the phone.

        ``expires_in``: how long the push waits for the person, in seconds:
        30 (default) to 300; longer suits a request the person has to read
        first, such as an AI agent asking on their behalf.

        ``qr_pairing``: a browser pairing by QR code (``client.qr_pairings``),
        scanned and confirmed on the phone: only the phone that scanned it is
        asked, once, with number matching, for the user it scanned for.

        ``device_risk_request_id``: the page's identification from ``@touchque/web``
        (``deviceRisk.identify()``), for this account only; or ``device_risk``,
        the page's report (``deviceRisk.collect({ purpose })``), passed through untouched. Used
        only when your workspace turned Device risk on: its signals only ever
        ask for more, and a device your admin marked "step up always" asks at once.

        ``client_signals``: the end user's page check from ``@touchque/web``
        (``startClientSignals().encode()``), passed through untouched. A browser
        driven by software asks with number matching, or is refused where the
        workspace blocks it (403 ``automated_client``).

        ``security_changes``: when the user's sign-in security last changed in
        your system, ``{'password', 'mfa', 'device', 'email', 'phone'}`` each a
        datetime, ISO 8601 string or epoch milliseconds. TouchQue adds what it
        saw itself; access rules and Actions read the minutes since each
        (``minutesSince.mfaChange``, ``.deviceChange``, ...), e.g. refuse
        ``PAYOUT_CHANGE`` within 24 hours of a 2FA change.

        ``destination``: where the action sends money or value,
        ``{'kind': 'iban'|'account'|'wallet'|'address'|'payee', 'value': ..., 'known': [...]}``.
        The phone shows it in full in groups of four, with a warning when it
        looks like one the user used before but is not the same; the answer's
        ``destination`` is ``{'known', 'lookalike'}``. Do not repeat it in ``details``.

        ``locale``: ``'tr'`` (default) or ``'en'``, the language of those rows.

        ``reply``: ask the person to type back on the phone a sign-in code another service sent
        them, ``{'kind': 'code', 'key': new_code_reply_key()['public_key'], 'channel': 'sms',
        'target': '+**********26'}``. The phone encrypts it to ``key``; ``status()['reply']['ct']``
        holds only the ciphertext: open it with ``open_code_reply``. Such a request lives 5
        minutes. Not with ``qr_pairing``.
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
        if challenge_digits in (2, 3):
            payload['challengeDigits'] = challenge_digits
        if expires_in is not None:
            payload['expiresIn'] = expires_in
        if qr_pairing:
            payload['qrPairing'] = qr_pairing
        if reply is not None:
            payload['reply'] = reply
        if client_signals:
            payload['clientSignals'] = client_signals
        if device_risk:
            payload['deviceRisk'] = device_risk
        if device_risk_request_id:
            payload['deviceRiskRequestId'] = device_risk_request_id
        if details:
            payload['details'] = details
        if browser_proof:
            payload['browserProof'] = browser_proof
        if context:
            payload['context'] = context
        if security_changes:
            payload['securityChanges'] = _security_changes_body(security_changes)
        if destination:
            payload['destination'] = destination
        if locale:
            payload['locale'] = locale

        return self._http.post('/login/request', payload)

    def status(self, request_id: str) -> Dict[str, Any]:
        """Check the current status of a login request."""
        return self._http.get(f"/login/status/{quote(request_id, safe='')}")

    def wait_for_approval(self, request_id: str, timeout_ms: int = 30000, poll_interval_ms: int = 400) -> Dict[str, Any]:
        """Wait (poll) until the user approves or rejects a request you already sent with ``request``.

        Returns ``{'approved': True, 'status': 'CONFIRMED', 'requestId', 'assurance', 'confirmedVia',
        'provisional'}``. Raises ``TouchQueRejectedException`` when the user said no,
        ``TouchQueTimeoutException`` when the request expired or ``timeout_ms`` ran out, and
        ``TouchQuePasskeyRequiredError`` (``reason='step_up'``) when the user tapped Approve
        during a call and the request now waits for a passkey in the browser::

            req = tq.login.request(user, 'SEND_MONEY')
            tq.login.wait_for_approval(req['requestId'], timeout_ms=60000)"""
        start_time = time.time() * 1000

        while True:
            status_result = self.status(request_id)
            status = status_result.get('status')

            if status == 'CONFIRMED':
                return {
                    'approved': True,
                    'status': status,
                    'requestId': request_id,
                    'assurance': status_result.get('assurance'),
                    'confirmedVia': status_result.get('confirmedVia'),
                    # Vishing Shield: approved during a call; critical actions wait for the phone to re-confirm.
                    'provisional': bool(status_result.get('provisional')),
                }

            if status == 'REJECTED':
                raise TouchQueRejectedException(f"Request {request_id} was rejected by the user.")

            if status == 'EXPIRED':
                raise TouchQueTimeoutException(f"Request {request_id} expired before it was approved.")

            # Vishing Shield: tapped during a call, the request now waits for a passkey in the browser.
            if status == 'PENDING' and status_result.get('requiresPasskey'):
                raise TouchQuePasskeyRequiredError(request_id, 'step_up')

            elapsed = (time.time() * 1000) - start_time
            if elapsed > timeout_ms:
                raise TouchQueTimeoutException(f"Waiting for approval timed out after {timeout_ms}ms")

            time.sleep(poll_interval_ms / 1000)

    def verify(self, external_username: str, type: str = 'LOGIN', reference_id: Optional[str] = None, client_ip: Optional[str] = None, user_agent: Optional[str] = None, require_biometric: bool = False, require_number_match: bool = False, timeout_ms: int = 30000, details: Optional[LoginDetails] = None, browser_proof: Optional[str] = None, on_challenge: Optional[Callable[[Dict[str, Any]], Any]] = None, context: Optional[Dict[str, Any]] = None, challenge_digits: Optional[int] = None, security_changes: Optional[Dict[str, Any]] = None, destination: Optional[Dict[str, Any]] = None, locale: Optional[str] = None) -> Dict[str, Any]:
        """Request a login and wait (poll) until the user approves or rejects it.

        With number matching (your ``require_number_match``, a workspace policy
        or the risk engine can turn it on) the user must pick a number on the
        phone. ``on_challenge`` is called once, right after the request is
        created and before any waiting, with ``{'requestId', 'challengeCode',
        'expiresAt', 'reasons', 'caseCode'}``: show ``challengeCode`` to the
        user now; the phone asks for it. An exception it raises is logged and
        ignored (verify keeps waiting). It is not called when only a passkey
        can approve::

            tq.login.verify(user, 'SEND_MONEY',
                            on_challenge=lambda c: c.get('challengeCode') and show(f"Pick {c['challengeCode']} on your phone"))

        Raises ``TouchQuePasskeyRequiredError`` when a passkey must approve it:
        a phishing-resistant policy (``reason='policy'``, no push sent), or the
        user tapped Approve during a call (``reason='step_up'``, Vishing Shield):
        finish it in the browser with ``@touchque/web``."""
        request_result = self.request(external_username, type, reference_id, client_ip, user_agent, require_biometric, require_number_match, details, browser_proof, context, challenge_digits, security_changes=security_changes, destination=destination, locale=locale)
        request_id = request_result['requestId']
        if request_result.get('requiresPasskey'):
            raise TouchQuePasskeyRequiredError(request_id)

        if on_challenge is not None:
            challenge = {'requestId': request_id, 'expiresAt': request_result.get('expiresAt')}
            for key in ('challengeCode', 'reasons', 'caseCode'):
                if request_result.get(key):
                    challenge[key] = request_result[key]
            try:
                on_challenge(challenge)
            except Exception as err:  # noqa: BLE001 — the user's callback must not stop the wait
                # err.__class__, not type(err): the parameter `type` shadows the builtin here.
                logger.warning('[TouchQue] on_challenge failed: %s: %s', err.__class__.__name__, err)

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
                    # Vishing Shield: approved during a call; critical actions wait for the phone to re-confirm.
                    'provisional': bool(status_result.get('provisional')),
                }

            if status == 'REJECTED':
                raise TouchQueRejectedException(f"Request {request_id} was rejected by the user.")

            if status == 'EXPIRED':
                raise TouchQueTimeoutException(f"Request {request_id} expired before it was approved.")

            # Vishing Shield: tapped during a call, the request now waits for a passkey in the browser.
            if status == 'PENDING' and status_result.get('requiresPasskey'):
                raise TouchQuePasskeyRequiredError(request_id, 'step_up')

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

    FRAUD_REASONS = ('chargeback', 'account_takeover', 'social_engineering', 'other')

    def report_fraud(self, request_id: str, reason: Optional[str] = None, note: Optional[str] = None) -> Dict[str, Any]:
        """Report a request you later learned was fraud — a chargeback, a
        confirmed account takeover, a scam the user was talked into. TouchQue's
        risk engine learns from it (it is the strongest signal it gets) and the
        report is kept in your audit log. The request's status does not change.
        Safe to call more than once: a repeat answers ``alreadyReported: True``.

        :param reason: one of ``Login.FRAUD_REASONS`` (default ``'other'``).
        :param note: free text for your audit log, at most 500 characters.
        """
        if not request_id:
            raise TouchQueConfigException('report_fraud() needs the request id')
        payload: Dict[str, Any] = {}
        if reason:
            payload['reason'] = reason
        if note:
            payload['note'] = note
        return self._http.post(f"/login/{quote(request_id, safe='')}/report-fraud", payload)
