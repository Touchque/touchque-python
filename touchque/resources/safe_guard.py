"""Safe Guard: a Safe transaction approved on the approver's phone for TouchQueSafeGuard (the
guard on your Safe). You send the raw transaction; the phone gets the raw fields only, decodes
them itself, shows its own rows and signs, with a key only its biometrics unlock, a 105-byte
approval of the hash it computed. TouchQue never holds a key that can approve.

1. ``request(external_username, type, safe_tx)`` asks the phone (same pipeline as
   ``login.request``: risk engine, push limit, Vishing Shield, case code, always biometrics).
2. ``wait_for_approval(request_id)`` (or poll ``status``) until the phone answered.
3. Check ``safeTx['approval']`` yourself with ``touchque.verify_safe_approval``: it needs your
   own transaction and the approver's key from the guard, not this response.
4. ``purpose == 'approve'``: ``with_safe_approvals(owner_signatures, approvals)`` as the
   signatures of ``execTransaction``. ``purpose == 'schedule'``: send
   ``safe_schedule_call(safe, governance_hash, approvals)`` to the guard; the change runs once its
   waiting time is over.
"""
import time
from typing import Any, Dict, Mapping, Optional
from urllib.parse import quote

from ..exceptions import TouchQueConfigException, TouchQueRejectedException, TouchQueTimeoutException
from ..http_client import HttpClient

_NUMBERS = ('value', 'safeTxGas', 'baseGas', 'gasPrice', 'nonce')


def _wire(safe_tx: Mapping[str, Any]) -> Dict[str, Any]:
    """Large integers go as decimal strings, as the API takes them."""
    out = dict(safe_tx)
    if isinstance(out.get('chainId'), int):
        out['chainId'] = str(out['chainId'])
    tx = dict(out['tx'])
    for name in _NUMBERS:
        if isinstance(tx.get(name), int) and not isinstance(tx.get(name), bool):
            tx[name] = str(tx[name])
    out['tx'] = tx
    return out


class SafeGuard:
    def __init__(self, http: HttpClient):
        self._http = http

    def request(self, external_username: str, type: str, safe_tx: Mapping[str, Any], reference_id: Optional[str] = None,
                expires_in: Optional[int] = None, client_ip: Optional[str] = None, user_agent: Optional[str] = None) -> Dict[str, Any]:
        """Asks the approver's phone to approve a Safe transaction.

        ``type``: an action type from your dashboard. ``safe_tx``: ``{"chainId", "safe", "guard",
        "tx": {"to", "value", "data", "operation", "safeTxGas", "baseGas", "gasPrice", "gasToken",
        "refundReceiver", "nonce"}, "config": {"threshold", "govThreshold", "govDelay", "exitDelay",
        "recipientLock"}, "batchTargets", "recipients", "approverIndex", "locale"}``.
        ``expires_in``: seconds, 30 to 300 (default 300)::

            sent = tq.safe_guard.request('treasurer@acme.com', 'safe_payment', {
                'chainId': 1, 'safe': SAFE, 'guard': GUARD,
                'tx': {'to': to, 'value': 0, 'data': data, 'operation': 0, 'nonce': 42},
                'config': {'threshold': 2, 'govThreshold': 3, 'govDelay': 172800, 'exitDelay': 259200},
                'approverIndex': 0,
            })
        """
        if not external_username:
            raise TouchQueConfigException('safe_guard.request() needs external_username.')
        if not type:
            raise TouchQueConfigException('safe_guard.request() needs type: an action type from your dashboard.')
        if not isinstance(safe_tx, Mapping) or not isinstance(safe_tx.get('tx'), Mapping):
            raise TouchQueConfigException('safe_guard.request() needs safe_tx: {"chainId", "safe", "guard", "tx", "config", "approverIndex"}.')
        body: Dict[str, Any] = {'externalUsername': external_username, 'type': type, 'safeTx': _wire(safe_tx)}
        if reference_id:
            body['referenceId'] = reference_id
        if expires_in is not None:
            body['expiresIn'] = expires_in
        if client_ip:
            body['clientIp'] = client_ip
        if user_agent:
            body['userAgent'] = user_agent
        return self._http.post('/safe-guard/approvals', body)

    def status(self, request_id: str) -> Dict[str, Any]:
        """The request's status and, once approved, the approval (``safeTx['approval']``, 105 bytes hex)."""
        if not request_id:
            raise TouchQueConfigException('safe_guard.status() needs a request_id.')
        return self._http.get(f'/safe-guard/approvals/{quote(request_id, safe="")}')

    def wait_for_approval(self, request_id: str, timeout_ms: int = 300000, poll_interval_ms: int = 1500) -> Dict[str, Any]:
        """Polls until the phone approved and returns the status with the approval.

        Raises ``TouchQueRejectedException`` when the person said no, ``TouchQueTimeoutException``
        when it expired or ``timeout_ms`` (default 5 minutes, the request's own life) ran out."""
        start = time.monotonic()
        while True:
            status = self.status(request_id)
            if status.get('status') == 'CONFIRMED':
                return status
            if status.get('status') == 'REJECTED':
                raise TouchQueRejectedException(f'Request {request_id} was rejected by the user.')
            if status.get('status') == 'EXPIRED':
                raise TouchQueTimeoutException(f'Request {request_id} expired before it was approved.')
            if (time.monotonic() - start) * 1000 > timeout_ms:
                raise TouchQueTimeoutException(f'Safe Guard approval timed out after {timeout_ms}ms')
            time.sleep(poll_interval_ms / 1000)
