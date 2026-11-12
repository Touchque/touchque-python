import os
import json
import time
import hmac
import hashlib
import requests
from typing import Dict, Any, Optional
from urllib.parse import urlencode

from .config import Config
from .exceptions import TouchqueAPIException, TouchqueNetworkException, api_exception

SDK_VERSION = '5.1.0'

def _query_value(value: Any) -> Any:
    # The API reads only 'true' / 'false'; urlencode would send Python's 'True' / 'False'.
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return value


def _build_query(params: Optional[Dict[str, Any]]) -> str:
    """Deterministic query string: keys sorted, `?`-prefixed (or '')."""
    if not params:
        return ''
    items = sorted((k, _query_value(v)) for k, v in params.items() if v is not None)
    if not items:
        return ''
    return '?' + urlencode(items)


class HttpClient:
    def __init__(self, config: Config):
        self.config = config

    def post(self, endpoint: str, body: Dict[str, Any]) -> Dict[str, Any]:
        body_str = json.dumps(body, separators=(',', ':'))
        headers = self._auth_headers('POST', endpoint, body_str)
        try:
            timeout_sec = self.config.timeout / 1000.0
            response = requests.post(
                f"{self.config.base_url}{endpoint}", data=body_str, headers=headers,
                timeout=timeout_sec, allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            raise TouchqueNetworkException(f"Network Error: {e}") from e
        return self._handle_response(response)

    def put(self, endpoint: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._send('PUT', endpoint, body)

    def patch(self, endpoint: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._send('PATCH', endpoint, body)

    def _send(self, method: str, endpoint: str, body: Dict[str, Any]) -> Dict[str, Any]:
        body_str = json.dumps(body, separators=(',', ':'))
        headers = self._auth_headers(method, endpoint, body_str)
        try:
            response = requests.request(
                method, f"{self.config.base_url}{endpoint}", data=body_str, headers=headers,
                timeout=self.config.timeout / 1000.0, allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            raise TouchqueNetworkException(f"Network Error: {e}") from e
        return self._handle_response(response)

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query = _build_query(params)
        path_with_query = endpoint + query
        headers = self._auth_headers('GET', path_with_query, '')
        try:
            timeout_sec = self.config.timeout / 1000.0
            # The query string is sent as part of the URL (not `requests`'
            # `params=`) so the bytes on the wire match what was signed.
            response = requests.get(
                f"{self.config.base_url}{path_with_query}", headers=headers,
                timeout=timeout_sec, allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            raise TouchqueNetworkException(f"Network Error: {e}") from e
        return self._handle_response(response)

    def get_text(self, endpoint: str) -> str:
        """A GET whose answer is a file (CSV or JSON lines), returned as text."""
        headers = self._auth_headers('GET', endpoint, '')
        try:
            response = requests.get(
                f"{self.config.base_url}{endpoint}", headers=headers,
                timeout=self.config.timeout / 1000.0, allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            raise TouchqueNetworkException(f"Network Error: {e}") from e
        if response.status_code >= 400:
            self._handle_response(response)
        return response.text

    def delete(self, endpoint: str) -> Dict[str, Any]:
        headers = self._auth_headers('DELETE', endpoint, '')
        try:
            timeout_sec = self.config.timeout / 1000.0
            response = requests.delete(
                f"{self.config.base_url}{endpoint}", headers=headers,
                timeout=timeout_sec, allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            raise TouchqueNetworkException(f"Network Error: {e}") from e
        return self._handle_response(response)

    def _auth_headers(self, method: str, path_with_query: str, body: str) -> Dict[str, str]:
        timestamp = str(int(time.time() * 1000))
        # 16 bytes / 32 hex chars — the API requires at least 16 hex chars.
        nonce = os.urandom(16).hex()
        signature = self._sign_request(method, path_with_query, body, timestamp, nonce)
        return {
            'x-api-key': self.config.api_key,
            'x-signature': signature,
            'x-timestamp': timestamp,
            'x-nonce': nonce,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': f'touchque-python-sdk/{SDK_VERSION}',
        }

    def _handle_response(self, response: 'requests.Response') -> Dict[str, Any]:
        try:
            response_data = response.json()
        except ValueError:
            response_data = {}
        return self._result(response.status_code, response_data, response.headers.get('Retry-After'))

    def _result(self, status: int, response_data: Dict[str, Any], retry_after_header: Optional[str] = None) -> Dict[str, Any]:
        """The parsed answer, or the exception for an error answer (status >= 400)."""
        if status >= 400:
            error_message = response_data.get('error') or response_data.get('message') or 'Unknown API Error'
            retry_after = response_data.get('retryAfter')
            if retry_after is None:
                try:
                    retry_after = int(retry_after_header) if retry_after_header else None
                except ValueError:
                    retry_after = None
            raise api_exception(
                error_message,
                status=status,
                code=response_data.get('code'),
                reason=response_data.get('reason'),
                attempts_left=response_data.get('attemptsLeft'),
                retry_after=retry_after,
                data=response_data,
                case_code=response_data.get('caseCode') if isinstance(response_data.get('caseCode'), str) else None,
            )

        return response_data

    def _sign_request(self, method: str, path: str, body: str, timestamp: str, nonce: str) -> str:
        body_hash = hashlib.sha256((body or '').encode('utf-8')).hexdigest()
        message = f"{method.upper()}:{path}:{timestamp}:{nonce}:{body_hash}"
        mac = hmac.new(self.config.api_secret.encode('utf-8'), message.encode('utf-8'), digestmod=hashlib.sha256)
        return mac.hexdigest()
