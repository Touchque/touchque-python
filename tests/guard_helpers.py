"""Shared by the adapter tests: a process without Touchque keys, what the
adapters answer then, and the run_guard results every adapter must send
exactly as its own guard_response() gives them."""
import copy
import dataclasses
import datetime
import decimal
import uuid

import pytest

from touchque import guard


@pytest.fixture
def no_keys(monkeypatch):
    """No TQ_API_KEY / TQ_API_SECRET, no default client built yet, and the
    "not set" line not logged yet in this process."""
    monkeypatch.delenv('TQ_API_KEY', raising=False)
    monkeypatch.delenv('TQ_API_SECRET', raising=False)
    monkeypatch.setattr('touchque.client._default_client', None)
    monkeypatch.setattr(guard, '_warned_unconfigured', False)


#: The body every adapter sends while Touchque is not set up.
MISCONFIGURED = {
    'touchque': {'state': 'blocked', 'reason': 'misconfigured'},
    'error': {'code': 'misconfigured', 'message': 'Two-factor approval is not configured correctly.'},
}
NOT_SET_LINE = ('[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: '
                'routes guarded by Touchque answer 500 misconfigured.')


# ── guard_response: what the adapters send for a run_guard result ────────

_TOKEN = 'v1.e30.x'

#: run_guard results (by name) that every adapter sends exactly as its guard_response() gives them.
GUARD_RESULTS = {
    '202 waiting': {'status': 202, 'body': {'touchque': {
        'state': 'waiting', 'requestId': 'r1', 'number': '47', 'expiresAt': '2026-11-12T10:05:00.000Z'},
        'token': _TOKEN}},
    '202 enrollment_off': {'status': 202, 'body': {'touchque': {'state': 'enroll', 'reason': 'enrollment_off'},
                                                   'token': _TOKEN}},
    '401 unauthenticated': {'status': 401, 'body': {'touchque': {'state': 'blocked', 'reason': 'unauthenticated'},
                                                    'error': {'code': 'unauthenticated', 'message': 'Sign in first.'}}},
    '403 rejected': {'status': 403, 'body': {'touchque': {'state': 'rejected', 'requestId': 'r1'}, 'token': _TOKEN}},
    '408 expired': {'status': 408, 'body': {'touchque': {'state': 'expired', 'requestId': 'r1'}, 'token': _TOKEN}},
    '423 frozen': {'status': 423, 'body': {'touchque': {'state': 'frozen', 'retryAfter': 900}, 'token': _TOKEN}},
    '429 rate_limited': {'status': 429, 'body': {'touchque': {'state': 'rate_limited', 'retryAfter': 60},
                                                 'token': _TOKEN}},
    '500 misconfigured': {'status': 500, 'body': MISCONFIGURED},
    '503 unavailable': {'status': 503, 'body': {'touchque': {'state': 'blocked', 'reason': 'unavailable'}, 'error': {
        'code': 'unavailable', 'message': 'Two-factor approval is temporarily unavailable.'}}},
}


@dataclasses.dataclass
class Shaped:
    message: str
    code: str


def _raises(refusal):
    raise RuntimeError('boom')


def _pydantic_alias(refusal):
    pydantic = pytest.importorskip('pydantic')

    class Problem(pydantic.BaseModel):
        model_config = pydantic.ConfigDict(populate_by_name=True)
        error_message: str = pydantic.Field(alias='errorMessage')

    return Problem(errorMessage=refusal['message'])


#: error_body kinds: the default body, plain JSON, a failing callback, and values only a framework encodes.
ERROR_BODIES = {
    'none': None,
    'dict': lambda r: {'message': r['message'], 'code': r['code']},
    'string': lambda r: r['message'],
    'list': lambda r: [r['code']],
    'None result': lambda r: None,
    'raises': _raises,
    'dataclass': lambda r: Shaped(r['message'], r['code']),
    'pydantic alias': _pydantic_alias,
    'datetime': lambda r: {'code': r['code'], 'at': datetime.datetime(2026, 11, 12, 10, 5)},
    'decimal': lambda r: {'code': r['code'], 'amount': decimal.Decimal('1.50')},
    'uuid': lambda r: {'code': r['code'], 'id': uuid.UUID('12345678-1234-5678-1234-567812345678')},
    'set': lambda r: {'code': r['code'], 'tags': {1}},
}

_ANSWER_HEADERS = ('Cache-Control', 'Retry-After', 'X-Touchque-State', 'X-Touchque-Reason')


def result_named(name):
    """A fresh copy of one of GUARD_RESULTS."""
    return copy.deepcopy(GUARD_RESULTS[name])


def sent(status, header, body):
    """An adapter's answer (its status, a header getter, its JSON body) as guard_response's triple."""
    return status, {name: header(name) for name in _ANSWER_HEADERS if header(name) is not None}, body
