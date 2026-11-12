"""Shared by the adapter tests: a process without Touchque keys, and what
the adapters answer then."""
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
