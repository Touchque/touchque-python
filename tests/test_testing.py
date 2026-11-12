"""touchque.testing.FakeTouchque: the real guard, answered in memory. No
network, no keys, no Node.js."""
import pytest

flask = pytest.importorskip('flask')

from touchque import TouchqueAPIException, get_default_client  # noqa: E402
from touchque.contrib.flask import require_touchque  # noqa: E402
from touchque.testing import FakeClient, FakeTouchque  # noqa: E402
from .guard_helpers import no_keys  # noqa: F401,E402


def make_app(client=None):
    app = flask.Flask(__name__)

    @app.before_request
    def _auth():
        flask.g.user = flask.request.headers.get('X-User')

    @app.post('/transfer')
    @require_touchque('SEND_MONEY', client=client, details=lambda: {'Amount': f"{flask.request.get_json()['amount']} EUR"})
    def transfer():
        return flask.jsonify(done=True, touchque=flask.g.touchque)

    return app


def send(http, token=None, user='jane@acme.com'):
    headers = {'X-User': user}
    if token:
        headers['X-Touchque-Token'] = token
    return http.post('/transfer', json={'amount': 5}, headers=headers)


def test_a_flask_route_waits_for_the_approval_then_runs_once(no_keys):
    tq = FakeTouchque()
    http = make_app(tq).test_client()

    first = send(http)
    assert first.status_code == 202
    body = first.get_json()
    assert body['touchque']['state'] == 'waiting'
    assert body['touchque']['details'] == [{'label': 'Amount', 'value': '5 EUR'}]
    assert send(http, body['token']).status_code == 202  # still waiting

    tq.approve()
    done = send(http, body['token'])
    assert done.status_code == 200
    assert done.get_json()['touchque']['assurance'] == {'phishingResistant': False, 'method': 'push'}
    assert send(http, body['token']).status_code == 408  # used once

    assert tq.requests[0]['user'] == 'jane@acme.com' and tq.requests[0]['type'] == 'SEND_MONEY'
    assert tq.requests[0]['status'] == 'CONFIRMED'
    assert tq.calls[0] == {'method': 'POST', 'path': '/login/request', 'body': {
        'externalUsername': 'jane@acme.com', 'type': 'SEND_MONEY', 'clientIp': '127.0.0.1',
        'userAgent': tq.calls[0]['body']['userAgent'], 'details': [{'label': 'Amount', 'value': '5 EUR'}]}}
    assert [c['path'] for c in tq.calls][1:] == [
        f"/login/status/{tq.requests[0]['id']}", f"/login/status/{tq.requests[0]['id']}",
        f"/login/{tq.requests[0]['id']}/consume", f"/login/status/{tq.requests[0]['id']}",
        f"/login/{tq.requests[0]['id']}/consume"]


def test_reject_expire_and_requests_by_id():
    tq = FakeTouchque(number_match=True)
    http = make_app(tq).test_client()
    jane, joe = send(http).get_json(), send(http, user='joe@acme.com').get_json()
    assert jane['touchque']['number'] == '47'

    assert tq.reject(jane['touchque']['requestId']) == jane['touchque']['requestId']
    tq.expire()  # the latest: joe's
    assert send(http, jane['token']).status_code == 403
    assert send(http, joe['token'], user='joe@acme.com').status_code == 408
    with pytest.raises(LookupError):
        FakeTouchque().approve()


def test_auto_approve():
    tq = FakeTouchque(auto_approve=True)
    http = make_app(tq).test_client()
    first = send(http)
    assert first.status_code == 202  # the guard never runs the route on the first request
    assert send(http, first.get_json()['token']).status_code == 200


def test_install_makes_it_the_default_client(no_keys):
    http = make_app().test_client()  # given no client
    with FakeTouchque() as tq:
        assert get_default_client() is tq
        first = send(http)
        assert first.status_code == 202
        tq.approve()
        assert send(http, first.get_json()['token']).status_code == 200
    assert send(http).status_code == 500  # back to no default client: no keys here
    assert FakeClient is FakeTouchque


def test_the_first_time_qr_stays_until_linked_and_a_new_one_after_it_expired():
    tq = FakeTouchque()
    tq.unlink('new@acme.com')
    http = make_app(tq).test_client()
    first = send(http, user='new@acme.com').get_json()
    qr = first['touchque']['enroll']
    assert qr['qrCodeDataUrl'].startswith('data:image/png;base64,') and qr['expiresAt'] and qr['recoveryCodes']

    before = len(tq.calls)
    poll = send(http, first['token'], user='new@acme.com').get_json()
    assert poll['touchque']['state'] == 'enroll' and 'enroll' not in poll['touchque']
    assert poll['touchque']['expiresAt'] == qr['expiresAt']
    assert [c['path'] for c in tq.calls[before:]] == ['/users/new%40acme.com']

    tq.unlink('new@acme.com')  # the QR is gone (404): a new one
    fresh = send(http, poll['token'], user='new@acme.com').get_json()
    assert fresh['touchque']['enroll']['qrCodeDataUrl'] != qr['qrCodeDataUrl']

    tq.link('new@acme.com')
    assert send(http, fresh['token'], user='new@acme.com').get_json()['touchque']['state'] == 'waiting'

    tq.secret_ttl_ms = 1000
    tq.unlink('late@acme.com')
    late = send(http, user='late@acme.com').get_json()
    replaced = send(http, late['token'], user='late@acme.com').get_json()
    assert replaced['touchque']['enroll']['qrCodeDataUrl'] != late['touchque']['enroll']['qrCodeDataUrl']


def test_a_link_check_that_fails_is_unavailable(monkeypatch):
    tq = FakeTouchque(linked=False)
    http = make_app(tq).test_client()
    first = send(http).get_json()
    assert first['touchque']['state'] == 'enroll'

    def down(user):
        raise TouchqueAPIException('down', status=500)

    monkeypatch.setattr(tq.auth, 'get_user', down)
    res = send(http, first['token'])
    assert res.status_code == 503 and res.get_json()['touchque']['reason'] == 'unavailable'


def test_offline_code_and_calls_it_does_not_answer():
    tq = FakeTouchque()
    http = make_app(tq).test_client()
    first = send(http).get_json()
    qr = http.post('/transfer', json={'amount': 5}, headers={
        'X-User': 'jane@acme.com', 'X-Touchque-Token': first['token'], 'X-Touchque-Offline': '1'}).get_json()
    assert qr['touchque']['state'] == 'offline'
    done = http.post('/transfer', json={'amount': 5}, headers={
        'X-User': 'jane@acme.com', 'X-Touchque-Token': qr['token'], 'X-Touchque-Code': tq.offline_code})
    assert done.status_code == 200 and done.get_json()['touchque']['confirmedVia'] == 'OFFLINE_CODE'

    tq.action_types.define('EXPORT', name='Export data', critical=True)
    assert tq.action_types.list()[0]['type'] == 'EXPORT'
    with pytest.raises(TouchqueAPIException) as err:
        tq.recovery.list(open=True)
    assert err.value.status == 404


def test_is_status_poll_takes_the_default_client_like_run_guard(no_keys):
    from touchque import is_status_poll, run_guard
    assert is_status_poll(None, 'jane@acme.com', 'LOGIN', token='v1.e30.x') is False  # no keys: False, no raise
    with FakeTouchque() as tq:
        token = run_guard(None, 'jane@acme.com', 'LOGIN')['body']['token']
        assert is_status_poll(None, 'jane@acme.com', 'LOGIN', token=token) is True
        assert is_status_poll(tq, 'jane@acme.com', 'LOGIN', token=token, ip='127.0.0.1') is True


def test_polls_repeat_the_requests_expires_at():
    tq = FakeTouchque()
    http = make_app(tq).test_client()
    first = send(http).get_json()
    expires_at = first['touchque']['expiresAt']
    assert expires_at == tq.requests[-1]['expiresAt']
    poll = send(http, first['token']).get_json()
    assert poll['touchque']['state'] == 'waiting' and poll['touchque']['expiresAt'] == expires_at
    again = send(http, poll['token']).get_json()
    assert again['touchque']['expiresAt'] == expires_at


def test_a_guard_without_enrollment_answers_enrollment_off():
    from touchque import run_guard
    tq = FakeTouchque(linked=False)
    first = run_guard(tq, 'new@acme.com', 'LOGIN', enroll=False)
    assert first['status'] == 202
    assert first['body']['touchque'] == {'state': 'enroll', 'reason': 'enrollment_off'}
    assert [c['path'] for c in tq.calls] == ['/login/request']  # no first-time QR, no recovery codes


def test_set_default_client_replaces_or_forgets_the_default_client(no_keys, monkeypatch):
    from touchque import run_guard, set_default_client
    tq = FakeTouchque()
    set_default_client(tq)
    assert get_default_client() is tq
    first = run_guard(None, 'jane@acme.com', 'LOGIN')
    assert first['status'] == 202 and tq.requests[-1]['user'] == 'jane@acme.com'

    set_default_client(None)  # forgotten: the next call reads the environment again
    assert run_guard(None, 'jane@acme.com', 'LOGIN')['status'] == 500  # no keys here
    monkeypatch.setenv('TQ_API_KEY', 'tq_rotated')
    monkeypatch.setenv('TQ_API_SECRET', 'rotated_secret')
    rebuilt = get_default_client()
    assert rebuilt is not tq and rebuilt.config.api_key == 'tq_rotated'
    assert get_default_client() is rebuilt  # kept once built
    monkeypatch.setenv('TQ_API_KEY', 'tq_rotated_again')
    assert get_default_client().config.api_key == 'tq_rotated'  # read once per process...
    set_default_client(None)
    assert get_default_client().config.api_key == 'tq_rotated_again'  # ...unless reset


def test_a_client_set_while_the_default_one_is_built_is_kept(no_keys, monkeypatch):
    """get_default_client and set_default_client share one lock: a client set during the first build wins."""
    import threading
    from touchque import client as client_module, set_default_client
    monkeypatch.setenv('TQ_API_KEY', 'tq_env')
    monkeypatch.setenv('TQ_API_SECRET', 'env_secret')
    building, release = threading.Event(), threading.Event()
    real = client_module.Touchque

    def slow_build(*args, **kwargs):
        building.set()
        release.wait(5)
        return real(*args, **kwargs)

    monkeypatch.setattr(client_module, 'Touchque', slow_build)
    builder = threading.Thread(target=get_default_client)
    builder.start()
    assert building.wait(5)
    mine = FakeTouchque()
    setter = threading.Thread(target=set_default_client, args=(mine,))
    setter.start()
    setter.join(0.2)  # unsynchronised, it would be done here and then lost to the build
    release.set()
    builder.join(5)
    setter.join(5)
    assert get_default_client() is mine
