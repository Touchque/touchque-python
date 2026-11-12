import dataclasses
import logging

import pytest

flask = pytest.importorskip('flask')

from touchque import Config, Touchque
from touchque.contrib.flask import require_touchque
from touchque.testing import FakeTouchque
from .fake_api import fake_api  # noqa: F401
from .guard_helpers import (  # noqa: F401
    ERROR_BODIES, GUARD_RESULTS, MISCONFIGURED, NOT_SET_LINE, no_keys, result_named, sent,
)


def make_app(tq, action='SEND_MONEY'):
    app = flask.Flask(__name__)

    @app.before_request
    def _auth():
        flask.g.user = flask.request.headers.get('X-User')

    @app.post('/transfer')
    @require_touchque(action, client=tq, details=lambda: {'Amount': f"{flask.request.get_json().get('amount')} EUR"})
    def transfer():
        return flask.jsonify(done=True, touchque=flask.g.touchque)

    return app


def test_full_flow(fake_api):
    fake_api.link('jane@acme.com')
    fake_api.opts(numberMatch=True)
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    client = make_app(tq).test_client()

    first = client.post('/transfer', json={'amount': 5}, headers={'X-User': 'jane@acme.com'})
    assert first.status_code == 202
    assert first.get_json()['touchque']['number'] == '47'
    token = first.get_json()['token']

    fake_api.approve()
    done = client.post('/transfer', json={'amount': 5}, headers={'X-User': 'jane@acme.com', 'X-Touchque-Token': token})
    assert done.status_code == 200
    assert done.get_json()['done'] is True

    replay = client.post('/transfer', json={'amount': 5}, headers={'X-User': 'jane@acme.com', 'X-Touchque-Token': token})
    assert replay.status_code != 200


def test_no_user_is_401(fake_api):
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    client = make_app(tq).test_client()
    res = client.post('/transfer', json={'amount': 5})
    assert res.status_code == 401


# ── silent sign-ins ──────────────────────────────────────────────────────

def make_login_app(tq, silent_sign_in=False):
    app = flask.Flask(__name__)

    @app.post('/login/2fa')
    @require_touchque('LOGIN', client=tq, user=lambda: 'jane@acme.com', silent_sign_in=silent_sign_in)
    def login():
        return flask.jsonify(done=True, touchque=flask.g.touchque)

    return app


def test_silent_sign_in_runs_the_view_at_once_for_a_known_browser(fake_api):
    from .silent_vectors import PROOF
    fake_api.link('jane@acme.com')
    fake_api.opts(silent=True)
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    res = make_login_app(tq, silent_sign_in=True).test_client().post('/login/2fa', headers={'X-Touchque-Browser': PROOF})
    assert res.status_code == 200
    assert res.get_json()['touchque']['confirmedVia'] == 'SILENT'
    assert res.get_json()['touchque']['assurance']['method'] == 'silent'
    assert fake_api.last_check()['browserProof'] == PROOF


def test_without_silent_sign_in_the_header_is_ignored(fake_api):
    from .silent_vectors import PROOF
    fake_api.link('jane@acme.com')
    fake_api.opts(silent=True)
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    res = make_login_app(tq).test_client().post('/login/2fa', headers={'X-Touchque-Browser': PROOF})
    assert res.status_code == 202
    assert '/risk/check' not in fake_api.paths()
    assert 'browserProof' not in fake_api.calls()[-1]['body']


# ── no keys: a JSON answer, never a raise ─────────────────────────────────

def make_guarded_app(ran, **options):
    app = flask.Flask(__name__)

    @app.before_request
    def _auth():
        flask.g.user = flask.request.headers.get('X-User')

    @app.post('/transfer')
    @require_touchque('SEND_MONEY', **options)
    def transfer():
        ran.append(True)
        return flask.jsonify(done=True)

    return app


def test_without_keys_the_route_answers_500_misconfigured_and_never_runs(no_keys, caplog):
    ran = []
    client = make_guarded_app(ran).test_client()  # no client: nothing raised at startup
    with caplog.at_level(logging.ERROR, logger='touchque'):
        for _ in range(2):
            res = client.post('/transfer', json={}, headers={'X-User': 'jane@acme.com'})
            assert res.status_code == 500
            assert res.get_json() == MISCONFIGURED
            assert res.headers['Cache-Control'] == 'no-store'
        anonymous = client.post('/transfer', json={})
    assert anonymous.status_code == 401
    assert anonymous.get_json()['error']['code'] == 'unauthenticated'
    assert ran == []
    assert [r.getMessage() for r in caplog.records if 'TQ_API_KEY' in r.getMessage()] == [NOT_SET_LINE]


def test_without_keys_error_body_shapes_the_500(no_keys):
    res = make_guarded_app([], error_body=lambda r: {'error': r['message'], 'status': r['status']}).test_client() \
        .post('/transfer', json={}, headers={'X-User': 'jane@acme.com'})
    assert res.status_code == 500
    assert res.get_json() == {'error': 'Two-factor approval is not configured correctly.', 'status': 500,
                              'touchque': MISCONFIGURED['touchque']}


# ── error_body: the app's own error shape ────────────────────────────────

def test_error_body_object_is_merged_with_the_step_and_never_called_on_202():
    tq, seen = FakeTouchque(), []

    def body(refusal):
        seen.append(refusal)
        return {'message': refusal['message'], 'code': refusal['code'], 'touchque': 'mine'}

    client = make_guarded_app([], client=tq, error_body=body).test_client()
    first = client.post('/transfer', json={}, headers={'X-User': 'jane@acme.com'})
    assert first.status_code == 202 and 'token' in first.get_json()
    assert seen == []

    tq.reject()
    res = client.post('/transfer', json={}, headers={'X-User': 'jane@acme.com',
                                                      'X-Touchque-Token': first.get_json()['token']})
    assert res.status_code == 403
    assert res.headers['Cache-Control'] == 'no-store'
    step = {'state': 'rejected', 'requestId': tq.requests[-1]['id']}
    assert res.get_json() == {'message': 'The approval was rejected.', 'code': 'rejected', 'touchque': step}
    assert seen == [{'status': 403, 'code': 'rejected', 'message': 'The approval was rejected.', 'touchque': step}]

    anonymous = client.post('/transfer', json={})
    assert anonymous.status_code == 401
    assert anonymous.get_json() == {'message': 'Sign in first.', 'code': 'unauthenticated',
                                    'touchque': {'state': 'blocked', 'reason': 'unauthenticated'}}


@pytest.mark.parametrize('custom', ['Approval refused', ['refused'], None, 7])
def test_error_body_anything_but_an_object_is_sent_as_it_is(custom):
    tq = FakeTouchque()
    client = make_guarded_app([], client=tq, error_body=lambda r: custom).test_client()
    first = client.post('/transfer', json={}, headers={'X-User': 'jane@acme.com'})
    tq.expire()
    res = client.post('/transfer', json={}, headers={'X-User': 'jane@acme.com',
                                                      'X-Touchque-Token': first.get_json()['token']})
    assert res.status_code == 408
    assert res.get_json() == custom


def test_error_body_that_raises_sends_the_default_body(caplog):
    def broken(refusal):
        raise ValueError('boom')

    with caplog.at_level(logging.ERROR, logger='touchque'):
        res = make_guarded_app([], client=FakeTouchque(), error_body=broken).test_client().post('/transfer', json={})
    assert res.status_code == 401
    assert res.get_json() == {'touchque': {'state': 'blocked', 'reason': 'unauthenticated'},
                              'error': {'code': 'unauthenticated', 'message': 'Sign in first.'}}
    assert '[Touchque] error_body failed: boom' in [r.getMessage() for r in caplog.records]


def test_error_body_keeps_status_and_retry_after(fake_api):
    fake_api.link('jane@acme.com')
    fake_api.opts(frozen=True)
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    res = make_guarded_app([], client=tq, error_body=lambda r: {'code': r['code'], 'message': r['message']}) \
        .test_client().post('/transfer', json={}, headers={'X-User': 'jane@acme.com'})
    assert res.status_code == 423
    assert res.headers['Retry-After'] == '900' and res.headers['Cache-Control'] == 'no-store'
    assert res.get_json() == {'code': 'frozen', 'message': 'Too many rejected approvals. Try again later.',
                              'touchque': {'state': 'frozen', 'retryAfter': 900, 'caseCode': 'REF-USE'}}


# ── round 2: refusal headers, what counts as an object ──────────────────

UNAUTHENTICATED_STEP = {'state': 'blocked', 'reason': 'unauthenticated'}


@dataclasses.dataclass
class Problem:
    code: str
    message: str


def test_refusals_carry_the_touchque_state_headers():
    tq = FakeTouchque()
    client = make_guarded_app([], client=tq, error_body=lambda r: 'refused').test_client()
    anonymous = client.post('/transfer', json={})
    assert anonymous.status_code == 401 and anonymous.get_json() == 'refused'
    assert anonymous.headers['X-Touchque-State'] == 'blocked'
    assert anonymous.headers['X-Touchque-Reason'] == 'unauthenticated'
    first = client.post('/transfer', json={}, headers={'X-User': 'jane@acme.com'})
    assert first.status_code == 202 and 'X-Touchque-State' not in first.headers
    tq.reject()
    res = client.post('/transfer', json={}, headers={'X-User': 'jane@acme.com',
                                                      'X-Touchque-Token': first.get_json()['token']})
    assert res.status_code == 403 and res.headers['X-Touchque-State'] == 'rejected'
    assert 'X-Touchque-Reason' not in res.headers


def test_error_body_counts_by_its_json_encoding():
    res = make_guarded_app([], client=FakeTouchque(), error_body=lambda r: Problem(r['code'], r['message'])) \
        .test_client().post('/transfer', json={})
    assert res.status_code == 401
    assert res.get_json() == {'code': 'unauthenticated', 'message': 'Sign in first.', 'touchque': UNAUTHENTICATED_STEP}


def test_error_body_with_a_pydantic_model():
    pydantic = pytest.importorskip('pydantic')

    class Model(pydantic.BaseModel):
        code: str

    res = make_guarded_app([], client=FakeTouchque(), error_body=lambda r: Model(code=r['code'])) \
        .test_client().post('/transfer', json={})
    assert res.status_code == 401 and res.get_json() == {'code': 'unauthenticated', 'touchque': UNAUTHENTICATED_STEP}


def test_error_body_that_cannot_be_encoded_sends_the_default_body(caplog):
    with caplog.at_level(logging.ERROR, logger='touchque'):
        res = make_guarded_app([], client=FakeTouchque(), error_body=lambda r: {r['code']}) \
            .test_client().post('/transfer', json={})
    assert res.status_code == 401 and res.headers['Content-Type'] == 'application/json'
    assert res.get_json() == {'touchque': UNAUTHENTICATED_STEP,
                              'error': {'code': 'unauthenticated', 'message': 'Sign in first.'}}
    assert any(r.getMessage().startswith('[Touchque] error_body failed: ') for r in caplog.records)


def test_error_body_gets_a_deep_copy_of_the_step():
    def meddle(refusal):
        refusal['touchque']['state'] = 'approved'
        refusal['touchque']['details'][0]['value'] = '1 EUR'  # nested: a shallow copy would leak it
        return {'code': refusal['code']}

    tq = FakeTouchque()
    client = make_guarded_app([], client=tq, details=lambda: {'Amount': '5 EUR'}, error_body=meddle).test_client()
    first = client.post('/transfer', json={}, headers={'X-User': 'jane@acme.com'})
    tq.reject()
    res = client.post('/transfer', json={}, headers={'X-User': 'jane@acme.com',
                                                      'X-Touchque-Token': first.get_json()['token']})
    assert res.status_code == 403 and res.headers['X-Touchque-State'] == 'rejected'
    assert res.get_json() == {'code': 'rejected', 'touchque': {
        'state': 'rejected', 'requestId': tq.requests[-1]['id'], 'details': [{'label': 'Amount', 'value': '5 EUR'}]}}


# ── guard_response: the decorator sends what this module's helper gives ──

@pytest.mark.parametrize('error_body_name', ERROR_BODIES)
def test_the_decorator_sends_what_its_guard_response_gives(monkeypatch, error_body_name):
    from touchque.contrib import flask as adapter
    error_body = ERROR_BODIES[error_body_name]
    for result_name in GUARD_RESULTS:
        monkeypatch.setattr(adapter, 'run_guard', lambda *a, _name=result_name, **k: result_named(_name))
        app = make_guarded_app([], client=FakeTouchque(), error_body=error_body)
        res = app.test_client().post('/transfer', json={}, headers={'X-User': 'jane@acme.com'})
        with app.app_context():  # as in a view: the app's JSON provider encodes
            want = adapter.guard_response(result_named(result_name), error_body)
        assert res.headers['Content-Type'] == 'application/json', result_name
        assert sent(res.status_code, res.headers.get, res.get_json()) == want, result_name


def test_dates_decimals_and_uuids_are_encoded_like_the_app_does():
    """Not the default body: the decorator and this module's guard_response both use the app's JSON provider."""
    from touchque.contrib import flask as adapter
    step = {'state': 'rejected', 'requestId': 'r1'}
    for name, want in (('datetime', {'code': 'rejected', 'at': 'Thu, 12 Nov 2026 10:05:00 GMT', 'touchque': step}),
                       ('decimal', {'code': 'rejected', 'amount': '1.50', 'touchque': step}),
                       ('uuid', {'code': 'rejected', 'id': '12345678-1234-5678-1234-567812345678', 'touchque': step})):
        error_body = ERROR_BODIES[name]
        app = make_guarded_app([], client=FakeTouchque(), error_body=error_body)
        with app.app_context():
            status, headers, body = adapter.guard_response(result_named('403 rejected'), error_body)
        assert (status, body) == (403, want), name
        original = adapter.run_guard
        adapter.run_guard = lambda *a, **k: result_named('403 rejected')
        try:
            res = app.test_client().post('/transfer', json={}, headers={'X-User': 'jane@acme.com'})
        finally:
            adapter.run_guard = original
        assert res.status_code == 403 and res.get_json() == want, name
