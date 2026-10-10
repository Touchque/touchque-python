"""Flask adapter for the relay: touchque.contrib.flask.touchque_relay_blueprint."""
import pytest

flask = pytest.importorskip('flask')

from touchque import TouchQueAPIException  # noqa: E402
from touchque.contrib.flask import touchque_relay_blueprint  # noqa: E402
from .fake_api import fake_api  # noqa: F401,E402
from .relay_helpers import fake_tq, real_tq  # noqa: E402


def make_app(tq, **options):
    app = flask.Flask(__name__)
    app.secret_key = 'test'
    options.setdefault('get_user_id', lambda req: req.headers.get('X-User'))
    app.register_blueprint(touchque_relay_blueprint(tq, **options), url_prefix='/touchque')
    return app


def test_auth_required_401_and_unknown_404():
    client = make_app(fake_tq()).test_client()
    res = client.post('/touchque/enroll/start')
    assert res.status_code == 401
    assert res.get_json()['error'] == 'UNAUTHORIZED_FOR_2FA'
    assert client.get('/touchque/nope').status_code == 404


def test_login_flow_on_authenticated_sets_cookie_and_session(fake_api):
    fake_api.link('alice@example.com')
    seen = []

    def opened(req, resp, info):
        seen.append(info)
        assert req is flask.request._get_current_object()
        flask.session['user'] = info['externalUsername']
        resp.set_cookie('tq_session', 'opened')

    app = make_app(real_tq(fake_api), rate_limit=False, on_authenticated=opened,
                   get_login_user=lambda req: flask.session.get('password_ok'))

    @app.post('/password')
    def password():
        flask.session['password_ok'] = 'alice@example.com'
        return 'ok'

    client = app.test_client()
    assert client.post('/touchque/login', json={'externalUsername': 'victim@example.com'}).status_code == 401
    client.post('/password')
    first = client.post('/touchque/login', json={'externalUsername': 'victim@example.com'})
    assert first.status_code == 202
    assert first.headers['Cache-Control'] == 'no-store'
    fake_api.approve()
    done = client.post('/touchque/login', json={}, headers={'X-TouchQue-Token': first.get_json()['token']})
    assert done.status_code == 200
    assert done.get_json()['status'] == 'success'
    assert 'tq_session=opened' in done.headers.get('Set-Cookie', '')
    assert seen == [{'externalUsername': 'alice@example.com', 'requestId': first.get_json()['touchque']['requestId'],
                     'via': 'login'}]
    with client.session_transaction() as sess:
        assert sess['user'] == 'alice@example.com'


def test_rate_limit_429_with_retry_after():
    tq = fake_tq()
    tq.offline.verify.return_value = {'approved': False, 'reason': 'invalid_code', 'attemptsLeft': 3}
    client = make_app(tq, allow_offline_without_first_factor=True, rate_limit={'per_ip': 2}).test_client()
    env = {'REMOTE_ADDR': '203.0.113.7'}
    codes = [client.post('/touchque/offline/verify', json={'challengeId': 'c1', 'code': 'A'}, environ_base=env)
             for _ in range(3)]
    assert [r.status_code for r in codes] == [401, 401, 429]
    assert int(codes[2].headers['Retry-After']) > 0
    assert codes[2].get_json()['error'] == 'RATE_LIMITED'


def test_offline_disabled_403_and_delete_credential():
    tq = fake_tq()
    client = make_app(tq).test_client()
    res = client.post('/touchque/offline/challenge', json={'externalUsername': 'v@example.com'})
    assert res.status_code == 403
    res = client.delete('/touchque/passkey/credentials/cred_1', headers={'X-User': 'u@example.com'})
    assert res.status_code == 200 and res.get_json() == {'deleted': True}
    tq.webauthn.delete_credential.assert_called_once_with('cred_1', external_username='u@example.com')


def test_passkey_login_verify_mismatch_and_error_mapping():
    tq = fake_tq()
    tq.webauthn.authenticate_verify.return_value = {'success': True, 'externalUsername': 'other@example.com'}
    client = make_app(tq, get_login_user=lambda req: 'alice@example.com', rate_limit=False).test_client()
    res = client.post('/touchque/passkey/login/verify', json={'requestId': 'r', 'response': {}})
    assert res.status_code == 401 and res.get_json() == {'error': 'verification_failed'}

    tq.webauthn.list_credentials.side_effect = TouchQueAPIException('secret text', status=403, code='forbidden')
    res = client.get('/touchque/passkey/credentials', headers={'X-User': 'u@example.com'})
    assert res.status_code == 403 and res.get_json() == {'error': 'forbidden'}
    tq.webauthn.list_credentials.side_effect = TouchQueAPIException('boom', status=503)
    res = client.get('/touchque/passkey/credentials', headers={'X-User': 'u@example.com'})
    assert res.status_code == 502 and res.get_json() == {'error': 'relay_error'}
