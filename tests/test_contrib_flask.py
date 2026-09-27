import pytest

flask = pytest.importorskip('flask')

from touchque import Config, TouchQue
from touchque.contrib.flask import require_touchque
from .fake_api import fake_api  # noqa: F401


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
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    client = make_app(tq).test_client()

    first = client.post('/transfer', json={'amount': 5}, headers={'X-User': 'jane@acme.com'})
    assert first.status_code == 202
    assert first.get_json()['touchque']['number'] == '47'
    token = first.get_json()['token']

    fake_api.approve()
    done = client.post('/transfer', json={'amount': 5}, headers={'X-User': 'jane@acme.com', 'X-TouchQue-Token': token})
    assert done.status_code == 200
    assert done.get_json()['done'] is True

    replay = client.post('/transfer', json={'amount': 5}, headers={'X-User': 'jane@acme.com', 'X-TouchQue-Token': token})
    assert replay.status_code != 200


def test_no_user_is_401(fake_api):
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    client = make_app(tq).test_client()
    res = client.post('/transfer', json={'amount': 5})
    assert res.status_code == 401
