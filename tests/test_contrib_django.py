import json

import pytest

django = pytest.importorskip('django')
from django.conf import settings as _settings
if not _settings.configured:  # test_relay_django.py may have configured it already
    _settings.configure(DEBUG=True, ALLOWED_HOSTS=['*'], DEFAULT_CHARSET='utf-8')
    import django as _django
    _django.setup()

from django.test import RequestFactory  # noqa: E402

from touchque import Config, TouchQue  # noqa: E402
from touchque.contrib.django import require_touchque  # noqa: E402
from .fake_api import fake_api  # noqa: F401,E402


def make_view(tq, action='SEND_MONEY'):
    @require_touchque(action, client=tq, user=lambda req: req.headers.get('X-User'),
                       details=lambda req: {'Amount': '5 EUR'})
    def transfer(request):
        from django.http import JsonResponse
        return JsonResponse({'done': True, 'touchque': request.touchque})
    return transfer


def test_full_flow(fake_api):
    fake_api.link('jane@acme.com')
    fake_api.opts(numberMatch=True)
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    view = make_view(tq)
    rf = RequestFactory()

    first = view(rf.post('/transfer', data=b'{}', content_type='application/json', HTTP_X_USER='jane@acme.com'))
    assert first.status_code == 202
    body = json.loads(first.content)
    assert body['touchque']['number'] == '47'

    fake_api.approve()
    done = view(rf.post('/transfer', data=b'{}', content_type='application/json',
                         HTTP_X_USER='jane@acme.com', HTTP_X_TOUCHQUE_TOKEN=body['token']))
    assert done.status_code == 200
    assert json.loads(done.content)['done'] is True


def test_silent_sign_in_runs_the_view_at_once_for_a_known_browser(fake_api):
    from .silent_vectors import PROOF
    from django.http import JsonResponse

    fake_api.link('jane@acme.com')
    fake_api.opts(silent=True)
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))

    @require_touchque('LOGIN', client=tq, user=lambda req: 'jane@acme.com', silent_sign_in=True)
    def login(request):
        return JsonResponse({'done': True, 'touchque': request.touchque})

    res = login(RequestFactory().post('/login/2fa', data=b'{}', content_type='application/json',
                                      HTTP_X_TOUCHQUE_BROWSER=PROOF))
    assert res.status_code == 200
    body = json.loads(res.content)
    assert body['touchque']['confirmedVia'] == 'SILENT'
    assert [r['code'] for r in body['touchque']['reasons']][0] == 'known_browser'
    assert fake_api.last_check()['browserProof'] == PROOF
