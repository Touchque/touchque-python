import dataclasses
import json

import pytest

django = pytest.importorskip('django')
from django.conf import settings as _settings
if not _settings.configured:  # test_relay_django.py may have configured it already
    _settings.configure(DEBUG=True, ALLOWED_HOSTS=['*'], DEFAULT_CHARSET='utf-8')
    import django as _django
    _django.setup()

from django.test import RequestFactory  # noqa: E402

from touchque import Config, Touchque  # noqa: E402
from touchque.contrib.django import require_touchque  # noqa: E402
from touchque.testing import FakeTouchque  # noqa: E402
from .fake_api import fake_api  # noqa: F401,E402
from .guard_helpers import MISCONFIGURED, no_keys  # noqa: F401,E402


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
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
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
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))

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


def make_guarded_view(ran, **options):
    @require_touchque('SEND_MONEY', user=lambda req: req.headers.get('X-User'), **options)
    def transfer(request):
        from django.http import JsonResponse
        ran.append(True)
        return JsonResponse({'done': True})
    return transfer


def post(view, **headers):
    return view(RequestFactory().post('/transfer', data=b'{}', content_type='application/json', **headers))


def test_without_keys_the_view_answers_500_misconfigured_and_never_runs(no_keys):
    ran = []
    view = make_guarded_view(ran)  # no client: nothing raised at import
    res = post(view, HTTP_X_USER='jane@acme.com')
    assert res.status_code == 500
    assert json.loads(res.content) == MISCONFIGURED
    assert res['Cache-Control'] == 'no-store'
    anonymous = post(view)
    assert anonymous.status_code == 401 and json.loads(anonymous.content)['error']['code'] == 'unauthenticated'
    assert ran == []


def test_error_body_object_is_merged_and_anything_else_sent_as_it_is():
    tq, seen = FakeTouchque(), []

    def body(refusal):
        seen.append(refusal['status'])
        return {'message': refusal['message'], 'code': refusal['code']}

    view = make_guarded_view([], client=tq, error_body=body)
    first = post(view, HTTP_X_USER='jane@acme.com')
    assert first.status_code == 202 and seen == []
    tq.expire()
    res = post(view, HTTP_X_USER='jane@acme.com', HTTP_X_TOUCHQUE_TOKEN=json.loads(first.content)['token'])
    assert res.status_code == 408 and res['Cache-Control'] == 'no-store'
    assert json.loads(res.content) == {'message': 'The approval expired. Try again.', 'code': 'expired',
                                       'touchque': {'state': 'expired', 'requestId': tq.requests[-1]['id']}}
    assert seen == [408]

    listed = post(make_guarded_view([], client=tq, error_body=lambda r: [r['code']]))
    assert listed.status_code == 401 and json.loads(listed.content) == ['unauthenticated']


@dataclasses.dataclass
class Problem:
    code: str
    message: str


def test_refusal_headers_and_error_body_by_its_json_encoding():
    step = {'state': 'blocked', 'reason': 'unauthenticated'}
    res = post(make_guarded_view([], client=FakeTouchque(), error_body=lambda r: Problem(r['code'], r['message'])))
    assert res.status_code == 401
    assert json.loads(res.content) == {'code': 'unauthenticated', 'message': 'Sign in first.', 'touchque': step}
    assert res['X-Touchque-State'] == 'blocked' and res['X-Touchque-Reason'] == 'unauthenticated'

    broken = post(make_guarded_view([], client=FakeTouchque(), error_body=lambda r: {r['code']}))
    assert broken.status_code == 401 and json.loads(broken.content) == {
        'touchque': step, 'error': {'code': 'unauthenticated', 'message': 'Sign in first.'}}

    tq = FakeTouchque()
    view = make_guarded_view([], client=tq)
    first = post(view, HTTP_X_USER='jane@acme.com')
    assert first.status_code == 202 and not first.has_header('X-Touchque-State')
    tq.reject()
    res = post(view, HTTP_X_USER='jane@acme.com', HTTP_X_TOUCHQUE_TOKEN=json.loads(first.content)['token'])
    assert res.status_code == 403 and res['X-Touchque-State'] == 'rejected' and not res.has_header('X-Touchque-Reason')
