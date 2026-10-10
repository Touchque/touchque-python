"""Django adapter for the relay: touchque.contrib.django.touchque_relay_urls."""
import json
from types import ModuleType

import pytest

django = pytest.importorskip('django')
from django.conf import settings as _settings  # noqa: E402
if not _settings.configured:
    _settings.configure(DEBUG=True, ALLOWED_HOSTS=['*'], DEFAULT_CHARSET='utf-8')
    import django as _django
    _django.setup()

from django.http import Http404  # noqa: E402
from django.test import RequestFactory  # noqa: E402
from django.urls import include, path, resolve  # noqa: E402

from touchque import TouchQueAPIException  # noqa: E402
from touchque.contrib.django import touchque_relay_urls  # noqa: E402
from .fake_api import fake_api  # noqa: F401,E402
from .relay_helpers import fake_tq, real_tq  # noqa: E402

rf = RequestFactory()


def make(tq, **options):
    options.setdefault('get_user_id', lambda req: req.headers.get('X-User'))
    conf = ModuleType('relay_test_urls')  # a urlconf: any hashable object with `urlpatterns`
    conf.urlpatterns = [path('touchque/', include(touchque_relay_urls(tq, **options)))]

    def send(method, url, body=None, session=None, **extra):
        kwargs = {'content_type': 'application/json'} if body is not None else {}
        data = json.dumps(body) if body is not None else None
        factory = getattr(rf, method.lower())
        req = factory(url, data, **kwargs, **extra) if data is not None else factory(url, **extra)
        req.session = session if session is not None else {}
        match = resolve(url, urlconf=conf)
        return match.func(req, *match.args, **match.kwargs)
    return send


def body(res):
    return json.loads(res.content)


def test_auth_required_401_and_unknown_404():
    send = make(fake_tq())
    res = send('POST', '/touchque/enroll/start')
    assert res.status_code == 401 and body(res)['error'] == 'UNAUTHORIZED_FOR_2FA'
    with pytest.raises(Http404):
        send('GET', '/touchque/nope')


def test_login_flow_on_authenticated_sets_cookie_and_session(fake_api):
    fake_api.link('alice@example.com')
    calls = []

    def opened(req, resp, info):
        calls.append(info)
        req.session['user'] = info['externalUsername']
        resp.set_cookie('tq_session', 'opened')

    send = make(real_tq(fake_api), rate_limit=False, on_authenticated=opened,
                get_login_user=lambda req: req.session.get('password_ok'))
    session = {'password_ok': 'alice@example.com'}
    first = send('POST', '/touchque/login', {'externalUsername': 'victim@example.com'}, session=session)
    assert first.status_code == 202 and first['Cache-Control'] == 'no-store'
    pushes = [c['body']['externalUsername'] for c in fake_api.calls() if c['path'] == '/login/request']
    assert pushes == ['alice@example.com']
    fake_api.approve()
    done = send('POST', '/touchque/login', {}, session=session, HTTP_X_TOUCHQUE_TOKEN=body(first)['token'])
    assert done.status_code == 200 and body(done)['status'] == 'success'
    assert done.cookies['tq_session'].value == 'opened'
    assert session['user'] == 'alice@example.com'
    assert len(calls) == 1 and calls[0]['via'] == 'login'


def test_rate_limit_429_with_retry_after():
    send = make(fake_tq(), allow_offline_without_first_factor=True, rate_limit={'per_ip': 1})
    assert send('POST', '/touchque/offline/challenge', {'externalUsername': 'a@example.com'}).status_code == 200
    res = send('POST', '/touchque/offline/challenge', {'externalUsername': 'b@example.com'})
    assert res.status_code == 429 and int(res['Retry-After']) > 0


def test_offline_disabled_403_delete_credential_and_errors():
    tq = fake_tq()
    send = make(tq)
    assert send('POST', '/touchque/offline/verify', {'challengeId': 'c', 'code': 'x'}).status_code == 403
    res = send('DELETE', '/touchque/passkey/credentials/cred_1', HTTP_X_USER='u@example.com')
    assert body(res) == {'deleted': True}
    tq.webauthn.delete_credential.assert_called_once_with('cred_1', external_username='u@example.com')
    tq.webauthn.register_options.side_effect = TouchQueAPIException('internal', status=500)
    res = send('POST', '/touchque/passkey/register/options', HTTP_X_USER='u@example.com')
    assert res.status_code == 502 and body(res) == {'error': 'relay_error'}


def test_csrf_exempt_option():
    from touchque.contrib.django import touchque_relay_view
    assert getattr(touchque_relay_view(fake_tq(), get_user_id=lambda r: None, csrf_exempt=True),
                   'csrf_exempt', False) is True
    assert not getattr(touchque_relay_view(fake_tq(), get_user_id=lambda r: None), 'csrf_exempt', False)
