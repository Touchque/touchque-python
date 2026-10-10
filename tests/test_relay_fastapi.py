"""FastAPI adapter for the relay: touchque.contrib.fastapi.touchque_relay_router."""
import pytest

fastapi = pytest.importorskip('fastapi')
httpx = pytest.importorskip('httpx')

from touchque import TouchQueAPIException  # noqa: E402
from touchque.contrib.fastapi import touchque_relay_router  # noqa: E402
from .fake_api import fake_api  # noqa: F401,E402
from .relay_helpers import fake_tq, real_tq  # noqa: E402


def client_for(tq, **options):
    options.setdefault('get_user_id', lambda req: req.headers.get('x-user'))
    app = fastapi.FastAPI()
    app.include_router(touchque_relay_router(tq, **options), prefix='/touchque')
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test')


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.mark.anyio
async def test_auth_required_401_and_unknown_404():
    async with client_for(fake_tq()) as c:
        res = await c.post('/touchque/passkey/register/options')
        assert res.status_code == 401 and res.json()['error'] == 'UNAUTHORIZED_FOR_2FA'
        assert (await c.get('/touchque/nope')).status_code == 404


@pytest.mark.anyio
async def test_login_flow_with_async_callbacks_sets_cookie(fake_api):
    fake_api.link('alice@example.com')
    calls = []

    async def login_user(req):
        return req.headers.get('x-password-ok')

    async def opened(req, resp, info):
        calls.append(info)
        resp.set_cookie('tq_session', 'opened')

    async with client_for(real_tq(fake_api), rate_limit=False, get_login_user=login_user,
                          on_authenticated=opened) as c:
        res = await c.post('/touchque/login', json={'externalUsername': 'victim@example.com'})
        assert res.status_code == 401 and res.json()['error'] == 'FIRST_FACTOR_REQUIRED'
        hdr = {'x-password-ok': 'alice@example.com'}
        first = await c.post('/touchque/login', json={'externalUsername': 'victim@example.com'}, headers=hdr)
        assert first.status_code == 202 and first.headers['cache-control'] == 'no-store'
        fake_api.approve()
        done = await c.post('/touchque/login', json={},
                            headers=dict(hdr, **{'x-touchque-token': first.json()['token']}))
        assert done.status_code == 200 and done.json()['status'] == 'success'
        assert 'tq_session=opened' in done.headers.get('set-cookie', '')
        assert done.headers['content-type'] == 'application/json'
    assert calls == [{'externalUsername': 'alice@example.com', 'requestId': first.json()['touchque']['requestId'],
                      'via': 'login'}]


@pytest.mark.anyio
async def test_rate_limit_429_with_retry_after():
    async with client_for(fake_tq(), rate_limit={'per_ip': 1}) as c:
        assert (await c.post('/touchque/passkey/authenticate/verify', json={})).status_code == 200
        res = await c.post('/touchque/passkey/authenticate/verify', json={})
        assert res.status_code == 429 and int(res.headers['retry-after']) > 0


@pytest.mark.anyio
async def test_mismatch_delete_and_error_mapping():
    tq = fake_tq()
    tq.webauthn.authenticate_verify.return_value = {'success': True, 'externalUsername': 'other@example.com'}
    async with client_for(tq, get_login_user=lambda req: 'alice@example.com', rate_limit=False) as c:
        res = await c.post('/touchque/passkey/login/verify', json={'requestId': 'r', 'response': {}})
        assert res.status_code == 401 and res.json() == {'error': 'verification_failed'}
        res = await c.delete('/touchque/passkey/credentials/cred_1', headers={'x-user': 'u@example.com'})
        assert res.json() == {'deleted': True}
        tq.webauthn.delete_credential.assert_called_once_with('cred_1', external_username='u@example.com')
        tq.auth.generate_secret.side_effect = TouchQueAPIException('internal text', status=422, code='bad_user')
        res = await c.post('/touchque/enroll/start', headers={'x-user': 'u@example.com'})
        assert res.status_code == 422 and res.json() == {'error': 'bad_user'}
        # get_login_user enables the offline routes and binds them to the first-factor user.
        res = await c.post('/touchque/offline/totp', json={'externalUsername': 'victim@example.com', 'code': '1'})
        assert res.status_code == 200
        assert tq.offline.verify_totp.call_args[0][0] == 'alice@example.com'
