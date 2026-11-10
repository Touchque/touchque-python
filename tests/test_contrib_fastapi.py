import pytest

fastapi = pytest.importorskip('fastapi')
httpx = pytest.importorskip('httpx')

from fastapi import Depends, Request

from touchque import Config, TouchQue
from touchque.contrib.fastapi import RequireTouchQue
from .fake_api import fake_api  # noqa: F401


def make_app(tq):
    app = fastapi.FastAPI()

    async def user(request: Request):
        return request.headers.get('x-user')

    @app.post('/transfer')
    async def transfer(request: Request, body: dict, touchque=Depends(
        RequireTouchQue('SEND_MONEY', client=tq, user=user, details=lambda req: {'Amount': '5 EUR'})
    )):
        return {'done': True, 'touchque': touchque}

    return app


@pytest.mark.anyio
async def test_full_flow(fake_api):
    fake_api.link('jane@acme.com')
    fake_api.opts(numberMatch=True)
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app(tq)), base_url='http://test') as client:
        first = await client.post('/transfer', json={'amount': 5}, headers={'x-user': 'jane@acme.com'})
        assert first.status_code == 202
        assert first.json()['detail']['touchque']['number'] == '47'
        token = first.json()['detail']['token']

        fake_api.approve()
        done = await client.post('/transfer', json={'amount': 5}, headers={'x-user': 'jane@acme.com', 'x-touchque-token': token})
        assert done.status_code == 200
        assert done.json()['done'] is True



@pytest.mark.anyio
async def test_silent_sign_in_resolves_at_once_for_a_known_browser(fake_api):
    from .silent_vectors import PROOF
    fake_api.link('jane@acme.com')
    fake_api.opts(silent=True)
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    app = fastapi.FastAPI()

    @app.post('/login/2fa')
    async def login(touchque=Depends(RequireTouchQue('LOGIN', client=tq, user=lambda req: 'jane@acme.com',
                                                      silent_sign_in={'max_age_seconds': 3600}))):
        return {'method': touchque['assurance']['method'], 'reasons': len(touchque['reasons'])}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        res = await client.post('/login/2fa', headers={'x-touchque-browser': PROOF})
    assert res.status_code == 200
    assert res.json() == {'method': 'silent', 'reasons': 5}
    assert fake_api.last_check()['maxAgeSeconds'] == 3600


@pytest.mark.anyio
async def test_the_exception_handler_flattens_touchque_and_leaves_other_errors_to_fastapi(fake_api):
    from fastapi import HTTPException
    from touchque.contrib.fastapi import install_touchque_exception_handler
    fake_api.link('jane@acme.com')
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    app = make_app(tq)
    install_touchque_exception_handler(app)

    @app.get('/cached')
    async def cached():
        raise HTTPException(status_code=304)

    @app.get('/missing')
    async def missing():
        raise HTTPException(status_code=404, detail='nope')

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        first = await client.post('/transfer', json={'amount': 5}, headers={'x-user': 'jane@acme.com'})
        assert first.status_code == 202 and first.json()['touchque']['state'] == 'waiting'
        not_modified = await client.get('/cached')
        assert not_modified.status_code == 304 and not_modified.content == b''
        not_found = await client.get('/missing')
        assert not_found.status_code == 404 and not_found.json() == {'detail': 'nope'}


@pytest.fixture
def anyio_backend():
    return 'asyncio'
