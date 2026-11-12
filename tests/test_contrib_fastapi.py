import dataclasses

import pytest

fastapi = pytest.importorskip('fastapi')
httpx = pytest.importorskip('httpx')

from fastapi import Depends, Request

from touchque import Config, Touchque
from touchque.contrib.fastapi import RequireTouchque, install_touchque_exception_handler
from touchque.testing import FakeTouchque
from .fake_api import fake_api  # noqa: F401
from .guard_helpers import MISCONFIGURED, no_keys  # noqa: F401


def make_app(tq):
    app = fastapi.FastAPI()

    async def user(request: Request):
        return request.headers.get('x-user')

    @app.post('/transfer')
    async def transfer(request: Request, body: dict, touchque=Depends(
        RequireTouchque('SEND_MONEY', client=tq, user=user, details=lambda req: {'Amount': '5 EUR'})
    )):
        return {'done': True, 'touchque': touchque}

    return app


@pytest.mark.anyio
async def test_full_flow(fake_api):
    fake_api.link('jane@acme.com')
    fake_api.opts(numberMatch=True)
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
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
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    app = fastapi.FastAPI()

    @app.post('/login/2fa')
    async def login(touchque=Depends(RequireTouchque('LOGIN', client=tq, user=lambda req: 'jane@acme.com',
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
    tq = Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
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


def make_guarded_app(ran, flat=True, **options):
    app = fastapi.FastAPI()
    if flat:
        install_touchque_exception_handler(app)

    async def user(request: Request):
        return request.headers.get('x-user')

    @app.post('/transfer')
    async def transfer(touchque=Depends(RequireTouchque('SEND_MONEY', user=user, **options))):
        ran.append(True)
        return {'done': True}

    return app


async def post(app, headers=None):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        return await client.post('/transfer', json={}, headers=headers or {})


@pytest.mark.anyio
async def test_without_keys_the_route_answers_500_misconfigured_and_never_runs(no_keys):
    ran = []
    app = make_guarded_app(ran)  # no client: nothing raised at startup
    res = await post(app, {'x-user': 'jane@acme.com'})
    assert res.status_code == 500
    assert res.json() == MISCONFIGURED
    assert res.headers['cache-control'] == 'no-store'
    anonymous = await post(app)
    assert anonymous.status_code == 401 and anonymous.json()['error']['code'] == 'unauthenticated'
    assert ran == []

    wrapped = await post(make_guarded_app(ran, flat=False), {'x-user': 'jane@acme.com'})
    assert wrapped.status_code == 500 and wrapped.json() == {'detail': MISCONFIGURED}
    assert ran == []


@pytest.mark.anyio
async def test_error_body_object_is_merged_and_anything_else_sent_as_it_is():
    tq, seen = FakeTouchque(), []

    def body(refusal):
        seen.append(refusal['status'])
        return {'message': refusal['message'], 'code': refusal['code']}

    app = make_guarded_app([], client=tq, error_body=body)
    first = await post(app, {'x-user': 'jane@acme.com'})
    assert first.status_code == 202 and first.json()['touchque']['state'] == 'waiting'
    assert seen == []
    tq.reject()
    res = await post(app, {'x-user': 'jane@acme.com', 'x-touchque-token': first.json()['token']})
    assert res.status_code == 403 and res.headers['cache-control'] == 'no-store'
    assert res.json() == {'message': 'The approval was rejected.', 'code': 'rejected',
                          'touchque': {'state': 'rejected', 'requestId': tq.requests[-1]['id']}}
    assert seen == [403]

    for custom in ('Sign in first', None):
        plain = await post(make_guarded_app([], client=tq, error_body=lambda r: custom))
        assert plain.status_code == 401 and plain.json() == custom


@dataclasses.dataclass
class Problem:
    code: str
    message: str


@pytest.mark.anyio
async def test_refusal_headers_and_error_body_by_its_json_encoding():
    step = {'state': 'blocked', 'reason': 'unauthenticated'}

    async def shaped(refusal):  # async, and a dataclass
        return Problem(refusal['code'], refusal['message'])

    res = await post(make_guarded_app([], client=FakeTouchque(), error_body=shaped))
    assert res.status_code == 401
    assert res.json() == {'code': 'unauthenticated', 'message': 'Sign in first.', 'touchque': step}
    assert res.headers['x-touchque-state'] == 'blocked' and res.headers['x-touchque-reason'] == 'unauthenticated'

    pydantic = pytest.importorskip('pydantic')

    class Model(pydantic.BaseModel):
        code: str

    modelled = await post(make_guarded_app([], client=FakeTouchque(), error_body=lambda r: Model(code=r['code'])))
    assert modelled.json() == {'code': 'unauthenticated', 'touchque': step}

    class Aliased(pydantic.BaseModel):  # FastAPI's own encoding: the aliases, as for a response_model
        error_code: str = pydantic.Field(alias='errorCode')

    aliased = await post(make_guarded_app([], client=FakeTouchque(),
                                          error_body=lambda r: Aliased(errorCode=r['code'])))
    assert aliased.json() == {'errorCode': 'unauthenticated', 'touchque': step}

    broken = await post(make_guarded_app([], client=FakeTouchque(), error_body=lambda r: object()))
    assert broken.status_code == 401 and broken.headers['cache-control'] == 'no-store'
    assert broken.json() == {'touchque': step, 'error': {'code': 'unauthenticated', 'message': 'Sign in first.'}}

    tq = FakeTouchque()
    app = make_guarded_app([], client=tq)
    first = await post(app, {'x-user': 'jane@acme.com'})
    assert first.status_code == 202 and 'x-touchque-state' not in first.headers
    tq.reject()
    res = await post(app, {'x-user': 'jane@acme.com', 'x-touchque-token': first.json()['token']})
    assert res.status_code == 403 and res.headers['x-touchque-state'] == 'rejected'
    assert 'x-touchque-reason' not in res.headers


@pytest.fixture
def anyio_backend():
    return 'asyncio'
