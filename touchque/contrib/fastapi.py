"""
FastAPI: one line per protected route, as a dependency.

    from fastapi import Depends, Request
    from touchque.contrib.fastapi import RequireTouchQue

    @app.post('/transfer')
    async def transfer(request: Request, touchque=Depends(
        RequireTouchQue('SEND_MONEY', details=lambda req: {'Amount': f'{req.state.amount} EUR'})
    )):
        return {'ok': True, 'touchque': touchque}

Until the user approves on their phone the dependency raises
``HTTPException(202, detail={"touchque": step, "token": ...})``. Your page
shows the step in its own design and sends the same request again with
header ``X-TouchQue-Token: <token>``. Once approved the dependency resolves
to the approval (once) and your route runs.

FastAPI's default exception handler puts that JSON under a top-level
``"detail"`` key (``{"detail": {"touchque": ..., "token": ...}}``) — unlike
the Django/Flask adapters, which return it at the top level. Call
``install_touchque_exception_handler(app)`` once at startup to flatten it and
match the other adapters exactly.

``run_guard`` makes a blocking HTTP call (the ``requests`` library); it runs
in FastAPI's threadpool via ``anyio.to_thread`` so it never blocks the event
loop.

Relay routes (POST /login, enrollment, offline codes, passkey ceremonies)
as one APIRouter - see ``touchque.relay.RelayHandler`` for every option.
Callbacks may be sync or async:

    from touchque.contrib.fastapi import touchque_relay_router

    async def opened(request, response, info):
        response.set_cookie('session', await create_session(info['externalUsername']))

    app.include_router(touchque_relay_router(
        tq,
        get_user_id=lambda req: req.session.get('user'),
        get_login_user=lambda req: req.session.get('password_ok'),
        on_authenticated=opened,
    ), prefix='/touchque')
"""
import json
from typing import Any, Awaitable, Callable, Optional

import anyio
import anyio.from_thread
import anyio.to_thread
import fastapi
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from ..client import TouchQue, get_default_client
from ..guard import SilentSignIn, guard_input_from_headers, run_guard, silent_input_from_headers
from ..relay import RELAY_ROUTES, RelayHandler
from ..steps import LoginDetails


async def _default_user(request: Request) -> Optional[str]:
    u = getattr(request.state, 'user', None)
    if u is None:
        return None
    if isinstance(u, str):
        return u
    return getattr(u, 'email', None) or getattr(u, 'id', None) or getattr(u, 'username', None)


def RequireTouchQue(  # noqa: N802 — reads as a dependency factory, PascalCase is idiomatic here
    action: str,
    client: Optional[TouchQue] = None,
    user: Optional[Callable[[Request], Any]] = None,
    details: Optional[Callable[[Request], Optional[LoginDetails]]] = None,
    reference_id: Optional[Callable[[Request], Any]] = None,
    silent_sign_in: SilentSignIn = False,
    context: Optional[Callable[[Request], Any]] = None,
) -> Callable[[Request], Any]:
    """
    ``user``: async or sync callable resolving who is approving from the
    request. Default: ``request.state.user``. For the login step, return the
    user who just passed your password check.

    ``silent_sign_in`` (default off): when on, a new attempt whose browser
    sent its device-bound key proof (``X-TouchQue-Browser``, added by
    ``@touchque/web`` with ``browserKey: true``) first asks TouchQue whether
    anything about it is new. If nothing is, the dependency resolves at once
    with no push (``approval['assurance']['method'] == 'silent'``,
    ``approval['reasons']``). Otherwise, and on any error, the usual push
    starts and its approval makes the browser known.
    ``{'max_age_seconds': n}`` sets your own limit on how long ago the last
    phone approval in that browser may be.

    ``context``: for your TouchQue Actions only (``event.context``), e.g. the
    user's roles. Never shown on the phone.
    """
    user_of = user or _default_user
    tq = client

    async def dependency(request: Request) -> Any:
        c = tq or get_default_client()
        uid = user_of(request)
        if hasattr(uid, '__await__'):
            uid = await uid
        det = details(request) if details else None
        if hasattr(det, '__await__'):
            det = await det
        ref = reference_id(request) if reference_id else None
        if hasattr(ref, '__await__'):
            ref = await ref
        ctx = context(request) if context else None
        if hasattr(ctx, '__await__'):
            ctx = await ctx

        result = await anyio.to_thread.run_sync(lambda: run_guard(
            c, uid, action, details=det, reference_id=ref, context=ctx,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get('user-agent'),
            **guard_input_from_headers(lambda name: request.headers.get(name)),
            **silent_input_from_headers(silent_sign_in, lambda name: request.headers.get(name)),
        ))
        if 'approved' in result:
            return result['approved']
        headers = {'Cache-Control': 'no-store'}
        retry = result['body']['touchque'].get('retryAfter')
        if retry:
            headers['Retry-After'] = str(retry)
        raise HTTPException(status_code=result['status'], detail=result['body'], headers=headers)

    return dependency


def install_touchque_exception_handler(app: fastapi.FastAPI) -> None:
    """Optional: makes a raised TouchQue step return the SAME JSON shape as
    the Django/Flask adapters (no ``{"detail": ...}`` wrapper)."""
    from fastapi import Request as _Request
    from fastapi.responses import JSONResponse

    @app.exception_handler(HTTPException)
    async def _touchque_exception_handler(request: _Request, exc: HTTPException):  # type: ignore[no-redef]
        if isinstance(exc.detail, dict) and 'touchque' in exc.detail:
            return JSONResponse(exc.detail, status_code=exc.status_code, headers=exc.headers)
        return JSONResponse({'detail': exc.detail}, status_code=exc.status_code, headers=exc.headers)


async def _await(awaitable: Awaitable[Any]) -> Any:
    return await awaitable


def _run_async(awaitable: Awaitable[Any]) -> Any:
    """Resolves an async callback's result from the relay's worker thread."""
    return anyio.from_thread.run(_await, awaitable)


def touchque_relay_router(
    client: Optional[TouchQue] = None,
    prefix: str = '',
    handler: Optional[RelayHandler] = None,
    **options: Any
) -> APIRouter:
    """An APIRouter with every relay route. ``options`` are ``RelayHandler``'s
    (``get_user_id`` is required); or pass a ready ``handler``. Callbacks may
    be sync or async.

    Callbacks get the Starlette ``Request``; ``on_authenticated(request,
    response, info)`` gets a ``fastapi.Response`` whose headers (e.g.
    ``response.set_cookie(...)``) are copied onto the JSON response - the same
    pattern as a FastAPI ``response: Response`` parameter - or it may write
    ``request.session``. ``request.client.host`` is the client IP the rate
    limiter uses: behind a proxy, run uvicorn with ``--proxy-headers``.
    The relay (blocking HTTP calls) runs in the threadpool.
    """
    relay = handler or RelayHandler(client, **options)
    router = APIRouter(prefix=prefix)

    def make_endpoint(method: str, sub: str) -> Callable[[Request], Awaitable[Response]]:
        async def endpoint(request: Request) -> Response:
            raw = await request.body()
            body = None
            if raw and request.headers.get('content-type', '').split(';')[0].strip() == 'application/json':
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
            native = Response()
            path = sub.replace('<id>', request.path_params.get('cred_id', ''))
            result = await anyio.to_thread.run_sync(lambda: relay.handle(
                method, path, body=body,
                ip=request.client.host if request.client else None,
                user_agent=request.headers.get('user-agent'),
                get_header=lambda name: request.headers.get(name),
                request=request, response=native, run_async=_run_async,
            ))
            if result is None:
                raise HTTPException(status_code=404)
            out = JSONResponse(result.body, status_code=result.status, headers=result.headers)
            out.raw_headers.extend(
                (k, v) for k, v in native.raw_headers if k not in (b'content-length', b'content-type'))
            return out
        return endpoint

    for method, sub in RELAY_ROUTES:
        router.add_api_route(sub.replace('<id>', '{cred_id}'), make_endpoint(method, sub), methods=[method],
                             include_in_schema=False)
    return router
