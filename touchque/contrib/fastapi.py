"""
FastAPI: one line per protected route, as a dependency.

    from fastapi import Depends, Request
    from touchque.contrib.fastapi import RequireTouchque

    @app.post('/transfer')
    async def transfer(request: Request, touchque=Depends(
        RequireTouchque('SEND_MONEY', details=lambda req: {'Amount': f'{req.state.amount} EUR'})
    )):
        return {'ok': True, 'touchque': touchque}

Until the user approves on their phone the dependency raises
``HTTPException(202, detail={"touchque": step, "token": ...})``. Your page
shows the step in its own design and sends the same request again with
header ``X-Touchque-Token: <token>``. Once approved the dependency resolves
to the approval (once) and your route runs.

FastAPI's default exception handler puts that JSON under a top-level
``"detail"`` key (``{"detail": {"touchque": ..., "token": ...}}``), where
``@touchque/web`` never sees the step. Call
``install_touchque_exception_handler(app)`` once at startup: it is REQUIRED
when your pages use ``@touchque/web``. It sends the answer at the top level,
like the Django/Flask adapters (also what ``error_body`` returns).

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
import inspect
import json
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

import anyio
import anyio.from_thread
import anyio.to_thread
import fastapi
from fastapi import APIRouter, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response

from ..client import Touchque
from ..guard import (
    ErrorBody, SilentSignIn, _custom_body, _error_body_failed, _refusal, guard_input_from_headers, run_guard,
    silent_input_from_headers,
)
from ..guard import guard_response as _guard_response
from ..relay import RELAY_ROUTES, RelayHandler
from ..steps import LoginDetails


class _GuardAnswer(HTTPException):
    """A step or refusal from ``RequireTouchque``: ``install_touchque_exception_handler``
    sends its body as it is, whatever its shape (``detail`` cannot be None)."""

    def __init__(self, status_code: int, body: Any, headers: Dict[str, str]):
        super().__init__(status_code=status_code, detail=body, headers=headers)
        self.touchque_body = body


def _encode(value: Any) -> str:
    """How FastAPI encodes a body: ``jsonable_encoder``, then ``JSONResponse``'s ``json.dumps``."""
    return json.dumps(jsonable_encoder(value), ensure_ascii=False, allow_nan=False, separators=(',', ':'))


async def guard_response(result: Dict[str, Any], error_body: Optional[Callable[[Dict[str, Any]], Any]] = None
                         ) -> Tuple[int, Dict[str, str], Any]:
    """What ``RequireTouchque`` sends for a ``run_guard`` result that is not
    an approval, as ``(status, headers, body)``, to await:
    ``touchque.guard_response`` with an async ``error_body`` awaited and its
    result encoded by ``jsonable_encoder`` (a pydantic model keeps its
    aliases), as the dependency does. For the guard inside your own route
    (``run_guard`` blocks: run it in a thread from an ``async def`` route)::

        result = await anyio.to_thread.run_sync(lambda: run_guard(None, user, 'SEND_MONEY', ...))
        if 'approved' not in result:
            status, headers, body = await guard_response(result, error_body)
            return JSONResponse(body, status_code=status, headers=headers)
    """
    status, headers, body = _guard_response(result)
    if error_body is None or status < 400:
        return status, headers, body
    try:
        custom = error_body(_refusal(result))
        if inspect.isawaitable(custom):
            custom = await custom
        return status, headers, _custom_body(result, custom, _encode, plain=False)
    except Exception as err:  # noqa: BLE001 - your callback must not turn a refusal into a crash
        return status, headers, _error_body_failed(result, err)


async def _default_user(request: Request) -> Optional[str]:
    u = getattr(request.state, 'user', None)
    if u is None:
        return None
    if isinstance(u, str):
        return u
    return getattr(u, 'email', None) or getattr(u, 'id', None) or getattr(u, 'username', None)


def RequireTouchque(  # noqa: N802 — reads as a dependency factory, PascalCase is idiomatic here
    action: str,
    client: Optional[Touchque] = None,
    user: Optional[Callable[[Request], Any]] = None,
    details: Optional[Callable[[Request], Optional[LoginDetails]]] = None,
    reference_id: Optional[Callable[[Request], Any]] = None,
    silent_sign_in: SilentSignIn = False,
    context: Optional[Callable[[Request], Any]] = None,
    error_body: Optional[ErrorBody] = None,
) -> Callable[[Request], Any]:
    """
    ``client``: default ``get_default_client()``, built from ``TQ_API_KEY`` /
    ``TQ_API_SECRET`` on the first request. Without them the route answers
    500 ``misconfigured`` (401 when nobody is signed in) and your route never
    runs; nothing is raised at startup.

    ``user``: async or sync callable resolving who is approving from the
    request. Default: ``request.state.user``. For the login step, return the
    user who just passed your password check.

    ``silent_sign_in`` (default off): when on, a new attempt whose browser
    sent its device-bound key proof (``X-Touchque-Browser``, added by
    ``@touchque/web`` with ``browserKey: true``) first asks Touchque whether
    anything about it is new. If nothing is, the dependency resolves at once
    with no push (``approval['assurance']['method'] == 'silent'``,
    ``approval['reasons']``). Otherwise, and on any error, the usual push
    starts and its approval makes the browser known.
    ``{'max_age_seconds': n}`` sets your own limit on how long ago the last
    phone approval in that browser may be.

    ``context``: for your Touchque Actions only (``event.context``), e.g. the
    user's roles. Never shown on the phone.

    ``error_body``: your app's own error shape for the refusals (401, 403,
    408, 423, 429, 500, 503), e.g.
    ``error_body=lambda r: {'message': r['message'], 'code': r['code']}``.
    It may be async. It gets ``{'status', 'code', 'message', 'touchque'}``;
    what it returns counts by FastAPI's JSON encoding (``jsonable_encoder``):
    an object (a dict, a pydantic model, a dataclass) is sent with
    ``touchque`` set to the step, anything else as it is. Status and headers
    stay, and every refusal carries ``X-Touchque-State`` (and
    ``X-Touchque-Reason``). Never called for a 202 step. With
    ``install_touchque_exception_handler`` it is the whole body; without it,
    FastAPI puts it under ``"detail"``. For ``run_guard`` in your own route,
    this module's awaitable ``guard_response`` gives the same answer.
    """
    user_of = user or _default_user
    tq = client

    async def dependency(request: Request) -> Any:
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
            tq, uid, action, details=det, reference_id=ref, context=ctx,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get('user-agent'),
            **guard_input_from_headers(lambda name: request.headers.get(name)),
            **silent_input_from_headers(silent_sign_in, lambda name: request.headers.get(name)),
        ))
        if 'approved' in result:
            return result['approved']
        status, headers, body = await guard_response(result, error_body)
        raise _GuardAnswer(status, body, headers)

    return dependency


def install_touchque_exception_handler(app: fastapi.FastAPI) -> None:
    """Required when your pages use ``@touchque/web``: without it a
    ``RequireTouchque`` step is sent as ``{"detail": {...}}`` and the page
    never sees it. Sends Touchque's steps and refusals with the SAME JSON
    shape as the Django/Flask adapters (no ``{"detail": ...}`` wrapper), and an
    ``error_body`` result exactly as returned.

    It handles only Touchque's answers (and an ``HTTPException`` whose
    ``detail`` is a dict with ``touchque``). Every other ``HTTPException``
    goes to FastAPI's default handler (``http_exception_handler``),
    unchanged (no body on a 204 or 304). It is registered for
    ``fastapi.HTTPException``, so it replaces your own handler for that
    class (one you register after it replaces it instead), and the
    ``fastapi.HTTPException``s you raise no longer reach a handler you set
    for Starlette's ``HTTPException``."""
    from fastapi import Request as _Request
    from fastapi.exception_handlers import http_exception_handler
    from fastapi.responses import JSONResponse

    @app.exception_handler(HTTPException)
    async def _touchque_exception_handler(request: _Request, exc: HTTPException):  # type: ignore[no-redef]
        if isinstance(exc, _GuardAnswer):
            return JSONResponse(exc.touchque_body, status_code=exc.status_code, headers=exc.headers)
        if isinstance(exc.detail, dict) and 'touchque' in exc.detail:
            return JSONResponse(exc.detail, status_code=exc.status_code, headers=exc.headers)
        return await http_exception_handler(request, exc)


async def _await(awaitable: Awaitable[Any]) -> Any:
    return await awaitable


def _run_async(awaitable: Awaitable[Any]) -> Any:
    """Resolves an async callback's result from the relay's worker thread."""
    return anyio.from_thread.run(_await, awaitable)


def touchque_relay_router(
    client: Optional[Touchque] = None,
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
