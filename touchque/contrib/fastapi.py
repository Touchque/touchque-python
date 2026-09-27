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
"""
from typing import Any, Callable, Optional

import anyio
import fastapi
from fastapi import HTTPException, Request

from ..client import TouchQue, get_default_client
from ..guard import guard_input_from_headers, run_guard
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
) -> Callable[[Request], Any]:
    """
    ``user``: async or sync callable resolving who is approving from the
    request. Default: ``request.state.user``. For the login step, return the
    user who just passed your password check.
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

        result = await anyio.to_thread.run_sync(lambda: run_guard(
            c, uid, action, details=det, reference_id=ref,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get('user-agent'),
            **guard_input_from_headers(lambda name: request.headers.get(name)),
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
