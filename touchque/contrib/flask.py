"""
Flask: one line per protected route.

    from touchque.contrib.flask import require_touchque

    @app.post('/transfer')
    @require_touchque('SEND_MONEY', details=lambda: {'Amount': f'{request.json["amount"]} EUR'})
    def transfer():
        return jsonify(ok=True, touchque=g.touchque)

Until the user approves on their phone this answers
202 {"touchque": step, "token": ...}. Your page shows the step in its own
design and sends the same request again with header
``X-TouchQue-Token: <token>``. Once approved the view runs ONCE, with
``flask.g.touchque`` set to the approval.
"""
import functools
from typing import Any, Callable, Optional

from flask import g, jsonify, request

from ..client import TouchQue, get_default_client
from ..guard import guard_input_from_headers, run_guard
from ..steps import LoginDetails


def _default_user() -> Optional[str]:
    u = getattr(g, 'user', None)
    if u is None:
        return None
    if isinstance(u, str):
        return u
    return getattr(u, 'email', None) or getattr(u, 'id', None) or getattr(u, 'username', None)


def require_touchque(
    action: str,
    client: Optional[TouchQue] = None,
    user: Optional[Callable[[], Optional[str]]] = None,
    details: Optional[Callable[[], Optional[LoginDetails]]] = None,
    reference_id: Optional[Callable[[], Optional[str]]] = None,
) -> Callable:
    """
    ``user``: who is approving. Default: ``flask.g.user`` (string, or an
    object with ``.email``/``.id``/``.username``). For the login step, return
    the user who just passed your password check, e.g.
    ``user=lambda: session.get('password_ok')``.
    """
    user_of = user or _default_user
    tq = client

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            c = tq or get_default_client()
            uid = user_of()
            result = run_guard(
                c, uid, action,
                details=details() if details else None,
                reference_id=reference_id() if reference_id else None,
                ip=request.remote_addr, user_agent=request.headers.get('User-Agent'),
                **guard_input_from_headers(lambda name: request.headers.get(name)),
            )
            if 'approved' in result:
                g.touchque = result['approved']
                return view(*args, **kwargs)
            resp = jsonify(result['body'])
            resp.status_code = result['status']
            resp.headers['Cache-Control'] = 'no-store'
            retry = result['body']['touchque'].get('retryAfter')
            if retry:
                resp.headers['Retry-After'] = str(retry)
            return resp
        return wrapped
    return decorator
