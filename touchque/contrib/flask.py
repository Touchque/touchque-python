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
``X-Touchque-Token: <token>``. Once approved the view runs ONCE, with
``flask.g.touchque`` set to the approval.

Relay routes (POST /login, enrollment, offline codes, passkey ceremonies)
as one Blueprint - see ``touchque.relay.RelayHandler`` for every option:

    from touchque.contrib.flask import touchque_relay_blueprint

    def opened(req, resp, info):
        session['user'] = info['externalUsername']

    app.register_blueprint(touchque_relay_blueprint(
        tq,
        get_user_id=lambda req: session.get('user'),
        get_login_user=lambda req: session.get('password_ok'),
        on_authenticated=opened,
    ), url_prefix='/touchque')
"""
import functools
from typing import Any, Callable, Dict, Optional

from flask import Blueprint, abort, current_app, g, json, jsonify, request

from ..client import Touchque
from ..guard import (
    ErrorBody, SilentSignIn, guard_input_from_headers, guard_response_body, guard_response_headers, run_guard,
    silent_input_from_headers,
)
from ..relay import RELAY_ROUTES, RelayHandler
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
    client: Optional[Touchque] = None,
    user: Optional[Callable[[], Optional[str]]] = None,
    details: Optional[Callable[[], Optional[LoginDetails]]] = None,
    reference_id: Optional[Callable[[], Optional[str]]] = None,
    silent_sign_in: SilentSignIn = False,
    context: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
    error_body: Optional[ErrorBody] = None,
) -> Callable:
    """
    ``client``: default ``get_default_client()``, built from ``TQ_API_KEY`` /
    ``TQ_API_SECRET`` on the first request. Without them the route answers
    500 ``misconfigured`` (401 when nobody is signed in) and the view never
    runs; nothing is raised at import or on a request.

    ``user``: who is approving. Default: ``flask.g.user`` (string, or an
    object with ``.email``/``.id``/``.username``). For the login step, return
    the user who just passed your password check, e.g.
    ``user=lambda: session.get('password_ok')``.

    ``silent_sign_in`` (default off): when on, a new attempt whose browser
    sent its device-bound key proof (``X-Touchque-Browser``, added by
    ``@touchque/web`` with ``browserKey: true``) first asks Touchque whether
    anything about it is new. If nothing is, your view runs at once with no
    push (``g.touchque['assurance']['method'] == 'silent'``,
    ``g.touchque['reasons']``). Otherwise, and on any error, the usual push
    starts and its approval makes the browser known.
    ``{'max_age_seconds': n}`` sets your own limit on how long ago the last
    phone approval in that browser may be.

    ``context``: for your Touchque Actions only (``event.context``), e.g.
    ``context=lambda: {'roles': g.user.roles}``. Never shown on the phone.

    ``error_body``: your app's own error shape for the refusals (401, 403,
    408, 423, 429, 500, 503), e.g.
    ``error_body=lambda r: {'message': r['message'], 'code': r['code']}``.
    It gets ``{'status', 'code', 'message', 'touchque'}``; what it returns
    counts by Flask's JSON encoding: an object (a dict, a dataclass, a pydantic
    model) is sent with ``touchque`` set to the step, anything else as it is.
    Status and headers stay, and every refusal carries ``X-Touchque-State``
    (and ``X-Touchque-Reason``). Never called for a 202 step (see
    ``guard_response_body``).
    """
    user_of = user or _default_user
    tq = client

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            uid = user_of()
            result = run_guard(
                tq, uid, action,
                details=details() if details else None,
                reference_id=reference_id() if reference_id else None,
                context=context() if context else None,
                ip=request.remote_addr, user_agent=request.headers.get('User-Agent'),
                **guard_input_from_headers(lambda name: request.headers.get(name)),
                **silent_input_from_headers(silent_sign_in, lambda name: request.headers.get(name)),
            )
            if 'approved' in result:
                g.touchque = result['approved']
                return view(*args, **kwargs)
            # Encoded like the response (the app's JSON provider), so a value it cannot encode is caught.
            resp = jsonify(guard_response_body(result, error_body, encode=json.dumps))
            resp.status_code = result['status']
            for name, value in guard_response_headers(result).items():
                resp.headers[name] = value
            return resp
        return wrapped
    return decorator


def touchque_relay_blueprint(
    client: Optional[Touchque] = None,
    name: str = 'touchque_relay',
    url_prefix: Optional[str] = None,
    handler: Optional[RelayHandler] = None,
    **options: Any
) -> Blueprint:
    """A Blueprint with every relay route. ``options`` are ``RelayHandler``'s
    (``get_user_id`` is required); or pass a ready ``handler``.

    Callbacks get ``flask.request``; ``on_authenticated(request, response,
    info)`` gets the Flask response that will be sent, so it may call
    ``response.set_cookie(...)`` or write ``flask.session``.
    ``request.remote_addr`` is the client IP the rate limiter uses: behind a
    proxy, wrap the app in werkzeug's ``ProxyFix``.
    """
    relay = handler or RelayHandler(client, **options)
    bp = Blueprint(name, __name__, url_prefix=url_prefix)

    def make_view(method: str, sub: str) -> Callable:
        def view(cred_id: Optional[str] = None) -> Any:
            response = current_app.response_class(mimetype='application/json')
            result = relay.handle(
                method, sub.replace('<id>', cred_id or ''),
                body=request.get_json(silent=True),
                ip=request.remote_addr, user_agent=request.headers.get('User-Agent'),
                get_header=lambda name_: request.headers.get(name_),
                request=request._get_current_object(),  # type: ignore[attr-defined]
                response=response,
            )
            if result is None:
                abort(404)
            response.set_data(json.dumps(result.body))
            response.status_code = result.status
            for key, value in result.headers.items():
                response.headers[key] = value
            return response
        return view

    for method, sub in RELAY_ROUTES:
        endpoint = method.lower() + sub.replace('/', '_').replace('<id>', 'id')
        bp.add_url_rule(sub.replace('<id>', '<cred_id>'), endpoint=endpoint,
                        view_func=make_view(method, sub), methods=[method])
    return bp
