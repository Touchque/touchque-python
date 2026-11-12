"""
Django: one line per protected view.

    from touchque.contrib.django import require_touchque

    @require_touchque('SEND_MONEY', details=lambda req: {'Amount': f'{req.POST["amount"]} EUR'})
    def transfer(request):
        return JsonResponse({'ok': True, 'touchque': request.touchque})

Until the user approves on their phone this answers
202 {"touchque": step, "token": ...}. Your page shows the step in its own
design and sends the same request again with header
``X-Touchque-Token: <token>``. Once approved the view runs ONCE, with
``request.touchque`` set to the approval.

Relay routes (POST /login, enrollment, offline codes, passkey ceremonies)
under one URL prefix - see ``touchque.relay.RelayHandler`` for every option:

    # urls.py
    from touchque.contrib.django import touchque_relay_urls

    def opened(request, response, info):
        request.session['user'] = info['externalUsername']

    urlpatterns = [
        path('touchque/', include(touchque_relay_urls(
            get_user_id=lambda req: req.session.get('user'),
            get_login_user=lambda req: req.session.get('password_ok'),
            on_authenticated=opened,
        ))),
    ]

Django's CSRF protection stays on for these POST/DELETE routes: send the
token from the page (``@touchque/web``: ``headers: {'X-CSRFToken': ...}``),
or pass ``csrf_exempt=True`` if you protect them another way.
"""
import functools
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

from django.core.serializers.json import DjangoJSONEncoder
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.urls import re_path
from django.views.decorators.csrf import csrf_exempt as _csrf_exempt

from ..client import Touchque
from ..guard import ErrorBody, SilentSignIn, guard_input_from_headers, run_guard, silent_input_from_headers
from ..guard import guard_response as _guard_response
from ..relay import RelayHandler
from ..steps import LoginDetails


def _default_user(request: HttpRequest) -> Optional[str]:
    u = getattr(request, 'user', None)
    if u is None or not getattr(u, 'is_authenticated', True):
        return None
    if isinstance(u, str):
        return u
    email = getattr(u, 'email', None)
    return email or getattr(u, 'username', None) or str(getattr(u, 'pk', '') or '') or None


def guard_response(result: Dict[str, Any], error_body: Optional[ErrorBody] = None) -> Tuple[int, Dict[str, str], Any]:
    """What ``require_touchque`` sends for a ``run_guard`` result that is not
    an approval, as ``(status, headers, body)``: ``touchque.guard_response``
    with ``error_body``'s result encoded by ``DjangoJSONEncoder`` (dates,
    ``Decimal``, ``UUID``), as the decorator encodes it. For the guard inside
    your own view::

        status, headers, body = guard_response(result, error_body)
        resp = JsonResponse(body, status=status, safe=False)
        for name, value in headers.items():
            resp[name] = value
        return resp
    """
    return _guard_response(result, error_body, encode=_encode)


def require_touchque(
    action: str,
    client: Optional[Touchque] = None,
    user: Optional[Callable[[HttpRequest], Optional[str]]] = None,
    details: Optional[Callable[[HttpRequest], Optional[LoginDetails]]] = None,
    reference_id: Optional[Callable[[HttpRequest], Optional[str]]] = None,
    silent_sign_in: SilentSignIn = False,
    context: Optional[Callable[[HttpRequest], Optional[Dict[str, Any]]]] = None,
    error_body: Optional[ErrorBody] = None,
) -> Callable:
    """
    ``client``: default ``get_default_client()``, built from ``TQ_API_KEY`` /
    ``TQ_API_SECRET`` on the first request. Without them the view answers
    500 ``misconfigured`` (401 when nobody is signed in) and never runs;
    nothing is raised at import or on a request.

    ``user``: who is approving, given the request. Default:
    ``request.user.email`` (Django auth). For the login step, return the user
    who just passed your password check, e.g.
    ``user=lambda req: req.session.get('password_ok')``.

    ``silent_sign_in`` (default off): when on, a new attempt whose browser
    sent its device-bound key proof (``X-Touchque-Browser``, added by
    ``@touchque/web`` with ``browserKey: true``) first asks Touchque whether
    anything about it is new. If nothing is, your view runs at once with no
    push (``request.touchque['assurance']['method'] == 'silent'``,
    ``request.touchque['reasons']``). Otherwise, and on any error, the usual push
    starts and its approval makes the browser known.
    ``{'max_age_seconds': n}`` sets your own limit on how long ago the last
    phone approval in that browser may be.

    ``context``: for your Touchque Actions only (``event.context``), e.g. the
    user's roles. Never shown on the phone.

    ``error_body``: your app's own error shape for the refusals (401, 403,
    408, 423, 429, 500, 503), e.g.
    ``error_body=lambda r: {'message': r['message'], 'code': r['code']}``.
    It gets ``{'status', 'code', 'message', 'touchque'}``; what it returns
    counts by its JSON encoding (``DjangoJSONEncoder``): an object (a dict, a
    dataclass, a pydantic model) is sent with ``touchque`` set to the step,
    anything else as it is. Status and headers stay, and every refusal carries
    ``X-Touchque-State`` (and ``X-Touchque-Reason``). Never called for a 202
    step. For ``run_guard`` in your own view, this module's ``guard_response``
    gives the same answer.
    """
    user_of = user or _default_user
    tq = client

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            uid = user_of(request)
            result = run_guard(
                tq, uid, action,
                details=details(request) if details else None,
                reference_id=reference_id(request) if reference_id else None,
                context=context(request) if context else None,
                ip=request.META.get('REMOTE_ADDR'), user_agent=request.META.get('HTTP_USER_AGENT'),
                **guard_input_from_headers(lambda name: request.headers.get(name)),
                **silent_input_from_headers(silent_sign_in, lambda name: request.headers.get(name)),
            )
            if 'approved' in result:
                request.touchque = result['approved']
                return view(request, *args, **kwargs)
            status, headers, body = guard_response(result, error_body)
            resp = JsonResponse(body, status=status, safe=False)
            for name, value in headers.items():
                resp[name] = value
            return resp
        return wrapped
    return decorator


def _encode(value: Any) -> str:
    """How ``JsonResponse`` encodes a body."""
    return json.dumps(value, cls=DjangoJSONEncoder)


def _json_body(request: HttpRequest) -> Any:
    if request.content_type != 'application/json' or not request.body:
        return None
    try:
        return json.loads(request.body)
    except ValueError:
        return None


def touchque_relay_view(
    client: Optional[Touchque] = None,
    csrf_exempt: bool = False,
    handler: Optional[RelayHandler] = None,
    **options: Any
) -> Callable:
    """One view for every relay route; the sub-path comes from the ``sub``
    URL kwarg (see ``touchque_relay_urls``). ``options`` are
    ``RelayHandler``'s (``get_user_id`` is required); or pass a ready ``handler``.

    Callbacks get the ``HttpRequest``; ``on_authenticated(request, response,
    info)`` gets the ``HttpResponse`` that will be sent, so it may call
    ``response.set_cookie(...)`` or write ``request.session``.
    ``REMOTE_ADDR`` is the client IP the rate limiter uses: behind a proxy,
    make sure it holds the real client address.
    """
    relay = handler or RelayHandler(client, **options)

    def view(request: HttpRequest, sub: str = '') -> HttpResponse:
        response = HttpResponse(content_type='application/json')
        result = relay.handle(
            request.method or '', '/' + sub, body=_json_body(request),
            ip=request.META.get('REMOTE_ADDR'), user_agent=request.META.get('HTTP_USER_AGENT'),
            get_header=lambda name: request.headers.get(name),
            request=request, response=response,
        )
        if result is None:
            raise Http404()
        response.status_code = result.status
        response.content = json.dumps(result.body, cls=DjangoJSONEncoder).encode('utf-8')
        for key, value in result.headers.items():
            response[key] = value
        return response

    return _csrf_exempt(view) if csrf_exempt else view


def touchque_relay_urls(
    client: Optional[Touchque] = None,
    csrf_exempt: bool = False,
    handler: Optional[RelayHandler] = None,
    **options: Any
) -> List[Any]:
    """URL patterns for the relay, to mount with
    ``path('touchque/', include(touchque_relay_urls(...)))``."""
    view = touchque_relay_view(client, csrf_exempt=csrf_exempt, handler=handler, **options)
    return [re_path(r'^(?P<sub>.*)$', view, name='touchque_relay')]
