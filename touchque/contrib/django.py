"""
Django: one line per protected view.

    from touchque.contrib.django import require_touchque

    @require_touchque('SEND_MONEY', details=lambda req: {'Amount': f'{req.POST["amount"]} EUR'})
    def transfer(request):
        return JsonResponse({'ok': True, 'touchque': request.touchque})

Until the user approves on their phone this answers
202 {"touchque": step, "token": ...}. Your page shows the step in its own
design and sends the same request again with header
``X-TouchQue-Token: <token>``. Once approved the view runs ONCE, with
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
from typing import Any, Callable, Dict, List, Optional

from django.core.serializers.json import DjangoJSONEncoder
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.urls import re_path
from django.views.decorators.csrf import csrf_exempt as _csrf_exempt

from ..client import TouchQue, get_default_client
from ..guard import SilentSignIn, guard_input_from_headers, run_guard, silent_input_from_headers
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


def require_touchque(
    action: str,
    client: Optional[TouchQue] = None,
    user: Optional[Callable[[HttpRequest], Optional[str]]] = None,
    details: Optional[Callable[[HttpRequest], Optional[LoginDetails]]] = None,
    reference_id: Optional[Callable[[HttpRequest], Optional[str]]] = None,
    silent_sign_in: SilentSignIn = False,
    context: Optional[Callable[[HttpRequest], Optional[Dict[str, Any]]]] = None,
) -> Callable:
    """
    ``user``: who is approving, given the request. Default:
    ``request.user.email`` (Django auth). For the login step, return the user
    who just passed your password check, e.g.
    ``user=lambda req: req.session.get('password_ok')``.

    ``silent_sign_in`` (default off): when on, a new attempt whose browser
    sent its device-bound key proof (``X-TouchQue-Browser``, added by
    ``@touchque/web`` with ``browserKey: true``) first asks TouchQue whether
    anything about it is new. If nothing is, your view runs at once with no
    push (``request.touchque['assurance']['method'] == 'silent'``,
    ``request.touchque['reasons']``). Otherwise, and on any error, the usual push
    starts and its approval makes the browser known.
    ``{'max_age_seconds': n}`` sets your own limit on how long ago the last
    phone approval in that browser may be.

    ``context``: for your TouchQue Actions only (``event.context``), e.g. the
    user's roles. Never shown on the phone.
    """
    user_of = user or _default_user
    tq = client

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            c = tq or get_default_client()
            uid = user_of(request)
            result = run_guard(
                c, uid, action,
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
            resp = JsonResponse(result['body'], status=result['status'])
            resp['Cache-Control'] = 'no-store'
            retry = result['body']['touchque'].get('retryAfter')
            if retry:
                resp['Retry-After'] = str(retry)
            return resp
        return wrapped
    return decorator


def _json_body(request: HttpRequest) -> Any:
    if request.content_type != 'application/json' or not request.body:
        return None
    try:
        return json.loads(request.body)
    except ValueError:
        return None


def touchque_relay_view(
    client: Optional[TouchQue] = None,
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
    client: Optional[TouchQue] = None,
    csrf_exempt: bool = False,
    handler: Optional[RelayHandler] = None,
    **options: Any
) -> List[Any]:
    """URL patterns for the relay, to mount with
    ``path('touchque/', include(touchque_relay_urls(...)))``."""
    view = touchque_relay_view(client, csrf_exempt=csrf_exempt, handler=handler, **options)
    return [re_path(r'^(?P<sub>.*)$', view, name='touchque_relay')]
