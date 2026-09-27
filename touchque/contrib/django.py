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
"""
import functools
from typing import Any, Callable, Optional

from django.http import HttpRequest, JsonResponse

from ..client import TouchQue, get_default_client
from ..guard import guard_input_from_headers, run_guard
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
) -> Callable:
    """
    ``user``: who is approving, given the request. Default:
    ``request.user.email`` (Django auth). For the login step, return the user
    who just passed your password check, e.g.
    ``user=lambda req: req.session.get('password_ok')``.
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
                ip=request.META.get('REMOTE_ADDR'), user_agent=request.META.get('HTTP_USER_AGENT'),
                **guard_input_from_headers(lambda name: request.headers.get(name)),
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
