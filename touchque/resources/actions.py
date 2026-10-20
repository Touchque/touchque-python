"""TouchQue Actions: your own code at points of the approval pipeline (before
the push is sent, the silent sign-in decision, after an approval, fraud
reports, device and recovery events). TouchQue runs it in a sandbox; this
resource deploys, tests, replays and observes it::

    tq.actions.deploy(
        'night-alert',
        trigger='approval.decided',
        template={'id': 'alert', 'params': {'channel': 'slack', 'when': {'countries': ['TR'], 'hours': {'from': 0, 'to': 6}}}},
    )

Action code itself is JavaScript (``exports.onExecute = async (event, api) => {...}``),
whatever language your server is written in.
"""
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from ..exceptions import TouchQueConfigException
from ..http_client import HttpClient

_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,62}$')
_SECRET_RE = re.compile(r'^[A-Z][A-Z0-9_]{0,63}$')
_TEMPLATE_RE = re.compile(r'^[a-z_]{1,64}$')


def _slug_path(slug: str) -> str:
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        raise TouchQueConfigException('An Action slug is 2-63 lowercase letters, digits or - (e.g. "night-alert")')
    return f'/actions/{slug}'


def _secret_path(name: str) -> str:
    if not isinstance(name, str) or not _SECRET_RE.match(name):
        raise TouchQueConfigException('A secret name is capital letters, digits or _ (e.g. SLACK_WEBHOOK_URL)')
    return f'/actions/secrets/{name}'


def _draft(trigger=None, code=None, template=None, slug=None, secrets=None, allowed_hosts=None,
           capabilities=None) -> Dict[str, Any]:
    body: Dict[str, Any] = {}
    if trigger is not None:
        body['trigger'] = trigger
    if slug is not None:
        body['slug'] = slug
    if code is not None:
        body['code'] = code
    if template is not None:
        body['template'] = template
    if secrets is not None:
        body['secrets'] = list(secrets)
    if allowed_hosts is not None:
        body['allowedHosts'] = list(allowed_hosts)
    if capabilities is not None:
        body['capabilities'] = list(capabilities)
    return body


def _iso(value: Union[str, datetime, None]) -> Optional[str]:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


class ActionSecrets:
    """Secrets your Actions read (``event.secrets.NAME``) or notify with. A
    value is encrypted and never readable again through the API."""

    def __init__(self, http: HttpClient):
        self._http = http

    def set(self, name: str, value: str) -> Dict[str, Any]:
        if not isinstance(value, str) or not value:
            raise TouchQueConfigException('A secret value is a non-empty string')
        return self._http.put(_secret_path(name), {'value': value})

    def list(self) -> List[Dict[str, Any]]:
        """Names only."""
        res = self._http.get('/actions/secrets')
        return res.get('secrets', []) if isinstance(res, dict) else []

    def delete(self, name: str) -> Dict[str, Any]:
        return self._http.delete(_secret_path(name))


class Actions:
    """TouchQue Actions management: deploy, roll back, test, dry run, logs,
    metrics, secrets and no-code templates."""

    def __init__(self, http: HttpClient):
        self._http = http
        self.secrets = ActionSecrets(http)

    def deploy(self, slug: str, trigger: Optional[str] = None, code: Optional[str] = None,
               template: Optional[Dict[str, Any]] = None, name: Optional[str] = None,
               secrets: Optional[List[str]] = None, allowed_hosts: Optional[List[str]] = None,
               capabilities: Optional[List[str]] = None, on_failure: Optional[str] = None,
               order: Optional[int] = None, enabled: Optional[bool] = None,
               activate: Optional[bool] = None) -> Dict[str, Any]:
        """Creates the Action or adds a version and makes it live (idempotent:
        the same code and settings change nothing). A version asking for a
        loosening capability (``skip_number_match``, ``override_block``,
        ``allow_silent``) waits for an admin's phone approval: the answer then
        has ``deployed: False`` and ``approval['required']``.

        :param trigger: required for a new Action (``login.request``,
            ``risk.check``, ``approval.decided``, …); cannot change later.
        :param code: JavaScript exporting ``onExecute``.
        :param template: ``{'id': 'alert' | 'block_or_step_up' | ..., 'params': {...}}``
            instead of code.
        :param on_failure: pre triggers only: ``continue`` (default, never
            blocks), ``step_up`` or ``deny`` when the Action errors or times out.
        :param activate: ``False`` saves the version without making it live.
        """
        if code is None and template is None:
            raise TouchQueConfigException('deploy() needs code or template')
        body = _draft(trigger=trigger, code=code, template=template, secrets=secrets,
                      allowed_hosts=allowed_hosts, capabilities=capabilities)
        if name is not None:
            body['name'] = name
        if on_failure is not None:
            body['onFailure'] = on_failure
        if order is not None:
            body['order'] = order
        if enabled is not None:
            body['enabled'] = enabled
        if activate is not None:
            body['activate'] = activate
        return self._http.put(_slug_path(slug), body)

    def list(self) -> List[Dict[str, Any]]:
        res = self._http.get('/actions')
        return res.get('actions', []) if isinstance(res, dict) else []

    def get(self, slug: str) -> Dict[str, Any]:
        """The Action, the active version's code and its versions."""
        return self._http.get(_slug_path(slug))

    def version(self, slug: str, number: int) -> Dict[str, Any]:
        """One version, with its code."""
        if not isinstance(number, int):
            raise TouchQueConfigException('version() needs a version number')
        return self._http.get(f'{_slug_path(slug)}/versions/{number}')

    def update(self, slug: str, name: Optional[str] = None, enabled: Optional[bool] = None,
               order: Optional[int] = None, on_failure: Optional[str] = None) -> Dict[str, Any]:
        """Rename, turn on or off, reorder, change on_failure."""
        body: Dict[str, Any] = {}
        if name is not None:
            body['name'] = name
        if enabled is not None:
            body['enabled'] = enabled
        if order is not None:
            body['order'] = order
        if on_failure is not None:
            body['onFailure'] = on_failure
        return self._http.patch(_slug_path(slug), body).get('action')

    def delete(self, slug: str) -> Dict[str, Any]:
        return self._http.delete(_slug_path(slug))

    def rollback(self, slug: str, version: Optional[int] = None) -> Dict[str, Any]:
        """Back to ``version``, or to the newest runnable version before the
        active one. Takes effect at once."""
        return self._http.post(f'{_slug_path(slug)}/rollback', {} if version is None else {'version': version})

    def test(self, trigger: Optional[str] = None, code: Optional[str] = None,
             template: Optional[Dict[str, Any]] = None, slug: Optional[str] = None,
             event_id: Optional[str] = None, event: Optional[Dict[str, Any]] = None,
             secrets: Optional[List[str]] = None, allowed_hosts: Optional[List[str]] = None,
             capabilities: Optional[List[str]] = None, network: Optional[bool] = None) -> Dict[str, Any]:
        """Runs a draft (or the deployed Action ``slug``) once on a recorded
        event (``event_id``), your own ``event`` or the trigger's sample.
        Sends no notification."""
        body = _draft(trigger=trigger, code=code, template=template, slug=slug, secrets=secrets,
                      allowed_hosts=allowed_hosts, capabilities=capabilities)
        if event_id is not None:
            body['eventId'] = event_id
        if event is not None:
            body['event'] = event
        if network is not None:
            body['network'] = network
        return self._http.post('/actions/test', body)

    def dry_run(self, trigger: Optional[str] = None, code: Optional[str] = None,
                template: Optional[Dict[str, Any]] = None, slug: Optional[str] = None,
                replaces: Optional[str] = None, limit: Optional[int] = None,
                since: Union[str, datetime, None] = None, on_failure: Optional[str] = None,
                secrets: Optional[List[str]] = None, allowed_hosts: Optional[List[str]] = None,
                capabilities: Optional[List[str]] = None) -> Dict[str, Any]:
        """Replays a draft against recent real decisions: how many it would
        have changed (``changed``, ``transitions`` such as
        ``{'push→number_match': 12}``), notifications it would have sent,
        errors and timing. ``replaces``: the deployed Action it would replace."""
        body = _draft(trigger=trigger, code=code, template=template, slug=slug, secrets=secrets,
                      allowed_hosts=allowed_hosts, capabilities=capabilities)
        if replaces is not None:
            body['replaces'] = replaces
        if on_failure is not None:
            body['onFailure'] = on_failure
        if limit is not None:
            body['limit'] = limit
        if since is not None:
            body['since'] = _iso(since)
        return self._http.post('/actions/dry-run', body)

    def events(self, trigger: Optional[str] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Recorded events (newest first, kept 30 days); use an id with test()."""
        res = self._http.get('/actions/events', {'trigger': trigger, 'limit': limit})
        return res.get('events', []) if isinstance(res, dict) else []

    def logs(self, slug: str, limit: Optional[int] = None,
             before: Union[str, datetime, None] = None) -> List[Dict[str, Any]]:
        """Live runs: decision, notifications, console output, errors."""
        res = self._http.get(f'{_slug_path(slug)}/logs', {'limit': limit, 'before': _iso(before)})
        return res.get('logs', []) if isinstance(res, dict) else []

    def metrics(self, slug: str, window: Optional[str] = None) -> Dict[str, Any]:
        """``window``: ``1h``, ``24h`` (default), ``7d`` or ``30d``."""
        return self._http.get(f'{_slug_path(slug)}/metrics', {'window': window})

    def triggers(self) -> Dict[str, Any]:
        """Every trigger with its decisions, capabilities, notification types and a sample event."""
        return self._http.get('/actions/triggers')

    def templates(self) -> List[Dict[str, Any]]:
        res = self._http.get('/actions/templates')
        return res.get('templates', []) if isinstance(res, dict) else []

    def render_template(self, id: str, trigger: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """A template as plain code (to read, or to start a code Action from)."""
        if not isinstance(id, str) or not _TEMPLATE_RE.match(id):
            raise TouchQueConfigException('Unknown template id')
        return self._http.post(f'/actions/templates/{id}/render', {'trigger': trigger, 'params': params or {}})
