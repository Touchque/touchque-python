"""TouchQue Actions in the Python SDK: every management call sends exactly what
the shared vectors (fixtures/actions-api-vectors.json) say, against the shared
fake TouchQue API, signed like the real API."""
import json
import os
from urllib.parse import parse_qsl, urlparse

import pytest

from touchque import Config, TouchQue
from touchque.exceptions import TouchQueConfigException
from .fake_api import fake_api  # noqa: F401 (fixture)

with open(os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'actions-api-vectors.json'), encoding='utf-8') as f:
    VECTORS = json.load(f)


def client_for(api) -> TouchQue:
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))


def call(tq: TouchQue, name: str, a: dict):
    acts = tq.actions
    return {
        'deploy': lambda: acts.deploy(a['slug'], trigger=a['trigger'], code=a['code'], secrets=a['secrets'], name=a['name']),
        'deployTemplate': lambda: acts.deploy(a['slug'], trigger=a['trigger'], template=a['template'], on_failure=a['onFailure']),
        'deployLoosening': lambda: acts.deploy(a['slug'], trigger=a['trigger'], code=a['code'], capabilities=a['capabilities'], allowed_hosts=a['allowedHosts']),
        'list': lambda: acts.list(),
        'get': lambda: acts.get(a['slug']),
        'version': lambda: acts.version(a['slug'], a['number']),
        'update': lambda: acts.update(a['slug'], enabled=a['enabled']),
        'rollback': lambda: acts.rollback(a['slug'], a['version']),
        'rollbackPrevious': lambda: acts.rollback(a['slug']),
        'test': lambda: acts.test(trigger=a['trigger'], code=a['code'], event_id=a['eventId']),
        'testDeployed': lambda: acts.test(slug=a['slug'], event=a['event']),
        'dryRun': lambda: acts.dry_run(trigger=a['trigger'], code=a['code'], replaces=a['replaces'], limit=a['limit']),
        'events': lambda: acts.events(trigger=a['trigger'], limit=a['limit']),
        'logs': lambda: acts.logs(a['slug'], limit=a['limit']),
        'metrics': lambda: acts.metrics(a['slug'], window=a['window']),
        'triggers': lambda: acts.triggers(),
        'templates': lambda: acts.templates(),
        'renderTemplate': lambda: acts.render_template(a['id'], a['trigger'], a['params']),
        'setSecret': lambda: acts.secrets.set(a['name'], a['value']),
        'listSecrets': lambda: acts.secrets.list(),
        'deleteSecret': lambda: acts.secrets.delete(a['name']),
        'delete': lambda: acts.delete(a['slug']),
    }[name]()


def dig(obj, path):
    for k in path.split('.'):
        obj = obj.get(k) if isinstance(obj, dict) else None
    return obj


def test_actions_api_vectors(fake_api):
    tq = client_for(fake_api)
    for v in VECTORS['calls']:
        result = call(tq, v['name'], v['args'])
        last = fake_api.calls()[-1]
        assert last['method'] == v['request']['method'], v['name']
        assert last['path'] == v['request']['path'], v['name']
        assert dict(parse_qsl(urlparse(last['url']).query)) == v['request'].get('query', {}), v['name']
        if v['request']['method'] not in ('GET', 'DELETE'):
            assert last['body'] == v['request'].get('body', {}), v['name']
        for path, want in (v.get('expect') or {}).items():
            assert dig(result, path) == want, (v['name'], path)


def test_context_is_passed_through(fake_api):
    tq = client_for(fake_api)
    fake_api.link('ctx@example.com')
    tq.login.request('ctx@example.com', type='LOGIN', context={'roles': ['admin'], 'amount': 2500})
    assert fake_api.calls()[-1]['body'] == VECTORS['context']['loginRequest']['body']
    tq.risk.check('ctx@example.com', type='LOGIN', context={'roles': ['admin']})
    assert fake_api.calls()[-1]['body'] == VECTORS['context']['riskCheck']['body']


def test_loosening_version_waits_for_the_phone(fake_api):
    tq = client_for(fake_api)
    res = tq.actions.deploy('silent-office', trigger='risk.check', code='exports.onExecute = (e, api) => api.allowSilent("office");', capabilities=['allow_silent'])
    assert res['deployed'] is False and res['approval']['required'] is True
    fake_api.approve_version('silent-office', 1)
    assert tq.actions.get('silent-office')['action']['activeVersion'] == 1


def test_bad_input_is_refused_before_any_request(fake_api):
    tq = client_for(fake_api)
    with pytest.raises(TouchQueConfigException):
        tq.actions.deploy('Bad Slug', trigger='login.request', code='x')
    with pytest.raises(TouchQueConfigException):
        tq.actions.deploy('no-code', trigger='login.request')
    with pytest.raises(TouchQueConfigException):
        tq.actions.secrets.set('lowercase', 'v')
    assert fake_api.calls() == []


def test_action_types_moved(fake_api):
    tq = client_for(fake_api)
    tq.action_types.define('EXPORT_DATA', name='Export data', critical=True)
    last = fake_api.calls()[-1]
    assert (last['method'], last['path'], last['body']) == ('POST', '/action-types', {'type': 'EXPORT_DATA', 'name': 'Export data', 'critical': True})
