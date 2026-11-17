"""client.identity (Touchque Login Management API): each call sends the
method, path and body the API expects, signed like every partner call."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import touchque
from touchque import Config, CustomDomainsOverview, Touchque, TouchqueAPIException, TouchqueFeatureException

SEEN = []
# (method, path) -> (status, body): what the API answers there; a body of None is no body (204).
ANSWERS = {}


@pytest.fixture(autouse=True)
def _answers():
    ANSWERS.clear()
    yield
    ANSWERS.clear()


class _Handler(BaseHTTPRequestHandler):
    def _answer(self):
        n = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(n).decode() if n else ''
        SEEN.append({'method': self.command, 'url': self.path, 'body': json.loads(raw) if raw else None, 'signed': bool(self.headers.get('x-signature'))})
        status, payload = ANSWERS.get((self.command, self.path), (200, {'roles': []} if self.path.startswith('/identity/roles') else {'status': 'done'}))
        body = b'' if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if payload is not None:
            self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = _answer

    def log_message(self, *args):
        pass


@pytest.fixture(scope='module')
def client():
    server = HTTPServer(('127.0.0.1', 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield Touchque(Config(api_key='tq_test_key', api_secret='test_secret', base_url=f'http://127.0.0.1:{server.server_port}'))
    server.shutdown()


def test_identity_calls(client):
    client.identity.users.list(q='ayse', limit=10)
    client.identity.users.create('a@x.com', passwordHash='$2b$10$abc')
    client.identity.users.update('usr_1', appMetadata={'plan': None})
    client.identity.users.block('usr_1', reason='fraud')
    client.identity.users.delete('usr_1')
    client.identity.users.reset_mfa('usr_1')
    client.identity.users.password_reset('usr_1', send_email=False)
    client.identity.users.add_roles('usr_1', ['rol_1'], organization_id='org_1')
    client.identity.users.remove_role('usr_1', 'rol_1', organization_id='org_1')
    client.identity.imports.start(users=[{'email': 'b@x.com'}], upsert=True)
    client.identity.organizations.invite('org_1', 'c@x.com', 'cli', role_ids=['rol_1'])
    assert client.identity.roles.list() == []
    client.identity.update_tenant(slug='acme', displayName='Acme')
    assert client.identity.exports.wait('job_1', interval=0.001)['status'] == 'done'
    client.identity.set_delivery('email', provider='postmark', from_='login@acme.test', serverToken='pm')
    client.identity.test_delivery('sms', '+905321234567')
    client.identity.set_attack_protection(bot={'provider': 'turnstile', 'siteKey': 'k', 'secret': 's', 'mode': 'risky'})
    client.identity.set_approver_app_name('Acme Pay')
    client.identity.set_custom_domain_only(True)
    client.identity.check_domain_certificate('dom_1')
    client.identity.users.end_session('usr_1', 'ses_1')
    assert client.identity.exports.file('job_1') == '{"status": "done"}'
    assert [f"{r['method']} {r['url']}" for r in SEEN] == [
        'GET /identity/users?limit=10&q=ayse',
        'POST /identity/users',
        'PATCH /identity/users/usr_1',
        'POST /identity/users/usr_1/block',
        'DELETE /identity/users/usr_1',
        'DELETE /identity/users/usr_1/mfa',
        'POST /identity/users/usr_1/password-reset',
        'POST /identity/users/usr_1/roles',
        'DELETE /identity/users/usr_1/roles/rol_1?organizationId=org_1',
        'POST /identity/users-imports',
        'POST /identity/organizations/org_1/invitations',
        'GET /identity/roles',
        'PUT /identity/tenant',
        'GET /identity/users-exports/job_1',
        'PUT /identity/delivery/email',
        'POST /identity/delivery/sms/test',
        'PUT /identity/attack-protection',
        'PUT /identity/tenant',
        'PUT /identity/tenant',
        'POST /identity/custom-domains/dom_1/check-certificate',
        'DELETE /identity/users/usr_1/sessions/ses_1',
        'GET /identity/users-exports/job_1/file',
    ]
    assert SEEN[17]['body'] == {'branding': {'approverAppName': 'Acme Pay'}}
    assert SEEN[18]['body'] == {'customDomainOnly': True}
    assert SEEN[14]['body'] == {'provider': 'postmark', 'from': 'login@acme.test', 'serverToken': 'pm'}
    assert SEEN[1]['body'] == {'email': 'a@x.com', 'passwordHash': '$2b$10$abc'}
    assert SEEN[2]['body'] == {'appMetadata': {'plan': None}}
    assert SEEN[7]['body'] == {'roleIds': ['rol_1'], 'organizationId': 'org_1'}
    assert all(r['signed'] for r in SEEN)


def test_users_list_sends_filters_as_the_api_reads_them(client):
    start = len(SEEN)
    client.identity.users.list(blocked=True, email_verified=False)
    assert SEEN[start]['url'] == '/identity/users?blocked=true&emailVerified=false'


def test_passkey_domain(client):
    start = len(SEEN)
    client.identity.set_passkey_domain('acme.com')
    client.identity.set_passkey_domain(None)
    assert [(c['method'], c['url'], c['body']) for c in SEEN[start:]] == [
        ('PUT', '/identity/tenant', {'passkeyDomain': 'acme.com'}),
        ('PUT', '/identity/tenant', {'passkeyDomain': None}),
    ]


def test_user_store(client):
    start = len(SEEN)
    client.identity.get_user_store()
    client.identity.set_user_store(url='https://api.acme.test/touchque/user-store', enabled=True)
    client.identity.test_user_store()
    client.identity.remove_user_store()
    assert [(c['method'], c['url'], c['body']) for c in SEEN[start:]] == [
        ('GET', '/identity/user-store', None),
        ('PUT', '/identity/user-store', {'url': 'https://api.acme.test/touchque/user-store', 'enabled': True}),
        ('POST', '/identity/user-store/test', {}),
        ('DELETE', '/identity/user-store', None),
    ]


def _refused(call, status, body):
    """The exception a call raises when the API answers `status` with `body`."""
    with pytest.raises(TouchqueAPIException) as e:
        call()
    assert not isinstance(e.value, TouchqueFeatureException)
    assert (e.value.status, str(e.value), e.value.data) == (status, body['error'], body)
    return e.value


def test_passkey_domain_answer_and_refusals(client):
    # The API answers the tenant; refusals carry error, field (and count) as sent.
    ANSWERS[('PUT', '/identity/tenant')] = (200, {'slug': 'acme', 'passkeyDomain': 'acme.com', 'customDomainOnly': False})
    assert client.identity.set_passkey_domain('acme.com') == {'slug': 'acme', 'passkeyDomain': 'acme.com', 'customDomainOnly': False}
    refusals = [
        (409, {'error': 'passkeys_exist', 'field': 'passkeyDomain', 'count': 3,
               'message': '3 customer passkeys belong to the current setting and would stop working'}),
        (409, {'error': 'not_your_domain', 'field': 'passkeyDomain',
               'message': 'example.com must be one of your verified custom domains, or a domain above one that your organization verified (Organization → Domains)'}),
        (409, {'error': 'organization_unavailable', 'field': 'passkeyDomain',
               'message': 'Your organization’s verified domains could not be read; try again'}),
        (400, {'error': 'invalid_request', 'field': 'passkeyDomain', 'message': 'passkeyDomain must be a domain like example.com, or null'}),
        # Before Touchque Login is set up for the workspace, PUT /identity/tenant would create the tenant: it asks for a slug.
        (400, {'error': 'invalid_request', 'field': 'slug', 'message': 'slug must be 3–63 lowercase letters, digits or hyphens'}),
    ]
    for status, body in refusals:
        ANSWERS[('PUT', '/identity/tenant')] = (status, body)
        _refused(lambda: client.identity.set_passkey_domain('example.com'), status, body)
    # Clearing it while customers have passkeys on it is refused the same way.
    ANSWERS[('PUT', '/identity/tenant')] = refusals[0]
    assert _refused(lambda: client.identity.set_passkey_domain(None), *refusals[0]).data['count'] == 3


def test_user_store_sends_only_what_is_given(client):
    # PUT keeps a field left out (url once set; enabled), so None is never sent; enabled=False is.
    start = len(SEEN)
    client.identity.set_user_store(enabled=False)
    client.identity.set_user_store(url='https://api.acme.test/user-store?v=2&tenant=café')
    client.identity.set_user_store()
    client.identity.test_user_store('https://staging.acme.test/user-store')
    client.identity.test_user_store('')
    client.identity.test_user_store(url=None)
    assert [(c['method'], c['url'], c['body']) for c in SEEN[start:]] == [
        ('PUT', '/identity/user-store', {'enabled': False}),
        ('PUT', '/identity/user-store', {'url': 'https://api.acme.test/user-store?v=2&tenant=café'}),
        ('PUT', '/identity/user-store', {}),
        ('POST', '/identity/user-store/test', {'url': 'https://staging.acme.test/user-store'}),
        ('POST', '/identity/user-store/test', {}),
        ('POST', '/identity/user-store/test', {}),
    ]
    assert all(c['signed'] for c in SEEN[start:])


def test_user_store_answers_come_back_whole(client):
    # The API: GET and PUT (201 the first time) answer the same view; DELETE is a 204, also when nothing is set.
    view = {
        'url': 'https://api.acme.test/touchque/user-store', 'enabled': True, 'active': True, 'movedIn': 12,
        'lastCall': {'at': '2026-11-17T06:00:00.000Z', 'event': 'user_store.get_user', 'ok': True, 'status': 200, 'ms': 41, 'error': None},
        'paused': False, 'updatedAt': '2026-11-16T20:00:00.000Z',
        'signing': "Signed like Touchque webhooks: HMAC-SHA256 with your API secret (x-signature); check it with your SDK's webhook verify.",
    }
    ANSWERS[('GET', '/identity/user-store')] = (200, view)
    ANSWERS[('PUT', '/identity/user-store')] = (201, view)
    ANSWERS[('POST', '/identity/user-store/test')] = (200, {'ok': False, 'error': 'no answer in 5 seconds', 'ms': 5003})
    ANSWERS[('DELETE', '/identity/user-store')] = (204, None)
    assert client.identity.get_user_store() == view
    assert client.identity.set_user_store(url=view['url']) == view
    assert client.identity.test_user_store() == {'ok': False, 'error': 'no answer in 5 seconds', 'ms': 5003}
    assert client.identity.remove_user_store() == {}
    assert client.identity.remove_user_store() == {}


def test_user_store_refusals(client):
    passwords_off = {'error': 'passwords_off', 'field': 'enabled', 'message': 'Moving users in checks their passwords: turn passwords on first'}
    ANSWERS[('PUT', '/identity/user-store')] = (409, passwords_off)
    _refused(lambda: client.identity.set_user_store(enabled=True), 409, passwords_off)
    url_required = {'error': 'invalid_request', 'field': 'url', 'message': 'url is required'}
    ANSWERS[('PUT', '/identity/user-store')] = (400, url_required)
    _refused(lambda: client.identity.set_user_store(enabled=True), 400, url_required)
    not_https = {'error': 'invalid_request', 'field': 'url', 'message': 'url must use https'}
    ANSWERS[('POST', '/identity/user-store/test')] = (400, not_https)
    _refused(lambda: client.identity.test_user_store('http://api.acme.test/user-store'), 400, not_https)
    # A 404 is Touchque Login not set up for the workspace, never "no user store" (DELETE answers 204 then).
    not_enabled = {'error': 'not_enabled', 'message': 'PUT /identity/tenant first'}
    for method, path in [('GET', '/identity/user-store'), ('DELETE', '/identity/user-store')]:
        ANSWERS[(method, path)] = (404, not_enabled)
    _refused(client.identity.get_user_store, 404, not_enabled)
    _refused(client.identity.remove_user_store, 404, not_enabled)


def test_custom_domains_list_answer_get_and_verify(client):
    # GET /identity/custom-domains answers { domains, verifiedDomains, slugPasskeys }; the API has no GET by id.
    answer = {
        'domains': [
            {'id': 'dom_1', 'domain': 'login.acme.com', 'status': 'verified', 'primary': True,
             'dns': {'points': 'here', 'cloudflareProxy': False, 'caaBlocks': False, 'problems': []}, 'autoCheckUntil': '2026-11-19T20:00:00.000Z'},
            {'id': 'dom/2', 'domain': 'id.acme.com', 'status': 'pending', 'primary': False, 'dns': None, 'autoCheckUntil': '2026-11-20T08:00:00.000Z'},
        ],
        'verifiedDomains': ['acme.com'],
        'slugPasskeys': 2,
    }
    ANSWERS[('GET', '/identity/custom-domains')] = (200, answer)
    ANSWERS[('POST', '/identity/custom-domains/dom%2F2/verify')] = (200, answer['domains'][1])
    # The API's own 404 for an id the workspace does not have.
    ANSWERS[('POST', '/identity/custom-domains/dom_9/verify')] = (404, {'error': 'not_found'})
    start = len(SEEN)
    assert client.identity.custom_domains.overview() == answer
    assert client.identity.custom_domains.list() == answer['domains']
    assert client.identity.custom_domains.get('dom/2') == answer['domains'][1]
    missing = _refused(lambda: client.identity.custom_domains.get('dom_9'), 404,
                       {'error': 'not_found', 'message': 'No custom domain with this id'})
    assert client.identity.custom_domains.verify('dom/2') == answer['domains'][1]
    api_404 = _refused(lambda: client.identity.custom_domains.verify('dom_9'), 404, {'error': 'not_found'})
    # get()'s 404 has the shape of the API's own: the same class, message and attributes (data adds a sentence).
    assert type(missing) is type(api_404) is TouchqueAPIException
    assert [getattr(missing, a) for a in ('code', 'reason', 'attempts_left', 'retry_after', 'case_code')] == \
        [getattr(api_404, a) for a in ('code', 'reason', 'attempts_left', 'retry_after', 'case_code')]
    assert [f"{c['method']} {c['url']}" for c in SEEN[start:]] == [
        'GET /identity/custom-domains',
        'GET /identity/custom-domains',
        'GET /identity/custom-domains',
        'GET /identity/custom-domains',
        'POST /identity/custom-domains/dom%2F2/verify',
        'POST /identity/custom-domains/dom_9/verify',
    ]
    assert SEEN[-2]['body'] == {} and all(c['signed'] for c in SEEN[start:])


def test_custom_domains_overview_is_typed():
    # A TypedDict of the plain JSON answer (a dict subclass on Python 3.7), exported from touchque.
    assert 'CustomDomainsOverview' in touchque.__all__
    assert list(CustomDomainsOverview.__annotations__) == ['domains', 'verifiedDomains', 'slugPasskeys']
