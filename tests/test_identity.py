"""client.identity (Touchque Login Management API): each call sends the
method, path and body the API expects, signed like every partner call."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from touchque import Config, Touchque

SEEN = []


class _Handler(BaseHTTPRequestHandler):
    def _answer(self):
        n = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(n).decode() if n else ''
        SEEN.append({'method': self.command, 'url': self.path, 'body': json.loads(raw) if raw else None, 'signed': bool(self.headers.get('x-signature'))})
        body = json.dumps({'roles': []} if self.path.startswith('/identity/roles') else {'status': 'done'}).encode()
        self.send_response(200)
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
