"""Touchque Login Management API (``client.identity``): your customers'
accounts, roles, business-customer organizations, apps, APIs, connections and
the tenant itself, from your server with your workspace key.

    found = client.identity.users.list(q="ayse")
    client.identity.users.block(user_id, reason="chargeback")
    job = client.identity.imports.start(users=[{"email": e, "passwordHash": "$2b$10$..."}])
    client.identity.imports.wait(job["id"])
"""

import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from ..http_client import HttpClient


def _id(value: str) -> str:
    return quote(str(value), safe='')


def _clean(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


class IdentityUsers:
    def __init__(self, http: HttpClient):
        self._http = http

    def list(self, q: Optional[str] = None, blocked: Optional[bool] = None, email_verified: Optional[bool] = None,
             connection: Optional[str] = None, organization: Optional[str] = None, limit: Optional[int] = None,
             cursor: Optional[str] = None) -> Dict[str, Any]:
        return self._http.get('/identity/users', _clean({
            'q': q, 'blocked': blocked, 'emailVerified': email_verified, 'connection': connection,
            'organization': organization, 'limit': limit, 'cursor': cursor,
        }))

    def get(self, user_id: str) -> Dict[str, Any]:
        return self._http.get(f'/identity/users/{_id(user_id)}')

    def create(self, email: str, **fields: Any) -> Dict[str, Any]:
        """fields: password, passwordHash (bcrypt/argon2), customPasswordHash, emailVerified,
        name, givenName, familyName, phone, locale, userMetadata, appMetadata, sendVerificationEmail."""
        return self._http.post('/identity/users', {'email': email, **fields})

    def update(self, user_id: str, **changes: Any) -> Dict[str, Any]:
        """Metadata is merged; a key set to None is removed."""
        return self._http.patch(f'/identity/users/{_id(user_id)}', changes)

    def delete(self, user_id: str) -> Dict[str, Any]:
        """Erasure (KVKK/GDPR): the account and every workspace row that names it."""
        return self._http.delete(f'/identity/users/{_id(user_id)}')

    def block(self, user_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        return self._http.post(f'/identity/users/{_id(user_id)}/block', _clean({'reason': reason}))

    def unblock(self, user_id: str) -> Dict[str, Any]:
        return self._http.post(f'/identity/users/{_id(user_id)}/unblock', {})

    def export(self, user_id: str) -> Dict[str, Any]:
        """Everything about the person (KVKK/GDPR access request); never hashes."""
        return self._http.get(f'/identity/users/{_id(user_id)}/export')

    def sessions(self, user_id: str) -> Dict[str, Any]:
        return self._http.get(f'/identity/users/{_id(user_id)}/sessions')

    def end_session(self, user_id: str, session_id: str) -> Dict[str, Any]:
        """Signs the person out of one session (the others stay)."""
        return self._http.delete(f'/identity/users/{_id(user_id)}/sessions/{_id(session_id)}')

    def sign_out_everywhere(self, user_id: str) -> Dict[str, Any]:
        return self._http.delete(f'/identity/users/{_id(user_id)}/sessions')

    def reset_mfa(self, user_id: str) -> Dict[str, Any]:
        """Removes passkeys, unlinks the Touchque app, turns email codes off, signs out everywhere."""
        return self._http.delete(f'/identity/users/{_id(user_id)}/mfa')

    def connected_accounts(self, user_id: str) -> Dict[str, Any]:
        """Accounts at providers whose tokens the vault keeps for the user (connections with tokenVault on)."""
        return self._http.get(f'/identity/users/{_id(user_id)}/connected-accounts')

    def disconnect_account(self, user_id: str, account_id: str) -> Dict[str, Any]:
        """Deletes the stored tokens: apps stop using the account for the user; signing in with it stays."""
        return self._http.delete(f'/identity/users/{_id(user_id)}/connected-accounts/{_id(account_id)}')

    def unlink_identity(self, user_id: str, identity_id: str, force: bool = False) -> Dict[str, Any]:
        return self._http.delete(f'/identity/users/{_id(user_id)}/identities/{_id(identity_id)}' + ('?force=true' if force else ''))

    def send_verification_email(self, user_id: str, return_to: Optional[str] = None) -> Dict[str, Any]:
        return self._http.post(f'/identity/users/{_id(user_id)}/verification-email', _clean({'returnTo': return_to}))

    def password_reset(self, user_id: str, send_email: bool = True, ttl_sec: Optional[int] = None) -> Dict[str, Any]:
        """send_email=False: the link comes back for you to deliver."""
        return self._http.post(f'/identity/users/{_id(user_id)}/password-reset', _clean({'sendEmail': send_email, 'ttlSec': ttl_sec}))

    def roles(self, user_id: str) -> Dict[str, Any]:
        return self._http.get(f'/identity/users/{_id(user_id)}/roles')

    def add_roles(self, user_id: str, role_ids: List[str], organization_id: Optional[str] = None) -> Dict[str, Any]:
        return self._http.post(f'/identity/users/{_id(user_id)}/roles', _clean({'roleIds': role_ids, 'organizationId': organization_id}))

    def remove_role(self, user_id: str, role_id: str, organization_id: Optional[str] = None) -> Dict[str, Any]:
        query = f'?organizationId={_id(organization_id)}' if organization_id else ''
        return self._http.delete(f'/identity/users/{_id(user_id)}/roles/{_id(role_id)}{query}')

    def logs(self, user_id: str, limit: Optional[int] = None) -> Dict[str, Any]:
        return self._http.get(f'/identity/users/{_id(user_id)}/logs', _clean({'limit': limit}))


class IdentityJobs:
    def __init__(self, http: HttpClient, kind: str):
        self._http = http
        self._kind = kind

    def start(self, users: Optional[List[Dict[str, Any]]] = None, upsert: Optional[bool] = None, format: Optional[str] = None) -> Dict[str, Any]:
        """imports: users (and upsert); exports: format 'csv' or 'json'."""
        return self._http.post(f'/identity/users-{self._kind}', _clean({'users': users, 'upsert': upsert, 'format': format}))

    def get(self, job_id: str) -> Dict[str, Any]:
        return self._http.get(f'/identity/users-{self._kind}/{_id(job_id)}')

    def file(self, job_id: str) -> str:
        """Exports: the finished file (CSV or JSON lines), as text."""
        return self._http.get_text(f'/identity/users-{self._kind}/{_id(job_id)}/file')

    def wait(self, job_id: str, interval: float = 1.0, timeout: float = 600.0) -> Dict[str, Any]:
        end = time.time() + timeout
        while True:
            job = self.get(job_id)
            if job.get('status') != 'running' or time.time() > end:
                return job
            time.sleep(interval)


class _Crud:
    def __init__(self, http: HttpClient, base: str, list_key: str):
        self._http = http
        self._base = base
        self._list_key = list_key

    def list(self, **params: Any) -> List[Dict[str, Any]]:
        return self._http.get(self._base, _clean(params) or None).get(self._list_key, [])

    def get(self, item_id: str) -> Dict[str, Any]:
        return self._http.get(f'{self._base}/{_id(item_id)}')

    def create(self, **body: Any) -> Dict[str, Any]:
        return self._http.post(self._base, body)

    def update(self, item_id: str, **body: Any) -> Dict[str, Any]:
        return self._http.patch(f'{self._base}/{_id(item_id)}', body)

    def delete(self, item_id: str) -> Dict[str, Any]:
        return self._http.delete(f'{self._base}/{_id(item_id)}')


class IdentityOrganizations(_Crud):
    def __init__(self, http: HttpClient):
        super().__init__(http, '/identity/organizations', 'organizations')

    def members(self, org_id: str) -> Dict[str, Any]:
        return self._http.get(f'{self._base}/{_id(org_id)}/members')

    def add_members(self, org_id: str, user_ids: List[str]) -> Dict[str, Any]:
        return self._http.post(f'{self._base}/{_id(org_id)}/members', {'userIds': user_ids})

    def remove_member(self, org_id: str, user_id: str) -> Dict[str, Any]:
        return self._http.delete(f'{self._base}/{_id(org_id)}/members/{_id(user_id)}')

    def set_connections(self, org_id: str, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self._http.put(f'{self._base}/{_id(org_id)}/connections', {'connections': connections})

    def invitations(self, org_id: str) -> Dict[str, Any]:
        return self._http.get(f'{self._base}/{_id(org_id)}/invitations')

    def invite(self, org_id: str, email: str, client_id: str, role_ids: Optional[List[str]] = None,
               inviter_name: Optional[str] = None, send_email: Optional[bool] = None) -> Dict[str, Any]:
        """The link opens the app's sign-in route (initiateLoginUri) with organization and invitation."""
        return self._http.post(f'{self._base}/{_id(org_id)}/invitations', _clean({
            'email': email, 'clientId': client_id, 'roleIds': role_ids, 'inviterName': inviter_name, 'sendEmail': send_email,
        }))

    def revoke_invitation(self, org_id: str, invitation_id: str) -> Dict[str, Any]:
        return self._http.delete(f'{self._base}/{_id(org_id)}/invitations/{_id(invitation_id)}')


class IdentityClients(_Crud):
    def __init__(self, http: HttpClient):
        super().__init__(http, '/identity/clients', 'clients')

    def rotate_secret(self, client_id: str) -> Dict[str, Any]:
        """The new secret is in the answer, this once."""
        return self._http.post(f'{self._base}/{_id(client_id)}/rotate-secret', {})


class Identity:
    def __init__(self, http: HttpClient):
        self._http = http
        self.users = IdentityUsers(http)
        self.imports = IdentityJobs(http, 'imports')
        self.exports = IdentityJobs(http, 'exports')
        self.roles = _Crud(http, '/identity/roles', 'roles')
        self.organizations = IdentityOrganizations(http)
        self.clients = IdentityClients(http)
        self.apis = _Crud(http, '/identity/apis', 'apis')
        self.connections = _Crud(http, '/identity/connections', 'connections')
        self.custom_domains = _Crud(http, '/identity/custom-domains', 'domains')

    def get_tenant(self) -> Dict[str, Any]:
        return self._http.get('/identity/tenant')

    def update_tenant(self, **body: Any) -> Dict[str, Any]:
        """Turns Touchque Login on (slug, displayName) or changes its settings."""
        return self._http.put('/identity/tenant', body)

    def rotate_signing_key(self) -> Dict[str, Any]:
        return self._http.post('/identity/tenant/signing-keys/rotate', {})

    def set_approver_app_name(self, name: Optional[str]) -> Dict[str, Any]:
        """The phone app the hosted pages tell customers to approve on ("Approve on the Acme app").

        None: your brand name when the Mobile SDK is set up, else Touchque (``approverApp`` in the tenant shows which).
        """
        return self._http.put('/identity/tenant', {'branding': {'approverAppName': name}})

    def set_custom_domain_only(self, on: bool) -> Dict[str, Any]:
        """Serve sign-in only on the primary custom domain: {slug}.login.touchque.com redirects page loads there and
        refuses other calls. Turning it on needs a verified primary domain with a working certificate."""
        return self._http.put('/identity/tenant', {'customDomainOnly': on})

    def check_domain_certificate(self, domain_id: str) -> Dict[str, Any]:
        """Checks a verified custom domain's certificate at the sign-in edge now (``certificate``: pending | active | error)."""
        return self._http.post(f'/identity/custom-domains/{_id(domain_id)}/check-certificate', {})

    def outbox(self, to: Optional[str] = None, limit: Optional[int] = None) -> Dict[str, Any]:
        """The delivery log. Message text only in the local dev inbox."""
        return self._http.get('/identity/outbox', _clean({'to': to, 'limit': limit}))

    def get_attack_protection(self) -> Dict[str, Any]:
        """Wrong passwords, suspicious addresses, bot challenge, breached passwords, new-browser notices, the risk engine."""
        return self._http.get('/identity/attack-protection')

    def set_attack_protection(self, **settings: Any) -> Dict[str, Any]:
        """Partial; the bot challenge's secret is write-only."""
        return self._http.put('/identity/attack-protection', settings)

    def attack_events(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """What attack protection caught lately."""
        return self._http.get('/identity/attack-protection/events', _clean({'limit': limit}))

    def get_delivery(self) -> Dict[str, Any]:
        """The email and SMS providers; secrets never come back (secretsSet)."""
        return self._http.get('/identity/delivery')

    def set_delivery(self, channel: str, **provider: Any) -> Dict[str, Any]:
        """Your own provider: email smtp, ses, postmark, sendgrid; sms twilio, netgsm.
        provider='postmark', from_='login@acme.com', serverToken=... (from_ is sent as "from").
        A secret left out keeps its stored value."""
        body = {('from' if k == 'from_' else k): v for k, v in provider.items()}
        return self._http.put(f'/identity/delivery/{_id(channel)}', body)

    def remove_delivery(self, channel: str) -> Dict[str, Any]:
        """Back to Touchque's transport."""
        return self._http.delete(f'/identity/delivery/{_id(channel)}')

    def test_delivery(self, channel: str, to: str) -> Dict[str, Any]:
        """One test message through the provider in use."""
        return self._http.post(f'/identity/delivery/{_id(channel)}/test', {'to': to})
