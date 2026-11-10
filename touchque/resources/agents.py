from typing import Any, Dict, List, Optional
from urllib.parse import quote

import time

from ..approval_token import assert_approval_matches, decode_approval_token, verify_approval_token_with
from ..exceptions import TouchQueApprovalMismatchError, TouchQueConfigException
from ..http_client import HttpClient


def _public_only(jwk: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Refuses a private key before it leaves this process."""
    if isinstance(jwk, dict) and 'd' in jwk:
        raise TouchQueConfigException(
            "Pass the agent's PUBLIC key: this one has private parts (d). "
            'The private key must stay where the agent runs.')
    return jwk


def _id(value: str) -> str:
    return quote(value, safe='')


class AgentVault:
    """The token vault for your agents (``client.agents.vault``): after your own OAuth flow with a
    person, deposit their tokens; TouchQue keeps them sealed and refreshes them, and the agents a
    connection names get a short-lived access token (``TouchQueAgent.get_connection_token``),
    never the refresh token."""

    def __init__(self, http: HttpClient):
        self._http = http

    def list_connections(self) -> List[Dict[str, Any]]:
        return self._http.get('/agents/vault/connections')['connections']

    def put_connection(self, name: str, provider: str, client_id: str, client_secret: Optional[str] = None,
                       tenant: Optional[str] = None, issuer: Optional[str] = None, agent_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Adds or replaces a connection (google, microsoft, github, facebook, linkedin, x, oidc);
        ``client_secret`` is kept when left out of a replacement."""
        body: Dict[str, Any] = {'provider': provider, 'clientId': client_id}
        for key, value in (('clientSecret', client_secret), ('tenant', tenant), ('issuer', issuer), ('agentIds', agent_ids)):
            if value is not None:
                body[key] = value
        return self._http.put(f'/agents/vault/connections/{_id(name)}', body)['connection']

    def remove_connection(self, name: str) -> Dict[str, Any]:
        """Removes it, and every person's tokens kept for it."""
        return self._http.delete(f'/agents/vault/connections/{_id(name)}')

    def deposit(self, connection: str, user: str, access_token: str, refresh_token: Optional[str] = None,
                expires_in: Optional[int] = None, scope: Optional[str] = None) -> Dict[str, Any]:
        """Keeps a person's tokens (replacing earlier ones) after your own OAuth flow with them."""
        body: Dict[str, Any] = {'accessToken': access_token}
        for key, value in (('refreshToken', refresh_token), ('expiresIn', expires_in), ('scope', scope)):
            if value is not None:
                body[key] = value
        return self._http.put(f'/agents/vault/accounts/{_id(connection)}/{_id(user)}', body)['account']

    def list_accounts(self, user: str) -> List[Dict[str, Any]]:
        """A person's accounts in the vault (never a token)."""
        return self._http.get('/agents/vault/accounts', {'externalUsername': user})['accounts']

    def remove_account(self, connection: str, user: str) -> None:
        """Deletes a person's tokens: agents get nothing more for them there."""
        self._http.delete(f'/agents/vault/accounts/{_id(connection)}/{_id(user)}')


class Agents:
    """AI agents as identities of their own (``client.agents``): register an
    agent with its PUBLIC key, give it an accountable owner and the action
    types it may ask approvals for, suspend, revoke or stop every agent at
    once. The agent itself never gets your API key: it signs in with its own
    key (``TouchQueAgent``).

        keys = generate_agent_key()                       # where the agent runs
        agent = client.agents.create('Invoice bot', ['PAY_INVOICE'], public_key=keys['public_jwk'])
    """

    def __init__(self, http: HttpClient):
        self._http = http
        # The token vault: people's tokens at other services, for your agents.
        self.vault = AgentVault(http)
        self._jwks: Optional[Dict[str, Any]] = None
        self._jwks_at = 0.0
        self._audience: Optional[str] = None

    def redeem_approval(self, token: str, user: Optional[str] = None, type: Optional[str] = None,
                        authorization_details: Any = None) -> Dict[str, Any]:
        """Uses an agent's approval exactly once, right before you execute:
        checks your expectations against the token first (nothing is used on a
        mismatch), then TouchQue checks the token and marks it used, and the
        answer is checked again. Raises TouchQueApprovalMismatchError or a
        TouchQueAPIException (``already_redeemed``, ``token_expired``...)."""
        expect = {'user': user, 'type': type, 'authorization_details': authorization_details}
        assert_approval_matches(decode_approval_token(token)['claims'], **expect)
        approval = self._http.post('/agents/approvals/redeem', {'token': token})['approval']
        assert_approval_matches({'sub': approval.get('externalUsername'), 'type': approval.get('type'),
                                 'authorization_details': approval.get('authorizationDetails')}, **expect)
        return approval

    def approval_audience(self) -> str:
        """The ``aud`` of this workspace's approval tokens (``touchque:workspace:<id>``),
        from GET /agents/approval-audience; asked once, then kept."""
        if not self._audience:
            audience = (self._http.get('/agents/approval-audience') or {}).get('audience')
            if not isinstance(audience, str) or not audience:
                raise TouchQueApprovalMismatchError("Touchque did not name this workspace's approval audience")
            self._audience = audience
        return self._audience

    def verify_approval_token(self, token: str, audience: Optional[str] = None, **expect: Any) -> Dict[str, Any]:
        """Verifies an approval token offline (TouchQue's published keys, expiry,
        ``aud``, ``user`` / ``type`` / ``authorization_details``). ``aud`` must be
        this workspace's: ``audience`` defaults to ``approval_audience()``, and a
        token without aud or for another workspace is refused. It does not make
        the token single-use: ``redeem_approval`` does."""
        audience = audience or self.approval_audience()
        if self._jwks is None or time.time() - self._jwks_at > 300:
            self._jwks, self._jwks_at = self._http.get('/agents/jwks.json'), time.time()
        try:
            return verify_approval_token_with(token, self._jwks, audience=audience, **expect)
        except TouchQueApprovalMismatchError as exc:
            if 'unknown key' not in str(exc):
                raise
            self._jwks, self._jwks_at = self._http.get('/agents/jwks.json'), time.time()
            return verify_approval_token_with(token, self._jwks, audience=audience, **expect)

    def create(self, name: str, allowed_types: List[str], public_key: Optional[Dict[str, Any]] = None,
               public_keys: Optional[List[Dict[str, Any]]] = None, description: Optional[str] = None,
               owner_email: Optional[str] = None, platform: Optional[str] = None,
               review_in_days: Optional[int] = None) -> Dict[str, Any]:
        """Registers an agent (needs the ``agents:write`` scope). ``owner_email``:
        the accountable person, a member of the organization (default: the
        API key's creator); the agent stops when they leave."""
        body: Dict[str, Any] = {'name': name, 'allowedTypes': allowed_types}
        if description is not None:
            body['description'] = description
        if owner_email is not None:
            body['ownerEmail'] = owner_email
        if platform is not None:
            body['platform'] = platform
        if review_in_days is not None:
            body['reviewInDays'] = review_in_days
        if public_key is not None:
            body['publicKey'] = _public_only(public_key)
        if public_keys is not None:
            body['publicKeys'] = [_public_only(k) for k in public_keys]
        return self._http.post('/agents', body)['agent']

    def list(self, status: Optional[str] = None) -> Dict[str, Any]:
        """``{'agents': [...], 'killSwitch': {...}}``."""
        return self._http.get('/agents', {'status': status} if status else None)

    def get(self, agent_id: str) -> Dict[str, Any]:
        return self._http.get(f'/agents/{_id(agent_id)}')['agent']

    def update(self, agent_id: str, name: Optional[str] = None, description: Optional[str] = None,
               owner_email: Optional[str] = None, platform: Optional[str] = None,
               allowed_types: Optional[List[str]] = None, review_in_days: Optional[int] = None) -> Dict[str, Any]:
        """Changes, hands over (``owner_email``) or renews (``review_in_days``) an agent."""
        body: Dict[str, Any] = {}
        for key, value in (('name', name), ('description', description), ('ownerEmail', owner_email),
                           ('platform', platform), ('allowedTypes', allowed_types), ('reviewInDays', review_in_days)):
            if value is not None:
                body[key] = value
        return self._http.patch(f'/agents/{_id(agent_id)}', body)['agent']

    def add_key(self, agent_id: str, public_key: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a key (rotation: add the new one, move the agent to it, then remove the old one)."""
        return self._http.post(f'/agents/{_id(agent_id)}/keys', {'publicKey': _public_only(public_key)})['agent']

    def remove_key(self, agent_id: str, kid: str) -> Dict[str, Any]:
        """Removes a key; tokens the agent got with it stop at once."""
        return self._http.delete(f'/agents/{_id(agent_id)}/keys/{_id(kid)}')['agent']

    def suspend(self, agent_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """Stops an agent at once (its tokens too) until resumed."""
        return self._http.post(f'/agents/{_id(agent_id)}/suspend', {'reason': reason} if reason else {})['agent']

    def resume(self, agent_id: str) -> Dict[str, Any]:
        return self._http.post(f'/agents/{_id(agent_id)}/resume', {})['agent']

    def revoke(self, agent_id: str) -> Dict[str, Any]:
        """Revokes an agent for good (the record stays for the audit trail)."""
        return self._http.delete(f'/agents/{_id(agent_id)}')['agent']

    def set_policy(self, agent_id: str, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Sets the agent's budgets, amounts, recipients and background rule (a
        full replacement; left-out fields take the defaults): requestsPer10Min,
        requestsPerUserPer10Min, amountPerRequest / amountPerDay ({'TRY': '1000.00'}),
        background ('non_critical' | 'never'), newRecipients ('ask' | 'deny'),
        recipientAllowlist (IBANs / account numbers), fourEyes, requirePasskeyAbove
        ({'TRY': '10000.00'}: over it the person approves with a passkey on your
        page, never on the phone or with a mandate)."""
        return self._http.put(f'/agents/{_id(agent_id)}/policy', {'policy': policy})['agent']

    def list_events(self, after: Optional[str] = None, since: Optional[str] = None, limit: Optional[int] = None) -> Dict[str, Any]:
        """The workspace's agent events for a SIEM, oldest first: ``{'events', 'next',
        'hasMore'}``. Keep ``next`` and pass it as ``after``; the first call reads from
        ``since`` (ISO 8601; default the last 24 hours)."""
        params: Dict[str, Any] = {}
        for key, value in (('after', after), ('since', since), ('limit', limit)):
            if value is not None:
                params[key] = value
        return self._http.get('/agents/events', params or None)

    def get_workspace_policy(self) -> Dict[str, Any]:
        """The workspace's policy: every agent's floor (an agent's own policy can only make it stricter)."""
        return self._http.get('/agents/workspace-policy')['policy']

    def set_workspace_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Sets the workspace's policy (a full replacement; a field left out sets no floor)."""
        return self._http.put('/agents/workspace-policy', {'policy': policy})['policy']

    def list_blocks(self, agent_id: str) -> List[Dict[str, Any]]:
        """The people who stopped this agent asking them (reason not_me, coached or rejections)."""
        return self._http.get(f'/agents/{_id(agent_id)}/blocks')['blocks']

    def lift_block(self, agent_id: str, user: str) -> None:
        """Lets the agent ask this person again (check with them first)."""
        self._http.delete(f'/agents/{_id(agent_id)}/blocks/{_id(user)}')

    def list_mandates(self, agent_id: str, user: Optional[str] = None) -> List[Dict[str, Any]]:
        """An agent's mandates, optionally one person's."""
        return self._http.get(f'/agents/{_id(agent_id)}/mandates', {'externalUsername': user} if user else None)['mandates']

    def revoke_mandate(self, agent_id: str, mandate_id: str) -> Dict[str, Any]:
        """Ends an agent's mandate at once."""
        return self._http.post(f'/agents/{_id(agent_id)}/mandates/{_id(mandate_id)}/revoke', {})

    def set_kill_switch(self, engaged: bool, reason: Optional[str] = None) -> Dict[str, Any]:
        """Stops (True) or restarts (False) every agent of the workspace at once."""
        body: Dict[str, Any] = {'engaged': engaged}
        if reason:
            body['reason'] = reason
        return self._http.put('/agents/kill-switch', body)['killSwitch']
