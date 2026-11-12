# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [5.1.0] — 2026-11-12

### Fixed
- **No API keys is a JSON answer, never an exception.** The Flask, FastAPI and Django adapters given no `client` built the default one before anything else, so a missing `TQ_API_KEY` / `TQ_API_SECRET` raised `TouchqueConfigException` on every request (the framework's own 500 page). The default client is now built per request inside the guard and kept once built. While it cannot be built, a guarded route answers 500 `{"touchque": {"state": "blocked", "reason": "misconfigured"}, "error": {"code": "misconfigured", ...}}` with `Cache-Control: no-store` (401 `unauthenticated` when nobody is signed in), the view never runs, and `[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.` is logged once per process. `run_guard(None, ...)` does the same.
- **The first-time QR stays on screen while it works.** Every poll with an `enroll` token started again (login request, 404, generate-secret 409, reset), so each poll replaced the QR and the recovery codes being scanned. The enroll step now carries `enroll.expiresAt` (the API's `expiresAt` when it is ISO 8601, else now + `ttlMs`) and its token the claim `ee`. A poll with such a token reads the link state (`GET /users/{user}`): linked, it starts as before (`waiting` …); not linked and more than 15 seconds before the expiry, it answers 202 `{"touchque": {"state": "enroll", "expiresAt": ...}, "token": ...}` with no `enroll` and no other call, so the page keeps the QR and codes it shows; an expired QR (or a 404) gets a new one in `enroll.qrCodeDataUrl`. Another error of that check answers 503 `unavailable`. `is_status_poll` counts such polls while the QR is up (more than 15 seconds before its expiry), so the relay's per-user limit no longer refuses enrollment polls after a few seconds; the poll that renews an expiring QR, and a replayed old token, still count against it. Starts are always charged: `run_guard(..., before_start=)` is called at most once, right before a first-time-QR token starts something (a push once the phone is linked, or a new QR), and a result it returns is answered instead; the relay's `POST /login` charges its per-user `login` limit there, as for a fresh attempt, and answers its usual 429 when it is over (30 replays of an enroll token after linking gave 30 pushes on the poll budget). `is_status_poll` and `BeforeStart` are exported from `touchque`, and `is_status_poll(None, ...)` uses the default client as `run_guard` does (False while it cannot be built). Pages on `@touchque/web` need 2.1.0.

### Added
- **`error_body=` on `require_touchque` (Flask, Django) and `RequireTouchque` (FastAPI, where it may be async): refusals in your app's own error shape.** Called for every answer with status 400 or above (never a 202 step) with `{'status', 'code', 'message', 'touchque'}` (a copy of the step). What it returns counts by the framework's JSON encoding: what encodes to an object (a dict, a dataclass, a pydantic model; on FastAPI through `jsonable_encoder`, so a model keeps its aliases) is sent with `touchque` set to the step, anything else as it is; status and headers stay; if it raises or returns what cannot be encoded, the default body is sent and `[Touchque] error_body failed: ...` logged. On FastAPI, `install_touchque_exception_handler(app)` sends it as the whole body. `touchque.guard.guard_response_body(result, error_body, encode)` does the same for your own adapter.
- **Refusals carry `X-Touchque-State` (and `X-Touchque-Reason` when the step has a reason)**, from the three adapters and from the relay (`POST /login`, passkey registration), so `@touchque/web` 2.1.0 knows the state when an `error_body` sends no `touchque`. `guard_response_headers(result)` gives a `run_guard` result's headers (`Cache-Control`, `Retry-After`, these two) for your own handler.
- **`touchque.testing.FakeTouchque` (also `FakeClient`): a fake client for your app's tests**, with no network, no API keys and no Node.js. It is a `Touchque` whose calls are answered in memory, so the real guard runs. Every user has a phone linked unless you `unlink()` them (`link()`, `linked=False`); `approve()`, `reject()` and `expire()` the latest request or one by id; `auto_approve`; `number_match`; `requests` and `calls` record what your app asked; `install()` / `uninstall()` (or `with FakeTouchque() as tq:`) make it the default client for routes given no `client`.
- README: "Guard inside your handler" (`run_guard` after your own checks, the answers and headers to send, the 202 / enroll poll contract), "Refusals in your own error shape", "Without API keys" and "Testing your routes".

## [5.0.0] — 2026-11-11

### Breaking
- **Every name is spelled Touchque instead of TouchQue.** The client class `TouchQue` → `Touchque` (`from touchque import Touchque`). The error classes: `TouchQueException` → `TouchqueException`, `TouchQueAPIException` → `TouchqueAPIException`, `TouchQueFeatureException` → `TouchqueFeatureException`, `TouchQueFeatureNotInPlanException` → `TouchqueFeatureNotInPlanException`, `TouchQueFeatureReadOnlyException` → `TouchqueFeatureReadOnlyException`, `TouchQueFeatureOffException` → `TouchqueFeatureOffException`, `TouchQueNetworkException` → `TouchqueNetworkException`, `TouchQueTimeoutException` → `TouchqueTimeoutException`, `TouchQueRejectedException` → `TouchqueRejectedException`, `TouchQueWebhookSignatureException` → `TouchqueWebhookSignatureException`, `TouchQueWebhookReplayException` → `TouchqueWebhookReplayException`, `TouchQueConfigException` → `TouchqueConfigException`, `TouchQuePasskeyRequiredError` → `TouchquePasskeyRequiredError`, `TouchQueApprovalError` → `TouchqueApprovalError`, `TouchQueApprovalMismatchError` → `TouchqueApprovalMismatchError`. The agent clients: `TouchQueAgent` → `TouchqueAgent`, `TouchQueOrgAgent` → `TouchqueOrgAgent`. The FastAPI dependency `touchque.contrib.fastapi.RequireTouchQue` → `RequireTouchque`. The headers in the docs and examples: `X-TouchQue-Token`, `X-TouchQue-Offline`, `X-TouchQue-Code`, `X-TouchQue-Code-Type`, `X-TouchQue-Browser` → `X-Touchque-Token`, `X-Touchque-Offline`, `X-Touchque-Code`, `X-Touchque-Code-Type`, `X-Touchque-Browser`; HTTP header names are case-insensitive, so servers are unaffected, and the SDK reads them case-insensitively. Error messages and log lines say Touchque (`[Touchque] ...`). The module `touchque`, the PyPI package `touchque-authenticator` and the lowercase names (`require_touchque`, `install_touchque_exception_handler`, `with_touchque_approval`...) stay; the signed Safe Guard governance type keeps its spelling, so governance hashes do not change. Code using the old names must be updated (replace `TouchQue` with `Touchque`); nothing else changes.

### Changed
- The README links work where the package is read (npm, PyPI, GitHub): the Actions and Touchque Login guides point to support.touchque.com, SECURITY.md and CONTRIBUTING.md to this package's public repository.
- The README has an "Action types" section: define a type once (dashboard → Developers → Action types, or from code); the guard answers 500 `misconfigured` for an undefined name and 403 `action_disabled` for one turned off.
- The `dev` extra installs `httpx`, which FastAPI's TestClient needs in the tests.

## [4.2.0] — 2026-11-10

### Security
- **The offline approval-token check refuses another workspace's token.** `GET /agents/jwks.json` is one key set for every Touchque workspace, and the check used to compare `aud` only when you passed an audience, so a token Touchque signed for someone else's workspace (their own phone, any person's name, any details) could pass your executor. Now:
  - `agents.verify_approval_token(token, audience=None, **expect)` uses this workspace's own audience by default: `agents.approval_audience()` asks `GET /agents/approval-audience` once (`touchque:workspace:<id>`) and keeps it.
  - `verify_approval_token_with(token, jwks, audience, ...)` requires the audience. A missing or empty one throws TouchqueApprovalMismatchError (`audience is required`).
  - A token without `aud` is refused (`the approval token names no workspace`), as is one for another workspace (`the approval token is for another workspace`).
  - Breaking for callers of the low-level function who passed no audience: pass agents.approval_audience()'s value.
  - `redeemApproval` was already safe: Touchque compares `aud` with your workspace there.
- **Hosted login: an empty `iss` is refused too (RFC 9207).** `handle_callback` already refused a callback whose `iss` names another issuer; one with an empty `iss=` now raises `issuer_mismatch` as well, before the code is exchanged. A callback without `iss` (a server that does not send it yet) is still accepted.
- **Safe Guard:** `verify_safe_approval` without `purpose` now accepts only an approval to execute (`approve`). An approval that schedules a governance change covers neither the Safe nonce nor the gas fields, so it passes only with `purpose='schedule'`; before, either one was accepted. Name the purpose you will act on (`status()['safeTx']['purpose']`).
- **Touchque Login:** `HostedLogin` and `MyAccount` refuse a plaintext `http://` domain except on this machine (`localhost`, `127.0.0.1`, `::1`, `*.localhost`), as `Config` does for `base_url`: authorization codes, PKCE verifiers, client secrets and tokens would travel in the clear.

### Added
- **`device_risk.search_events(...)`: search your workspace's Device risk identifications**, newest first, one page at a time (`GET /device-risk/events`): `from_`/`to` (7 days by default, at most 90, within your retention), `signal`, `step_up`, `kind`, `origin`, `ip` (an address or a CIDR range; never returned), `account`, `visitor_id`, `request_id`, `limit` (1 to 100) and the opaque `cursor` from the previous page's `nextCursor`.
- `device_risk.check()` returns `'engine'` (str or None): the engine's state for this check; `'unavailable'` when the risk engine could not be reached and the verdict is a safe default (`stepUp` True), so an outage can be told apart from risk.
- **`webauthn.primary_availability()`: is passkey sign-in on for your workspace?** `GET /webauthn/authenticate/primary/availability` answers `{'enabled': bool, 'userVerification': 'required' | 'preferred' | None}`. Ask before your sign-in page shows its passkey button and passkey autofill; when it is off, `primary_options` answers 403 `passwordless_login_disabled`.
- **Shared Signals: receive the security events an identity provider sends after sign-in.** Touchque SSO sends Security Event Tokens (OpenID Shared Signals Framework 1.0) for an organization's members to the receivers its admin adds (Organization > Continuous access): CAEP `session-revoked`, `credential-change`, `device-compliance-change`, RISC `account-disabled`, `credential-compromise`; `txn` carries the case code of Touchque's decision. `SecurityEventVerifier(issuer=, audience=, jwks_uri=, jwks=, clock_skew=).verify(token)` returns a `SecurityEvent` (`jti`, `issuer`, `audience`, `issued_at`, `txn`, `subject`, `type`, `name`, `claims`) or raises `SecurityEventError` with the RFC 8935 code to answer (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`); `poll_security_events(url=, token=, ack=, set_errs=, max_events=)` for poll delivery (RFC 8936); `SECURITY_EVENT_TYPES` (the `[agent]` extra). The keys come from the issuer's `/.well-known/ssf-configuration`; a SET does not expire, so keep the jtis you handled. Tested against the shared vectors (`fixtures/security-event-vectors.json`).
- **Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard.** `tq.safe_guard.request(external_username, type, safe_tx)` sends the raw transaction (the phone decodes it itself and signs with a key only its biometrics unlock), `status(request_id)` and `wait_for_approval(request_id)` hand back the 105-byte approval. `verify_safe_approval(target, approval, approver_key, purpose=, approver_index=, rows= | display_digest=, now=)` checks it the way the guard does, without trusting Touchque: the Safe transaction hash (EIP-712) and the governance hash computed here, the 149-byte message, low `s`, the one-day expiry window, the P-256 signature (the `[proof]` extra). `with_safe_approvals(owner_signatures, approvals)` for `execTransaction`, `safe_schedule_call(safe, governance_hash, approvals)` for a governance change; `safe_tx_hash`, `safe_governance_hash`, `safe_approval_message`, `safe_display_digest`. Tested against the shared vectors (`fixtures/safe-guard-vectors.json`).
- **Webhook event constants for the Mobile SDK, Never Locked Out and the help desk** (`WebhookEvents`): `MOBILE_PUSH`; `RECOVERY_STARTED`, `RECOVERY_DEVICE_BOUND`, `RECOVERY_COOLING`, `RECOVERY_COMPLETED`, `RECOVERY_VETOED`, `RECOVERY_EXPIRED`, `RECOVERY_FAILED`; `ASSIST_OPENED`, `ASSIST_ENDED`, `ASSIST_CHECK_PASSED`, `ASSIST_CHECK_FAILED`, `ASSIST_UNFROZEN`, `ASSIST_CLAIM_CONFIRMED`, `ASSIST_CLAIM_UNVERIFIED`. The names Touchque already sends.
- `login.wait_for_approval(request_id, timeout_ms=30000, poll_interval_ms=400)`: waits for a request you sent with `login.request`, like `verify` does after sending one (`TouchqueRejectedException`, `TouchqueTimeoutException`, `TouchquePasskeyRequiredError` with `reason='step_up'`).
- `assist.list(open=True)` (the name `recovery.list` and the other SDKs use) and `qr_pairings.create(..., os=...)`, aliases of `open_only` and `os_name`, which keep working.
- README: "Shared Signals (security events from Touchque SSO)", verifying a pushed SET and polling. Tests for discovery through `/.well-known/ssf-configuration` and for `poll_security_events`, against a local transmitter.

### Fixed
- `identity.users.list(blocked=, email_verified=)` sent `True` / `False`, which the API ignores, so every user came back. Booleans in a query string now go as `true` / `false`.
- `login.verify(..., on_challenge=)`: a callback that raised made `verify` fail with `TypeError` instead of logging the error and waiting for the phone.
- README: the webhook example passed Flask's `request.data` (bytes) to `webhook.verify`, which takes text, so it refused every genuine webhook. It now passes `request.get_data(as_text=True)`.
- A non-ASCII `X-Touchque-Token` header made the step-up guard and the relay raise (HTTP 500). It is now an invalid token like any other.
- `webhook.verify` raised `TypeError` for a non-ASCII signature instead of `TouchqueWebhookSignatureException`.
- `McpAuth.verify` / `verify_token`, `IdJagVerifier.verify`, `verify_agent_card` and `verify_approval_token_with` raised `ValueError` for a signature segment that is not base64url. They now refuse it with their own error (`McpAuthError` 401 `invalid_token`, `IdJagError('invalid_grant')`, `AgentCardError('invalid_signature')`, `TouchqueApprovalMismatchError`).
- `install_touchque_exception_handler(app)` no longer replaces FastAPI's handling of every other `HTTPException`: those go to FastAPI's own handler, which sends no body on a 204 or 304.
- `with_touchque_approval` on an async tool, `touchque_can_use_tool` and `guard_mcp_session` used `asyncio.to_thread` and failed on Python 3.7 and 3.8.
- The unknown-action error now points to `client.action_types.define(...)`; `client.actions` is Touchque Actions since 4.0.

## [4.1.0] — not published (these changes ship in 4.2.0)

### Added
- **Device risk events like a device-intelligence event, without raw traits:** `deviceRisk.check` and `getEvent` answers carry `network`, `velocity` and `bot`: the address as the risk engine saw it (country, region, city, never coordinates; the operator; `type` isp, hosting or tor; `timezoneMismatch` when the browser's clock does not fit the address), the visitor's counts (accounts, sign-ups, countries, stored-id resets, identifications in the last hour and day) and one answer to "a bot?" (`detected`, `suspected` or `not_detected`, with reasons). The field the script tag fills may now carry its pointer summary after the requestId: pass it as it came.
- **A code typed back on the phone:** `login.request(..., reply={'kind': 'code', 'key': ..., 'channel': ..., 'target': ...})`; `new_code_reply_key()` and `open_code_reply(private_key, request_id, ct)` (with the `[proof]` extra) open `status()['reply']['ct']`.
- **Feature errors:** a feature your organization cannot use here (403 `feature_not_in_plan`, `feature_read_only`, `feature_off`) raises `TouchqueFeatureNotInPlanException`, `TouchqueFeatureReadOnlyException` or `TouchqueFeatureOffException`, all `TouchqueFeatureException` (with `feature` and `feature_reason`) and still `TouchqueAPIException`.
- **Webhook events `DEVICE_RISK_SIGNAL` and `DEVICE_RISK_ALERT`** (`WebhookEvents`): a Device risk signal that asks for more (identifiers, signals and the engine's verdict, never a trait), and an alert rule of the workspace that went off. Signed like every event.
- **Device risk in one line: `tq.device_risk.check(request.form.get('touchque_request_id'), event=, external_username=)`** with the script tag (`device.js`, `@touchque/web` 1.6.0), which fills that field. Pass it as it came: None, empty, made up or expired is still a verdict (`report`: `missing`, `unknown`, `expired`, `invalid`; the signal `device_identification_missing`, a number-matched step-up at most), never an exception. `DEVICE_RISK_REPORTS`.
- **Device risk: `tq.device_risk.check(request_id, event=, external_username=, client_ip=)` and `tq.device_risk.get_event(request_id)`** (a paid add-on; 409 `device_risk_off` until the workspace turns it on), and `device_risk_request_id=` (or `device_risk=`) on `login.request` and `risk.check`. The page's `requestId` comes from `@touchque/web` `deviceRisk.identify`. Every signal only ever asks for more (`stepUp`, never a refusal); signals start in shadow. `parse_device_risk_check`, `DEVICE_RISK_EVENTS`.
- **Pairing a browser by QR code: `client.qr_pairings`.** `create(key_thumbprint, client_ip=, user_agent=, browser=, os_name=, ttl_seconds=)` registers a pairing for the browser key your page holds (`@touchque/web` `browserKey.thumbprint()`) and returns `uri` (`touchque://pair-browser?...`) to show as a QR code; the nonce in it stays with you (Touchque keeps its hash). `get(pairing_id)` says who scanned it and how near the phone was (`proximity`), `refuse(pairing_id, reason, message)` tells the phone why your own checks said no. `login.request(..., qr_pairing=)` asks the phone that scanned, once, with number matching. `qr_pairing_uri`, `QR_PAIRING_REFUSAL_REASONS`.
- **Touchque Login Management API:** `identity.users.end_session(user_id, session_id)` signs the person out of one session, `identity.exports.file(job_id)` returns the finished export (CSV or JSON lines) as text.
- **Actions: the `agent.approval` trigger**, before an AI agent's request reaches the phone (`deploy(..., trigger='agent.approval')`); only tightening counts: `api.deny`, `api.requirePasskey`, `api.stepUp`. See ACTIONS.md.
- **Webhook reason `user_blocked_agent`** (`WebhookReasons.USER_BLOCKED_AGENT`): the person rejected an AI agent's request with Block this agent on their phone; the agent may not ask them again, and 2FA is not frozen. `list_blocks` can return the block reason `'phone'`.
- **AI agents: events for a SIEM.** `agents.list_events(after=None, since=None, limit=None)`: the workspace's agent events (`AGENT_*`, `AGENTS_*`) oldest first, each with its agent, person, approval and case code; keep `next` and pass it as `after`.
- **AI agents: the workspace's policy and a passkey line.** `agents.get_workspace_policy()` / `set_workspace_policy(policy)`: every agent's floor (an agent's own policy can only be stricter, field by field). `requirePasskeyAbove: {'TRY': '10000.00'}` in any policy: over it the person approves with a passkey on your page (`requiresPasskey` on the approval), never on the phone or with a mandate; a background request gets 409 `interactive_required`. Webhook `AGENT_WORKSPACE_POLICY_CHANGED`. A second approver who answers sooner than a person can gets no token (status `blocked`, reason `inhuman_approval`).
- **Touchque Login: the approving app's name and custom-domain-only sign-in.** `identity.set_approver_app_name(name)`: the phone app the hosted pages tell customers to approve on ("Approve on the Acme app"; `None` = your brand when the Mobile SDK is set up, else Touchque). `identity.set_custom_domain_only(True)`: serve sign-in only on the primary custom domain ({slug}.login.touchque.com redirects page loads there and refuses other calls; needs a verified primary domain with a working certificate). `identity.check_domain_certificate(domain_id)`: the domain's certificate at the sign-in edge now (`certificate`: pending, active or error).
- **Cross App Access (ID-JAG) and A2A agent cards.** `request_id_jag` trades a member's ID token for an ID-JAG at the organization's identity provider, `redeem_id_jag` trades it for an access token at the other service (jwt-bearer); `IdJagVerifier` checks one at your own authorization server (typ, issuer, single audience, client, expiry, used once; `first_use` for a shared store). `verify_agent_card` checks an A2A card's signatures (JWS over the RFC 8785 canonical card; `jku` only on the card's host or `trusted_jku_hosts`), `sign_agent_card`, `canonical_json`.
- **Security-change lock, look-alike destinations, Second Thought questions — for any action type.** `login.request(..., security_changes={'password', 'mfa', 'device', 'email', 'phone'})` (when each last changed in your system; a datetime, ISO 8601 or epoch ms): access rules and Actions read `minutesSince.mfaChange`, `.deviceChange`, … (e.g. refuse `PAYOUT_CHANGE` within 24 h of a 2FA change). `destination={'kind': 'iban'|'account'|'wallet'|'address'|'payee', 'value': ..., 'known': [...]}` is shown in full on the phone in groups of four, with a warning when it looks like one the user used before but is not the same; the answer's `destination` is `{'known', 'lookalike'}`, rules read `destination.lookalike`. `locale='tr'|'en'` for those rows; `verify` takes the same three. `action_types.define(type, second_thought={'questions': [...], 'locale': ...})` (at most two of `SECOND_THOUGHT_QUESTIONS`, `None` turns them off): the phone asks them before Approve and a risky answer makes the approval `provisional`.
- **Mobile SDK: your own app approves for your users.** `tq.mobile.create_enrollment(external_username, replace=False, ttl_seconds=None)` gives a one-time `tqe_` token your iOS/Android app spends with the Touchque Mobile SDK; `list_devices`, `get_device`, `remove_device`, `settings`, `update_settings`. `mobile_push_from_webhook(event)` turns the signed `MOBILE_PUSH` webhook into the APNs payload / FCM data you send with your own keys; `is_mobile_push_expired`.
- **Mobile SDK: Touchque can send the push.** `update_settings(apns={...}, fcm={'serviceAccount': ...})` gives Touchque your own APNs key / Firebase service account; it then pushes that platform itself instead of the `MOBILE_PUSH` webhook (`None` removes a key). `settings()['push']` shows who pushes, never the keys. `update_settings(android_certs=...)`: the SHA-256 of each Android app's signing certificate, checked against Key Attestation at enrollment. `mobile.test_push(device_id)` sends a harmless push the way a request would reach the phone and says which way it went and whether APNs / FCM took it; a `MOBILE_PUSH` webhook may now have `kind: 'test'`.
- **`client_signals` on `login.request` and `risk.check`:** the end user's page check from `@touchque/web`; a browser driven by software is never silent and asks with number matching, or is refused where the workspace blocks it (403 `automated_client`).
- **Help desk.** `tq.assist.open(external_username, {'name': ..., 'title': ..., 'ref': ...}, reason=...)` before your help desk acts on someone's account (their phone gets a calm notice; their "someone says they're from IT" button shows the agent), `verify(id, action)` before a sensitive action (a 2-digit `challengeCode` the agent reads to the person, who types it and approves on their phone; `no_phone` routes to Never Locked Out), `spend(id, request_id, action)` right before the action, `unfreeze`, `get`, `list`, `end`; `is_assist_check_passed(session, request_id)`. Webhooks `ASSIST_*`, among them `ASSIST_CLAIM_UNVERIFIED` (someone pretended to be IT).
- **Touchque Login: an app acting for a customer.** `login.exchange_token(user_access_token, audience=..., scope=...)` (RFC 8693), `login.ask_user(login_hint, scope, ...)` and `login.wait_for_user(ask)` (CIBA, poll mode); `TokenSet.authorization_details`, `issued_token_type`, `UserApprovalRequest`.
- **Touchque Login: token vault.** `login.get_connection_token(user_access_token, connection, scope=None)` returns the provider's own access token (Google, Microsoft, GitHub...) for the signed-in customer from a connection that stores tokens (`options.tokenVault`); Touchque refreshes it and the refresh token never leaves (`TokenSet.connection`, `CONNECTION_TOKEN_TYPE`). `identity.users.connected_accounts(user_id)` and `disconnect_account(user_id, account_id)`; My Account `stop_app_access(access_id)` and `identities[].appAccess`.
- **`expires_in` on `login.request`:** how long the push waits for the person, 30 (default) to 300 seconds, for requests the person has to read first (an AI agent asking on their behalf).
- **`McpAuth` for MCP servers whose authorization server is Touchque SSO** (Organization → MCP servers). `McpAuth(issuer=..., resource=..., tools={...})`:
  `protected_resource_metadata()` at `metadata_paths()` (RFC 9728), `verify(method, url, headers)` (Touchque's JWKS, issuer,
  audience = this server, expiry, DPoP proof for a bound token), `verify_token(token)` for FastMCP's `TokenVerifier`,
  `require_tool(claims, tool)` (403 `insufficient_scope` with the scope). `McpAuthError` carries the status and the `WWW-Authenticate` header.
- **Attack protection in `client.identity`:** `get_attack_protection()`, `set_attack_protection(**settings)`,
  `attack_events()`. Actions accept the Touchque Login triggers (`identity.post_login`, …).
- **Email and SMS providers in `client.identity`:** `get_delivery()`, `set_delivery(channel, provider=..., from_=..., ...)`,
  `remove_delivery(channel)`, `test_delivery(channel, to)`. **My Account:** `start_sms_enrollment(phone)`,
  `verify_sms_enrollment(code)`, `remove_sms_codes()`.
- **Touchque Login My Account API.** `login.my_account_token(refresh_token, scope)` trades a first-party app's
  refresh token for a `https://<domain>/me/` token (keep the rotated refresh token); `login.my_account(access_token)`
  returns `MyAccount` (get, update_profile, authentication_methods, remove_passkey, unlink_touchque_app,
  set_email_codes, unlink_identity, set_password, remove_password, change_email, sessions, end_session,
  end_other_sessions, apps, revoke_app, consents, set_marketing, export_data, delete_account). A too-old sign-in
  raises `MyAccountError` with `step_up` True. `login.account_url(section)` links the hosted account page.
- **Touchque Login Management API: `client.identity`.** `users` (list/search, get, create with a password,
  a bcrypt/argon2 `passwordHash` or a `customPasswordHash`, update with merged metadata, block, unblock, delete
  (KVKK/GDPR erasure), export, sessions, sign_out_everywhere, reset_mfa, unlink_identity, send_verification_email,
  password_reset, add_roles, remove_role, logs), `imports` and `exports` (start, get, wait), `roles`,
  `organizations` (members, connections, invite), `clients` (rotate_secret), `apis`, `connections`,
  `custom_domains`, and the tenant (get_tenant, update_tenant, rotate_signing_key, outbox).
- **Touchque Login (hosted sign-in) for your app.** `HostedLogin` is an OpenID Connect client for your tenant
  (`acme.login.touchque.com` or your own domain): `authorization_url()` (PKCE S256, state, nonce, `screen_hint`,
  `login_hint`, `ui_locales`, `connection`, `organization`, `max_age`, `acr_values`), `handle_callback()` (state and
  `iss` checks, code exchange, ID token verified against the JWKS: signature, issuer, audience, expiry, nonce,
  `at_hash`), `refresh()`, `client_credentials()`, `revoke()`, `userinfo()`, `logout_url()`, and
  `verify_access_token(token, audience=..., required_scopes=...)` for your API. RS256 is verified in pure Python, so
  it needs nothing beyond `requests`.
- **AI agents as identities of their own.** `client.agents` registers an agent with its PUBLIC key, an accountable
  owner, the action types it may ask approvals for and a review date (`create`, `list`, `get`, `update`, `add_key`,
  `remove_key`, `suspend`, `resume`, `revoke`, `set_kill_switch`). `TouchqueAgent` is the agent side: its own key
  (private_key_jwt, RFC 7523), a 10-minute token bound to that key with DPoP (RFC 9449), never your API key.
  `generate_agent_key('ES256' | 'EdDSA')`, `jwk_thumbprint()`. Needs the `agent` extra (`cryptography`).
- **Agent policies and people who stopped an agent:** `client.agents.set_policy(id, policy)`, `list_blocks(id)`, `lift_block(id, user)`.
- **Agents ask people to approve on their phone.** `agent.request_approval(user, type, authorization_details, reason=...,
  presence=..., expires_in=..., locale=...)`, `agent.wait_for_approval(id)` (approval token or `TouchqueApprovalError`),
  `client.agents.redeem_approval(token, user=..., type=..., authorization_details=...)` (checked before anything is used,
  then used exactly once; `TouchqueApprovalMismatchError`), `client.agents.verify_approval_token()` and
  `verify_approval_token_with()` offline, `matches_authorization_details()`.
- **Four eyes and mandates.** `fourEyes` in the agent policy (a second approver on their phone; `awaiting_second`
  keeps `wait_for_approval` waiting). `agent.request_mandate(user, type, max_count, max_total, per_request=...,
  recipients=..., valid_for=...)`, `get_mandate()`, `revoke_mandate()`; `request_approval(..., mandate_id=...)` is
  approved within the mandate without a push. `client.agents.list_mandates(id, user=...)`, `revoke_mandate(id, mandate_id)`.
- **What Touchque notices about an agent.** Refusals carry `case_code`; new codes `suspicious_content` (400, `markers`),
  `interactive_required` (409), `name_too_similar` (409 on create/update, `similarTo`); an approval answered faster than a
  person ends `blocked` with reason `inhuman_approval`. `WebhookEvents` names every agent event.
- **Organization AI agents on Touchque SSO: `TouchqueOrgAgent`.** DPoP-bound tokens for one of the organization's apps
  with its own key or its platform's token (`assertion=github_actions_token('touchque')`, `file_token(path)`):
  `get_token(resource=, scope=)`, `authorization(method, url)`, `request(method, url)`, `dpop_proof()`.
- **An organization's agent acts for a member.** `exchange_token(subject_token, resource=, scope=)` (RFC 8693),
  `ask_member(login_hint, binding_message=, authorization_details=)` and `wait_for_member(request)` (CIBA, poll mode).
- **An organization's agent uses a member's own account elsewhere (token vault).** `agent.get_connection_token(subject_token, connection, scope=None)`: the member's own access token at Google, Microsoft 365, GitHub, Slack, Salesforce or any OAuth 2.0 service they connected on Touchque (portal `/connections`), for a connection that names the agent. A Bearer token for that service; Touchque refreshes it and the refresh token never leaves; `invalid_grant` when the member has not connected it, disconnected or left.
- **An organization's agent asks for a shared account.** `agent.ask_to_open_shared_account(account, login_hint, message=None)` → `{'ask_id', 'open_url', 'status', 'expires_in'}`: the member opens `open_url` where their Touchque extension is paired, their phone approves with the agent named, and the extension signs in there; the agent never sees the password. `agent.shared_account_ask_status(ask_id)` and `agent.wait_for_shared_account(ask)` say only how it ended (`opened`, `refused` with a reason, `declined`, `expired`).
- **Token vault for your agents (`client.agents.vault`).** `put_connection(name, provider, client_id, client_secret=, tenant=, issuer=, agent_ids=)` (google, microsoft, github, facebook, linkedin, x, oidc: your OAuth app there), `deposit(connection, user, access_token, refresh_token=, expires_in=, scope=)` after your own OAuth flow with the person, `list_connections`, `list_accounts(user)` (never a token), `remove_account`, `remove_connection`. The agent: `agent.get_connection_token(user, connection, scope=None)` (scope `vault:read`): a fresh Bearer token for that service, refreshed by Touchque; the refresh token never leaves.
- **Agent framework helpers.** `ApprovalPolicy` + `@with_touchque_approval(policy)` runs a tool (sync or async) only after the person approved on the phone (`current_approval()` holds the approval token; the signature is kept for LangChain `@tool`, LlamaIndex `FunctionTool`, OpenAI Agents SDK `@function_tool`), `require_agent_approval`, `approve_interruptions_with_touchque` (OpenAI Agents SDK `needs_approval`), `touchque_can_use_tool` (Claude Agent SDK), `guard_mcp_session` (an MCP `ClientSession`; the token goes in `_meta`).
- **API key scopes are enforced:** a narrower key (for example `login:*`) is refused elsewhere with 403 `insufficient_scope`.
- **`device` on `auth.get_user()`:** the linked phone's posture (platform, model, OS version, security patch, screen
  lock, jailbreak/root, hardware key, attestation, `state`, `issues`), or `None` before a phone is linked. Documented dict shape.
- **`challenge_digits`** on `login.request` / `login.verify` (`2` or `3`): the length of the matching number
  when one is shown, `3` for 100–999. The longer of this and your workspace policy wins: a request can
  lengthen the number, never shorten it.
- **Codes during a Touchque outage:** `offline.totp_verifiers()` and `offline.match_totp_verifier()`. While Touchque answers, fetch salted,
  slow digests of your users' next time-based codes (up to 4 hours ahead, 24,000 user-steps a call; never a key); while it
  cannot be reached, check a typed code against them locally. Needs the workspace policies `offlineTotpEnabled`
  and `outageVerifiersEnabled`; frozen and removed users fall out on the next fetch.

### Changed
- **Silent by default.** The `touchque` logger has a `NullHandler`: the SDK's own problems (a misconfigured guard, a failed `on_challenge`, a relay error) print nothing unless your app configures logging (`logging.basicConfig()` or a handler on `'touchque'`). Lines carry the error's class and message, never the error object.
- `TouchqueApprovalMismatchError` no longer names the other person in its message.

## [4.0.0] — 2026-10-20 — Touchque Actions

> 3.6.0 (Never Locked Out) and 3.7.0 ("Why?" case codes) below were not published on their own; they ship in 4.0.0.

### Breaking
- **Action types moved to `tq.action_types`** (`define`, `list`; class `ActionTypes` in
  `touchque.resources.action_types`). `tq.actions` is now Touchque Actions. Replace `tq.actions.define(...)`
  with `tq.action_types.define(...)`.

### Added
- **Touchque Actions** (`tq.actions`): your own code at points of the approval pipeline, run by Touchque in a
  sandbox. See [ACTIONS.md](../ACTIONS.md).
  - `deploy(slug, trigger=, code= | template=, name=, secrets=, allowed_hosts=, capabilities=, on_failure=,
    order=, enabled=, activate=)` (idempotent; a version asking for a loosening capability answers
    `deployed: False` with `approval['required']` and waits for an admin's phone approval), `list`, `get`,
    `version`, `update`, `delete`, `rollback(slug, version=None)`.
  - Developer loop: `test(..., event_id= | event=)` (one run, nothing sent), `dry_run(..., replaces=, limit=,
    since=)` (replay against recent real decisions), `events`, `logs`, `metrics`.
  - `triggers()`, `templates()`, `render_template(id, trigger, params)`; `secrets.set | list | delete`.
- `context=` on `login.request`, `risk.check`, `start`, `run_guard` and the Flask, Django and FastAPI guards:
  for your Actions only (`event.context`), never shown on the phone.
- **`on_challenge=` on `login.verify()`**: with number matching the phone asks for a number that `verify()` used to
  return only after the approval. `on_challenge` runs once, right after the request is created and before the
  wait, with a dict of `requestId`, `expiresAt` and, when present, `challengeCode`, `reasons`, `caseCode`. Show
  `challengeCode` to the user now; the phone asks for it. Not called when only a passkey can approve. An exception
  it raises is logged (`touchque` logger) and ignored: `verify()` keeps waiting. `verify()` also takes `context=`.
- `HttpClient.put` / `patch`.
- **Passkey autofill** (WebAuthn conditional mediation): `webauthn.primary_options()` without
  `external_username` asks for options that accept any passkey of your site, and `primary_verify` names the
  user the passkey belongs to. The relay's `POST /passkey/authenticate/options` does the same when the body
  has no `email`, so `@touchque/web`'s `passkeys.autofill()` works with no extra route.

## [3.7.0] — 2026-10-19 — "Why?" case codes

### Added
- **Case codes.** Every approval decision (`login.request`, `risk.check`) now names a short case code
  (`K7P-2QX`). Show it to your user ("Tell your support team: K7P-2QX"); your team opens the decision by it in
  the dashboard (Logs → Look up a case).
  - The `login.request` answer has `caseCode` and, for a step-up, `reasons` (plain English, never a score).
  - `risk.check` returns `caseCode`.
  - `TouchqueAPIException.case_code` on refusals (blocked, frozen, rate limited, provisional, keys lost).
  - Steps (`start`, the guard, the relay and the Flask / Django / FastAPI integrations) carry `caseCode` and
    `reasons`; the guard keeps showing the code while it waits.

## [3.6.0] — 2026-10-19 — Never Locked Out

### Added
- **Never Locked Out.** A user whose phone is lost, dead or replaced moves to a new phone without a help desk:
  colleagues they named vouch on their own phones, then a cooling-off anyone can veto.
  - `tq.recovery.set_vouchers(external_username, vouchers)` and `tq.recovery.vouchers(external_username)` (who can
    vouch today and why not). Ask for the user's phone before you change the list.
  - `tq.recovery.start(external_username, client_ip=None, user_agent=None, display_name=None,
    fallback_vouchers=None, required=None, cool_off_minutes=None, details=None)` returns the recovery with
    `bindUri` (show it as a QR for the new phone); `tq.recovery.status(id)`, `tq.recovery.list(external_username=None,
    open=False)`, `tq.recovery.veto(id, by=None, reason=None)`, `is_recovery_open`.
  Only after your first factor (password, IdP). The risk engine's BLOCK refuses; hard signals add a voucher and
  double the cooling-off. Errors carry `code`: `not_enough_vouchers` (with `required`, `eligible`, `vouchers`),
  `recovery_in_progress`, `blocked`, `frozen`, `rate_limited`, `device_not_linked`. After a vouch move, critical
  actions answer 403 `blocked` / `recovery_probation` for 24 h. New webhook events `RECOVERY_STARTED`,
  `RECOVERY_DEVICE_BOUND`, `RECOVERY_COOLING`, `RECOVERY_COMPLETED`, `RECOVERY_VETOED`, `RECOVERY_EXPIRED`,
  `RECOVERY_FAILED`; `DEVICE_LINKED` can carry `via: 'recovery'`.
- `details` / `noticeDetails` on start: what the vouchers' phones and the old phone show, in your words (default
  English lines otherwise).
- Approval requests on the phone carry `expiresAt` (a vouch stays open for 10 minutes).

### Changed
- Phone-to-phone transfers must be signed by a phone with a hardware key (the apps do since this release) and move
  only the accounts the phone chose.

## [3.5.0] — 2026-10-18 — Silent sign-ins

### Added
- **Silent sign-ins.** Stop asking the phone again and again when nothing about a sign-in is new. Touchque's
  risk engine decides; the push is skipped only when it says so.
  - `tq.risk.check(external_username, type='LOGIN', client_ip=None, user_agent=None, browser_proof=None,
    max_age_seconds=None)` returns `{'prompt', 'reasons', 'assurance', 'silentMode'}`. Sends nothing to the
    phone. Read fail-closed: `prompt` is `False` only when the API answered the boolean `false`; malformed
    `reasons` become `[]`, a missing `assurance` is `'normal'` (`parse_risk_check`).
  - `tq.risk.browsers(external_username)` and `tq.risk.forget_browsers(external_username, thumbprint=None)`: the
    browsers Touchque knows for a user, and forgetting one or all of them.
  - `login.request(..., browser_proof=...)`, `login.verify(..., browser_proof=...)` and
    `tq.start(..., browser_proof=...)`: the browser's device-bound key proof (`X-Touchque-Browser`, made by
    `@touchque/web` 1.4.0), passed through untouched; once the request is approved, Touchque knows that browser.
  - `silent_sign_in` option (default off) on the Flask and Django `require_touchque`, FastAPI's
    `RequireTouchque`, `RelayHandler` (POST /login; every relay adapter passes it through) and `run_guard`: a new
    attempt carrying the `X-Touchque-Browser` header is checked first; `prompt: false` approves it at once with
    no push (`assurance['method'] == 'silent'`, `confirmedVia == 'SILENT'`, `requestId == 'silent'`, `reasons`;
    `on_authenticated` gets `via: 'silent'`). Otherwise, and on any error in the check, the usual push starts
    with the proof attached. `{'max_age_seconds': n}` sets your own limit on the age of the last phone approval.
  - `BROWSER_HEADER` (`x-touchque-browser`), `silent_input_from_headers`.

## [3.4.0] — 2026-10-18

### Added
- **Vishing Shield.** When the user taps Approve during a call (or with the screen shared or the phone
  remote-controlled), Touchque can move the request to a passkey, refuse it, or approve it as provisional.
  The approval dict from `complete()` and `login.verify()` carry `provisional`, `revoked`, `revokeReason` and
  `reconfirmedAt`: a provisional approval lets the user in, but Touchque refuses their critical actions
  (`blocked` / `provisional`) until the phone re-confirms it after the call.
- `WebhookReasons` and `WebhookEvents` for the webhook reasons (`vishing_suspected`, `phishing_origin`,
  `user_reported_coached`, and the existing ones) and events (`APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`, and
  the existing ones).
- **Mirror Alarm.** The first waiting step carries `step['canary']`; `@touchque/web` 1.3.0 loads it on the page
  that shows the sign-in, so a real-time phishing proxy gets the approval refused (`phishing_origin`). Allow
  the canary host in your CSP (`img-src`, `connect-src`).

### Changed (behaviour)
- **`login.verify()` raises `TouchquePasskeyRequiredError` (`reason == 'step_up'`) when a poll shows the request now needs a passkey** (PENDING with
  `requiresPasskey`), instead of polling into a timeout. Finish it in the browser with `@touchque/web`. The
  error has a new `reason` attribute (`'policy'` for the passkey-only policy, as before).
- The guard switches a waiting offline QR to `passkey_required` when its push moved to a passkey, and an
  offline code Touchque refuses for that reason answers `passkey_required` instead of `blocked`.
- An approval the user took back on the phone answers the guard with `expired` / `revoked`.

## [3.3.0] — 2026-10-12

### Security
- **Adding a passkey needs the phone.** `RelayHandler`'s `/passkey/register/options` used to hand out
  registration options to anyone holding your app's session, and a passkey approves requests on its
  own, so a stolen session cookie could become a permanent second factor. For a user with a linked
  phone the route now answers the same two-phase step as `/login` (202 with the number to show; the
  user approves a `PASSKEY_ENROLL` request on the phone) and returns the options only after that
  approval, once. Users without a linked phone are unchanged. The Touchque API enforces this too:
  `webauthn.register_options` takes the approved request id as `approval_request_id`.
- **Passkey delete needs the user.** The API now refuses `DELETE /webauthn/credentials/{id}` without
  `externalUsername`: `webauthn.delete_credential(id, external_username=...)`.

### Fixed
- **Waiting on an approval no longer hits the rate limit.** Each browser poll of `/login` counted against
  the per-user limit (5 a minute), so a user who took more than about 7.5 s to approve got a 429 while
  the push was still on the phone. A poll that carries a valid, still-waiting token only reads the
  status and now has its own per-IP budget; new attempts are counted as before.

### Added
- The waiting step carries `telemetryToken` when the workspace collects behavioural signals, so
  `@touchque/web` can send them (pass `telemetry: { apiBaseUrl }` to `touchqueFetch`). Before, the token
  never reached the browser and the bot and browser signals never ran for SDK integrations.

## [3.2.1] — 2026-10-11

### Security
- **The pre-auth relay no longer hands out a first-time linking QR.** `RelayHandler`'s `POST /login` used to answer
  an unlinked user with a linking QR code and recovery codes for whatever username was typed.
  Anyone could scan that QR first and link their own phone to someone else's account. Now it
  answers `{ state: 'enroll' }` without a QR unless `get_login_user` is set, i.e. unless the route
  only runs after your own password step. Linking from a signed-in page (`/enroll/start`, the
  step-up guard) is unchanged. Your own guards can opt out with `run_guard(..., enroll=False)`.

## [3.2.0] — 2026-10-11

### Added
- **`verify_approval_proof(proof, request_id=..., type=..., details=..., challenge_code=...,
  expected_public_key=...)`** — check the phone's own signature over the request, action,
  number-match code and details it showed, without trusting Touchque (same as the Node SDK's
  `verifyApprovalProof`). Fails closed without a pinned key unless `allow_unpinned_key=True`.
  Needs the optional extra: `pip install "touchque-authenticator[proof]"` (the core stays
  requests-only). Tested against `fixtures/approval-proof-vectors.json`, shared by all SDKs.
- **`tq.login.report_fraud(request_id, reason=..., note=...)`** — report a request you later learned
  was fraud (chargeback, account takeover, social engineering). Touchque's risk engine uses it as its
  strongest training signal; the request's status does not change. Idempotent.
- **Relay routes** for Flask (`touchque_relay_blueprint`), FastAPI (`touchque_relay_router`) and Django
  (`touchque_relay_urls` / `touchque_relay_view`), on top of a framework-agnostic `RelayHandler`: the same
  14 routes and behaviour as the Node SDK's `touchqueRouter` (`POST /login` with the two-phase guard contract,
  enrollment, offline codes, passkey ceremonies and credential management). `get_login_user` binds `/login`
  and the offline routes to the user who passed your first factor; the offline routes answer
  `403 OFFLINE_REQUIRES_FIRST_FACTOR` without it; `/enroll/start` never replaces an already linked phone
  (`409 already_linked`); sessions open only for the user Touchque returns. Pre-auth routes are rate limited
  per IP and per username by default (`FixedWindowLimiter`, `429 RATE_LIMITED` + `Retry-After`).

## [3.1.0] — 2026-09-30

### Security
- **A phone-side reject kills the offline QR.** `tq.offline.challenge(..., request_id=...)` and
  `verify_totp(..., request_id=...)` tie the QR / time-based code to the push it follows. Once the phone REJECTS the push,
  no new QR is issued for that sign-in (`409 request_rejected`) and no code — QR or time-based — finishes it
  (`reason: request_rejected`). The guard links the QR
  automatically; while the QR is on screen the guard keeps checking the push, so the page learns about a reject
  straight away (`state: rejected`) — and about an approval, which finishes the action without typing a code.

### Added
- **Number matching on the offline QR.** When the linked push (or `require_number_match=True`) uses number
  matching, `challenge()` returns `challengeCode` — print it under the QR. The phone shows it among two decoys
  after scanning and the user taps the match; the phone is never told which is right, so a wrong tap yields a code
  that fails verification. The guard's offline step carries it as `offline.challengeCode`.

## [3.0.0] — 2026-09-29

### Security
- `webhook.verify()` rejects a webhook whose signed `timestamp` is missing or
  unparseable (previously the freshness check was silently skipped).
- New `replay_cache` argument (`MemoryReplayCache`, or your own `ReplayCache`
  over Redis/DB): a second delivery of the same `jti` raises
  `TouchqueWebhookReplayException` (a subclass of
  `TouchqueWebhookSignatureException`) — answer 200 to it, it is a duplicate.

## [2.0.0] — 2026-09-28

### Added
- `Touchque()` with no arguments reads `TQ_API_KEY` / `TQ_API_SECRET` /
  `TQ_API_URL` from the environment.
- `tq.start` / `tq.check` / `tq.complete` — the headless step-up flow: start
  an approval, get back a JSON-safe "step" (the matching number, the
  enrollment QR, or a `blocked`/`frozen`/`rate_limited` refusal) to render in
  your own UI, and complete an approved request exactly once.
- `touchque.contrib.flask.require_touchque`, `touchque.contrib.django.require_touchque`,
  `touchque.contrib.fastapi.RequireTouchque` — one line per protected route,
  built on `touchque.guard.run_guard`. The matching number is now available
  **before** approval (previously only `login.request()`'s raw response
  carried it, with no framework support for relaying it to the browser, so
  number matching could not be completed through a one-line guard).
- `tq.offline` (`challenge`, `verify`, `verify_totp`) and `tq.actions`
  (`define`, `list`) — previously only in the Node SDK.
- `TouchqueAPIException.status` / `.code` / `.reason` / `.attempts_left` /
  `.retry_after`; a network failure now raises `TouchqueNetworkException`
  instead of being indistinguishable from a real API error.
- `TouchquePasskeyRequiredError`, raised by `login.verify()` when a
  phishing-resistant policy requires a passkey.
- `webauthn.delete_credential(id, external_username=...)` — scope a deletion
  to one user (previously any credential id your key could reach was
  deletable).

### Changed
- **Breaking:** default `base_url` is `https://api.touchque.com` (the
  previous default, `api-authenticator.touchque.com`, has no DNS record and
  was unreachable).
- **Breaking:** `login.verify()` now raises `TouchqueTimeoutException` (not
  `TouchqueRejectedException`) when a request expires unapproved, and returns
  `requestId` / `challengeCode` / `assurance` / `confirmedVia` alongside
  `approved` / `status`.
- Request signing now covers the query string (`GET`/`DELETE` with
  parameters) and uses a 16-byte nonce (previously 8).
- Added `details` keyword on `login.request()` / `login.verify()`:
  transaction context shown on the mobile approval screen
  (`{'Amount': '1,250.00 USD'}` or a list of `{'label': ..., 'value': ...}`).
  The API rejects out-of-limit values with a 400 (at most 8 entries, labels
  <= 40, values <= 120 characters) rather than truncating them.

## [1.3.0] — 2026-09-06

### Added
- **`webauthn` resource** (`tq.webauthn.*`), parity with the Node SDK:
  `register_options`, `register_verify`, `authenticate_options`,
  `authenticate_verify`, `primary_options`, `primary_verify`,
  `list_credentials`, `delete_credential`.
- **`Auth.get_user(external_username)`** — user link status without a push.
- `HttpClient.delete()` for `delete_credential`.
- `Login.status` now URL-encodes the request id.

### Note
- The `telemetryToken` login-response field flows through untouched (responses
  are dicts) — documented in the README's behavioral section.
- Version aligned to `1.3.0` across the server SDK line (node / go / php / python).

## [1.1.0] — 2026-08-22

### Changed
- **Breaking (distribution name only):** PyPI package renamed from
  `touchque` to `touchque-authenticator` to reflect that this SDK is scoped
  to the Touchque Authenticator (2FA/MFA) product specifically. The
  importable module name is unchanged (`import touchque`) — no code changes
  needed, only `pip install touchque-authenticator` instead of
  `pip install touchque`.

### Added
- First real automated test suite (`pytest`, 20 tests covering `Config`
  validation, `HttpClient` signing/error-handling via mocked `requests`
  calls, `Auth`, `Login` including its polling `verify()`, and `Webhook`).
  `setup.py` gained an `extras_require={"dev": [...]}` group for this.
- `LICENSE` (MIT) file, matching the license already declared in
  `setup.py`'s classifiers.

## [1.0.0] — prior to this changelog

Initial public functionality: `Auth` (generate_secret/reset_secret/
validate_secret), `Login` (request/status/verify/approve_with_recovery_code),
`Webhook` (verify).
