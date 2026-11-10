# touchque-authenticator

The official Python server SDK for [TouchQue](https://touchque.com) — biometric push
2FA, passkeys, and offline approval codes, added to any backend with one
decorator per route. Adapters for Flask, Django and FastAPI included.

[![PyPI version](https://img.shields.io/pypi/v/touchque-authenticator.svg)](https://pypi.org/project/touchque-authenticator/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

📘 Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

```bash
pip install touchque-authenticator
# with a framework adapter:
pip install "touchque-authenticator[flask]"    # or [django] / [fastapi]
```

The importable package is `touchque` (`import touchque`).

## Setup

Get an API key and secret from your [TouchQue Dashboard](https://dashboard.touchque.com):

```bash
export TQ_API_KEY=tq_auth_your_key
export TQ_API_SECRET=your_api_secret
```

`TouchQue()` with no arguments reads these automatically.

## Quick start (Flask)

```python
from flask import request, jsonify
from touchque.contrib.flask import require_touchque

@app.post('/transfer')
@require_touchque('SEND_MONEY', details=lambda: {'Amount': f'{request.json["amount"]} EUR'})
def transfer():
    return jsonify(ok=True)
```

Django and FastAPI look the same:

```python
# Django
from touchque.contrib.django import require_touchque

@require_touchque('SEND_MONEY')
def transfer(request):
    ...
```

```python
# FastAPI
from touchque.contrib.fastapi import RequireTouchQue, install_touchque_exception_handler

install_touchque_exception_handler(app)  # optional: flattens the response shape

@app.post('/transfer')
def transfer(approval = Depends(RequireTouchQue('SEND_MONEY'))):
    ...
```

Until the user approves on their phone, the decorator answers
**`202 {"touchque": step, "token": "..."}`** instead of running your view.
Your frontend renders `step` in its own UI (a matching number, or a QR code
the first time the user links the app) and sends the same request again with
header `X-TouchQue-Token: <token>` — see
[`@touchque/web`](https://www.npmjs.com/package/@touchque/web), which does
this loop for you in the browser. Once approved, the retried request reaches
your view exactly once.

## Relay routes (sign-in, enrollment, passkeys, offline)

Instead of hand-writing the routes a frontend such as `@touchque/web` calls,
mount the relay: `POST /login` (two-phase, same `202` + token contract as
above), `/enroll/start`, `/enroll/status`, `/offline/challenge|verify|totp`,
`/passkey/authenticate/*`, `/passkey/login/*`, `/passkey/register/*`,
`GET /passkey/credentials` and `DELETE /passkey/credentials/<id>`.
`POST /passkey/authenticate/options` with no `email` answers options for any
passkey of your site, for `@touchque/web`'s passkey autofill
(`webauthn.primary_options()` with no username does the same).

```python
# Flask
from touchque.contrib.flask import touchque_relay_blueprint

def opened(request, response, info):          # open YOUR session here
    session['user'] = info['externalUsername']  # info: externalUsername, requestId, via

app.register_blueprint(touchque_relay_blueprint(
    tq,
    get_user_id=lambda req: session.get('user'),
    # The user who already passed your password step. Binds POST /login and the
    # offline routes to them; the offline routes stay off (403) without it.
    get_login_user=lambda req: session.get('password_ok'),
    on_authenticated=opened,
), url_prefix='/touchque')
```

```python
# FastAPI (callbacks may be async)
from touchque.contrib.fastapi import touchque_relay_router
app.include_router(touchque_relay_router(tq, get_user_id=..., get_login_user=...), prefix='/touchque')

# Django (urls.py) - CSRF stays on: send X-CSRFToken from the page, or pass csrf_exempt=True
from touchque.contrib.django import touchque_relay_urls
urlpatterns = [path('touchque/', include(touchque_relay_urls(get_user_id=..., get_login_user=...)))]
```

Every callback gets the framework's request; `on_authenticated(request,
response, info)` also gets the response that will be sent, so it can call
`response.set_cookie(...)`. Other options: `rate_limit` (on by default: 20 per
IP and 5 per username per route per minute; a dict with `window_ms` /
`per_ip` / `per_user`, or `False`), `action_type` (default `'LOGIN'`),
`get_details`, `allow_offline_without_first_factor` and `silent_sign_in` (see
[Silent sign-ins](#silent-sign-ins-stop-asking-when-nothing-is-new)). Without a framework,
call `touchque.RelayHandler(...).handle(method, path, body=..., ...)` and
send the `RelayResponse` it returns.

## The three primitives, if you're not using a framework adapter

```python
from touchque import TouchQue

tq = TouchQue()  # from TQ_API_KEY / TQ_API_SECRET

step = tq.start('SEND_MONEY', user='jane@acme.com', details={'Amount': '250 EUR', 'To': 'DE89...'})
# step['state']: 'waiting' (show step['number']) | 'enroll' (show step['enroll']['qrCodeDataUrl'])
#                | 'approved' | 'rejected' | 'expired' | 'passkey_required' | 'frozen' | 'blocked'

latest = tq.check(step['requestId'])

# Once approved, consume it exactly once, right before doing the protected thing:
approval = tq.complete(step['requestId'], user='jane@acme.com', action='SEND_MONEY',
                        details={'Amount': '250 EUR', 'To': 'DE89...'})
```

`complete()` verifies the approval was actually issued for this user, action
and transaction, and can only be consumed once.

## Passkeys (phishing-resistant)

Push approval and offline codes stop password reuse and push fatigue, but a
real-time phishing proxy can still relay them. A passkey can't be phished —
the browser signs your site's real origin, and TouchQue refuses any other
(NIST SP 800-63B-4 §3.2.5). Register one via `tq.webauthn` on the server and
`@touchque/web`'s `passkeys.register()` in the browser; optionally require it
for critical actions in the Dashboard's Security Policy.

## Offline sign

```python
ch = tq.offline.challenge(external_username='jane@acme.com', type='WITHDRAW',
                           details={'Amount': '1,250.00 USD', 'Recipient': 'Jane Doe'})
# show ch['qrDataUrl'] — the phone scans it offline and shows a 7-character code
result = tq.offline.verify(challenge_id=ch['challengeId'], code=code)
```

**A QR that follows a push.** Pass the push's request id when the offline QR is the fallback for a push
the user already started (the guard does this for you):

```python
ch = tq.offline.challenge(user, type='LOGIN', request_id=step['requestId'])
# ch.get('challengeCode') is the number to print under the QR when number matching applies.
```

If the user **rejects the push on the phone, the offline QR dies with it**: no new QR is issued for that
sign-in (409 `request_rejected`), a code for a QR already on screen is refused (`reason: 'request_rejected'`)
and so is the time-based code (`verify_totp(..., request_id=...)`). With number matching, print `challengeCode`
under the QR: the phone shows it among two decoys and the user taps the match; a wrong tap yields a code that
fails verification.

## Webhooks

```python
from touchque import WebhookEvents, WebhookReasons
from touchque.exceptions import TouchQueWebhookSignatureException

try:
    # raw_body is text: in Flask request.get_data(as_text=True), in Django request.body.decode('utf-8').
    event = tq.webhook.verify(raw_body=request.get_data(as_text=True), signature=request.headers['X-Signature'])
except TouchQueWebhookSignatureException:
    return '', 403  # not from TouchQue
if event.get('event') == WebhookEvents.APPROVAL_REVOKED:
    end_sessions_built_on(event['requestId'])
```

Login results carry `status` (`SUCCESS` | `REJECTED`) and, when rejected, a `reason` (`WebhookReasons`):
`user_rejected`, `user_reported_fraud`, `user_reported_coached` (the user said someone on the phone told
them to approve), `risk_reversed`, `risk_step_up`, `approval_signature_invalid`, `device_integrity_failed`,
`vishing_suspected` and `phishing_origin` (see Vishing Shield). Treat a reason you do not know as a rejection.
Event webhooks carry `event` (`WebhookEvents`): `DEVICE_LINKED`, `DEVICE_UNLINKED`, `PASSKEY_REGISTERED`,
`PASSKEY_DELETED`, `APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`. Ignore events you do not know.

## Vishing Shield (someone on the phone guiding the user)

The phone tells TouchQue, signed with its hardware key, whether a call was active (or just ended), the screen
was shared or the phone remote-controlled when the user tapped Approve. Depending on the server's mode:

- **Passkey instead.** A user with a passkey finishes in the browser: the request stays open and turns into
  `passkey_required` mid-flight. The step-up flow and the relay handle it; the blocking `login.verify` raises
  `TouchQuePasskeyRequiredError` (`reason == 'step_up'`). No offline or recovery code can finish such a request.
- **Refused.** A critical action without a passkey is rejected (`reason: vishing_suspected`).
- **Provisional.** Anything else is approved with `provisional` set on the approval dict from `complete`. Let the user
  in, but treat the session as limited: TouchQue refuses the user's critical actions (`blocked` / `provisional`)
  until the phone re-confirms after the call (`APPROVAL_RECONFIRMED`). `APPROVAL_REVOKED` (`reason` `COACHED` or
  `UNDO`) means end the session; an approval revoked before you consumed it can no longer be consumed
  (409 `revoked`).

**Mirror Alarm.** The first waiting step carries `canary.url`. `@touchque/web` loads it on the page showing the
sign-in and sends a beacon to it, so a real-time phishing proxy in front of your site shows up as itself: the
approval is refused (`reason: phishing_origin`) and the phone warns the user. Allow the canary host in your
Content-Security-Policy (`img-src` and `connect-src`).

## TouchQue Actions (your code in the approval pipeline)

Alerts, step-ups and refusals by country, local time, role or amount, passkeys
for admins — from a template or a few lines of JavaScript, replayed against your
real recent sign-ins before they go live. Full guide: [support.touchque.com/actions](https://support.touchque.com/actions).

```python
tq.actions.deploy('night-alert', trigger='approval.decided',
                  template={'id': 'alert', 'params': {'channel': 'slack', 'when': {'countries': ['TR'], 'hours': {'from': 0, 'to': 6}}}})

draft = 'exports.onExecute = async (event, api) => { if (event.context?.amount > 10000) api.stepUp("Over 10,000"); };'
report = tq.actions.dry_run(trigger='login.request', code=draft)   # report['transitions'] → {'push→number_match': 3}
tq.actions.deploy('big-transfers', trigger='login.request', code=draft)
```

Give Actions what only your server knows with `context=` (never shown on the
phone): `@require_touchque('SEND_MONEY', context=lambda: {'amount': request.json['amount']})`.
Loosening calls need a capability an admin approves on their phone. Action types
moved to `tq.action_types` in 4.0.

## AI agents (an identity per agent, never your API key)

Register each agent with its **public** key; the private key stays where the agent runs. The agent signs in
with its own key and gets a 10-minute token bound to that key (DPoP). `pip install "touchque-authenticator[agent]"`.

```python
from touchque import TouchQue, TouchQueAgent, generate_agent_key

keys = generate_agent_key()                      # or where the agent runs
agent = client.agents.create('Invoice bot', ['PAY_INVOICE'], public_key=keys['public_jwk'],
                             owner_email='ada@acme.com', platform='langchain')
# store agent['id'] and keys['private_jwk'] in the agent's secrets (TQ_AGENT_ID, TQ_AGENT_KEY)

me = TouchQueAgent().me()                        # in the agent
```

`client.agents.suspend(agent_id)` stops one agent at once, `client.agents.set_kill_switch(True)` every agent.

```python
ask = agent.request_approval('jane@example.com', 'PAY_INVOICE', [{
    'type': 'payment_initiation', 'instructedAmount': {'currency': 'TRY', 'amount': '500.00'},
    'creditorName': 'Jane Doe', 'creditorAccount': {'iban': 'TR330006100519786457841326'}}], reason='October rent')
reply(f"Type {ask['challengeCode']} in the TouchQue app to approve.")
token = agent.wait_for_approval(ask['approvalId'])['approvalToken']

# in your executor, right before paying: used once, only for what you are about to do
approval = client.agents.redeem_approval(token, user='jane@example.com', type='PAY_INVOICE',
    authorization_details={'type': 'payment_initiation', 'instructedAmount': {'currency': 'TRY', 'amount': '500.00'}})
```

In an agent framework, a policy says who approves which tool calls and what their
phone shows; the tool runs only after the person approved, `current_approval()`
holds the approval token inside it, and the function keeps its signature (LangChain
`@tool`, LlamaIndex `FunctionTool.from_defaults`, OpenAI Agents SDK `@function_tool`):

```python
from touchque import ApprovalPolicy, with_touchque_approval, current_approval, approve_interruptions_with_touchque, touchque_can_use_tool, guard_mcp_session

policy = ApprovalPolicy(agent, user='jane@example.com', type='PAY_INVOICE',
    details=lambda a, tool: [{'type': 'payment_initiation', 'instructedAmount': {'currency': 'TRY', 'amount': a['amount']}, 'creditorAccount': {'iban': a['iban']}}],
    on_challenge=lambda s, tool: reply(f"Type {s['challengeCode']} in the TouchQue app to approve."))

@tool
@with_touchque_approval(policy)
def pay_invoice(iban: str, amount: str) -> str:
    return bank.pay(iban, amount, current_approval()['approvalToken'])

state = approve_interruptions_with_touchque(result, {'pay_invoice': policy})       # OpenAI Agents SDK
options = ClaudeAgentOptions(can_use_tool=touchque_can_use_tool({'pay_invoice': policy}))  # Claude Agent SDK
session = guard_mcp_session(session, {'pay_invoice': policy})                      # an MCP ClientSession
```

Agents also stop when their review date passes and when their owner leaves the organization.

### Cross App Access (ID-JAG) and A2A agent cards

An organization's identity provider (TouchQue SSO) can let one of its apps reach another service for a member with no consent screen (Cross App Access, ID-JAG, an open IETF draft): the app trades the member's ID token for an ID-JAG, then the ID-JAG for an access token at the other service. If you run an authorization server, the verifier checks an ID-JAG (issuer, single audience, your client, expiry, `typ`) and uses it once. Before your agent trusts another agent's A2A card, check its signatures (A2A 1.0 §8.4: JWS over the RFC 8785 canonical card); keys named by `jku` are only fetched from the card's own host or hosts you trust.

```python
from touchque import request_id_jag, redeem_id_jag, IdJagVerifier, verify_agent_card

jag = request_id_jag(issuer='https://sso.touchque.com', client_id=client_id, client_secret=secret,
                     id_token=id_token, audience='https://auth.files.example')
tokens = redeem_id_jag(token_endpoint='https://auth.files.example/token', client_id='acme',
                       client_secret=files_secret, assertion=jag['assertion'])

# Your own authorization server (jwt-bearer grant):
claims = IdJagVerifier(issuer='https://sso.touchque.com', audience='https://auth.files.example') \
    .verify(form['assertion'], client_id=authenticated_client_id)

verify_agent_card(card, card_url='https://agent.example/.well-known/agent-card.json')
```

## Shared Signals (security events from Touchque SSO)

Touchque SSO tells your app when something happens to a member's account after sign-in, as Security Event Tokens
(OpenID Shared Signals Framework 1.0): CAEP `session-revoked`, `credential-change`, `device-compliance-change`; RISC
`account-disabled`, `credential-compromise`. The organization's admin adds your app as a receiver (Organization >
Continuous access), by push to your endpoint or by poll. The verifier finds the keys through the issuer's
`/.well-known/ssf-configuration` and checks the signature, `typ`, issuer, audience and that there is one event; `txn`
is the case code of Touchque's decision. A SET does not expire: keep the `jti`s you handled and skip a repeat.
`pip install "touchque-authenticator[agent]"`.

```python
from touchque import SecurityEventVerifier, SecurityEventError, poll_security_events

verifier = SecurityEventVerifier(issuer='https://sso.touchque.com', audience='https://app.example.com')

# Push (RFC 8935): the SET is the request body (application/secevent+jwt).
@app.post('/ssf')
def ssf():
    try:
        event = verifier.verify(request.get_data(as_text=True))
    except SecurityEventError as e:  # e.code: invalid_request, invalid_key, invalid_issuer, invalid_audience
        return {'err': e.code, 'description': str(e)}, 503 if e.code == 'temporarily_unavailable' else 400
    if event.name == 'session-revoked':
        end_sessions_of(event.subject.get('email'))
    return '', 202

# Poll (RFC 8936): acknowledge what you handled on the next call.
out = poll_security_events(url=poll_url, token=stream_token, ack=handled_jtis, max_events=50)
for jti, token in out['sets'].items():
    event = verifier.verify(token)  # then act on it as above
```

## Silent sign-ins (stop asking when nothing is new)

A user who approved on their phone in this browser a little while ago, from the same phone, network and country,
with no risk signal since, does not need another push. TouchQue's risk engine decides; your server only skips the
push when it says so.

1. In the browser, `@touchque/web` 1.4.0 with `createTouchQueWeb({ browserKey: true })` keeps a non-extractable
   key for your site and sends a fresh, signed proof of it in the `X-TouchQue-Browser` header.
2. On the server, turn on `silent_sign_in`:

```python
# Flask (Django's require_touchque and FastAPI's RequireTouchQue take the same option)
@app.post('/login/2fa')
@require_touchque('LOGIN', user=lambda: session.get('password_ok'), silent_sign_in=True)
def login_2fa():
    # g.touchque['assurance']['method'] is 'silent' when no push was needed.
    return jsonify(ok=True)

# Relay POST /login
app.register_blueprint(touchque_relay_blueprint(
    tq,
    get_user_id=lambda req: session.get('user'),
    get_login_user=lambda req: session.get('password_ok'),
    silent_sign_in=True,  # or {'max_age_seconds': 8 * 3600} for your own limit
), url_prefix='/touchque')
```

With it on, a new attempt that carries the header first calls `tq.risk.check`. Only an answer of exactly
`prompt: false` approves it at once, with nothing sent to the phone: the approval has
`assurance == {'phishingResistant': False, 'method': 'silent'}`, `confirmedVia == 'SILENT'`,
`requestId == 'silent'` and `reasons` (`known_browser`, `recent_approval`, `same_phone`, `familiar_network`,
`no_risk_signal`); the relay calls `on_authenticated` with `via: 'silent'`. Anything else, and any error in the
check, starts the usual push with the proof attached, so its approval makes the browser known. Polling with the
token never checks again. `run_guard(..., browser_proof=..., silent_sign_in=True)` does the same for your own
framework (`silent_input_from_headers` reads the header).

TouchQue only lets a sign-in through silently when all of this holds: the browser proved its key and was approved
on the phone (a confirmed push, not one approved during a call, or a passkey) within your `max_age_seconds` and at
most 7 days ago, by the phone that is linked now; the country and the network were seen in the user's earlier
approved sign-ins; the risk engine allows it with no risk signal; and the action is an everyday one. A critical
action always asks. In `shadow` mode (`silentMode`) it always asks and the reasons say what would have happened.

Without the adapters:

```python
browser_proof = request.headers.get('X-TouchQue-Browser')
risk = tq.risk.check(user, type='LOGIN', client_ip=request.remote_addr, browser_proof=browser_proof)
if risk['prompt'] is False:
    return open_session(user)  # risk['reasons'] say why
step = tq.start('LOGIN', user, ip=request.remote_addr, browser_proof=browser_proof)  # the approval makes the browser known

browsers = tq.risk.browsers(user)['browsers']  # for an "approved browsers" list
tq.risk.forget_browsers(user)                  # all; or thumbprint=... for one
```

Forget a user's browsers after a password reset or a "sign out everywhere". `risk.check` reads the answer
fail-closed (`parse_risk_check`): `prompt` is `False` only when TouchQue answered the boolean `false`; malformed
`reasons` become `[]` and a missing `assurance` is `'normal'`.

## Never Locked Out (lost, dead or new phone)

A user whose phone is gone moves to a new phone without a help desk. Colleagues they named beforehand vouch on their own
phones, each typing a number the user reads them on a call; then a cooling-off (default 60 minutes) lets the old phone, any
voucher or an admin stop it. The risk engine can refuse it or ask for more vouchers, and for 24 hours afterwards critical
actions are refused. It is an option: offer it next to passkeys and the old phone's transfer, never as the only way. Every
step is a hash-chained receipt (`receipts`); a voucher's step carries the signature of their phone's hardware key.

```python
# Settings page, after an approval on the user's phone:
tq.recovery.set_vouchers(user, ['bo@acme.com', 'cy@acme.com'])

# "I lost my phone", after the password:
r = tq.recovery.start(user, client_ip=ip, display_name='Ada', fallback_vouchers=admins)
show_qr(r['bindUri'])                      # the TouchQue app on the new phone scans it
now = tq.recovery.status(r['recoveryId'])  # each voucher's 'code' to read to them
# now['status']: AWAITING_DEVICE -> VOUCHING -> COOLING -> COMPLETED (or VETOED / EXPIRED / FAILED)

tq.recovery.veto(r['recoveryId'], by='admin@acme.com')  # an admin who does not believe it
```

## "Why?": case codes instead of guesswork

Every approval decision names a short case code (`K7P-2QX`: 6 characters, no I, O, 0 or 1). A user who was asked to
match a number, needed a passkey or was refused reads it out to your support team, and the team opens the whole
decision by it in the TouchQue dashboard (Logs → Look up a case): what went in, each check's verdict (the access rule
that matched, the risk signals that were acted on and the ones only measured), and the single change that would have
let it through. No screenshots, no log digging. The code opens nothing on its own: only your workspace sees its
decisions.

```python
step = client.start('WITHDRAW', user, ip=request.remote_addr)
# step['caseCode'] -> 'K7P-2QX'; step['reasons'] -> [{'code': 'critical_action', 'text': 'The action is marked critical'}]
try:
    client.login.request(user, type='LOGIN')
except TouchQueAPIException as err:
    if err.case_code:
        show(f'Tell your support team: {err.case_code}')
```

`caseCode` is in the `login.request` and `risk.check` answers and every step (the guard keeps it while it waits);
`TouchQueAPIException.case_code` carries it on refusals.

## Blocking `verify()` and number matching

`tq.login.verify()` sends the request and waits for the phone in one call. With number matching (your option, a
workspace policy, a critical action or the risk engine can turn it on) the phone asks the user to pick a number,
and the call returns only after they have. Pass `on_challenge`: it runs once, right after the request is created
and before the wait. **Show `challengeCode` to the user now; the phone asks for it.**

```python
def show(challenge):
    if challenge.get('challengeCode'):
        notify_user(f"Pick {challenge['challengeCode']} on your phone", case=challenge.get('caseCode'))

tq.login.verify(user, 'SEND_MONEY', on_challenge=show)
```

It gets a dict with `requestId`, `expiresAt` and, when present, `challengeCode`, `reasons` and `caseCode`. It is
not called when only a passkey can approve (`verify()` raises `TouchQuePasskeyRequiredError` first). An exception it
raises is logged (`touchque` logger, warning) and ignored: `verify()` keeps waiting. In a web request, where the
page hears nothing until you answer, use the relay or `tq.start()`: their first answer already carries the number.

## Verifying the device proof (no need to trust TouchQue)

Every approval from a phone with a hardware key carries `approvalProof`: the phone's own
signature over the request id, action, number-match code and the exact details it showed.
`pip install "touchque-authenticator[proof]"`, then:

```python
from touchque import verify_approval_proof

ok = verify_approval_proof(
    event['approvalProof'], request_id=request_id, type='WITHDRAW', details=details,
    challenge_code=challenge_code,
    expected_public_key=user.touchque_device_key,  # stored from their first verified approval
)
```

Without `expected_public_key` it returns `False` unless `allow_unpinned_key=True` (trust on first
use — store `proof['publicKey']`, then pin it).

## Reporting fraud

Learned later that an approved request was fraud? Report it — it is the strongest signal
TouchQue's risk engine learns from, and it stays in your audit log:

```python
tq.login.report_fraud(request_id, reason='chargeback', note='Disputed by card holder')
# reason: 'chargeback' | 'account_takeover' | 'social_engineering' | 'other'
```

## Pairing a browser by QR code

Your page shows a QR code, the person scans it with the TouchQue app, and the phone that scanned is the one asked to approve, with number matching. Your page sends the thumbprint of its browser key (`@touchque/web` `browserKey.thumbprint()`); the nonce in the QR never leaves your server (TouchQue keeps its hash).

```python
p = client.qr_pairings.create(key_thumbprint, client_ip=ip, user_agent=ua)
# show p['uri'] (touchque://pair-browser?...) as a QR code; poll:
now = client.qr_pairings.get(p['pairingId'])          # waiting -> scanned -> confirmed
if now['state'] == 'confirmed':
    client.login.request(now['externalUsername'], qr_pairing=p['pairingId'])
# or: client.qr_pairings.refuse(p['pairingId'], 'device_not_approved', 'Ask IT to approve this computer.')
```

`get` says `scanned` / `confirmed` once a phone holding one of your users' accounts read it (with `proximity`: same network, same country), `reported` when the person said someone told them to scan it (their 2FA freezes). `refuse` tells the phone why your own checks said no.

## A code typed back on the phone

When a sign-in needs a code another service sent the person (a text message, WhatsApp, e-mail), ask them to type it on the phone instead. The phone encrypts it to a one-time key you made for this request: TouchQue only ever holds the ciphertext. Such a request lives 5 minutes.

```python
key = new_code_reply_key()   # pip install "touchque-authenticator[proof]"; keep key['private_key']
sent = tq.login.request(user, reply={'kind': 'code', 'key': key['public_key'], 'channel': 'sms', 'target': '+**********26'})
status = tq.login.status(sent['requestId'])   # once CONFIRMED
code = open_code_reply(key['private_key'], sent['requestId'], status['reply']['ct']) if 'reply' in status else None
```

## Safe Guard (Safe transactions approved on the phone)

TouchQueSafeGuard is a transaction guard for a Safe: a transaction runs only with approvals signed by the P-256 keys on its approvers' phones. You send the raw transaction; the phone decodes it itself, shows its own rows and signs what it computed with a key only its biometrics unlock. Delegatecalls, changes to the Safe and proxy upgrades are governance: scheduled, time-locked and vetoable. A phone without that key yet gets `409 crypto_key_missing`.

```python
from touchque import verify_safe_approval, with_safe_approvals, safe_schedule_call   # pip install "touchque-authenticator[proof]"

target = {'chainId': 1, 'safe': SAFE, 'guard': GUARD, 'tx': {'to': to, 'value': 0, 'data': data, 'operation': 0, 'nonce': 42}}
sent = tq.safe_guard.request('treasurer@acme.com', 'safe_payment', {   # an action type from your dashboard
    **target,
    'config': {'threshold': 2, 'govThreshold': 3, 'govDelay': 172800, 'exitDelay': 259200},
    'batchTargets': [MULTI_SEND_CALL_ONLY],
    'approverIndex': 0,   # this approver's index in the guard
})
done = tq.safe_guard.wait_for_approval(sent['requestId'])   # 5 minutes at most
approval = done['safeTx']['approval']

# Check it yourself: your own transaction, the approver's key from the guard on chain, and what you will do with it.
purpose = done['safeTx']['purpose']   # 'approve' (execute it) or 'schedule' (a governance change)
check = verify_safe_approval(target, approval, approver_key, purpose=purpose, approver_index=0)
if not check['valid']:
    raise RuntimeError(f"approval refused: {check['reason']}")
if purpose == 'approve':
    signatures = with_safe_approvals(owner_signatures, [approval])   # execTransaction(..., signatures)
else:
    data = safe_schedule_call(SAFE, check['governanceHash'], [approval])   # a call to the guard; runs after govDelay
```

`verify_safe_approval` makes the guard's check off chain, so a co-signer or your own server never has to trust TouchQue: it computes the Safe transaction hash (EIP-712) and the governance hash from the raw fields, rebuilds the 149-byte message the phone signed and checks the P-256 signature. Without `purpose` it accepts only an approval to execute this exact transaction (`approve`); an approval that schedules a governance change covers neither the Safe nonce nor the gas fields, so it passes only when you name `purpose='schedule'`. It refuses a high `s`, an approval that expired or is valid for more than a day, another approver index, and, when you pass `rows` or `display_digest` from your own decoding, rows the phone did not show. `reason` is `approval_malformed`, `public_key_invalid`, `approver_index_mismatch`, `approval_expired`, `rows_differ`, `high_s` or `signature_invalid`. `safe_tx_hash`, `safe_governance_hash`, `safe_approval_message` and `safe_display_digest` are exported too.

## Errors

All SDK errors extend `TouchQueException`: `TouchQueAPIException`,
`TouchQueNetworkException`, `TouchQueRejectedException`,
`TouchQueTimeoutException`, `TouchQueWebhookSignatureException`,
`TouchQueConfigException`.

A feature your organization cannot use here raises a `TouchQueFeatureException` (still a `TouchQueAPIException`, status 403) with `feature` (`device_risk`, `ai_agents`…) and `feature_reason`: `TouchQueFeatureNotInPlanException`, `TouchQueFeatureReadOnlyException` or `TouchQueFeatureOffException` — not in its plan (an owner or admin adds it in the TouchQue dashboard), being turned off (reads work for 14 days, changes are refused) or switched off on this TouchQue deployment.

## Security

- Every API request is signed HMAC-SHA256 (method, path+query, timestamp, nonce, body hash).
- The `X-TouchQue-Token` a frontend echoes back is itself signed and bound to
  one user + action + transaction digest.
- An approval is consumed exactly once, server-side.
- Your API secret never leaves your server.

See [SECURITY.md](./SECURITY.md) to report a vulnerability.

## Requirements

- Python 3.7+
- A [TouchQue Dashboard](https://dashboard.touchque.com) account

## Logging

The SDK's own problems (a misconfigured guard, a failed `on_challenge`, a relay error) go to `logging.getLogger('touchque')`, which has a `NullHandler`: nothing is printed until your app configures logging (`logging.basicConfig()`, or a handler on `'touchque'`). Lines carry an error's class and message, never the request.

## License

MIT © [TouchQue](https://touchque.com)

## TouchQue Login (hosted sign-in)

Sign-up and sign-in pages for your own customers, on your brand, with OpenID Connect. See [support.touchque.com/touchque-login](https://support.touchque.com/touchque-login) for this SDK's client and a quickstart.
