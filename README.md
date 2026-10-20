# touchque-authenticator

The official Python server SDK for [TouchQue](https://touchque.com) — biometric push
2FA, passkeys, and offline approval codes, added to any backend with one
decorator per route. Adapters for Flask, Django and FastAPI included.

[![PyPI version](https://img.shields.io/pypi/v/touchque-authenticator.svg)](https://pypi.org/project/touchque-authenticator/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

📘 Full docs: **[authenticator.touchque.com/docs](https://authenticator.touchque.com/docs)**

## Install

```bash
pip install touchque-authenticator
# with a framework adapter:
pip install "touchque-authenticator[flask]"    # or [django] / [fastapi]
```

The importable package is `touchque` (`import touchque`).

## Setup

Get an API key and secret from your [TouchQue Dashboard](https://authenticator.touchque.com):

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
    event = tq.webhook.verify(raw_body=request.data, signature=request.headers['X-Signature'])
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
real recent sign-ins before they go live. Full guide: [ACTIONS.md](../ACTIONS.md).

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

## Errors

All SDK errors extend `TouchQueException`: `TouchQueAPIException`,
`TouchQueNetworkException`, `TouchQueRejectedException`,
`TouchQueTimeoutException`, `TouchQueWebhookSignatureException`,
`TouchQueConfigException`.

## Security

- Every API request is signed HMAC-SHA256 (method, path+query, timestamp, nonce, body hash).
- The `X-TouchQue-Token` a frontend echoes back is itself signed and bound to
  one user + action + transaction digest.
- An approval is consumed exactly once, server-side.
- Your API secret never leaves your server.

See [SECURITY.md](./SECURITY.md) to report a vulnerability.

## Requirements

- Python 3.7+
- A [TouchQue Dashboard](https://authenticator.touchque.com) account

## License

MIT © [TouchQue](https://touchque.com)
