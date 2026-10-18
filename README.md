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
`get_details` and `allow_offline_without_first_factor`. Without a framework,
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
