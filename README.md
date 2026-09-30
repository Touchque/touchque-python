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
ch = tq.offline.challenge(user='jane@acme.com', type='WITHDRAW',
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
from touchque.exceptions import TouchQueWebhookSignatureException

try:
    event = tq.webhook.verify(raw_body=request.data, signature=request.headers['X-TouchQue-Signature'])
except TouchQueWebhookSignatureException:
    return '', 403  # not from TouchQue
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
