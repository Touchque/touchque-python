# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
  `TouchQueWebhookReplayException` (a subclass of
  `TouchQueWebhookSignatureException`) — answer 200 to it, it is a duplicate.

## [2.0.0] — 2026-09-28

### Added
- `TouchQue()` with no arguments reads `TQ_API_KEY` / `TQ_API_SECRET` /
  `TQ_API_URL` from the environment.
- `tq.start` / `tq.check` / `tq.complete` — the headless step-up flow: start
  an approval, get back a JSON-safe "step" (the matching number, the
  enrollment QR, or a `blocked`/`frozen`/`rate_limited` refusal) to render in
  your own UI, and complete an approved request exactly once.
- `touchque.contrib.flask.require_touchque`, `touchque.contrib.django.require_touchque`,
  `touchque.contrib.fastapi.RequireTouchQue` — one line per protected route,
  built on `touchque.guard.run_guard`. The matching number is now available
  **before** approval (previously only `login.request()`'s raw response
  carried it, with no framework support for relaying it to the browser, so
  number matching could not be completed through a one-line guard).
- `tq.offline` (`challenge`, `verify`, `verify_totp`) and `tq.actions`
  (`define`, `list`) — previously only in the Node SDK.
- `TouchQueAPIException.status` / `.code` / `.reason` / `.attempts_left` /
  `.retry_after`; a network failure now raises `TouchQueNetworkException`
  instead of being indistinguishable from a real API error.
- `TouchQuePasskeyRequiredError`, raised by `login.verify()` when a
  phishing-resistant policy requires a passkey.
- `webauthn.delete_credential(id, external_username=...)` — scope a deletion
  to one user (previously any credential id your key could reach was
  deletable).

### Changed
- **Breaking:** default `base_url` is `https://api.touchque.com` (the
  previous default, `api-authenticator.touchque.com`, has no DNS record and
  was unreachable).
- **Breaking:** `login.verify()` now raises `TouchQueTimeoutException` (not
  `TouchQueRejectedException`) when a request expires unapproved, and returns
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
  to the TouchQue Authenticator (2FA/MFA) product specifically. The
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
