# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [4.0.0] — 2026-10-20 — TouchQue Actions

> 3.6.0 (Never Locked Out) and 3.7.0 ("Why?" case codes) below were not published on their own; they ship in 4.0.0.

### Breaking
- **Action types moved to `tq.action_types`** (`define`, `list`; class `ActionTypes` in
  `touchque.resources.action_types`). `tq.actions` is now TouchQue Actions. Replace `tq.actions.define(...)`
  with `tq.action_types.define(...)`.

### Added
- **TouchQue Actions** (`tq.actions`): your own code at points of the approval pipeline, run by TouchQue in a
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
  - `TouchQueAPIException.case_code` on refusals (blocked, frozen, rate limited, provisional, keys lost).
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
- **Silent sign-ins.** Stop asking the phone again and again when nothing about a sign-in is new. TouchQue's
  risk engine decides; the push is skipped only when it says so.
  - `tq.risk.check(external_username, type='LOGIN', client_ip=None, user_agent=None, browser_proof=None,
    max_age_seconds=None)` returns `{'prompt', 'reasons', 'assurance', 'silentMode'}`. Sends nothing to the
    phone. Read fail-closed: `prompt` is `False` only when the API answered the boolean `false`; malformed
    `reasons` become `[]`, a missing `assurance` is `'normal'` (`parse_risk_check`).
  - `tq.risk.browsers(external_username)` and `tq.risk.forget_browsers(external_username, thumbprint=None)`: the
    browsers TouchQue knows for a user, and forgetting one or all of them.
  - `login.request(..., browser_proof=...)`, `login.verify(..., browser_proof=...)` and
    `tq.start(..., browser_proof=...)`: the browser's device-bound key proof (`X-TouchQue-Browser`, made by
    `@touchque/web` 1.4.0), passed through untouched; once the request is approved, TouchQue knows that browser.
  - `silent_sign_in` option (default off) on the Flask and Django `require_touchque`, FastAPI's
    `RequireTouchQue`, `RelayHandler` (POST /login; every relay adapter passes it through) and `run_guard`: a new
    attempt carrying the `X-TouchQue-Browser` header is checked first; `prompt: false` approves it at once with
    no push (`assurance['method'] == 'silent'`, `confirmedVia == 'SILENT'`, `requestId == 'silent'`, `reasons`;
    `on_authenticated` gets `via: 'silent'`). Otherwise, and on any error in the check, the usual push starts
    with the proof attached. `{'max_age_seconds': n}` sets your own limit on the age of the last phone approval.
  - `BROWSER_HEADER` (`x-touchque-browser`), `silent_input_from_headers`.

## [3.4.0] — 2026-10-18

### Added
- **Vishing Shield.** When the user taps Approve during a call (or with the screen shared or the phone
  remote-controlled), TouchQue can move the request to a passkey, refuse it, or approve it as provisional.
  The approval dict from `complete()` and `login.verify()` carry `provisional`, `revoked`, `revokeReason` and
  `reconfirmedAt`: a provisional approval lets the user in, but TouchQue refuses their critical actions
  (`blocked` / `provisional`) until the phone re-confirms it after the call.
- `WebhookReasons` and `WebhookEvents` for the webhook reasons (`vishing_suspected`, `phishing_origin`,
  `user_reported_coached`, and the existing ones) and events (`APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`, and
  the existing ones).
- **Mirror Alarm.** The first waiting step carries `step['canary']`; `@touchque/web` 1.3.0 loads it on the page
  that shows the sign-in, so a real-time phishing proxy gets the approval refused (`phishing_origin`). Allow
  the canary host in your CSP (`img-src`, `connect-src`).

### Changed (behaviour)
- **`login.verify()` raises `TouchQuePasskeyRequiredError` (`reason == 'step_up'`) when a poll shows the request now needs a passkey** (PENDING with
  `requiresPasskey`), instead of polling into a timeout. Finish it in the browser with `@touchque/web`. The
  error has a new `reason` attribute (`'policy'` for the passkey-only policy, as before).
- The guard switches a waiting offline QR to `passkey_required` when its push moved to a passkey, and an
  offline code TouchQue refuses for that reason answers `passkey_required` instead of `blocked`.
- An approval the user took back on the phone answers the guard with `expired` / `revoked`.

## [3.3.0] — 2026-10-12

### Security
- **Adding a passkey needs the phone.** `RelayHandler`'s `/passkey/register/options` used to hand out
  registration options to anyone holding your app's session, and a passkey approves requests on its
  own, so a stolen session cookie could become a permanent second factor. For a user with a linked
  phone the route now answers the same two-phase step as `/login` (202 with the number to show; the
  user approves a `PASSKEY_ENROLL` request on the phone) and returns the options only after that
  approval, once. Users without a linked phone are unchanged. The TouchQue API enforces this too:
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
  number-match code and details it showed, without trusting TouchQue (same as the Node SDK's
  `verifyApprovalProof`). Fails closed without a pinned key unless `allow_unpinned_key=True`.
  Needs the optional extra: `pip install "touchque-authenticator[proof]"` (the core stays
  requests-only). Tested against `fixtures/approval-proof-vectors.json`, shared by all SDKs.
- **`tq.login.report_fraud(request_id, reason=..., note=...)`** — report a request you later learned
  was fraud (chargeback, account takeover, social engineering). TouchQue's risk engine uses it as its
  strongest training signal; the request's status does not change. Idempotent.
- **Relay routes** for Flask (`touchque_relay_blueprint`), FastAPI (`touchque_relay_router`) and Django
  (`touchque_relay_urls` / `touchque_relay_view`), on top of a framework-agnostic `RelayHandler`: the same
  14 routes and behaviour as the Node SDK's `touchqueRouter` (`POST /login` with the two-phase guard contract,
  enrollment, offline codes, passkey ceremonies and credential management). `get_login_user` binds `/login`
  and the offline routes to the user who passed your first factor; the offline routes answer
  `403 OFFLINE_REQUIRES_FIRST_FACTOR` without it; `/enroll/start` never replaces an already linked phone
  (`409 already_linked`); sessions open only for the user TouchQue returns. Pre-auth routes are rate limited
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
