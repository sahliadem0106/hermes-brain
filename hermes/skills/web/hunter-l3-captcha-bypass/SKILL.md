---
name: hunter-l3-captcha-bypass
description: "Use when hunting Captcha Bypass on a target. Loads the L3 technique sheet: Captcha Bypass covers findings where a CAPTCHA or anti-bot challenge (reCAPTCHA, hCaptcha-style tokens, Django simple captchas) fails to actually stop automation — most commonly because the server nev"
domain: cybersecurity
subdomain: web
tags:
- web
- captcha-bypass
- hunting
- l3
version: '1.0'
---

# Captcha Bypass — Technique Sheet

## Overview

Captcha Bypass covers findings where a CAPTCHA or anti-bot challenge (reCAPTCHA, hCaptcha-style tokens, Django simple captchas) fails to actually stop automation — most commonly because the server never validates the captcha/token server-side, or the challenge is trivially solvable/readable client-side. The class pays in programs where captcha is the *only* rate-limit or anti-abuse control on sensitive endpoints (registration, password reset, contact forms). Impact is almost always abuse-at-scale: account flooding, email/reset bombing, enumeration, and DoS — rarely critical alone, but consistently valid Medium/Low findings, and it compounds when paired with response-differentiation leaks.

## Distinct sub-patterns

### 1. Server never validates the captcha parameter — just delete it

- **Endpoint shape / param:** `POST /forgot_password` on an affiliate portal, with body params `captcha`, `email`, plus a CSRF `_token`. Template: `POST /forgot_password HTTP/1.1 Host: affiliate.kartpay.com ... _token=...&email=<victim@email>`
- **Payload that fired (verbatim):** the original request with the `captcha` parameter **deleted entirely** from the body: `_token=...&email=test%40gmail.com` — no captcha key, no blank value, just absent.
- **Root cause:** the backend processes the request without checking for the captcha field at all; the captcha is enforced only client-side (or not enforced anywhere), so omission ≠ rejection.
- **Impact proven:** valid forgot-password response returned without captcha, enabling automated password-reset requests and email/user enumeration (differential responses leak which emails exist).
- **Exemplars:** id=700075 (Kartpay), id=642498 (Kartpay — same flow, captcha validation "missed" on the forgot-password page).

### 2. reCAPTCHA token never validated server-side — signup completes without it

- **Endpoint shape / param:** `POST /auth/register` (Acronis) with a `recaptcha token` field; `POST /signup` (Coinbase) with the standard `g-recaptcha-response` field.
- **Payload that fired:** payload not stated for either — the technique is to submit the registration request with an empty/absent/invalid `g-recaptcha-response` (or a single token reused), and observe the account still being created.
- **Root cause:** the server accepts the request without contacting Google's `siteverify` (or without checking the response). On Coinbase specifically, "the g-recaptcha-response value is not validated server-side on signup."
- **Impact proven:** (a) Acronis — a **single** recaptcha token reused for **unlimited** account creation at `/auth/register`, enabling account flooding and DoS; (b) Coinbase — signup completed with no valid captcha response, enabling fake account creation and email/username enumeration.
- **Exemplars:** id=1655629 (Acronis), id=246801 (Coinbase).

### 3. Token reuse — one valid token replayed unlimited times

- **Endpoint shape / param:** same as above (`POST /auth/register`, recaptcha token param).
- **Payload that fired:** payload not stated — capture one legitimate token from solving the challenge once, then replay it across repeated registration requests.
- **Root cause:** distinct from sub-pattern 2 in that validation may exist but is not single-use: no server-side consumption/one-time binding of the token to a session or request, so one solve unlocks unlimited requests.
- **Impact proven:** unlimited user signups from one token → account flooding, DoS.
- **Exemplar:** id=1655629 (Acronis).

### 4. Client-side solvable captcha — value readable in the DOM

- **Endpoint shape / param:** `POST /accounts/register/` (Weblate, Django-based), captcha field `div_id_captcha`.
- **Payload that fired (verbatim):** `document.getElementById("div_id_captcha")` — the captcha value is trivially extractable from the rendered page via client-side script, so a bot reads the answer rather than solving an image.
- **Root cause:** the captcha challenge/answer is exposed in the DOM (or otherwise trivially machine-readable), so the "challenge" imposes zero cost on automation.
- **Impact proven:** registration captcha solvable programmatically → automated bot account registration at scale.
- **Exemplar:** id=229584 (Weblate).

### 5. Bypass on a rate-limited sensitive flow — captcha on password reset defeated

- **Endpoint shape / param:** `POST /accounts/reset/` (Weblate email reset), param `email`.
- **Payload that fired:** payload not stated — the captcha protecting the reset flow can be bypassed (per the program's own summary confirming the bypass).
- **Root cause:** captcha added as the sole abuse control on the email-reset flow is bypassable; mechanism beyond that not detailed in the record.
- **Impact proven:** victim's inbox flooded with reset emails (email bombing) — confirmed by the program.
- **Exemplar:** id=229541 (Weblate).

### 6. Off-the-shelf solver extension defeats the challenge (weak finding)

- **Endpoint shape / param:** `POST http://www.mopub.com/about/contact/`, param `captcha`.
- **Payload that fired:** none — demonstration is that the **Rumola browser extension** solves the captcha automatically.
- **Root cause:** the captcha is solvable by commodity automation; no site-specific flaw demonstrated. Note: this was resolved **Informative** — programs generally do not pay for "a generic solver tool can solve my captcha."
- **Impact claimed (not exploited):** bots could bypass the check and flood the database via contact submissions.
- **Exemplar:** id=15047 (MoPub / xAI). Treat this as the *negative* exemplar — see Gotchas.

## Bypass / chain notes

- **Deletion is the first test, blanking the second:** the proven bypass in this set is removing the `captcha` parameter outright (id=700075), not sending an empty value. Test both, plus sending arbitrary junk values.
- **Token replay:** where validation exists, test single-use semantics — capture one legit `g-recaptcha-response`/recaptcha token and replay it across N requests (id=1655629). Unlimited reuse of one token is as strong as no validation.
- **Chains observed:** none of the records contain multi-step chains, but the impacts themselves are chain-enablers: captcha bypass + response differentiation = email/user enumeration (Kartpay, Coinbase); captcha bypass + no rate limit = email bombing (Weblate reset) and account flooding (Acronis, Weblate register).

## Gotchas / what NOT to do

- **Do not report "extension/tool can solve the captcha"** — id=15047 (Rumola on MoPub) was resolved Informative. Programs require a *site-specific* flaw (missing validation, token reuse, DOM exposure), not generic solver capability.
- **Do not assume captcha protects anything** — in 5 of 7 records the captcha was entirely unenforced server-side; always verify by omitting the parameter and observing whether the action still succeeds.
- **Impact must be concrete** — the paid findings here demonstrated a specific abuse outcome (unlimited signups, inbox flooding, enumeration), not just "the captcha is bypassed."
- **Respect scope on flooding** — the Weblate reset-bombing (id=229541) targeted a victim inbox; keep volume minimal and demonstrative against your own/test addresses where possible.

## Real-world impact examples

- **Unlimited account creation from one token (Acronis, id=1655629):** a single recaptcha token reused at `POST /auth/register` produced unlimited signups — account flooding and potential DoS.
- **Email bombing via reset flow (Weblate, id=229541):** captcha bypass on `POST /accounts/reset/` let an attacker flood a victim's inbox with password-reset emails; confirmed by the program.
- **Enumeration via unenforced captcha (Kartpay, id=700075):** deleting the captcha param from `POST /forgot_password` still returned a valid response, leaking which email addresses are registered.
- **Fake accounts + enumeration at scale (Coinbase, id=246801):** `POST /signup` completed without a valid `g-recaptcha-response`, enabling fake account creation and email/username enumeration.
- **Bot registration via DOM-readable captcha (Weblate, id=229584):** captcha answer extracted with `document.getElementById("div_id_captcha")`, enabling automated bot account registration.