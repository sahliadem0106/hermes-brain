---
name: hunter-l3-missing-rate-limit
description: "Use when hunting Missing Rate Limit on a target. Loads the L3 technique sheet: Missing Rate Limit covers any authenticated or unauthenticated endpoint that triggers a side effect (email send, resource creation, brute-forceable check) but lacks throttling, CAPTCHA, or resource caps."
domain: cybersecurity
subdomain: web
tags:
- web
- missing-rate-limit
- hunting
- l3
version: '1.0'
---

# Missing Rate Limit — Technique Sheet

## Overview
Missing Rate Limit covers any authenticated or unauthenticated endpoint that triggers a side effect (email send, resource creation, brute-forceable check) but lacks throttling, CAPTCHA, or resource caps. It is one of the easiest classes to verify — send the same request 20-100+ times and observe the effect — and it pays because the impact is often more than "spam": email bombing, server load/DoS, and in the worst case brute-forcing a credential (PIN/code) to take over a user session. The highest-value variants are brute-force-capable endpoints and unauthenticated resource-creation endpoints.

## Distinct sub-patterns

### 1. Forgot-password email bombing (the dominant pattern — 5 of 11 records)
- **Endpoint shape:** `POST /api/v1/users/password/remind` (Nord Security), `POST /reset-password-request/` (Stripo), `POST /a/forgot-password` (CompanyHub), `POST /users/forgot_password` (Nord Security legacy), password reset at `infogram.com`.
- **Payload that actually fired:**
  - Nord: `{"email":"██████████"}` — repeated 100x.
  - CompanyHub: form-encoded `Email=apugodspower%40gmail.com` — 100+ requests, 71 reset emails received.
  - Nord legacy: `data%5BUser%5D%5Bemail%5D=%0a` (note: an invalid/empty email — the endpoint also lacked input validation, firing reset emails for arbitrary addresses).
  - Stripo: `POST /reset-password-request/ ... {}` — 100+ reset emails.
- **Root cause:** No rate limit and no CAPTCHA on the reset-request endpoint. Each request unconditionally triggers an outbound email.
- **Impact proven:** 100+ (Nord), 5000 (Infogram), 71 (CompanyHub), 100+ (Stripo) reset emails into the victim's inbox = email bombing / mass mailing; hundreds of backend email jobs = server load.
- **Exemplars:** 751604, 764335 (Infogram — notably a *bypass* of an incomplete fix for report 280389).

### 2. Brute-force of a PIN / code at login → account-level access
- **Endpoint shape:** `POST /v0/cash/auth/login`, param `pin`. Attacker knows only the victim's phone number.
- **Payload:** payload not stated.
- **Root cause:** PIN verification at login has no attempt limit. Worse than plain brute force: a correct PIN causes the *user's info (email, DOB, verification documents) to be attached to the attacker's operator wallet* — the login itself is a data-attachment action.
- **Impact proven:** Any user's PII (email, date of birth, verification documents) accessible knowing only their phone number.
- **Exemplar:** 75702.

### 3. Unauthenticated resource-creation flooding
- **Endpoint shapes:**
  - `GET/POST /pages/create_project` (Localize) — created **thousands of new projects in under 5 minutes**.
  - `POST (add new product request)` (BitHunt) — 20 consecutive submissions, all `HTTP 200 OK`; no CAPTCHA, no rate limit → automated bot submissions.
  - `POST /dictionaries/{project}/{lang}/en/#add` (Weblate) — unlimited word additions.
  - `POST /translate/{project}/{lang}?checksum=...#suggestions` (Weblate) — unlimited add-suggestion requests (attacker could send ~a million suggestions).
- **Payload:** payloads not stated (plain repeated requests suffice).
- **Root cause:** No per-user/IP rate limit and no platform-level resource quota on create actions; suggestions/words/projects are cheap to request but expensive to store and process.
- **Impact proven:** Storage/data pollution at scale; potential server-side DoS; botspam through form endpoints.
- **Exemplars:** 8093, 89178, 479021, 481654.

### 4. Outbound-email spam via transactional email triggers (non-password)
- **Endpoint shape:** `POST /accounts/email/` (Weblate demo), params `email,content`.
- **Payload (verbatim):** a raw request with `Host: demo.weblate.org`, standard browser headers, `Referer: https://demo` — i.e., the email-sending form posted directly.
- **Root cause:** The email-sending endpoint has no rate limit, so the attacker can send arbitrary emails (with attacker-controlled `content`) to victim addresses through the platform's mailer.
- **Impact proven:** Spam delivered to victim emails from the target's infrastructure; potential DoS of the mail pipeline.
- **Exemplar:** 223557.

## Bypass / chain notes
- **Rate-limit fix bypass:** Infogram (764335) shows the classic retest pattern — a prior report (280389) added *some* limit; the bounty was for demonstrating the fix was incomplete (5000 emails still got through). Always re-test after a fix: try changed email casing, alternate reset flows, or higher volumes than the original report used.
- **Email-bomb amplifiers:** an endpoint with missing *validation* as well as missing rate limit (Nord legacy, 798913) lets you fire hundreds of requests with arbitrary/invalid addresses (`%0a` as the email value worked) — no real inbox needed to prove server load.
- **Brute-force → takeover chain:** rate-limit absence is only severe impact when the result of guessing is account access or PII (75702). Frame the report around the chain: "no limit on PIN → brute force → PII attached to attacker wallet."

## Gotchas / what NOT to do
- **Volume matters for the proof, not the request.** Reports that paid sent 20-100+ requests and *counted the received emails* (71, 100+, 5000). "I could send many requests" without evidence is not enough.
- **Do not claim DoS you didn't demonstrate.** These records show spam and load as side effects; none caused an actual outage. Frame as mass-mailing / resource exhaustion *potential*.
- **Don't test with your real inbox only at 5000 volume** — Infogram did (it was accepted), but use a controlled address you own, and stop at the first few responses on other programs unless the program explicitly welcomes heavier testing.
- **Simple SPA/automation is fine but show server-side acceptance:** BitHunt's proof was 20 requests all returning `HTTP 200 OK` — capture status codes, not just client-side success.
- **Form-encoded vs JSON:** note the exact encoding the endpoint expects (`Email=...%40...` vs `{"email":...}` vs `data[User][email]`); wrong encoding can silently hit validation instead of the mail trigger.
- **Never brute-force credentials on a live account without program permission** — the 75702 pattern pays because impact is explicit, but it's the highest-risk variant to execute.

## Real-world impact examples
- **5000 password-reset emails** flooded into a user's inbox at Infogram — even after a previous fix (764335).
- **100+ reset emails** received in a target inbox from a single automated loop at Nord Security (751604).
- **Any user's email, DOB, and verification documents** obtainable by brute-forcing a 4-6 digit PIN knowing only their phone number, with the PII landing directly in the attacker's operator wallet (75702).
- **Thousands of projects created in under 5 minutes** on Localize — unauthenticated, no CAPTCHA (8093).
- **~71 reset emails** delivered from 100+ `POST /a/forgot-password` requests (CompanyHub, 794395).
- **Spam sent to arbitrary victims** through Weblate's own email endpoint with attacker-controlled content (223557).