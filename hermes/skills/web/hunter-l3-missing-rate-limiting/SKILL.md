---
name: hunter-l3-missing-rate-limiting
description: "Use when hunting Missing Rate Limiting on a target. Loads the L3 technique sheet: Missing Rate Limiting covers endpoints that accept unlimited repeated requests where repetition itself is the abuse: credential brute force, email/SMS bombing, mass resource creation, account creation, and spam."
domain: cybersecurity
subdomain: web
tags:
- web
- missing-rate-limiting
- hunting
- l3
version: '1.0'
---

# Missing Rate Limiting — Technique Sheet

## Overview

Missing Rate Limiting covers endpoints that accept unlimited repeated requests where repetition itself is the abuse: credential brute force, email/SMS bombing, mass resource creation, account creation, and spam. It pays when you demonstrate concrete abuse at volume — N emails delivered, N accounts created, N requests with no throttle — rather than merely asserting "no rate limit." The strongest reports pair a measured burst (85–300+ requests) with a business-harm narrative (mail costs, account takeover, DoS).

## Distinct sub-patterns

### 1. Password brute force on login / password-verified actions
- Endpoint shape: `POST /login`, `POST /index.php/apps/preferred_providers/password/submit/{token}`, `POST /settings/pass/edit` (HackerOne), `POST stats.nextcloud.com login`
- Payload: Nextcloud: `ocsapirequest=&email=<target username>&password=<target password>`
- Root cause: no rate limit or account lockout on failed password attempts; password-confirmed actions (email change, disable account) share the same gap.
- Impact proven: 85+ consecutive requests all HTTP 200 (Nextcloud 922470); unlimited dictionary attacks across password change / PayPal email change / disable-account without lockout (HackerOne 157750); unlimited guessing confirmed on stats login with full-site-compromise potential (Nextcloud 146424).
- Exemplars: 922470, 157750.

### 2. Brute-force protection implemented but non-functional (code-level defect)
- Endpoint shape: Nextcloud AppFramework endpoints annotated `@BruteForceProtection`, gated by `BruteForceMiddleware`.
- Payload: none — verified by code inspection.
- Root cause: `BruteForceMiddleware` never calls `throttle()` on the response, so failed attempts are never counted. The control exists on paper and does nothing.
- Impact: all protected endpoints are effectively unrate-limited despite the annotation.
- Exemplar: 1596918. Lesson: when a rate limiter is present, check it actually throttles — middleware that doesn't call throttle() is silent dead code.

### 3. Password reset email flooding (including "rate limited" endpoints that don't limit)
- Endpoint shape: `POST /password_resets/new` (Coinbase), `POST /accounts/reset/` (Weblate), `POST /users/regeneratepassword` (PortSwigger)
- Payload: Weblate verbatim: `csrfmiddlewaretoken=csrfmiddlewaretoken_here&email=email@here.com&content=&captcha=captcha_here` — note it includes a CAPTCHA token and still replayed fine.
- Root cause: no limiter, or a limiter that fails on replay (Intruder with the same CSRF+CAPTCHA token succeeded). "Regenerate password" treated as a normal state-changing action with no send cap.
- Impact proven: 300 password reset emails delivered to one inbox despite rate limiting being enabled (Weblate 229825); multiple reset emails from a handful of repeated forgot-password requests (Coinbase 119605); 100 regenerate requests → mailbox flood + email API cost/storage risk (PortSwigger 1337425).
- Exemplars: 229825, 1337425, 119605.

### 4. Confirmation / invite / notification email bombing
- Endpoint shape: resend-confirmation on account settings (`POST .../settings/account`, WakaTime), invite-user API (Mixmax), invite-contact action (Algolia), support mail `POST /support` (Moneybird)
- Payload: none stated for most; WakaTime varied User-Agent headers across replays.
- Root cause: transactional send endpoints have no per-target or per-session send cap.
- Impact proven: inbox bombed with confirmation emails by replaying with varied User-Agents (WakaTime 245147); unlimited invite emails (Mixmax 233376); same contact invited repeatedly with no limit (Algolia 151868); support mail repeatedly sendable until a better limiter was added (Moneybird 1145293).
- Exemplars: 245147, 233376.

### 5. SMS / call flooding via auth APIs
- Endpoint shape: VK API method `auth.signup` (registration flow), parameter `phone`.
- Payload: not stated.
- Root cause: no flood control on the API method — no per-phone or per-IP cap.
- Impact: mass SMS messages / voice calls to arbitrary phone numbers, confirmed by the program.
- Exemplar: 107877. Highest-impact sub-pattern here: phone-number flooding reaches real users off-platform.

### 6. Mass fake account / registration creation
- Endpoint shape: `POST /account/signinform/premium_tour_login` (XVIDEOS), `GET /registo/` (MTN Group SME registration)
- Payload: XVIDEOS: `email=...&password=...&username=...`
- Root cause: no CAPTCHA and no rate limit on account creation.
- Impact proven: automated creation of up to 1000 accounts, all processed successfully (XVIDEOS 2915502); unlimited registration submissions via Intruder → mass fake accounts / request flooding (MTN 1305766).
- Exemplars: 2915502, 1305766.

### 7. Unbounded resource/record creation (authenticated object spam)
- Endpoint shape: `POST /api/users/current/goals` (WakaTime), `POST /emailformdata/v1/amp-lists` (Stripo), create-list (X/Twitter)
- Payload: WakaTime verbatim: `{"type":"coding","seconds":3600,"delta":"day"}`; Stripo verbatim: `{"projectId":298427,"name":"ukibxiv4daehs7wdnupej63kgbm1aq.burpcollaborator.net","description":"...","url":null,"identifier":null,"sourceType":"JSON"}`
- Root cause: creation endpoints with no per-user quota or per-minute cap.
- Impact proven: 100+ identical goal POSTs all returned 200/201 (WakaTime 244813); unlimited data-source records → resource-abuse DoS (Stripo 1047100); unlimited list creation (X 42250).
- Exemplars: 244813, 1047100.

### 8. Content spam that degrades the platform (comments, reports, subscriptions)
- Endpoint shape: `POST /comment` (DRIVE.NET), redditgifts add-comment, report-video on tiktok.com (web), subscription form `POST /` on sifchain.finance
- Payload: none stated for most; Sifchain confirmed 10 consecutive subscribes of the same email, all HTTP 200, 10 confirmation emails delivered.
- Root cause: comment/report/subscribe endpoints with either no limiter or a uselessly high one.
- Impact proven: comment rate limit measured at 1000/min → mass comments measurably slowed the server / increased load time (Reddit 1202408); unlimited report-video submissions (TikTok 948146); email-bombing via repeated subscribes (Sifchain 1195429); comment spam overloading notification system (DRIVE.NET 835200).
- Exemplars: 1202408, 948146, 1195429.

### 9. Brute-forceable secrets: serial / identifier guessing
- Endpoint shape: `POST /auth/validate-switch-serial` (Myndr), parameter `switch-serial`.
- Payload: `switch-serial=MSA3/8878-XXXXXXX` (vary the masked portion).
- Root cause: validation endpoint has no rate limit, and the keyspace is small (7-digit serial).
- Impact: repeated guesses with no throttle message; brute-forcing a victim's serial lets the attacker continue the registration flow on their behalf.
- Exemplar: 1065127/1065128. Key idea: rate limiting gaps turn any "validate this identifier" endpoint into an enumeration oracle when entropy is low.

## Bypass / chain notes

- Replay through "protected" forms: Weblate's reset form included CSRF + CAPTCHA fields yet 300 Intruder replays succeeded — check whether the CAPTCHA token is validated server-side or just present (229825).
- Header variation: WakaTime confirmation-email bombing varied User-Agent across replays (245147) — naive per-UA limiters defeat themselves.
- Rate limiter that never throttles: Nextcloud's middleware skipped `throttle()` entirely (1596918) — code-review the limiter, don't just observe clean 200s.
- Measured-limit abuse: Reddit's 1000/min comment cap is technically a limit but was abused to measurably slow the server — "limit exists" ≠ "limit is sane" (1202408).
- Enumeration chain: unthrottled serial validation → guess victim's device → continue their registration (Myndr 1065128).
- Burp Intruder is the standard evidence tool across these records (MTN, Weblate, XVIDEOS, PortSwigger).

## Gotchas / what NOT to do

- Don't report "no rate limit" without measured evidence — every accepted report here quantified: 85+ requests, 100 regenerate emails, 300 resets, 100+ goals, 1000 accounts, 10 delivered emails.
- Don't actually compromise accounts: Nextcloud 146424 explicitly confirmed unlimited guessing without compromising any real account.
- Don't stop at the login form — password-confirmed actions (email change, account disable, password edit) and form-replay endpoints (reset, confirm, invite, support mail) are equally valid targets and frequently missed.
- Don't ignore low-severity-looking sends: mailbox flooding was accepted repeatedly because of concrete cost/abuse narratives (email API costs, storage, user harassment).
- Don't assume CAPTCHA or CSRF in the form means protection — verify by replay (229825).
- Don't spam production beyond the minimum demonstration needed; keep volumes at "proven" (dozens to low hundreds), not at actual DoS.

## Real-world impact examples

- 300 password reset emails delivered to one victim inbox on a "rate-limited" endpoint (Weblate, 229825).
- Automated creation of up to 1000 accounts with zero CAPTCHA/throttle (XVIDEOS, 2915502).
- 100+ identical goal-creation POSTs all returning 200/201 — unlimited record creation (WakaTime, 244813).
- Unlimited dictionary password attempts across four password-verified account actions with no lockout (HackerOne, 157750).
- Brute-forcing a 7-digit switch serial to hijack a victim's registration flow (Myndr, 1065128).
- Mass SMS/calls to arbitrary phone numbers via an unthrottled signup API (VK.com, 107877).
- Mass comments measurably degrading server response time under a nominally-existing 1000/min cap (Reddit, 1202408).