---
name: hunter-l3-input-validation-bypass
description: "Use when hunting Input Validation Bypass on a target. Loads the L3 technique sheet: Input Validation Bypass is the class of bugs where a server accepts input that its own validation logic was supposed to reject — invalid characters, control bytes, oversized strings, alternate numeric encodings, or unnormalized Unicode."
domain: cybersecurity
subdomain: web
tags:
- web
- input-validation-bypass
- hunting
- l3
version: '1.0'
---

# Input Validation Bypass — Technique Sheet

## Overview
Input Validation Bypass is the class of bugs where a server accepts input that its own validation logic was supposed to reject — invalid characters, control bytes, oversized strings, alternate numeric encodings, or unnormalized Unicode. It pays when validation exists only on the client, when the backend validator has parsing quirks (PHP `intval()`, null-byte handling, trailing-whitespace in HTTP parsers), or when accepted garbage propagates into identity fields, queues, or downstream security matchers. Individually these bugs can be low severity, but they chain into account impersonation, privilege escalation, data integrity corruption, DoS, and filter/security-control bypass.

## Distinct sub-patterns

### 1. Scientific notation accepted by numeric validators (PHP intval overflow → privilege escalation)
- Endpoint/param: `POST /signup-manager` (signup), params `age`, `lastname`.
- Payload (verbatim): `age=1e3`, `age=1e8`, with `lastname=YYYYYYYYYYYYYYY` (a lastname long enough to overflow a fixed-width field).
- Root cause: PHP's `intval()` happily accepts scientific notation (`1e3` → 1000, `1e8` → 100000000). The oversized integer representation overflows the fixed-width `age` database column, causing the `lastname` value to spill over into the adjacent admin-flag column position. The account is written with the admin flag set.
- Impact: Full admin privileges on a freshly registered account — flag retrieved (`flag{99309f0f-1752-44a5-af1e-a03e4150757d}`).
- Exemplars: 1065517, 1065583 (h1-ctf).

### 2. Null bytes accepted in email validation
- Endpoint/param: `POST https://gratipay.com/~{username}/emails/`, param `email`.
- Payloads (verbatim): `yourname@domain.com\0`, `you@abc.com%00`, `you@xyz.com$`.
- Root cause: Server-side email validation accepts invalid characters such as null bytes; client-side validation correctly rejects them, so the bug only exists server-side.
- Impact: An email containing a null byte is accepted, stored, and listed on the account after reload — corrupting the account's email integrity despite a visible client-side error.
- Chain observed: change input `type=email` to `type=text` via Inspect Element → submit null-byte email → reload page to see the invalid email listed.
- Exemplar: 150917 (Gratipay).

### 3. Null bytes prepended to free-text fields → corrupt, unprocessable records
- Endpoint/param: `POST /{program}/reports/new`, params `report[title]`, `report[vulnerability_information]`.
- Payload (verbatim): `%00` prepended to the fields.
- Root cause: Null bytes at the start of report title and body are not rejected by validation.
- Impact: Titleless and non-closable bug reports persisted and appeared in the program queue — corrupting program workflow (reports cannot be closed normally).
- Exemplar: 6350 (HackerOne).

### 4. Control characters (%0a, %0d%0a) accepted in identity fields → impersonation / duplicate accounts
- Endpoint/param (a): `POST register/update full name` (WakaTime), param `full_name`.
  - Payload (verbatim): `%0a` (meta/control characters).
  - Root cause: full name field does not filter control/meta characters such as null bytes and `%0a`.
  - Impact: control/meta characters stored in the display name, allowing impersonation of other users or hiding real identity.
  - Chain: intercept the full-name submission → append `%0a` → name accepted and stored.
- Endpoint/param (b): `POST /signup`, param `email` (HackerOne).
  - Payloads (verbatim): `genuine%40email.com%0d%0a`, `email%25char`.
  - Root cause: signup email validation accepts `%` and `%0d%0a` (CRLF) characters.
  - Impact: multiple accounts created with invalid emails; garbage stored in the database; duplicate accounts created for real addresses (an attacker can register `victim@email.com%0d%0a`-style variants).
- Endpoint/param (c): `POST /users/sign_up`, param `username` (HackerOne).
  - Payload (verbatim): `<username>%0a`.
  - Root cause: signup validation allows usernames containing newline control characters, which are not stripped — producing a distinct but inaccessible account.
  - Impact: profile with trailing `%0a` returns 404 (unusable account exists), and bug reports submitted under it appear to originate from another user — attribution corruption.
- Exemplars: 245236 (WakaTime), 815085 and 3227 (HackerOne).

### 5. Length restrictions enforced only client-side → oversized strings / app-level DoS
- Endpoint/param: `POST https://callerfeel.mtnonline.com/profile/feedback.html`, param `name`.
- Payload: `AAAA...` — a name exceeding the frontend length limit (e.g. >1000 chars).
- Root cause: string length restriction enforced only in the frontend; the backend accepts arbitrarily long values.
- Impact: bypassed the username length restriction; the oversized value caused the receiver page to delay — application-level DoS.
- Exemplar: 1638347 (MTN Group).

### 6. Unicode validation gaps in usernames (incomplete fix regression)
- Endpoint/param: username field at registration (Weblate), param `username`.
- Payload (verbatim): `ＡＢＣ` (fullwidth Unicode characters).
- Root cause: Unicode characters not properly validated on the username field despite a prior fix (issue #229483) — a regression / incomplete remediation.
- Impact: invalid Unicode characters accepted in username (confirmed via screenshot) — enables username spoofing/confusables.
- Exemplar: 241596 (Weblate). Closely related: 3052880 (Nintendo, Xenoblade Chronicles X user name field) — user names not validated/sanitized, allowing injected formatting tags and profanity-filter bypass (payload not stated).

### 7. Parser-level validation gaps: trailing LWS defeats downstream security matchers
- Endpoint/param: HTTP header value in `http_parser` / Envoy proxy layer (Node.js program).
- Payload (verbatim):
  ```
  GET / HTTP/1.1
  Host: my-super-private-domain.com 
  Hello: World
  ```
  (note the trailing space after the Host value)
- Root cause: `http_parser` did not trim trailing linear whitespace (LWS) from header values, so domain-blocking matchers that compare the Host value exactly fail to match values with trailing whitespace.
- Impact: requests to a blocked domain, sent with trailing whitespace in the Host header, bypassed Envoy's domain block — external users could tunnel requests that should have been blocked.
- Exemplar: 730779 (Node.js).

## Bypass / chain notes
- Client-side-only validation is trivially bypassed: intercept the request in a proxy, or edit the DOM (change `input type=email` to `type=text` via Inspect Element) before submitting — the server never re-validates (150917, 1638347).
- Trailing/leading whitespace and control characters are a repeatable trick to defeat exact-match security matchers: a trailing space in the Host header defeated Envoy's domain blocklist (730779); trailing `%0a` in usernames changed routing/attribution behavior (3227); `%0d%0a` in emails created duplicate accounts (815051/815085).
- Numeric encoding alternates (`1e3`, `1e8`) pass weak numeric validation while producing out-of-range values — the stored overflow then corrupts adjacent data (admin flag) (1065517, 1065583).
- Null bytes are multi-purpose: accepted in identity fields (emails) (150917) and prepended to content fields to break record lifecycle (titleless/non-closable reports) (6350).
- Regression testing pays: when a target previously fixed a validation bug (Weblate #229483), re-test the same field — the fix was incomplete and the same class of payload (`ＡＢＣ` fullwidth chars) still landed (241596).

## Gotchas / what NOT to do
- Don't stop at the client-side error message. In 150917 the UI showed a validation error, but the null-byte email was accepted and stored anyway — always reload and check server-side state.
- Don't assume a prior fix means the class is dead. Weblate's earlier fix (#229483) left the same Unicode gap open (241596).
- Don't limit control-character testing to `%0a` alone — test `%00`, `%0d%0a`, and `%` in the same fields; different characters produced different corrupt states (unusable accounts, duplicate accounts, non-closable reports).
- Don't test only text fields — numeric fields can accept scientific notation, and HTTP header values can carry trailing whitespace; both bypass validation in ways that escalate (admin flag, domain block bypass).
- Don't overlook the impact angle: these are not just "garbage input" bugs. Frame them as impersonation (245236), attribution corruption (3227), DoS (1638347), privilege escalation (1065517/1065583), or security-control bypass (730779) — otherwise they read as low-severity spam.
- Don't send unbounded oversized payloads against production without care — the MTN finding caused real page delays (DoS); keep impact demonstration minimal.
- Note when a record lacks a payload: 3052880 (Nintendo) — payload not stated; the technique (formatting-tag injection + profanity-filter bypass via unvalidated names) is still present in the data.

## Real-world impact examples
- Admin account creation + flag capture via `age=1e8` scientific-notation overflow on signup (1065517, 1065583, h1-ctf): `flag{99309f0f-1752-44a5-af1e-a03e4150757d}` obtained.
- Security-control bypass (730779, Node.js): trailing whitespace in the `Host` header (`my-super-private-domain.com `) bypassed Envoy's domain block, enabling request tunneling to blocked domains.
- Impersonation / identity hiding (245236, WakaTime): `%0a` accepted in full name lets an attacker impersonate users or hide their real identity.
- Attribution corruption (3227, HackerOne): a username with a trailing `%0a` creates a 404 profile; bug reports from it appear to come from another user.
- Non-closable reports in program queues (6350, HackerOne): `%00`-prefixed report titles/fields produced titleless reports that could not be closed.
- Duplicate/fraudulent accounts (815085, HackerOne): emails like `genuine%40email.com%0d%0a` and `email%25char` were accepted, creating duplicates of real addresses.
- Application-level DoS (1638347, MTN Group): >1000-char name bypassed the frontend length cap and delayed the receiver page.
- Email integrity corruption on a live production app (150917, Gratipay): `you@abc.com%00` stored and displayed on the account despite client-side rejection.
- Profanity-filter and formatting bypass (3052880, Nintendo): unvalidated game usernames accepted formatting-tag injection.