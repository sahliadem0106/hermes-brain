---
name: hunter-l3-authentication-brute-force
description: "Use when hunting Authentication Brute-force on a target. Loads the L3 technique sheet: Authentication brute-force weaknesses cover endpoints where a secret (password, API key, OTP/verification code) can be guessed at scale because the server fails to rate-limit, lock out, or otherwise c"
domain: cybersecurity
subdomain: web
tags:
- web
- authentication-brute-force
- hunting
- l3
version: '1.0'
---

# Authentication Brute-force — Technique Sheet

## Overview
Authentication brute-force weaknesses cover endpoints where a secret (password, API key, OTP/verification code) can be guessed at scale because the server fails to rate-limit, lock out, or otherwise constrain repeated attempts — or where a single request can batch-check many candidate secrets at once. It pays when the secret space is small (4-digit codes, weak passwords) or when amplification tricks (array params → SQL `IN` clauses) compress thousands of guesses into one request. Proven impact in these records is full account takeover, including admin accounts.

## Distinct sub-patterns

### 1. Array-parameter key batching via type-confused ORM lookup (single-request mass testing)
- **Endpoint shape:** `GET /api/v1/gems` (any authenticated-by-key API endpoint where the key is read from a request parameter)
- **Parameter:** `api_key`
- **Payload (verbatim):** `api_key[]=key1&api_key[]=key2`
- **Root cause:** Insufficient type checking on the credential parameter. Sending the key as an array caused `User.find_by_api_key` to build a SQL `IN (...)` query, checking every supplied value in one database round-trip instead of treating the array as an invalid credential.
- **Impact proven:** Up to **65534** api_key values could be checked in a single request — brute-force efficiency amplified ~65534x. (Impact rated minimal in practice only because the program's generated keys were long/high-entropy; the amplification primitive itself was confirmed.)
- **Exemplars:** id=449356 (RubyGems)
- **How to apply:** On any endpoint authenticating via a request parameter (`api_key`, `token`, `key`, `secret`), resend the parameter as an array (`param[]=guess1&param[]=guess2`) and vary the response to detect whether multiple values are actually evaluated (e.g., a mismatch between "invalid type" errors vs. "not found", or a hit on a known-valid value mixed into the array as a control).

### 2. Unthrottled login endpoint → credential brute-force to ATO
- **Endpoint shape:** `POST /api/v1/login`
- **Parameters:** `username`, `password`
- **Payload:** not stated (standard password guessing against the login form/API)
- **Root cause:** No rate limiting and no account lockout on the login API. Unlimited guessing against a single account with no defensive response.
- **Impact proven:** Valid credentials brute-forced, including an **ADMIN-role** account — full account takeover.
- **Exemplars:** id=766875 (Palo Alto Software)
- **How to apply:** Identify API login endpoints (especially `/api/v1/login`-style JSON endpoints, which often bypass WAF/rate-limit rules tuned for the web UI login). Confirm absence of throttling by issuing a controlled burst of deliberate failures and checking for: no 429, no CAPTCHA, no lockout message, no increasing delay. Then brute-force with a targeted wordlist. Prioritize admin/role-bearing accounts for impact.

### 3. Unthrottled verification-code endpoint with short code space → any-account password reset
- **Endpoint shape:** `POST /v1/verification-code/auth`
- **Parameter:** `code`
- **Payload (verbatim):** `0000` (4-character/4-digit code space)
- **Root cause:** No rate limit on the password-reset verification endpoint, combined with a weak code of only 4 characters — the entire keyspace (10,000 candidates for 4 digits) is enumerable.
- **Impact proven:** Brute-forced the 4-character verification code to reset **any account's** password knowing only the victim's email — account takeover with no prior credentials.
- **Exemplars:** id=767765 (Clario)
- **How to apply:** On password-reset / OTP / verification-code flows: (1) request a code for a victim identifier (email); (2) locate the endpoint that validates the code; (3) send a burst of candidate codes and check for absence of 429/lockout/expiry enforcement; (4) if the code is 4 digits (or otherwise short), enumerate the whole space. Test whether codes are single-use and whether the email/identifier binding can be swapped between attempts.

## Bypass / chain notes
- **Type-confusion chain (id=449356):** array parameter → ORM treats it as a collection → single `IN(...)` query → per-request guess capacity multiplied by array length (up to 65534). The chain was: send array param → one query checks all keys → brute-force efficiency amplified.
- **Endpoint-selection bypass (id=766875):** the API login endpoint (`/api/v1/login`) lacked the protections the program should have had — checking API endpoints separate from web-UI login is itself a bypass vector, since protections are frequently applied only to one surface.
- **State-machine chain (id=767765):** knowing only the victim's email → trigger code generation → enumerate code at the verification endpoint → reach the password-reset step → ATO. No multi-hop trickery needed because no throttle existed anywhere in the flow.

## Gotchas / what NOT to do
- **Don't dismiss batching bugs when keys are long.** In id=449356 the amplification was real (65534x) but overall severity was downgraded because generated keys were high-entropy. Report the primitive precisely: state the per-request amplification factor and note the key-entropy mitigation yourself rather than overstating.
- **Don't assume the web login's protections extend to the API.** The confirmed ATO in id=766875 was on an `/api/v1/` endpoint. Always test API login paths separately.
- **Verify code length/expiry before mass enumeration.** The Clario bug required both no rate limit AND a 4-character code; a long expiring code with the same missing throttle may be unexploitable in practice.
- **Don't hammer production blindly.** Confirm no-throttle behavior with a small controlled burst first; a real brute-force run against accounts you don't own can violate program rules. Demonstrate on a test account where possible.

## Real-world impact examples
- **RubyGems (id=449356):** `api_key[]=key1&api_key[]=key2` on `GET /api/v1/gems` caused a single `IN(...)` query checking up to 65,534 candidate API keys per request — a 65,534x brute-force amplifier (limited in practice only by long generated keys).
- **Palo Alto Software (id=766875):** unlimited login attempts on `POST /api/v1/login` yielded valid credentials for an **admin-role** account → account takeover.
- **Clario (id=767765):** enumerating the 4-character verification code (`0000`-style space) at `POST /v1/verification-code/auth` allowed resetting **any user's** password knowing only their email → universal account takeover.