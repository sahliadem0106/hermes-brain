---
name: hunter-l3-timing-attack
description: "Use when hunting Timing Attack on a target. Loads the L3 technique sheet: Timing attacks exploit the fact that non-constant-time string comparison operators (Python `==`, PHP `===`/`!==`, JavaScript `===`, Ruby `==`) exit early on the first mismatching byte."
domain: cybersecurity
subdomain: web
tags:
- web
- timing-attack
- hunting
- l3
version: '1.0'
---

# Timing Attack — Technique Sheet

## Overview
Timing attacks exploit the fact that non-constant-time string comparison operators (Python `==`, PHP `===`/`!==`, JavaScript `===`, Ruby `==`) exit early on the first mismatching byte. Each correct leading character takes measurably longer to reject than an incorrect one, letting an attacker recover secrets (HMACs, API tokens, OAuth tokens, application passwords, Basic Auth credentials) byte-by-byte through response timing alone — no key, no password, no valid OTP required. This class pays wherever a server compares an attacker-supplied secret or signature against a stored value before granting access. All seven records here were found by a single reporter (ajaysenr) across Shopify, Automattic, Yelp, WordPress plugins, joola.io, WP API, and Ruby on Rails — a signal that hunting for non-constant-time comparisons in open-source code is a repeatable, high-yield workflow.

## Distinct sub-patterns

### 1. Python SDK/library fallback to `==` for HMAC validation
- Endpoint shape: Not an HTTP endpoint — a code-level finding in `shopify_python_api` `shopify/session.py`, function `validate_hmac()`.
- Payload that fired (verbatim): `return hmac_calculated == hmac_to_verify`
- Root cause: `validate_hmac()` falls back to a plain `==` comparison when `hmac.compare_digest()` is unavailable (Python < 2.7.7). `==` on strings short-circuits at the first differing byte, so the time to return leaks how many leading bytes of the HMAC matched.
- Impact proven: PoC measured a significant timing difference (~100 ms) between the early-exit and constant-time comparisons — a demonstrable side channel enabling timing-based HMAC/token recovery.
- Exemplars: id=224096 (Shopify).

### 2. PHP `===` on payment-signature callbacks
- Endpoint shape: WooCommerce Simplify Commerce `return_handler` — the payment status callback that receives the signature parameter.
- Parameter: `signature`.
- Payload: not stated.
- Root cause: The MD5 payment signature is compared with PHP's `===` operator instead of `hash_equals()`. `===` compares byte-by-byte with early exit on mismatch.
- Impact proven: Non-constant-time comparison of the payment signature allows signature recovery via timing, potentially letting an attacker forge payment status updates for orders.
- Exemplars: id=239359 (Automattic).

### 3. Server-side token verification with `===`/`==` (API tokens, OAuth tokens)
- Endpoint shapes:
  - `lib/dispatch/users.js` (joola.io) — API token check, parameter `token`.
  - `lib/class-wp-json-authentication-oauth1.php` (WP API) — OAuth1 hashes/tokens compared with `!==` / `===`.
  - Yelp Firefly `verify_access_token()` — HMAC signature compared with `==` (byte-by-byte, early-exit).
- Payload: not stated in any of the three.
- Root cause: Identical in all three — token/hash verification implemented with language-native equality operators rather than constant-time primitives (`hmac.compare_digest`, `hash_equals`, PHP's timing-safe functions). The verifier leaks "how many leading characters were correct" through response latency.
- Impact proven:
  - joola.io: token verification shown to be susceptible to timing side-channel recovery of tokens (id=31167).
  - WP API OAuth1: token/hash verification shown susceptible (id=31168).
  - Yelp: attacker can recover a valid HMAC signature without knowing the key, forging access tokens (id=240958).
- Exemplars: id=31167, id=31168, id=240958.

### 4. Application-password / second-factor check using strict equality instead of `hash_equals()`
- Endpoint shape: WordPress plugin `login/authenticate` flow — the branch that validates the application password (parameter: application password).
- Payload: not stated.
- Root cause: The plugin used strict equality (`===`) instead of `hash_equals()` to compare the application password, leaking character matches through timing.
- Impact proven: An application password was brute-forced via the timing side channel, allowing login without the real password or a valid OTP — specifically for accounts with an app password enabled. This is the strongest impact in the record set: full account takeover of MFA-protected accounts.
- Exemplars: id=277534 (Ian Dunn).

### 5. Framework-level HTTP Basic Auth with non-constant-time comparison
- Endpoint shape: Rails `http_basic_authenticate_with` (Action Controller) — parameters `name`, `password`.
- Payload: not stated.
- Root cause: Action Controller compared the Basic Auth username and password with a non-constant-time comparison, leaking character matches through response timing. Notably, BOTH the username and password are recoverable, not just the secret.
- Impact proven: An attacker can analyze response timing to intuit the username and password used in Basic authentication. Assigned CVE-2015-7576 — framework-level findings get CVEs and affect every downstream app using the helper.
- Exemplars: id=94568 (Ruby on Rails).

## Bypass / chain notes
- No multi-step chains appear in the records (all seven list `chain: none`). The attacks are single-step: repeated request → timing measurement → byte recovery.
- The practical "chain" within the class is measurement methodology rather than endpoint chaining: the Shopify PoC (id=224096) demonstrated the side channel by measuring ~100 ms difference between early-exit and constant-time comparisons — i.e., differential measurement against a known-safe baseline is the accepted proof pattern.
- Where a signature gates a callback (payment status, OAuth verification), recovering the signature by timing effectively forges the entire authentication step — no separate bypass needed.

## Gotchas / what NOT to do
- Don't report the mere presence of `==`/`===` without a measured timing difference. Every accepted record here included either a PoC measurement (Shopify, ~100 ms) or concrete exploitation reasoning tied to the specific comparison site. Grep-only findings without demonstrating the leak are weak.
- Don't confuse the vulnerable code path with the deployed one. The Shopify finding hinged on a FALLBACK (`hmac.compare_digest()` unavailable on Python < 2.7.7) — the vuln exists only on that path/version. Read the conditional, not just the line.
- Don't limit scope to passwords. The records show the pattern in payment signatures, OAuth1 hashes, API tokens, HMAC signatures, application passwords, and framework Basic Auth — including the username side of credentials.
- Don't forget network noise dominates. Records don't state measurement harnesses, but real timing extraction requires many samples and statistical aggregation; a single measurement proves nothing.
- Don't assume `===` in PHP or `==` in Python is automatically a finding — target sites where the compared value is a secret (token, signature, password) AND attacker-controlled input reaches the comparison.
- Note: all records here came from code review of open-source components (SDKs, plugins, frameworks). The pattern is source-auditing driven, not black-box fuzzing — read the comparison code first, then build the timing PoC.

## Real-world impact examples
- Shopify (id=224096): ~100 ms measurable timing delta in HMAC validation, demonstrating the side channel for token/HMAC recovery in a payments-adjacent SDK.
- Automattic/WooCommerce (id=239359): timing recovery of the MD5 payment signature on the Simplify Commerce return handler → potential forging of payment status updates for orders.
- Yelp (id=240958): recovery of a valid HMAC signature without the key → forged access tokens against Firefly `verify_access_token()`.
- Ian Dunn WP plugin (id=277534): application password brute-forced via timing → login without the real password or a valid OTP (bypass of MFA on app-password accounts).
- joola.io (id=31167) and WP API OAuth1 (id=31168): demonstrated non-constant-time token verification, enabling token recovery via timing.
- Ruby on Rails (id=94568): CVE-2015-7576 — Basic Auth username and password recoverable via timing from the framework's `http_basic_authenticate_with`; impact multiplied across every app using the helper.