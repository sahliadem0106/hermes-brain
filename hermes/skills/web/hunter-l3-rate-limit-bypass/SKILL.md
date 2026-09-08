---
name: hunter-l3-rate-limit-bypass
description: "Use when hunting Rate Limit Bypass on a target. Loads the L3 technique sheet: Rate limit bypass covers techniques for evading per-request, per-IP, per-account, or per-token throttles on authentication, verification, and API endpoints."
domain: cybersecurity
subdomain: web
tags:
- web
- rate-limit-bypass
- hunting
- l3
version: '1.0'
---

# Rate Limit Bypass — Technique Sheet

## Overview
Rate limit bypass covers techniques for evading per-request, per-IP, per-account, or per-token throttles on authentication, verification, and API endpoints. It matters because throttles are the primary defense against brute force of credentials, tokens, and OTPs — bypassing one turns a "protected" endpoint into an unbounded guessing oracle. This class pays in three flavors: account takeover via credential/token brute force (Shopify, IBB, Acronis, Automattic), resource/abuse violations via unbounded API extraction or registration (Shopify GraphQL, Courier), and plain throttle reset tricks that unlock retry loops (WakaTime, Unikrn).

## Distinct sub-patterns

### 1. Input-canonicalization mismatch — whitespace/padding to make the same account look like a new key
- **Endpoint shape:** `POST /api/2020-07/graphql` (Shopify Storefront GraphQL), mutation `customerAccessTokenCreate(input: {email: ..., password: ...})`.
- **Payload (verbatim):**
  ```
  {"query":"mutation { customerAccessTokenCreate(input: {email: \"███\", password: \"████████\" }) { customerAccessToken { accessToken } } }"}
  ```
  with the email value carrying an appended trailing whitespace.
- **Root cause:** The login throttle keys attempts on the exact email string. Appending a trailing space produces a string that fails equality comparison with the throttled key but still resolves to the same account during authentication — the counter never increments against the victim.
- **Impact:** After "Login attempt limit exceeded", a request with the whitespace-padded email returned a valid `customerAccessToken`, enabling password brute force of user accounts (exposing contact info and order history).
- **Exemplars:** 1363672 (Shopify).

### 2. Parameter-as-array → batch operations in a single request, defeating per-request limits
- **Endpoint shape:** `GET /email_confirmations/confirm?token[]=...` — the rate limit was 100 requests / 10 minutes, each request carrying one token.
- **Payload (verbatim):**
  ```
  curl --globoff 'http://127.0.0.1:3000/email_confirmations/confirm?token[]=key1&token[]=key2'
  ```
  (extended to up to ~2 million confirmation tokens in one request).
- **Root cause:** The `confirmation_token` parameter accepts an array. The backend turns the lookup into a single `IN(...)` query over all supplied values, so N token guesses cost one "request" against the rate limiter.
- **Impact:** Rate limit of 100 req/10 min bypassed entirely; bulk brute force of `confirmation_token` becomes feasible. A valid confirmation_token for an MFA-less user allows sign-in / account takeover.
- **Exemplars:** 1559262 (Internet Bug Bounty).

### 3. Client-controlled IP header — cycling `X-Forwarded-For` to reset per-IP throttles (and geo-restrictions)
- **Endpoint shape:** `POST /login` and the OTP endpoint (Acronis); header `X-Forwarded-For`.
- **Payload (verbatim):** `X-Forwarded-For: 109.104.192.0` (cycled across 300+ requests).
- **Root cause:** The login/OTP endpoints trust the client-supplied `X-Forwarded-For` header for rate limiting (and geo-restriction), so every header value creates a fresh "IP" identity.
- **Impact:** Bypassed the 429 rate limit (300+ requests); also bypassed the geo-restriction error `ERR-B258C8` to attempt login on a Bulgarian employee account; rate limit on the OTP endpoint bypassed, enabling brute force toward it.
- **Exemplars:** 2627062 (Acronis).

### 4. Negative GraphQL cost — refill the rate-limit cost pool with a negative query
- **Endpoint shape:** Shopify GraphQL Admin API; pagination argument `first`.
- **Payload (verbatim):** `first: -1000` (also cited as `first(-100)`).
- **Root cause:** The GraphQL query-cost calculator accepts negative values. A query with negative `first` yields negative cost, and the cost pool's refill logic adds it, pushing the depleted pool back to maximum.
- **Impact:** Depleted the cost pool to 50, then used the negative query to refill it to 1000 — querying indefinitely, fully bypassing GraphQL rate limiting.
- **Exemplars:** 481518 (Shopify).

### 5. Frontend-only rate limit — call the backend/API directly
- **Endpoint shape:** AWS Cognito `SignUp` API (Courier), invoked directly instead of the web registration flow.
- **Payload:** payload not stated (standard Cognito SignUp request with the registration parameters).
- **Root cause:** The "too many requests" check lived in the web application layer only; the underlying AWS Cognito API has no rate limit of its own, so requests sent straight to it skip the check.
- **Impact:** Registration rate limit bypassed and a user account created by sending the signup request directly to the Cognito API.
- **Exemplars:** 947349 (Courier).

### 6. Stateless / resettable limiter — trivial state resets restore access
- **Endpoint shape:** `GET /login` (WakaTime) — no parameter.
- **Payload:** payload not stated (page refresh only).
- **Root cause:** Rate limiting state is weak and cleared simply by refreshing the page.
- **Impact:** After hitting a 429, refreshing the page regained access to the login endpoint, bypassing the limit.
- **Exemplars:** 246838 (WakaTime).

### 7. Resend-limit workaround on SMS verification
- **Endpoint shape:** phone number verification message flow (Unikrn) — no parameter.
- **Payload:** payload not stated; described as "a trivial workaround to the SMS resend rate limit".
- **Root cause:** The SMS resend rate limit could be circumvented by a trivial workaround in the verification message flow (details not disclosed in the record).
- **Impact:** SMS resend rate limit bypassed, allowing unlimited verification attempts.
- **Exemplars:** 619578 (Unikrn).

### 8. Missing limiter on an auth endpoint — plain unbounded brute force
- **Endpoint shape:** `POST /oauth/access_token` (Tumblr OAuth via Automattic), params `x_auth_username`, `x_auth_password`, `x_auth_mode=client_auth`.
- **Payload (verbatim):**
  ```
  data_p = 'x_auth_username='+user+'&x_auth_password='+p4ss+'&x_auth_mode=client_auth'
  ```
- **Root cause:** The OAuth login endpoint has no rate limit (or an extremely high one), permitting unlimited credential guessing.
- **Impact:** Brute-force attack over the login endpoint succeeded; weak-password accounts are accessed on success.
- **Exemplars:** 708917 (Automattic).

## Bypass / chain notes
- **Identity-key mismatch chain (1363672):** trigger login attempt limit → append whitespace to email → receive valid access token. The general shape: find *what key* the limiter counts on (email string, IP, token, cost pool) and corrupt it without changing server-side semantics.
- **Batching chain (1559262):** send `token[]=...` array with many tokens in one request → bypass 100 req/10 min limit and batch-test tokens → a valid confirmation_token signs in / takes over the account. Check any parameter that maps to a DB lookup — arrays converting to `IN(...)` multiply guesses per request.
- **Header cycling chain (2627062):** send 10 failed logins until 429 → add `X-Forwarded-For` header to reset the rate limit → spoof a Bulgarian IP (e.g. `109.104.192.0`) to bypass geo-restriction on the victim email → continue to the OTP endpoint and brute force it. The same header defeated *two* controls (throttle + geo-fence).
- **Cost-pool chain (481518):** send high-cost queries to deplete the rate-limit cost pool → send a query with `first: -1000` to get negative cost → cost pool refills to maximum (1000) → query indefinitely.
- **Layer-skipping chain (947349):** bypass the web "too many requests" check → send the signup request directly to the AWS Cognito API → account created without rate limit. When a SaaS frontend wraps a cloud API, test the cloud API directly.
- **Combinability:** these stack — e.g. cycling X-Forwarded-For while brute forcing OTPs, or padding the email while rotating IPs, defeats both per-account and per-IP counters simultaneously.

## Gotchas / what NOT to do
- Don't stop at the 429 — in several records (246838, 2627062) the limit was trivially resettable; the first block is where testing begins, not ends.
- Don't assume the frontend limit is the real one (947349) — identify the backing API and call it directly.
- Don't trust the server's identity derivation: if the limiter keys on a raw string (email, XFF, token), probe canonicalization (trailing whitespace, arrays) before concluding the throttle is sound (1363672, 1559262).
- Don't ignore non-throttle controls on the same header — XFF spoofing also defeated geo-restriction (ERR-B258C8) in 2627062.
- Don't limit negative-input testing to `first`/`limit`-style args only, but note that in the records the negative-cost trick is documented specifically against Shopify's GraphQL cost calculator — validate the cost model before assuming it generalizes.
- Don't test rate-limit brute force against accounts you don't control without care; the Shopify and Acronis impacts both centered on victim accounts — use your own test accounts and, for whitespace/array tricks, prove the bypass on your own credential/token before touching anything else.
- Keep volumes demonstrative but bounded (the Acronis record cites 300+ requests; the IBB token array was a feasibility proof) — the goal is proof of unbounded guessing, not a full brute force.

## Real-world impact examples
- **Account takeover via login brute force (1363672, Shopify):** despite "Login attempt limit exceeded", a trailing-space email yielded a valid `customerAccessToken` — full access to customer contact info and order history.
- **Bulk token brute force / account takeover (1559262, IBB):** ~2 million confirmation tokens tested per request, defeating a 100 req/10 min cap; a valid token on an MFA-less user means sign-in and account takeover.
- **Employee account + OTP brute force (2627062, Acronis):** 300+ login requests bypassing 429, geo-restriction bypass (ERR-B258C8) to target a Bulgarian employee account, plus an OTP-endpoint rate limit bypass enabling OTP brute force.
- **Unlimited API extraction (481518, Shopify):** GraphQL cost pool refilled from 50 to 1000 on demand via `first: -1000`, enabling indefinite high-volume querying.
- **Unbounded credential guessing (708917, Automattic/Tumblr):** brute force over `/oauth/access_token` compromised accounts with weak passwords.
- **Unauthorized account creation (947349, Courier):** registration performed directly against Cognito, sidestepping the web rate limit entirely.
- **Unlimited SMS verification attempts (619578, Unikrn):** resend limit circumvented, removing the cap on verification attempts.