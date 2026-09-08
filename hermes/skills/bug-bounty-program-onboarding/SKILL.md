---
name: bug-bounty-program-onboarding
description: "Use when onboarding a new bug bounty program."
version: 1.0.0
author: Sahli adem
license: MIT
metadata:
  hermes:
    tags: [security, bug-bounty, onboarding, recon, scope]
---

## When to Use
A new bug bounty program is being onboarded (signup, scope capture, first recon). Covers the setup class: account/credential logistics, scope file, tiered testing order. For live exploitation technique, use the hunter-l3/l4 skills instead.

## 1. Signup logistics (learned the hard way)

- **HackerOne email alias is `username@wearehackerone.com`, NOT `username@hackerone.com`.** Program policy pages often write the wrong domain. Always verify the exact alias in the hacker's H1 profile → Settings → Email alias before advising signup.
- Alias is receive-only, and will NOT forward mail from addresses associated with the hacker's own H1 account. External program verification mails forward fine.
- When a program asks for a marker string in the account name (e.g. "(BBP)"), combine it with the org-name requirement into ONE string (e.g. `HackerOne (BBP)`) — signup forms usually have a single "Project or company name" field.

## 2. Credential tiering — ask for the MINIMUM credential per test tier

Never ask for the highest-value secret up front. Offer the operator explicit tiers:
1. **Public-by-design IDs** (app IDs, client IDs): zero risk, unlocks the unauth boundary map.
2. **User-level tokens** (session JWTs, cookies): medium blast radius, unlocks user-boundary tests.
3. **Account secrets** (API secrets/keys): full power, ask only when a specific test requires it, state blast radius and storage plan first.
If the operator says save it, store in a `chmod 600` `.env.privacy` in the mission dir, never in chat-logged plaintext beyond the one paste.

## 3. Scope file first
Write `scopes/<program>.yaml` (see bugagent convention) BEFORE any request: in-scope assets, out-of-scope, excluded classes, signup rules, program rules (per-report rules, dup policy). Exclusion lists are gold: they tell you exactly which noise NOT to test, and which adjacent behaviors are the real surface (e.g. if CORS-any-domain is excluded, cross-tenant API logic is where money lives).

## 4. Recon sequence (passive-first)
1. OpenAPI/spec endpoints (`/openapi.json` etc.) — build the object model (tenant → object IDs) before any testing.
2. Wayback/CDX per in-scope host only; flag api/js/internal/param URLs.
3. Root pages + JS bundles: endpoint extraction, auth-flow endpoints, object-ID format regexes (cuid vs uuid vs hex — random cuids kill naive enumeration, pushing IDOR testing to authorized-cross-tenant instead).
4. Check each in-scope host resolves (NXDOMAIN on an in-scope asset is a finding-lead, not an error — the service may have moved into another in-scope host's API paths).
5. Unauth boundary probe with app ID only: expect 401s; record which endpoints validate input BEFORE auth (input-validation-order quirks) and which need feature flags enabled on the app.

## 5. Bounty strategy (operator rule)
Stack small PAID findings ($100–500, real impact) over chasing one big payout. Never informative. Auth-walled surfaces are secondary per the autonomous-first rule in memory.

## 6. Worker delegation contract (DS volume agent)
Give the worker: mission dir, scope law verbatim, rate limits (plain GETs only, no brute/fuzz), output contract ("tool failed" beats guessing), and distinct filenames from the brain's files to avoid collisions in the shared mission dir. Worker collects; brain (GLM) verifies and judges.

## References
- `references/privy-program.md` — Privy (HackerOne) session map: assets, API object model, findings so far.
