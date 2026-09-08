---
name: doppler-mission
description: "Use when resuming the Doppler (HackerOne) bug-hunt."
version: 1.0.0
---

## When to Use
Load when the mission is Doppler (HackerOne program) — resume point for Phase 1 recon and later ladder classes.

## Mission state
- Scope law: `~/bugagent/scopes/doppler.yaml` (6 in-scope assets; staging + onprem + support/docs/community OUT).
- Living log: `~/bugagent/missions/doppler/ATTACK-SURFACE.md` — read FIRST, it holds recon results and the ladder table.
- CLI source clone: `~/bugagent/missions/doppler/recon/cli` (github.com/DopplerHQ/cli, shallow).
- Signup alias: foutabax2+x@wearehackerone.com (plus-aliases OK). Account 1 created; max 3 accounts total.

## CDP setup gotcha (learned Sep 2026)
Operator's own visible Chromium has NO `--remote-debugging-port` — cannot attach retroactively. Operator must relaunch:

```
chromium --remote-debugging-port=9223 --remote-allow-origins='*' --user-data-dir=/tmp/doppler https://dashboard.doppler.com
```
then log in once with foutabax2+1@wearehackerone.com. Verify with `curl http://127.0.0.1:9223/json`.
(The agent's own headless instance occupies 9222.)

## Recon results (summary — details in ATTACK-SURFACE.md)
- All in-scope apps behind Cloudflare+GCP. share.doppler.com CSP: connect-src 'self', frame-src empty, form-action 'self' — strict.
- CLI auth flow: GET /v3/auth/cli/generate/2 → POST /v3/auth/cli/authorize {code} → POST /v3/auth/cli/roll {token} → /revoke. Plain Bearer token, no HMAC/signing → access control is purely token-scoped.
- High-value leads by ladder class: class 1 = /v3/configs/config/tokens (per-config service tokens); class 2 = mfa_recovery + CLI auth-code entropy/reuse/roll semantics; class 7 = /v3/configs/config/secrets/watch (streaming); class 8/10 = /v3/workplace/template/import; class 5 = config lock/unlock state machine + policy exclusion notes (>$500 referral, 70-day free team plan are IN scope).

## Program rules that shape testing
- share.doppler.com: ONLY secret-access-control bypasses eligible; no captcha/rate-limit submissions.
- Referral credit >$500 accumulation IS valid (under $500 excluded). Sustained free team-plan access after 70 days IS valid.
- BugSnag API key in frontend = intentional, out of scope. MFA bypass via Google Auth/SAML = intended behavior.

## Next actions on resume
1. Verify CDP port 9223 live; attach and capture dashboard JS bundles, full CSP, token storage format.
2. Mine JS bundles for API endpoints + SPA routes.
3. Map object model (/v3/me, workplace, project, config, secret) — seeds IDOR variants.
4. Finish CLI source audit: pkg/crypto, pkg/configuration (local token storage).
5. Start class 1 (load hunter-l3-idor + hunter-l4-idor sheets first — SKILL-MAP rule).