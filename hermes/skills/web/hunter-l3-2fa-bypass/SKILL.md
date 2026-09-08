---
name: hunter-l3-2fa-bypass
description: "Use when hunting 2FA Bypass on a target. Loads the L3 technique sheet: This class covers every way to complete a login or sensitive transaction without satisfying the second factor."
domain: cybersecurity
subdomain: web
tags:
- web
- 2fa-bypass
- hunting
- l3
version: '1.0'
---

# 2FA Bypass — Technique Sheet

## Overview
This class covers every way to complete a login or sensitive transaction without satisfying the second factor. The unifying root causes in the records are: state that should gate the session is client-controlled or stored in the wrong place (cookies, flags, challenge hashes), alternate authentication/recovery paths that skip the 2FA step entirely, and missing rate limits on short OTP codes. It pays well because impact is usually total account takeover with only credentials (or even just email), and programs consistently rate these critical/high.

## Distinct sub-patterns

### 1. Session cookie swap / cross-session token reuse
- Endpoint shape: `POST /login` with session cookies; the interesting artifact is a pre-2FA session cookie, e.g. `cookies['oc_sessionPassphrase'] = secondSession.getCookies()['oc_sessionPassphrase']`
- Payload: swap the `oc_sessionPassphrase` cookie from a second parallel session into the session that has 2FA enforced.
- Root cause: the cookie that signals "2FA satisfied" is not bound to the specific enforced-2FA session — any session's token works.
- Impact: full dashboard access without completing 2FA.
- Exemplars: Nextcloud id=1050244.

### 2. Client-controlled boolean flag skipping TOTP
- Endpoint shape: `POST /api/v1/login`
- Payload (verbatim):
```json
{"cas": true, "totp": {"code": "Not Today", "type": "resume", "login": {"user": {"username": "${USER}"}, "password": "${PASSWORD}"}}}
```
- Root cause: the login handler trusts the client-supplied `cas` flag and skips TOTP validation whenever it's truthy — a garbage code like `"Not Today"` is accepted.
- Impact: login returning `userId`/`authToken` with no valid second factor (CVE-2022-35248).
- Exemplars: Rocket.Chat id=1448268.

### 3. Client-supplied challenge hash (self-verifying 2FA)
- Endpoint shape: `POST /` with params `username,password,challenge,challenge_answer`
- Payload (verbatim, three variants from the same root cause):
  - `username=brian.oliver&password=V7h0inzX&challenge=c4ca4238a0b923820dcc509a6f75849b&challenge_answer=1`
  - `username=brian.oliver&password=V7h0inzX&challenge=098f6bcd4621d373cade4e832627b4f6&challenge_answer=test`
  - `username=brian.oliver&password=V7h0inzX&challenge=e11170b8cbd2d74102651cb967fa28e5&challenge_answer=1111111111`
- Root cause: 2FA "verification" is just `md5(challenge_answer) == challenge`, and `challenge` comes from the client. Compute md5 of any answer, set both, done. Method: view the hidden `challenge` field, recognize it as md5, forge the pair.
- Impact: authenticated session cookie as the target user.
- Exemplars: GitLab id=894569; h1-ctf id=894863, id=895172.

### 4. Missing rate limit / attempt cap on OTP entry
- Endpoint shapes: `POST /password/reset` (2FA step of reset); mobile API `POST /api/auth.signin` param `pin`; dashboard OTP field; `PUT https://p.grabtaxi.com/api/passenger/v2/profiles/edit` param `profileActivationCode`
- Payloads: `000000` (Slack PIN, repeated ×100); `profileActivationCode=3122` brute-forced over 1000–9999; "wrong 2FA codes 20 times" still allowed reset.
- Root cause: no rate limiting or lockout on the code-entry endpoint; worse, no code expiration on 4-digit SMS codes (only 9,000 combinations). Key technique: find the *mobile or internal API* variant of the endpoint, which often lacks the web app's rate limiting.
- Impact: brute-force the code → account takeover. Grab case: 204 on correct code, 400 on wrong, attacker can change email/phone.
- Exemplars: Slack id=121696 (reset), Slack id=165727 (iOS API), Cloudflare id=1664974, Grab id=202425.

### 5. State-issued-before-verification cookie gate
- Endpoint shape: the 2FA challenge page of the login flow; cookies `PHPSESSID`, `bb_sessionhash`, `bb_refresh`.
- Payload: payload not stated — the attack is "delete the `bb_refresh` cookie and refresh."
- Root cause: the server issues real session cookies (`PHPSESSID`, `bb_sessionhash`) before 2FA/email-OTP verification completes, and the only thing gating the login is the presence of the `bb_refresh` cookie. Delete it → server treats verification as done.
- Impact: logged in as the victim with only username + password, skipping email OTP entirely.
- Exemplars: Drugs.com id=2315420.

### 6. Sensitive action reachable pre-completion of the factor (step-skipping within the flow)
- Endpoint shape: Cloudflare dashboard recovery-codes API, callable after password check but before security-key auth.
- Payload: n/a (order-of-operations flaw).
- Root cause: endpoints in the auth sequence don't enforce that earlier steps of the same login completed — recovery codes are fetchable mid-login.
- Impact: retrieve recovery codes without touching the security key → account takeover.
- Exemplars: Cloudflare id=1805779.

### 7. Alternate login path / feature that skips 2FA
- Endpoint shapes: `GET /admin/auth/login?google_apps=1`; UK TikTok Seller login redirect URL; LinkedIn merge-accounts feature; forum.makerdao.com alternate auth path.
- Payloads: `google_apps=1`; payload not stated for the others (flow-based).
- Root cause: a second authentication path (SSO toggle, redirect return flow, account-merge, alternate channel) doesn't run the 2FA check the primary path runs. Notable variant: enabling Google Apps login *silently disables* 2FA — the 2FA tab disappears, no notification, and 2FA can't be re-enabled.
- Impact: direct admin-panel / account access with no code; on LinkedIn, login to the victim account via merge given only their credentials.
- Exemplars: Shopify id=178293, TikTok id=1247108, LinkedIn id=1842183, BlockDev/MakerDAO forum id=708303.

### 8. Deactivation + password reset clears 2FA
- Endpoint shape: account deactivation flow + `POST forgot/reset password` (param `email`).
- Payload: payload not stated (pure logic flaw).
- Root cause: the reset/reactivation pipeline drops the 2FA requirement — deactivated accounts can reset their password and log in without any 2FA prompt.
- Impact: with email access only, attacker deactivates the victim's account, resets the password, and gains full access with 2FA completely removed.
- Exemplars: HackerOne id=2463279, id=2543342 (same flaw, reported twice — logic flaws of this class often exist in multiple flows).

### 9. 2FA-gated action with an unguarded sibling endpoint
- Endpoint shapes: `POST /accounts/transfer_money` (param `transaction[to]`); `POST /recurring_payments/{id}/confirm`; BTC send "to paper wallet" path.
- Payload (verbatim, Coinbase transfer): multipart POST with `transaction[from]=51cf4e552f31a99ce200001b`, `transaction[to]=53440a8092adb7d95000001d`; and `utf8=%E2%9C%93&_method=patch` on the recurring-payment confirm.
- Root cause: 2FA is required on one UI flow but the setting isn't enforced server-side on the API/sibling endpoint; separately, the confirm request is replayable and restores a deleted payment without re-entering the code.
- Impact: 0.1 BTC transferred out without a 2FA code; deleted recurring payment restored via replay; BTC sent with 2FA requirement fully bypassed.
- Exemplars: Coinbase id=10554, id=176979, id=7369.

### 10. 2FA activation flow leaves enforcement off
- Endpoint shape: account settings / login after enabling 2FA.
- Payload: payload not stated.
- Root cause: bad 2FA activation flow — 2FA *appears* active in settings but is not actually enforced at login.
- Impact: account opened without performing 2FA after the user enabled it.
- Exemplars: Algolia id=145629.

### 11. Session reset without adequate verification
- Endpoint shape: VK.com session reset flow.
- Payload: payload not stated.
- Root cause: insufficient user verification when resetting sessions.
- Impact: two-step authorization bypassed via session reset; $1,000 bounty.
- Exemplars: VK id=163834.

### 12. Secrets exposure enabling the second factor to be forged (infra chain)
- Endpoint shape: pre-auth file read of `mtmp/system` on a Pulse Secure appliance.
- Payload: `a;id;echo pwned` (the file-read primitive that starts the chain).
- Root cause: the file contains the Duo integration key, secret key, API hostname, and LDAP password — with the Duo secret you can generate valid approvals yourself.
- Impact: full 2FA bypass via forged Duo auth.
- Exemplars: X/xAI id=591295.

### 13. Vulnerable 2FA implementation itself (shipped code)
- Endpoint shape: the `twofactor_totp` app in the product.
- Payload: payload not stated (advisory-level flaw, GHSA-9v72-9xv5-3p7c / CVE-2024-37313).
- Impact: confirmed second-factor bypass; $1,000 bounty.
- Exemplars: Nextcloud id=2419776.

## Bypass / chain notes
- Cookie surgery: the recurring theme is that the gate is a *cookie or client parameter*, not server state. Audit every cookie set on the 2FA page; try deleting each one and refreshing (Drugs.com), or transplanting tokens between two parallel sessions of the same account (Nextcloud).
- Endpoint twins: when the web app rate-limits OTP entry, find the mobile or internal API equivalent (`/api/auth.signin` vs web; Grab's app endpoint) — rate limiting is frequently applied only at one layer.
- Method tampering: `utf8=%E2%9C%93&_method=patch` shows Rails-style `_method` overrides in replayable sensitive requests — capture and replay them.
- Hash-recognition chain: see a `challenge` parameter in a login form → hash-identify it (md5 here) → forge challenge+answer pair. Chain used leaked credentials from logs in all three GitLab/h1-ctf records.
- Multi-step chains seen in records: (a) double login → cookie swap; (b) file read → extract Duo keys + LDAP creds → forge 2FA; (c) capture session header `x-mts-ssid` → brute 4-digit code → change email/phone; (d) deactivate → reset password → login with no 2FA.
- Flow-order abuse: call endpoints from later steps of the auth sequence (recovery codes) before finishing earlier steps (security key).

## Gotchas / what NOT to do
- Don't assume 2FA is enforced server-wide because the UI demands it — test every sibling endpoint that performs the same action (transfers, confirms, sends).
- Don't stop at "invalid code rejected" — Slack's PIN endpoint accepted 100 consecutive wrong codes; prove rate limiting by sending a high volume, then the correct code.
- Don't test on accounts you don't own; all verified takeovers here used the researcher's own or a consented account (GitLab records used leaked test credentials in a CTF context).
- Don't overlook flows that *disable* 2FA as a side effect (Shopify google_apps) — the bug is the silent downgrade, not just the login.
- Don't ignore state issued before verification: real session cookies on the 2FA interstitial are a red flag worth probing.
- A 4-digit or 6-digit code with no expiration is mathematically brute-forceable — always check expiry, not just rate limits.

## Real-world impact examples
- 0.1 BTC moved out of a Coinbase account with no 2FA code entered (id=10554).
- Full takeover of a 2FA-protected HackerOne account using only email access, with 2FA removed entirely (id=2463279, id=2543342).
- Cloudflare recovery codes exfiltrated without touching the hardware security key (id=1805779).
- Grab account takeover via 4-digit SMS code brute force, enabling email/phone change (id=202425).
- Authenticated session as target user Brian Oliver on GitLab with forged md5 challenge (id=894569).
- Shopify admin panel accessed with no 2FA code and 2FA permanently un-re-enableable (id=178293).
- Slack account takeover by brute-forcing the iOS PIN endpoint after 100 invalid attempts with no lockout (id=165727).
- Monetary bounties in records: VK $1,000 (id=163834), Nextcloud $1,000 (id=2419776), plus CVEs CVE-2022-35248 and CVE-2024-37313.