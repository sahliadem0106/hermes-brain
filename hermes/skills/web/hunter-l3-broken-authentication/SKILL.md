---
name: hunter-l3-broken-authentication
description: "Use when hunting Broken Authentication on a target. Loads the L3 technique sheet: Broken Authentication covers failures in the identity lifecycle: weak/default credentials, unsigned or under-validated session/token state, missing reauthentication on sensitive actions, and password-reset token lifecycle bugs."
domain: cybersecurity
subdomain: web
tags:
- web
- broken-authentication
- hunting
- l3
version: '1.0'
---

# Broken Authentication — Technique Sheet

## Overview
Broken Authentication covers failures in the identity lifecycle: weak/default credentials, unsigned or under-validated session/token state, missing reauthentication on sensitive actions, and password-reset token lifecycle bugs. It pays because every sub-pattern below directly yields account takeover (ATO) or unauthorized account actions — the highest-severity class of finding — often with minimal tooling (a browser, a second mailbox, and patience). The richest vein in these records is password-reset token invalidation logic, followed by unauthenticated/under-authenticated destructive account actions.

## Distinct sub-patterns

### 1. Default / weak credentials with no rate limiting
- **Endpoint shape:** `POST /secure-login` with params `username,password`.
- **Payload (verbatim):** `username=access&password=computer`
- **Root cause:** No rate limiting or lockout on the login endpoint allowed brute-forcing; the credential pair `access:computer` (a common/default pair) was live.
- **Impact:** Full authentication as user `access` on the target application.
- **Exemplars:** 1066851, 1067037 (h1-ctf).

### 2. Unsigned client-side session state (flag-flipping cookie)
- **Endpoint shape:** `POST /secure-login` with params `username,password,cookie`; session cookie is base64-encoded JSON.
- **Payload (verbatim, base64):** `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==` — decodes to `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}` with `admin` flipped to `true`.
- **Root cause:** Weak credentials got you in, but privilege was encoded client-side: the cookie carried an **unsigned** `admin:false` flag with no server-side signature, so flipping it to `true` granted admin.
- **Impact:** Logged in as admin, downloaded `my_secure_files_not_for_you.zip`, cracked its password (`hahahaha`), and obtained `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`.
- **Chain:** Brute-force `access:computer` → decode cookie → flip `admin:false` → `admin:true` → re-encode base64 → replay.
- **Exemplar:** 1069392 (U.S. Dept Of Defense).

### 3. Email-only authorization for destructive account actions
Two variants:
- **a) Unauthenticated support-flow deletion (HackerOne):** `POST /support/tickets/new`, params `email, username`. Support ticket creation required **no authentication or email verification** — only a target's email + username. Reporter opened ticket 460752 for a target account and requested deletion; support began processing it. Enables unauthorized deletion, suspension, or spam against any account. Exemplar: 2068830.
- **b) Delete-by-email (ownCloud):** `DELETE owncloud.com account`, param `email`. The deletion request for the marketing site had no protection beyond knowing the victim's email — the request could be submitted (deletion was manual, but the path existed). Exemplar: 113211.

- **Related — no password reauthentication on delete (Liberapay):** `POST /{username}/settings` (close account). Account deletion required no password confirmation, so an intruder on a shared computer could delete the victim's account. Exemplar: 361368.

### 4. Session cookie replay across browsers
- **Endpoint shape:** `www.reddit.com` session cookies.
- **Payload:** not stated (copied cookies).
- **Root cause:** Session cookies accepted in another browser/client without re-authentication or binding to the original client context — a session management weakness.
- **Impact:** Attacker logged into the victim's account with no username/password by replaying copied cookies.
- **Exemplar:** 1167029.

### 5. Password-reset tokens not invalidated — the big family
Five distinct invalidation gaps, all proven:

- **a) Token survives email change (Twitter/X):** `POST /account/password_reset`; the reset link token. Reset links are **not invalidated when the account's email is changed** — a link issued to the old email stays valid after the account email is updated, so a compromised old inbox can still take over the account. Exemplar: 22203.
- **b) Token survives email change (WakaTime):** `POST /reset_password`, param `email`. A reset link mailed to `a@x.com` still changed the password after the email was changed to `b@x.com`. Chain: request reset for victim email → victim changes email believing the old link is dead → use the still-valid old link. Exemplar: 244612.
- **c) Token survives password change (Concrete CMS):** `POST /login` (reset token use). After up to **10 password changes** — each destroying all active sessions — an old unused reset link from step 2 still worked and could change the password again. Exemplar: 23921.
- **d) Token survives use (WakaTime, two reports):** `GET /reset_password/{token}`, param `token`. Requesting two reset links produced two concurrently valid tokens; opening the first did not expire it or the others. Second instance: after requesting several resets, using the first link still changed the password with other tokens remaining valid. Note the reporters themselves framed the single-use variant as hardening gap, not standalone critical. Exemplars: 244614, 275242.
- **e) Multiple old tokens valid alongside new ones (Mavenlink):** password reset flow, param `token`. Old token (`token01`) and new token (`token02`) were both usable simultaneously — a leaked old token resets the password → ATO. Exemplar: 15166.

### 6. Reset-link delivered over HTTP (token leak in transit)
- **Endpoint shape:** `GET /register/reset/{token}` — delivered link form: `http://en.instagram-brand.com/register/reset/<the security token here>?email=<email address here>`
- **Root cause:** Reset links issued over `http` (via a `mandrillapp.com` tracking redirect) instead of https; token observable in cleartext on the wire. Also note the token is in the **URL query/GET**, which compounds leak surface (logs, Referer).
- **Impact:** Captured the reset token with Wireshark via MITM, enabling mass ATO of Instagram Brand accounts.
- **Exemplar:** 206650 (Automattic).

### 7. Reset link doubles as an authentication bypass
- **Endpoint shape:** `POST /login` (Concrete CMS variant above overlaps); distinct Phabricator variant: opening the reset link **authenticates the user before any password change is performed** — the session is granted on link-open alone. Anyone who obtains/intercepts the link gets an authenticated session without knowing the old password. Exemplar: 23363.

### 8. Parameter-controlled flow confusion on verification links
- **Endpoint shape:** `GET /user/validate_link?verify_token=<valid_token>` — param `step`.
- **Payload:** `/user/validate_link?verify_token=<valid_token>` (i.e., the same link with `step=account` **removed**).
- **Root cause:** Removing the `step=account` parameter from the email-verification link made the same `verify_token` act as a **password reset** link — server-side flow selection driven by a client-controlled parameter, with no separate authorization requirement on the reset flow.
- **Impact:** Email-verification link used to reach the password-change flow and reset the password → ATO. Anyone who can read the victim's email-verification mail (or induce one) gets reset capability.
- **Exemplar:** 98469 (Deriv.com).

### 9. No email verification before login / 2FA enablement (account lockout)
- **Endpoint shape:** `POST signup / login / 2FA enable` (Moneybird); `POST dashboard.omise.co signup + 2FA enable` (Omise).
- **Root cause:** Users can register with any email, log in, and enable 2FA **without verifying** the email address first.
- **Impact:** Attacker registers with a victim's email, logs in, enables 2FA → the victim can no longer register or log in with their own email (pre-registration lockout / hostile takeover of the email identity before the real user arrives).
- **Exemplars:** 649533 (Moneybird), 699200 (Omise).

### 10. Password change without current-password check; unverified phone changes
- **Endpoint shape:** Khan Academy password-change and mobile-number add/change flows.
- **Payload:** not stated.
- **Root cause:** Password change required no knowledge of the current password; mobile-number add/change had no SMS/call verification.
- **Impact:** A few seconds of access to a logged-in session (e.g., shared machine) was enough to change the password = ATO; plus notification spam to arbitrary phone numbers.
- **Exemplar:** 207552.

### 11. JWT user ID not validated at issuance
- **Endpoint shape:** Traffic Analytics Tool JWT token issuance (Semrush), param: user ID in JWT.
- **Payload:** "JWT token created with a user ID whose validation is broken" (payload not stated in full).
- **Root cause:** The user ID embedded in the JWT is not validated when the token is created — the server trusts a client-influenceable identity claim at issuance time.
- **Impact:** Manipulated/forged user id in the token could grant access to another user's subscription data.
- **Exemplar:** 853145.

### 12. Auth gate implemented as redirect-only (no server-side halt)
- **Endpoint shape:** PHP API `index.php` (Shopify).
- **Payload:** not stated — simply ignore the login redirect (e.g., request the protected page directly with redirects disabled).
- **Root cause:** Auth check relies on `header()` redirect **without `exit()`**, so the protected page body still renders when the client ignores the redirect.
- **Impact:** Authentication bypass plus full path disclosure.
- **Exemplar:** 64941.

### 13. Broken 2FA recovery (self-DoS)
- **Endpoint shape:** 2FA recovery flow (Legal Robot), param: n/a.
- **Root cause:** Improper client-side error handling left 2FA recovery codes non-functional.
- **Impact:** Users who enabled 2FA could not recover their accounts when their auth device was missing — recovery codes simply didn't work. Lower severity but a real availability bug in the auth system itself.
- **Exemplar:** 249337.

### 14. Session not fully invalidated on reset (resurrection window)
- **Endpoint shape:** VK.com session reset / password change flows.
- **Payload:** not stated.
- **Root cause:** Session tokens not fully invalidated on reset — a session could be **resurrected** shortly after being reset (post session-reset / password change / forced password change), letting an attacker regain access.
- **Exemplar:** 207062.

## Bypass / chain notes
- **Credential brute-force → cookie flag flip (1069392):** weak creds alone give user access; the privilege escalation needed the second step of decoding the base64 cookie, editing JSON (`admin:false` → `admin:true`), re-encoding, and replaying. Always decode any cookie that looks like base64 JSON and check for unsigned role/flag fields.
- **Email-change race on reset tokens (22203, 244612):** request reset → let the email change → the old link is your persistence mechanism. The chain in 244612: request reset for victim email → victim changes email believing the old link is dead → use the still-valid old link.
- **Parameter deletion as flow switch (98469):** removing `step=account` from a verify link re-routed it to the password-reset flow. Test reset/verify links with parameters stripped — the token's server-side authorization scope may be broader than the visible flow.
- **Redirect-ignore bypass (64941):** request protected pages with redirects disabled (curl without `-L`, Burp "do not follow redirects") — header-only auth gates render the protected body anyway.
- **Signup-first lockout chain (699200, 649533):** signup with victim email → login without verification → enable 2FA → victim is locked out. Chain confirmed in the records as multi-step.

## Gotchas / what NOT to do
- **Don't over-claim single-use token non-invalidation:** the WakaTime reporters themselves (244614) noted no immediate standalone threat for "token survives use" — frame it as a hardening gap unless you can chain it (e.g., leaked token in logs/Referer). Severity framing matters for triage.
- **Don't assume manual-action requests are critical (113211):** the ownCloud delete-by-email went through a manual deletion process — impact is limited to submitting the request. State the actual blast radius.
- **Don't report replaying your own session cookies in another browser of your own account as a bug (1167029 was about *victim* cookies); demonstrate cross-user impact.**
- **Don't miss `exit()` checks in server-rendered auth gates:** the Shopify bug (64941) is invisible if you follow redirects like a normal browser — always inspect the body of 302 responses once.
- **Don't test lockout/brute-force on production login forms without program permission** — the `access:computer` findings here were from CTF/DoD programs that permit it.
- **Impact ≠ root cause:** e.g., "users can't recover their account" (249337) is a self-availability bug, not an attacker win — classify accordingly.

## Real-world impact examples
- **Full admin + flag on a DoD target (1069392):** brute-forced `access:computer`, flipped unsigned `admin` cookie flag to `true`, downloaded `my_secure_files_not_for_you.zip`, cracked password `hahahaha`, captured `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`.
- **Mass ATO via cleartext reset tokens (206650):** reset security tokens captured in cleartext with Wireshark on the Instagram Brand reset flow — reporter framed it as enabling mass account takeover.
- **Confirmed ATO via parameter-stripped verify link (98469, Deriv.com):** `/user/validate_link?verify_token=<valid_token>` without `step=account` reset the account password.
- **Unauthorized deletion initiated at HackerOne (2068830):** support ticket 460752 opened with only victim email + username; support began processing account deletion.
- **Reset link valid after 10 password changes and full session destruction (23921, Concrete CMS).**
- **Old-mailbox persistence (244612, WakaTime):** link sent to `a@x.com` still reset the password after the account email moved to `b@x.com`.
- **Victim locked out of their own email identity (699200 Omise, 649533 Moneybird):** attacker-enabled 2FA on an unverified signup blocked the real owner from registering/logging in.