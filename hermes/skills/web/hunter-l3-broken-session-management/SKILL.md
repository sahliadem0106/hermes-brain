---
name: hunter-l3-broken-session-management
description: "Use when hunting Broken Session Management on a target. Loads the L3 technique sheet: This class covers failures to properly destroy or invalidate authentication state — session cookies, refresh tokens, and \"sign out everywhere\" mechanisms — after logout or password change."
domain: cybersecurity
subdomain: web
tags:
- web
- broken-session-management
- hunting
- l3
version: '1.0'
---

# Broken Session Management — Technique Sheet

## Overview
This class covers failures to properly destroy or invalidate authentication state — session cookies, refresh tokens, and "sign out everywhere" mechanisms — after logout or password change. It pays reliably on mid-size web apps (SaaS dashboards, donation/community platforms) where logout is implemented as a client-side cookie clear only. Testing is low-effort (capture → logout → replay) and impact is easy to prove as full persistent account takeover, since the replayed credential grants complete access to email/password/username changes.

## Distinct sub-patterns

### 1. Server-side session not destroyed on logout (cookie replay)
- Endpoint shape: any authenticated page; classic test targets are the account/settings page, e.g. `GET /dashboard` on WakaTime, or the generic `session/login` flow on coursera.org.
- Payload: none needed — the "payload" is the captured session cookie itself. In the Imgur-adjacent and Coursera cases no specific payload was recorded; for Liberapay the verbatim cookie was:
  ```
  session="1509265:1:YBAa_gGPtb0x1m_CjoNf4MgBhDG2mDJG.em"
  ```
- Root-cause pattern: logout clears the cookie in the browser but never invalidates the server-side session record (or never bumps a per-user session version), so any previously issued cookie continues to authenticate.
- Impact proven: cookies exported/captured before logout still logged into the victim account after logout — in the Coursera case, even a full day later, and allowed editing account information. On WakaTime, a captured authenticated request to `/dashboard` replayed after logout still returned the account response. On Liberapay, replaying the old cookie allowed editing username, mail, and password.
- Exemplars: 152080 (Coursera), 244875 and 245124 (WakaTime), 449671 (Liberapay).

### 2. Session replay via captured HTTP request (request-level proof)
- Endpoint shape: `GET /dashboard` (WakaTime) — any authenticated endpoint works; pick one whose response unambiguously proves the identity (Account Settings / dashboard).
- Payload: the original captured request, replayed verbatim (Burp "Repeater" style) — no modification of the cookie.
- Root-cause pattern: identical to sub-pattern 1, but the proof is a replayed raw request rather than re-imported cookies — this demonstrates server-side acceptance of the dead session cleanly and avoids browser cookie-handling noise.
- Impact proven: post-logout replay returned the full authenticated account response; a stolen cookie would retain full account access.
- Exemplar: 244875 (WakaTime).

### 3. Cookie export/import to prove persistence
- Endpoint shape: `GET /dashboard` after re-importing cookies.
- Payload: the full cookie jar exported from the logged-in session.
- Root-cause pattern: logout fails to invalidate the session token, so re-importing the exported jar restores the login state entirely client-side.
- Impact proven: after logout, re-imported cookies still logged into the victim's account — direct evidence a cookie thief (XSS, malware, shared machine) keeps permanent access.
- Exemplar: 245124 (WakaTime).

### 4. Logout via private window / cleared cookies still leaves replayable session
- Endpoint shape: `GET /{username}/edit/username` (Liberapay) — sensitive account-editing endpoints are the strongest targets to prove residual access.
- Payload: verbatim captured session cookie (see sub-pattern 1).
- Root-cause pattern: same missing server-side invalidation; the "logout + fresh private window" variant of the test rules out any client-side cookie residue and isolates the server-side failure.
- Impact proven: attacker logged back into the victim's account and could edit username, mail, and password — i.e., full account takeover.
- Exemplar: 449671 (Liberapay).

### 5. "Sign out everywhere" fails to kill all session classes
- Endpoint shape: the account "sign out everywhere" / "sign me out everywhere" option (Imgur account settings), specifically its effect on desktop sessions.
- Payload: not stated.
- Root-cause pattern: the global-invalidation feature only covers one session surface (e.g. web) and misses others (desktop app sessions / a separate token store), so "logout everywhere" leaves live sessions active.
- Impact proven: a user selecting 'Sign me out everywhere' remained signed in on desktop sessions.
- Exemplar: 91350 (Imgur).
- Testing note: enumerate every session-bearing surface (web, mobile, desktop, API tokens) and verify each independently after global logout — partial invalidation is the bug.

### 6. Password reset does not invalidate refresh tokens
- Endpoint shape: the password reset flow (Gener8), measured against previously issued refresh tokens.
- Payload: not stated — the test artifact is a valid refresh token captured before the reset.
- Root-cause pattern: credential change events are not wired to token revocation; the refresh-token store is untouched by the reset, so long-lived tokens survive.
- Impact proven: program-confirmed — after password reset, all active refresh tokens remained valid, letting an adversary holding one regain control of the account. This defeats the user's primary remediation action after credential theft.
- Exemplar: 917213 (Gener8).

## Bypass / chain notes
- No filter-bypass techniques appear in these records — the class is about missing invalidation, not input filtering.
- Multi-step chains observed (all from 449671 / 244875 / 245124, same skeleton):
  1. Login and capture an authenticated request (Burp) or export the cookie jar.
  2. Logout (and/or clear cookies / open a fresh private window to eliminate client-side residue).
  3. Replay the captured request or re-import the cookies and hit an authenticated endpoint (`/dashboard`, `/{username}/edit/username`).
  4. Observe authenticated response → demonstrated persistent access.
- The private-window step is the key evidentiary upgrade: it proves the server, not the browser, is still honoring the old session.
- Escalation to full ATO is implicit in the endpoints chosen: proving you can reach username/email/password edit pages turns "stale session" into "attacker can lock out and take over the victim."

## Gotchas / what NOT to do
- Don't judge by the browser alone — after logout the browser may look logged out; replay the raw request or import cookies elsewhere before concluding the session died.
- Don't test with a victim you don't own — all records use the researcher's own accounts ("victim" = self-registered second account). Cookie capture is of your own session.
- Don't report immediately after logout — the strongest variant waits (Coursera: cookies still valid a day later). Immediate validity can be dismissed as graceful expiry; delayed validity is a clean, undeniable bug.
- Don't limit the check to the web session — the Imgur case shows global-logout features can leave entire surfaces (desktop) untouched, and the Gener8 case shows credential resets can leave refresh tokens alive. Test logout AND password reset as separate invalidation triggers.
- Don't assume only the dashboard matters — pin the proof to sensitive endpoints (account/email/password edit) to establish takeover-grade impact.

## Real-world impact examples
- Coursera (152080): old session cookies still logged into the account a day after logout and allowed editing account information.
- WakaTime (244875, 245124): post-logout replay of a pre-logout request/cookie jar to `GET /dashboard` returned the authenticated account — stolen cookies grant indefinite access.
- Liberapay (449671): replayed session cookie re-authenticated into the victim account from a private window and permitted editing username, mail, and password.
- Imgur (91350): 'Sign me out everywhere' left desktop sessions active — global logout feature partially non-functional.
- Gener8 (917213): program-confirmed that a password reset left all active refresh tokens valid, enabling an attacker with one token to regain account control.