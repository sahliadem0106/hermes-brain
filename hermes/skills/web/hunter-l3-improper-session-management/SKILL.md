---
name: hunter-l3-improper-session-management
description: "Use when hunting Improper Session Management on a target. Loads the L3 technique sheet: Improper Session Management covers bugs where a server fails to invalidate authentication state when it should: after logout, after password change/reset, after 2FA enablement, after app deauthorization, or when an admin expires sessions."
domain: cybersecurity
subdomain: web
tags:
- web
- improper-session-management
- hunting
- l3
version: '1.0'
---

# Improper Session Management — Technique Sheet

## Overview

Improper Session Management covers bugs where a server fails to invalidate authentication state when it should: after logout, after password change/reset, after 2FA enablement, after app deauthorization, or when an admin expires sessions. The server treats a long-lived token/cookie as valid regardless of account-state changes, so anyone who captured the token (or an attacker who already had access) retains account access indefinitely. It pays reliably across programs because it requires no injection skill — just disciplined state-transition testing — and impact is easy to prove with a second browser or captured cookie.

## Distinct sub-patterns

### 1. Logout does not invalidate the bearer/auth token
- Endpoint shape: any logout action tied to an opaque auth token (e.g. Twitter-style `auth_token` cookie). Not endpoint-bound — test the token itself, not a page.
- Payload: none — the test is replaying the unchanged token after logout.
- Root cause: logout only clears the client-side cookie; the server never revokes the token server-side.
- Impact: token remains alive and fully usable post-logout; demonstrated via PoC video showing continued authenticated use.
- Exemplars: X / xAI (id=14177); HackerOne (id=737).

### 2. Session cookie replay after logout (full account takeover from a captured cookie)
- Endpoint shape: any authenticated page, e.g. `GET /settings/account` on fantasytote.com or WakaTime.
- Payload: the victim's raw session cookie, replayed verbatim. (Cookie value not stated in records.)
- Root cause: server-side session record is not destroyed on logout.
- Impact: WakaTime — replayed cookies after logout granted access to authenticated `/settings/account`, impersonating the user. FantasyTote — replayed cookie logs back into the victim's account.
- Exemplars: FantasyTote (id=147388); WakaTime (id=798812).
- Verified chain (FantasyTote): 1) Copy the victim's session cookie; 2) Log out and delete the cookie; 3) Paste the copied cookie to regain access to the victim account.

### 3. Missing cache-control on authenticated pages (back-button cache disclosure)
- Endpoint shape: `GET /` and other authenticated pages served without cache headers.
- Payload: none — browser-native.
- Root cause: authenticated responses lack `Cache-Control: no-store`-style headers, so the browser cache retains them after logout.
- Impact: after logout, clicking the browser Back button reveals all previously viewed authenticated pages.
- Exemplar: Certly (id=158270).

### 4. Password reset/change does not invalidate existing sessions
- Endpoint shape: the account password change/reset flow (e.g. Mavenlink `GET /` session reuse after reset; Rockset account password change; Udemy password change).
- Payload: none — state-transition test.
- Root cause: session invalidation is not triggered by credential rotation; old sessions survive both reset and subsequent login.
- Impact: Mavenlink — browsed simultaneously with two sessions in two browsers, each authenticated with a different password. Rockset — attacker with a stolen password stayed logged in with full account access after the victim changed the password. Udemy — change-password left all other sessions active.
- Exemplars: Mavenlink (id=15852); Udemy (id=164239); Rockset (id=957557).
- Verified chain (Rockset): 1) Attacker logs in with stolen password; 2) Victim changes password; 3) Attacker's session remains active.

### 5. OAuth app deauthorization does not kill the session
- Endpoint shape: Google account → Connected Apps → remove app (target: Mixmax).
- Payload: none.
- Root cause: revoking the app's Google OAuth grant does not invalidate the already-issued Mixmax session.
- Impact: after the user deletes Mixmax from Google Connected Apps, the signed-in session remains active with continued account access.
- Exemplar: Mixmax (id=262262).

### 6. Enabling 2FA does not invalidate pre-existing sessions
- Endpoint shape: account security settings → enable 2FA.
- Payload: none.
- Root cause: 2FA is enforced only at new login; sessions issued before 2FA was enabled are never re-validated.
- Impact: a session on a second device remained active and usable after 2FA activation.
- Exemplar: Superhuman / Grammarly (id=667739).

### 7. Admin "Expire User Sessions" misses some clients
- Endpoint shape: admin panel action "Expire User Sessions" (Shopify), vs. sessions held by the iOS Shopify app.
- Payload: none.
- Root cause: the server-side invalidation covers web sessions only; mobile/native app session tokens are not revoked.
- Impact: the target user's iOS app session remained valid after the owner/admin expired all user sessions.
- Exemplar: Shopify (id=67220).

### 8. Failed-CSRF logout leaves session active
- Endpoint shape: `GET /profile/edit` with `authenticity_token` parameter (HackerOne).
- Payload: request with an invalid `authenticity_token` (specific value not stated).
- Root cause: an invalid CSRF token logs the user out client-side, but the previously authenticated session cookie remains server-side active — a variant of pattern 2 where the logout path itself is broken.
- Impact: the authenticated session cookie remains active after logout, enabling continued use of the session.
- Exemplar: HackerOne (id=737).

## Bypass / chain notes

- Cookie-capture chain: the highest-impact pattern is capture → logout → replay. Prove it exactly as in FantasyTote: copy cookie, log out and delete it locally, paste it back. This defeats the "user just cleared their cookies" triage objection.
- Attacker-persistence chain (Rockset): a stolen-credential attacker survives credential rotation — this converts a "leaked password" scenario into persistent compromise, which is the framing that earns severity.
- Cross-surface gaps: invalidation often covers web but not mobile (Shopify iOS) or OAuth-grant revocation (Mixmax/Google). Always test every client surface against each invalidation trigger.
- Two-password coexistence (Mavenlink): demonstrating two simultaneous sessions under two different passwords is stronger evidence than a single stale session.
- Back-button variant: where token revocation is properly implemented, check whether authenticated pages are still browser-cached (Certly) — same "post-logout data exposure" story, different root cause.

## Gotchas / what NOT to do

- Don't only test logout. The invalidation triggers are a checklist: logout, password change, password reset, 2FA enablement, OAuth app removal, admin session expiry. Records show failures at every one.
- Don't test in one browser only. You need two browsers/devices (or a proxy holding the cookie) so the "other" session survives the state change while you perform it.
- Don't confuse missing cache-control (Certly) with token non-revocation (xAI/WakaTime) — different root cause, different fix (headers vs. server-side session destruction), and conflating them weakens the report.
- Don't skip the mobile/native app when the program has one — Shopify's web-only expiry was the bug, so the app session is the test subject, not the browser.
- Don't expect a payload. This class is almost entirely payload-free; evidence is behavioral (video, side-by-side browsers, replayed requests). Record that proof carefully.
- Don't report back-button cache retention where the pages contain nothing sensitive — scope the impact to what was actually exposed.

## Real-world impact examples

- WakaTime (id=798812): replayed session cookies after logout to reach `/settings/account`, fully impersonating the user.
- Rockset (id=957557): attacker retained full account access through the victim's password change.
- Mavenlink (id=15852): two concurrent authenticated sessions under two different passwords, both browsable at once.
- Shopify (id=67220): admin's "Expire User Sessions" silently failed for the iOS app, leaving an expired user with live admin-surface access.
- Certly (id=158270): all previously viewed authenticated pages retrievable from browser cache after logout.