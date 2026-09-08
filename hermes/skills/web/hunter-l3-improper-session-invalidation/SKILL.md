---
name: hunter-l3-improper-session-invalidation
description: "Use when hunting Improper Session Invalidation on a target. Loads the L3 technique sheet: Improper session invalidation covers bugs where a server continues to honor authentication state after an event that should have destroyed it — password reset, password change, or logout."
domain: cybersecurity
subdomain: web
tags:
- web
- improper-session-invalidation
- hunting
- l3
version: '1.0'
---

# Improper Session Invalidation — Technique Sheet

## Overview

Improper session invalidation covers bugs where a server continues to honor authentication state after an event that should have destroyed it — password reset, password change, or logout. The attacker needs no injection payload: they simply hold a captured or remembered session (old cookie, second browser, captured request) and demonstrate it still works after the invalidation event. It pays reliably on programs with real user accounts (SaaS, CMS, fintech) because it maps directly to account-takeover remediation logic: stolen-session survivors must be able to kill sessions with a password change.

## Distinct sub-patterns

### 1. Sessions not invalidated after password reset ("remember me" sessions persist)

- Endpoint shape: `POST /password/reset` (password change flow) on a site with a persistent-login checkbox ("Remember me for a week").
- Payload: none required — no crafted request. The test is procedural: create a session with "Remember me" checked, note the cookie, reset/change the password, then continue browsing with the old cookie.
- Root-cause pattern: the password-reset handler rotates credentials but does not iterate over and destroy existing session tokens for the account; sessions stamped with the persistent "remember" flag survive indefinitely. Additionally, logging in with the new password does not kill older sessions, so old and new sessions coexist.
- Impact proven: after the password reset, the researcher browsed the site with TWO concurrently valid sessions — one initiated with the old password, one with the new. An attacker who stole a remember-cookie keeps access even after the victim "secures" their account.
- Exemplar: id=15785 [ajaysenr] (HackerOne program).

### 2. Captured authenticated request remains valid after logout (no server-side token invalidation)

- Endpoint shape: any authenticated request that returns sensitive page data. Verbatim exemplar:
  `GET /wp-admin/admin-ajax.php?action=wpcom_load_template&template=settings.php&tcpg=&_=1404092392503 HTTP/1.1`
  with the captured auth cookies:
  `Cookie: wordpress=attacksecure%7C1498700135%7Cf984ae022a50fb3029888a3fa434c443; wordpress_sec=attacksecure%7C1498700135%7Cd3966032fd6f99fd1fdcc055869e5561; wordpress_logged_in=attacksecure%7C`
  (parameters of interest: `action`, `template`, `tcpg`; sensitive target template: `settings.php`).
- Payload: replay the captured request verbatim *after* the user has logged out.
- Root-cause pattern: logout is a client-side event — the browser drops the cookie, but the server never blacklists or expires the underlying session/auth tokens. A request captured before logout (proxy, MITM, XSS exfil, shared logs) remains fully valid server-side.
- Impact proven: after logout, replaying the captured request returned HTTP 200 with the full "My Account" settings page — authenticated account data served with a session the user believed was destroyed.
- Exemplar: id=18503 [ajaysenr] (Automattic program).

### 3. Password change + logout do not invalidate sessions in other browsers

- Endpoint shape: account session on a web application (go.exchange — Omise's exchange platform); test conducted across two browsers on the same account.
- Payload: none stated. Procedure: log into the account in browser A and browser B; change the password and log out of browser A; then interact with the account in browser B.
- Root-cause pattern: server-side session records are keyed only by token, not tied to a credential version; password change and explicit logout do not revoke sessions outstanding in other clients.
- Impact proven: the account profile remained fully editable in the second browser after the account was logged out and its password changed. A session thief retains full account control despite the victim changing the password — the primary defensive action fails.
- Exemplar: id=634488 [ajaysenr] (Omise program).

## Bypass / chain notes

- No filter bypasses were required in any record — the entire class is "old token still works", so there is nothing to evade. This also means no WAF or input validation will ever block these tests.
- Chains: none of the three records chained this into another bug. The natural chain (not demonstrated in these records, so treat as hypothetical) is capture-via-weak-transport/XSS → invalidation bug ensures long-lived stolen access. Within the records themselves, impact was established with replay alone.
- Practical amplification seen implicitly in the records: the "remember me" flag (record 15785) extends the survival window of the un-invalidated session from a single browsing session to a week, multiplying the exposure.

## Gotchas / what NOT to do

- Don't test with the same browser/profile only. Logging out and back in inside one browser destroys the old cookie client-side and will make the bug invisible. Use two browsers, or copy the cookie out and replay it via curl/Repeater (record 634488's method).
- Don't rely on a UI redirect as evidence. The failure signal in record 18503 was a *replayed request* returning 200 with authenticated content, not a browser behavior. Replay the raw request and check the response body contains authenticated data (e.g., the settings page), not just the status code.
- Don't report "I'm still logged in" from client-side caching. The server must have actually processed an authenticated request with the old token — confirm the response is served fresh (note the `_=1404092392503` cache-buster in the exemplar request; the server answered, it was not a cache hit of a static asset).
- Don't conflate the three invalidation events: test logout, password change, and password reset separately. The records show programs that fixed one but not the others (HackerOne record = reset only; Automattic record = logout only; Omise record = change + logout).
- Timestamped cache-buster parameters (`_=`) in captured requests are incidental, not the bug — keep them verbatim when replaying for fidelity but don't describe them as part of the vulnerability.
- This class requires the program to have self-service authentication flows; don't force it onto SSO-only or stateless-API programs where the records show no equivalent pattern.

## Real-world impact examples

- HackerOne (id=15785): after a password reset, two sessions created with two different passwords simultaneously browsed the platform — the old "remember me" session never died. Practical meaning: a victim reset their password to evict an attacker, and the attacker stayed in.
- Automattic (id=18503): a captured authenticated request to `/wp-admin/admin-ajax.php` (loading `settings.php`) returned HTTP 200 with the full "My Account" settings page *after logout* — proof that server-side auth tokens outlived the user's explicit logout.
- Omise (id=634488): on go.exchange, after the victim logged out AND changed their password, the account profile was still editable from the second browser — the strongest impact of the three, since both standard remediation actions were defeated.