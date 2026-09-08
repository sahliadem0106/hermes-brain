---
name: hunter-l3-session-management
description: "Use when hunting Session Management on a target. Loads the L3 technique sheet: Session management failures are cases where the server issues an authenticated session and then fails to control its lifecycle: the session survives logout, password changes, device removal, or idle t"
domain: cybersecurity
subdomain: web
tags:
- web
- session-management
- hunting
- l3
version: '1.0'
---

# Session Management — Technique Sheet

## Overview
Session management failures are cases where the server issues an authenticated session and then fails to control its lifecycle: the session survives logout, password changes, device removal, or idle timeout, or its token/CSRF values are never rotated. This class pays when an attacker has (or had) temporary access to an account — a shared computer, a stolen token, a malicious ex-partner — and the victim's obvious remediation ("change the password", "log out", "remove the device") silently fails to evict the attacker. Reports in this class are typically accepted as Medium/High because they break the user's only self-defense mechanism and can lead to permanent account takeover on high-value targets (exchanges, wallets).

## Distinct sub-patterns

### 1. Password change does not invalidate existing sessions
- Endpoint shape / parameter: the account's standard password-change flow. Concrete shapes seen: `POST /account/password` (param: `session_id` present in the flow) at Unikrn (id=272839); the account password change endpoint on app.c2fo.com (id=10377); HackerOne account password change/reset (id=9950); Liberapay account settings password change (id=1118402); help.nextcloud.com password change (id=145430).
- Payload: payload not stated — this is a state/behavioral bug, not an injection. Test procedure: establish Session A in browser 1, change the password (in browser 1 or via reset), then replay/refresh an authenticated request or reload the app from Session A (browser 2) and observe whether it still returns authenticated content.
- Root cause: the password-change handler updates the credential hash but never iterates and invalidates the server-side session store (or bumps a per-user "sessions valid after" timestamp). Session validity and password validity are decoupled.
- Impact proven: a session authenticated with the old password remains fully valid after the change. Concretely: continued full account access on C2FO (id=10377); the stale Liberapay session could still update account information (id=1118402); on Unikrn the old session ID stayed valid so an attacker who knew the password retained access even after the victim rotated it (id=272839); on Nextcloud the surviving session demonstrated session-takeover risk (id=145430); on HackerOne the attacker retained an active session after the victim changed or reset their password (id=9950).
- Exemplar report IDs: 272839 (Unikrn), 9950 (HackerOne).

### 2. Password change does not regenerate the session ID
- Endpoint shape / parameter: `POST /account/password` (Unikrn, id=272839). This is the identifier-rotation variant of sub-pattern 1: even where sessions are conceptually "tied" to a login, the `session_id` value itself is never rotated on a sensitive credential change.
- Payload: payload not stated.
- Root cause: no `session_regenerate`-equivalent on privilege/credential transitions, so an attacker who has learned or captured the current session ID keeps it after the victim rotates the password.
- Impact proven: old session ID remained valid post-password-change; attacker with prior password knowledge retained full account access.
- Exemplar report ID: 272839 (Unikrn).

### 3. Session not invalidated on logout — replay restores access
- Endpoint shape / parameter: any authenticated GET whose raw request you can capture and replay verbatim. Concrete shapes: `GET /user/{username}/edit` with the session cookie as the key parameter (Factlink, id=13602); `POST /profile/edit` (HackerOne, id=353).
- Payload: payload not stated (the "payload" is simply the captured authenticated request replayed byte-for-byte after logout).
- Root cause: logout is implemented client-side only (cookie deletion in the browser) — the server never invalidates the session token in its store. The token remains a valid credential until natural expiry.
- Impact proven: after logging out, replaying the captured settings request logged back into the Factlink account with no username or password (id=13602); on HackerOne, the replayed authenticated POST after logout still returned a valid response (id=353).
- Exemplar report IDs: 13602 (Factlink), 353 (HackerOne).

### 4. Device/client removal does not revoke that client's session
- Endpoint shape / parameter: web security settings UI — e.g. "remove device" for a linked Android device on Coinbase (id=112496); the "Sessions" revocation page under Nextcloud Personal > Sessions (id=165353).
- Payload: payload not stated.
- Root cause: the device-removal/session-revocation action only touches one session class (browser sessions) and is not plumbed through to other client types — native app tokens, desktop sync clients, mobile clients. Sessions are stored per-client-type with no unified revocation path.
- Impact proven: after removing the Android device from Coinbase web settings, the app session stayed active and could still rename/delete wallets (direct money-loss potential) and set a wallet as primary (id=112496). On Nextcloud, killing a session from the Sessions page left the desktop client syncing indefinitely without re-authentication, and Android client sessions were never even listed in the UI — invisible and unrevokable (id=165353).
- Exemplar report IDs: 112496 (Coinbase), 165353 (Nextcloud).

### 5. No server-side idle timeout / session persists after browser close
- Endpoint shape / parameter: no specific endpoint — measure session lifetime behavior directly (leave a session idle > policy, close and reopen the browser, replay a request).
- Payload: payload not stated.
- Root cause: session cookie without a server-side idle timeout and without expiry on browser close; validity enforced (if at all) purely by a long-lived cookie.
- Impact proven: on Gratipay, the session stayed active past 20 minutes of idle time and after browser closure — filed as informative because no sensitive data was accessed, but demonstrates the no-timeout condition (id=123897).
- Exemplar report ID: 123897 (Gratipay).

### 6. Static CSRF token across the authenticated/unauthenticated boundary
- Endpoint shape / parameter: `GET /` (login page), param: `csrf token` (Factlink, id=13639).
- Payload (verbatim): `z3qrwilV8lz7CXsMhmvqxn+93GDZm/m9w/d5DZjoj8w=`
- Root cause: the CSRF token is issued pre-authentication and reused after login instead of being rotated at the privilege transition. Token tied to nothing session-state-changing.
- Impact proven: the token was byte-identical before and after login; the reporter assessed this as enabling session hijacking. Note this is the weakest pattern in the set — impact is arguable, so frame it as "token not rotated at authentication".
- Exemplar report ID: 13639 (Factlink).

## Bypass / chain notes
- No filter bypasses appear in this class — the "bypass" here is behavioral: the victim performs the remediation (logout, password change, device removal) and the attacker's session survives it. Document the survival explicitly in the report: Session A before change → password changed → Session A request replayed → 200 with authenticated content.
- Implicit chains worth testing (present in the records' logic even when not multi-step in the report): capture session token (e.g. via logged-out replay capture, sub-pattern 3) → victim changes password (expected to neutralize you) → session still valid (sub-pattern 1/2) → persistent access. The Unikrn (272839) and HackerOne (9950) findings describe exactly this scenario: attacker knows the password, victim rotates, attacker retains access anyway.
- Client-type split (Nextcloud id=165353, Coinbase id=112496): even when the web session revocation works, test desktop/mobile/native client sessions — they frequently bypass the revocation path entirely and may not be listed anywhere for the user to see.

## Gotchas / what NOT to do
- Do not submit pure cookie-config nits (missing HttpOnly/Secure) as session management bugs — every accepted finding here is a demonstrable lifecycle failure with a before/after reproduction, not a config observation.
- The idle-timeout pattern (Gratipay, id=123897) was rated informative. Expect low severity for missing idle timeouts alone unless sensitive actions are exposed; always demonstrate what an attacker could do during the extended window.
- The static CSRF token (id=13639) is the weakest finding in the set — identical token pre/post login is real, but be prepared for the "attacker already needs a token" pushback. Lead with the pre-auth token surviving into the authenticated session.
- Never "test" this by logging out a real account you don't own or interfering with other users' sessions. All 11 records are self-contained: two of your own browsers/clients, one account. That's the entire lab.
- Preserve the replayed request verbatim and show the timestamp ordering (logout at T1, replay at T2) — reports that just assert "session still valid" without this evidence pattern get closed as non-reproducible.
- Don't assume revocation UI truth. On Nextcloud the Sessions page implied desktop sessions were killed when they weren't, and never listed Android sessions at all (id=165353). Verify each client type independently with a live request from it.

## Real-world impact examples
- Coinbase (id=112496): a removed Android device's session could still rename/delete wallets and set a wallet as primary — direct cryptocurrency loss potential from a security setting that appeared to work.
- Unikrn (id=272839): victim changed the password specifically to evict an attacker who had the old password; the old session ID kept working regardless, defeating the remediation entirely.
- Factlink (id=13602): logout provided zero protection — replaying one captured GET re-authenticated the account with no credentials at all.
- Liberapay (id=1118402): the stale post-password-change session could still modify account information — i.e. attacker persistence, not just read access.
- Nextcloud (id=165353): a desktop client kept syncing the user's files indefinitely after the user "killed" its session, with the mobile sessions unlisted and therefore unrevokable by the user through any UI path.