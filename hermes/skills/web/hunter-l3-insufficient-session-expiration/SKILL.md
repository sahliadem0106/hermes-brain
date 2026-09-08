---
name: hunter-l3-insufficient-session-expiration
description: "Use when hunting Insufficient Session Expiration on a target. Loads the L3 technique sheet: Insufficient Session Expiration covers every failure mode where a session, token, or cached credential remains valid after the event that should have killed it: logout, password change, provider disconnect, app removal, or history clearing."
domain: cybersecurity
subdomain: web
tags:
- web
- insufficient-session-expiration
- hunting
- l3
version: '1.0'
---

# Insufficient Session Expiration — Technique Sheet

## Overview

Insufficient Session Expiration covers every failure mode where a session, token, or cached credential remains valid after the event that should have killed it: logout, password change, provider disconnect, app removal, or history clearing. The bug is never in how sessions are issued — it's in the missing server-side revocation step. It pays across web apps (Rails/cookie sessions, OAuth), mobile APIs (bearer/app tokens), and GraphQL, because logout is routinely implemented as a client-side-only operation. It's a reliable, easy-to-verify class: you need two browsers (or two devices), a captured request, and one state-change event.

## Distinct sub-patterns

### 1. Password change does not invalidate other sessions
- **Endpoint shape:** `POST /accounts/password/` (password change form), e.g. Weblate `POST /accounts/password/`; also CLI password changes, e.g. Apache Airflow FAB provider via `airflow` CLI (vs. the `/resetmypassword` webserver flow, which DOES invalidate).
- **Payload:** `(change password while another session is active)` — no special payload; the test is the second session.
- **Root cause:** The password-change handler updates the credential hash but never iterates the user's session store / rotates the session ID. The Airflow variant shows the revocation exists in one flow (web reset) but was never wired into the CLI path.
- **Impact:** An attacker (or old device) with a stale session retains full account access after the victim changes the password — effectively permanent persistence, defeating the user's primary recovery action. Proven: profile update via replayed request (Weblate, id=223327), account info update (DoD, id=1069392), attacker staying logged in and continuing to update the victim's account (Omise, id=514577), stale session on second browser (Automattic/polldaddy, id=273881), sessions surviving CLI password change (IBB/Airflow, id=3073507).
- **Exemplars:** id=223327 (Weblate), id=514577 (Omise), id=3073507 (Airflow/IBB), id=1069392 (DoD).

### 2. Logout is client-side only — token/cookie never revoked server-side
- **Endpoint shape:** Logout endpoints that look legitimate but don't revoke: `DELETE /api/v1/logout` (Shopify Ping, missing required Logout Token Hint), Shopify POS Android app (Xauth token removed from shared_prefs locally only), Uber `cn-sjc1.uber.com/rt/riders/{uuid}/dispatch-view` with `x-uber-token` header.
- **Payload (verbatim):** `x-uber-token: 5ead9f1ab28780d48f8caa9d41a22973` — replayed in the header after logout, still returned the rider's Dispatch View.
- **Root cause:** The client deletes the token (shared_prefs, local storage) but no server-side revocation call is made. Sub-variant: the logout request is malformed (missing Logout Token Hint) so the server errors out and never revokes — a protocol-implementation bug, not just an omission.
- **Impact:** Full account takeover from a previously captured token. Uber: profile modification, trip history, dispatch scheduling/cancellation, payment info access. Shopify Ping: `GET /oauth/userinfo` still returned PII (email, family_name, given_name, locale, tfa_enabled) — full session recovery. Shopify POS: hijack and full store control.
- **Exemplars:** id=293363 (Uber), id=1172205 (Shopify Ping), id=1108662 (Shopify POS).

### 3. Session cookies survive logout (web cookie sessions)
- **Endpoint shape:** Standard cookie-authenticated actions replayed post-signout. Urban Dictionary: `POST /handle.save.php` with params `authenticity_token`, `user[handle]`, `_rails_session`.
- **Payload (verbatim):** `authenticity_token=C4EmquHAIijNq8UrFfbdfm%2B3Bp5RxvL1BpzMdf3%2FJgtw%2FSn%2FgTt4AlFlIDWFivaesfXJFgNqrWS8DD85obbnpA%3D%3D&user%5Bhandle%5D=H.H.+Vong&commit=Save` — the stale `_rails_session` cookie plus the replayed CSRF token still authorized the handle change.
- **Root cause:** Server-side session store is never cleared on sign-out; Rails CSRF tokens are bound to the (still-valid) session, so replaying both works.
- **Impact:** Privileged state change (handle modification) as the victim after they "signed out" — session hijack via replay. HackerOne (id=2469706): stolen cookies kept working after the victim cleared history and re-logged in; attacker repeatedly bypassed 2FA. Shopify exchangemarketplace.com (id=1162443): attacker logged into the victim's account using old cookies while the session was active.
- **Exemplars:** id=216294 (Urban Dictionary), id=2469706 (HackerOne), id=1162443 (Shopify).

### 4. Cookie "resurrection" — old session re-binds to the next user
- **Endpoint shape:** `GET /v0/me` with session cookie `federalist.sid` (GSA/Federalist).
- **Payload:** N/A — a saved old cookie is the payload.
- **Root cause:** Logout invalidates the linked auth (GitHub token) but not the session record; when the *next* user logs in, the old cookie's session ID matches the new user's session, re-validating it — for the attacker, against someone else's account.
- **Impact:** Cross-user backdoor / privilege escalation: attacker's saved `federalist.sid` granted access to whichever user logged in next.
- **Exemplars:** id=250688 (GSA Bounty).

### 5. Session survives auth-provider unlink / app removal
- **Endpoint shape:** OAuth provider disconnect flows — `accounts.shopify.com` external login provider disconnect (Google); removing the site's app from Facebook settings (Gratipay Facebook OAuth login).
- **Payload:** payload not stated — the action is the disconnect/removal, observed from the still-alive session.
- **Root cause:** Revoking the *link* (or the upstream app grant) doesn't touch the already-issued session on the target site. Sessions are anchored to the original OAuth handshake, not to the continued existence of the linkage.
- **Impact:** Persistence backdoor. Shopify (id=1547684): after the victim disconnected the attacker's Google account, the attacker's session remained valid AND they could re-link the Google account — surviving even a password change. Gratipay (id=129209): user remained fully logged in after removing the app from Facebook.
- **Exemplars:** id=1547684 (Shopify), id=129209 (Gratipay).

### 6. GraphQL / API tokens outlive session revocation
- **Endpoint shape:** `POST /graphql` with a captured query (HackerOne: `User_bounty_settings_page`), revocation performed at `/settings/sessions`.
- **Payload:** payload not stated (the captured GraphQL query itself); chain: capture GraphQL request while logged in → revoke session at `/settings/sessions` → replay the GraphQL request.
- **Root cause:** The session-revocation mechanism only destroys the web session; the API/GraphQL query token used for authorization is a separate credential never checked against session state.
- **Impact:** Sensitive data exfiltration after revocation: bounty records including awarded amounts, report titles, payout preferences, and payment method.
- **Exemplars:** id=417382 (HackerOne).

### 7. Client-side state resurrects the session (back button, login re-population)
- **Endpoint shape:** `POST /logout` + `GET /login` (Dust); `platform.hiro.so` logout; Hey.com login page after sign-in.
- **Payload:** payload not stated — navigation and browser back are the "payload."
- **Root cause:** Server does not destroy the session on logout (Dust), so revisiting the login page auto-re-authenticates without credentials. Hiro: session not destroyed server-side, so browser back-button cache restores the authenticated app. Hey.com: browser back re-populated the login form with credentials instead of showing a cleared page — client-side credential persistence.
- **Impact:** On shared devices, the next person (or an attacker with brief access) gets full account access. Dust: automatic re-login with zero credentials after logout.
- **Exemplars:** id=3101207 (Dust), id=3062299 (Hiro), id=1294231 (Basecamp/Hey).

### 8. Peripheral auth state not cleared on logout
- **Endpoint shape:** `GET /account` — Intercom chat widget on the login page (Legal Robot), param `session_cookie`.
- **Payload:** N/A.
- **Root cause:** The third-party widget's session is not cleared on logout and the widget view doesn't require an authenticated user — the widget holds its own unexpired state.
- **Impact:** After logout, the victim's full Intercom chat history remained readable on the login page and messages could still be sent from it.
- **Chain:** obtain user session cookies → log the user out → re-import the cookies → access chat on login page with full chat history.
- **Exemplars:** id=249798 (Legal Robot).

### 9. Weak session validation enables action replay with partial credentials
- **Endpoint shape:** VK.com session-based phone lookup — attacker needs only a known `remixsid` session value plus the target user ID.
- **Payload:** payload not stated.
- **Root cause:** The server validates possession of the session identifier but not that the session is legitimately bound to the acting user's context — insufficient session validation allows actions with a known `remixsid` and user id.
- **Impact:** Disclosure of digits of a user's phone number (enabling SMS flooding) and the ability to set users offline.
- **Exemplars:** id=390126 (VK.com).

## Bypass / chain notes

- **Two-browser baseline:** The core test rig across nearly all records (1069392, 223327, 273881, 514577, 1162443, 2469706): browser A and browser B logged into the same account; perform the state change (password change, logout, disconnect) in A; attempt a privileged action in B. If B still works — bug.
- **Persistence chains:** id=1547684 is the deepest: steal password → link own Google account → victim disconnects Google → attacker session survives → attacker re-links Google → survives victim's password change too. The unlink-failure turns one bug into a permanent backdoor.
- **Cookie resurrection chain (250688):** obtain valid `federalist.sid` → victim logs out (GitHub token invalidated, session not) → *next user* logs in → old cookie revalidates against their account. Timing the re-login converts a self-impact bug into cross-user escalation.
- **Replay chains:** capture the request first (GraphQL query, `POST /handle.save.php`, x-uber-token), then trigger the revocation event, then replay verbatim. Stale CSRF tokens (`authenticity_token`) replay fine when the session store isn't cleared, since CSRF tokens are session-bound.
- **Protocol-level bypass:** Shopify Ping's `DELETE /api/v1/logout` fails silently because it omits the required Logout Token Hint — the server errors and never revokes. Check whether the client's own logout request is even well-formed per the auth spec (OIDC logout token hints, back-channel logout).

## Gotchas / what NOT to do

- **Don't test only "logout then back"** — the interesting signal is *what still works* after the revocation event: an authenticated state-changing POST, a data-bearing GET, an OAuth userinfo call. "Still logged in" alone reads as low severity.
- **Don't confuse client-side token deletion with server-side revocation.** Shopify POS only proved revocation failure by replaying the token server-side after the app's local store was wiped — the replay is the proof.
- **Don't stop at the first revocation event.** Test the full matrix: logout, password change (web *and* CLI/admin paths — Airflow showed they differ), provider disconnect, app removal from the provider side, history clearing. HackerOne's 2469706 only manifested after the victim cleared history and re-logged in.
- **Don't ignore third-party widgets and peripheral state** (Intercom, login-form autofill re-population) — these are separate session lifetimes from the app's own cookie.
- **Don't forget the "next user" scenario** — a cookie that appears dead immediately after logout may resurrect when another session is created (250688). Wait and re-test with a second account.
- **Don't assume API tokens share session lifetime.** GraphQL query tokens (417382) and app bearer tokens (293363, 1108662) are frequently on independent revocation paths from the web session.
- **Self-impact framing matters:** "my own session survived logout" is often triaged as informational. Always demonstrate attacker value — data returned (PII, payment info), privileged actions performed, or cross-user effects.

## Real-world impact examples

- **Full store takeover (Shopify POS, id=1108662):** a logged-out user's `Xauth` token remained valid server-side, enabling session hijack and full control of the store.
- **Payment + trip data post-logout (Uber, id=293363):** replayed `x-uber-token: 5ead9f1ab28780d48f8caa9d41a22973` returned Dispatch View with profile modification, trip history, dispatch scheduling/cancellation, and payment info access.
- **2FA bypass via cookie persistence (HackerOne, id=2469706):** stolen cookies survived history clearing and re-login, letting the attacker log into the victim's account repeatedly with no 2FA challenge.
- **Sensitive bounty + payout data after session revocation (HackerOne, id=417382):** replayed `User_bounty_settings_page` GraphQL query returned awarded amounts, report titles, payout preferences, and payment method.
- **Permanent backdoor (Shopify, id=1547684):** attacker retained access and re-linkability through both a provider disconnect and a subsequent password change.
- **PII exposure post-logout (Shopify Ping, id=1172205):** `GET /oauth/userinfo` still returned email, names, locale, and `tfa_enabled`.
- **Cross-user escalation (GSA, id=250688):** an old `federalist.sid` became valid again against the next user to log in.
- **Privacy leak via widget (Legal Robot, id=249798):** full Intercom chat history readable and writable from the login page after logout.
- **Phone-number digit disclosure (VK.com, id=390126):** partial phone digits recoverable from a session with known `remixsid` + user id, enabling SMS flooding.