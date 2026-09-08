---
name: hunter-l3-session-fixation
description: "Use when hunting Session Fixation on a target. Loads the L3 technique sheet: Session fixation and session non-rotation bugs: the application binds authenticated identity to a session identifier that the attacker knew (or set) before authentication, or keeps a session identifie"
domain: cybersecurity
subdomain: web
tags:
- web
- session-fixation
- hunting
- l3
version: '1.0'
---

# Session Fixation — Technique Sheet

## Overview

Session fixation and session non-rotation bugs: the application binds authenticated identity to a session identifier that the attacker knew (or set) before authentication, or keeps a session identifier valid after it should have died (post-login, post-logout, post-password-entry). The class pays in three moments — pre-auth (attacker plants/steals the cookie, victim authenticates it), post-auth (session not rotated on login, exported cookie replays), and post-logout (token never invalidated). Impact is consistently full account takeover as the victim, proven across 7 records spanning Slack, Shopify, Nextcloud, Acronis, Clario and smaller programs. When hunting, every "did you see the session change after you logged in?" test costs one diff of a cookie value.

## Distinct sub-patterns

### 1. Session not rotated after login (classic fixation)

- Endpoint shape / parameter: any authenticated session cookie established pre-login and reused post-login. Concretely: `GET /` on `wallet.sandbox.romit.io` (session cookie), `POST /auth/login` on Acronis, and Shopify-built apps' OAuth2 login where the client-supplied `_flow_session` cookie is assigned login status.
- Payload that actually fired (verbatim): for Shopify —
  `document.cookie='_flow_session=7b2f6c606fab4186d7be385aa66d53d9'`
  for Romit sandbox —
  `SANDBOX-XSRF-TOKEN=AAG02cId-yyza3k8uhQR7JKuB-4YOmhizkjM; romit.sandbox.session=s%3AEHm0kA9uwWYHayOwdRQXbuZWEIRIliQZ.ndejz36ofa52c9ENnApLuaLkMnTYCot3IiY1qdTvz0w;`
  Acronis and ReddAPI records: payload not stated (session cookie captured/exported and replayed after login).
- Root-cause pattern: the login flow (including OAuth2 flows) never regenerates the session ID after authentication, so a pre-set or pre-known session value remains valid for the now-authenticated user.
- Impact proven: attacker's browser, holding the pre-set cookie, is logged into the victim's account after the victim authenticates (Romit, Shopify Flow/Transporter/Launchpad); attacker imports an exported session cookie and lands in the account with no credentials (Acronis).
- Exemplars: id=135797 (Enter/Romit), id=1486341 (Acronis), id=423136 (Shopify).

### 2. Session not invalidated on logout (post-logout replay)

- Endpoint shape / parameter: authenticated page reachable with the old token after logout. Concretely `GET /account` with the `sid` cookie (Clario); on ReddAPI, replay of an exported session cookie against the main site after logout.
- Payload that actually fired: payload not stated in either record — the technique is simply replaying the old `sid` / session cookie in a fresh request after logout.
- Root-cause pattern: logout destroys server-side state (or doesn't) but never invalidates the token itself, so the session remains usable after it should be dead.
- Impact proven: session token remains valid after logout; attacker reuses it to perform arbitrary actions with the victim's privileges (Clario). On ReddAPI, non-issuance + non-invalidation combine so a fixed session can be replayed for a credentials-free login.
- Exemplars: id=737058 (Clario), id=6504 (ReddAPI).

### 3. Session not renewed on privilege/step-up (guest → authenticated on a protected room)

- Endpoint shape / parameter: Nextcloud Talk public room link, `…/call/{id}` — the guest session cookie issued before the room password is entered.
- Payload that actually fired: payload not stated (pre-auth guest cookie captured, then used post-password).
- Root-cause pattern: the guest session ID is not renewed after the room password is entered, so a stolen pre-auth cookie stays valid after authentication.
- Impact proven: an attacker who stole userB's cookie before the password was entered could read the conversation after userB logged in — session takeover of the guest on the room.
- Exemplar: id=1181962 (Nextcloud).

### 4. Non-expiring, non-single-use session-URL

- Endpoint shape / parameter: `GET /go/{id}#signup` on slack.com — the post-registration session URL (the `{id}` in the path *is* the session credential).
- Payload that actually fired: payload not stated; the reusable artifact is the signup session-URL, verbatim form: `https://slack.com/go/...` (the record confirms the exact URL stays valid indefinitely).
- Root-cause pattern: the session-URL issued after registration is not single-use and never expires.
- Impact proven: anyone with access to browser history (shared machine, history sync leak, log aggregation) can reuse the URL and disclose the user's email address.
- Exemplar: id=2582 (Slack).

## Bypass / chain notes

- XSS-planted cookie chain (Shopify, id=423136): attacker generates a session ID on the app → uses a `shopifycloud` XSS to write it into the victim's browser → forces the victim to log into the app → attacker, holding the same ID, is authenticated as the victim. This is the canonical three-step fixation chain and shows fixation value multiplies when you have any cookie-write primitive.
- Cookie theft + step-up gap (Nextcloud, id=1181962): victim opens protected talk link without entering password → attacker steals userB's cookie → userB enters the password and logs in → attacker retains access. The chain exploits the un-renewed session rather than the password itself.
- Export/replay as verification (Acronis id=1486341, ReddAPI id=6504): the demonstration method common to the post-auth records is simply exporting the cookie and replaying it — in one case after login (non-rotation), in the other after logout (non-invalidation). Treat export+replay as your baseline proof-of-impact for this class.

## Gotchas / what NOT to do

- Don't test only "login rotates the cookie" — the records show the bug frequently lives at a different boundary: logout (Clario, ReddAPI) or a mid-flow step-up like a room password (Nextcloud). Diff the cookie at every transition, not just login.
- Don't dismiss non-rotation when the session is pre-issued by the app itself (no need for attacker-supplied values): Acronis and Romit were proven with app-issued sessions captured and replayed. Fixation via planting is one variant; replay of a legitimately issued pre-auth session is another equally valid one.
- Don't ignore URL-borne session identifiers: the Slack record shows the credential can be the URL path segment, which then leaks via browser history rather than any network capture — a different detection surface than cookie testing.
- Don't skip verification on the attacker side: in the confirmed records the attacker's own browser/session was shown to be logged in (Romit) — demonstrating the victim logged in is not enough; demonstrate the attacker-side session gained privileges.
- Don't assume OAuth flows rotate sessions just because a redirect is involved — Shopify's OAuth2 login assigned login status to the client-supplied session id without rotation.

## Real-world impact examples

- Shopify (id=423136): confirmed account authentication takeover on three production Shopify-built apps (Flow, Transporter, Launchpad) via `_flow_session` fixation — attacker authenticated as the victim after the victim logged in.
- Romit sandbox (id=135797): attacker's browser logged into the victim's account after the victim authenticated using attacker-set cookies (`romit.sandbox.session`).
- Acronis (id=1486341): logged into the account without entering any credentials by importing an exported session cookie.
- Clario (id=737058): logout left `sid` valid — arbitrary actions as the victim post-logout.
- Slack (id=2582): eternal, reusable signup session-URL (`slack.com/go/...`) exposed the user's email to anyone with the victim's browser history.
- Nextcloud Talk (id=1181962): attacker read a password-protected conversation after the victim entered the password, using a pre-password cookie.
- ReddAPI (id=6504): cookie replay → credentials-free login; logout also failed to invalidate.