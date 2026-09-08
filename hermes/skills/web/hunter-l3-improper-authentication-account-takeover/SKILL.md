---
name: hunter-l3-improper-authentication-account-takeover
description: "Use when hunting Improper Authentication / Account Takeover on a target. Loads the L3 technique sheet: This class covers authentication endpoints that trust client-supplied identity data without proper server-side binding or validation: unvalidated third-party OAuth/social tokens, password-reset tokens"
domain: cybersecurity
subdomain: web
tags:
- web
- improper-authentication-account-takeover
- hunting
- l3
version: '1.0'
---

# Improper Authentication / Account Takeover — Technique Sheet

## Overview

This class covers authentication endpoints that trust client-supplied identity data without proper server-side binding or validation: unvalidated third-party OAuth/social tokens, password-reset tokens not bound to the account identity, and insufficient rate limiting on password-change gate checks. It pays well because each sub-pattern directly yields full account takeover of arbitrary users — the highest-severity finding class on most programs. Detection requires testing identity-binding invariants: does the server actually verify that the token, reset link, or session belongs to the account being acted on?

## Distinct sub-patterns

### 1. Unvalidated social login token (cross-app token acceptance)

- Endpoint shape / parameter: `POST /api/auth/facebook` with body param `fb_token` (JSON). Template: `{"fb_token":"<access_token>"}`.
- Payload that actually fired: `{"fb_token":"[FACEBOOK_TOKEN_REDACTED]"}` — the token was a valid Facebook access token issued to a *different* application (e.g. lyst's app), not the target's app.
- Root-cause pattern: The Facebook login API accepted any application's Facebook access token without validating that it was issued to the site's own Facebook app ID. No `app_id`/audience check on the token, and no server-side verification of the token's signature/scope against the expected client.
- Impact proven: Logging in to *other users'* Reverb accounts using a foreign app's token — full account takeover of all accounts (any account reachable by presenting any valid third-party Facebook token).
- Exemplar report IDs: 314808 (Reverb.com, [ajaysenr]).

### 2. Password-reset token not bound to the requesting email (email swap)

- Endpoint shape / parameter: `POST /forgetPassword.php` with param `email`. Template: `email=<address>`. The attack happens on the *second* request — the one that applies the reset using a valid token.
- Payload that actually fired: `email=victim@example.com` — the reset application request was intercepted and the attacker's email replaced with the victim's, while keeping the valid token obtained for the attacker's own email. (Reset request payload itself is just the attacker's own address.)
- Root-cause pattern: The reset token was not cryptographically bound to the email/account it was issued for. The server accepted a valid-but-mismatched (token, email) pair, so a token minted for account A could reset account B.
- Impact proven: Attacker changed the victim's password and gained full access to the victim's Starbucks account *and the victim's card*, with zero victim interaction.
- Exemplar report IDs: 315879 (Starbucks, [ajaysenr]).

### 3. Missing rate limit on old-password verification during password change

- Endpoint shape / parameter: The password-change request in Settings (Settings and Privacy → Accounts → Email → Password), with the `old password` field as the gated parameter. The exploit targets the old-password check on the intercepted change-password request.
- Payload that actually fired: password brute-force list on the old-password field (a wordlist looped against the old-password parameter of the change request).
- Root-cause pattern: The old-password check acts as a second-factor gate for session hijackers, but the endpoint imposes no rate limiting, so the gate can be brute-forced. The check verifies knowledge rather than identity, and knowledge checks without attempt limits are not a control.
- Impact proven: With a hijacked logged-in session, the attacker changed the victim's password by bypassing the old-password prompt — full account takeover, defeating the last obstacle the victim could have used to lock the attacker out.
- Exemplar report IDs: 970157 (X / xAI, [ajaysenr]).

## Bypass / chain notes

- Email swap chain (315879): (1) Request a password reset for the attacker's *own* email to legitimately receive a valid reset token; (2) intercept the reset-application request carrying that token; (3) swap the `email` parameter from the attacker's address to the victim's address; (4) submit — the valid token is honored for the victim's account. This chain sidesteps any "did you get an unexpected reset email?" detection, because the victim never receives one.
- Hijacked-session chain (970157): (1) obtain a hijacked logged-in session; (2) navigate to Settings and Privacy → Accounts → Email → Password; (3) enter a random new password and intercept the request; (4) brute-force the old-password field until the check passes. Chain matters: the rate-limit bug is only exploitable *with* an authenticated session, and its impact is converting a hijacked session (which the user could recover) into permanent takeover via password + email change.
- Social-token chain (314808): no multi-step chain needed — a single request with a foreign app's token authenticates as the target user. The key "bypass" is sourcing a token from any third-party Facebook app (any app the hunter can OAuth into).

## Gotchas / what NOT to do

- Never perform the email-swap reset (315879 pattern) against a *real* victim account on a live program — use your own two test accounts as attacker and victim. The technique is identical with self-owned accounts and produces the same evidence.
- For the old-password brute force (970157), only demonstrate against an account you control, and use a tiny list to prove the absence of rate limiting — don't run a full wordlist; the finding is the missing limit, not the cracked password.
- Don't test social token acceptance with your *own* valid token for the target's app (that's just normal login). You need a token from a *different* app; verify the response actually returns the target-user session, not an error or a new account — some implementations create a fresh account for unknown tokens rather than matching an existing one, which is a lower-severity (or non-) issue.
- Don't report "weak token" guesses from the reset request itself; the 315879 bug is about *binding*, not token entropy — frame it as token-not-bound-to-identity with the swap demonstrated.
- Randomized/obfuscated tokens are red herrings here: all three bugs survive strong token generation, because the flaws are in identity binding (sub-patterns 1-2) and attempt limiting (sub-pattern 3).

## Real-world impact examples

- Reverb.com (314808): any third-party Facebook access token (e.g. from lyst) logged the attacker into arbitrary Reverb users' accounts — universal account takeover across the platform.
- Starbucks (315879): attacker reset a victim's password and gained full access to the Starbucks account and the victim's stored card — financial account access, no victim action required.
- X / xAI (970157): a session hijacker brute-forced the old-password gate and permanently changed the victim's password — converting recoverable session theft into irreversible account takeover.