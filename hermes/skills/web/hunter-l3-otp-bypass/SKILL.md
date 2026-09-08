---
name: hunter-l3-otp-bypass
description: "Use when hunting OTP Bypass on a target. Loads the L3 technique sheet: OTP bypass covers flaws where a one-time password (SMS or email) fails to actually gate the action it protects: verification logic leaks the OTP itself, OTPs aren't bound to the identity/flow that req"
domain: cybersecurity
subdomain: web
tags:
- web
- otp-bypass
- hunting
- l3
version: '1.0'
---

# OTP Bypass — Technique Sheet

## Overview
OTP bypass covers flaws where a one-time password (SMS or email) fails to actually gate the action it protects: verification logic leaks the OTP itself, OTPs aren't bound to the identity/flow that requested them, verification steps are skippable entirely, or state is persisted before verification completes. These bugs pay because OTPs are deployed as the *sole* control on sensitive flows — payment, order placement, account recovery, identity binding — so a bypass typically yields direct transactional or account-takeover impact rather than a mere policy violation.

## Distinct sub-patterns

### 1. OTP echoed in the error response (self-leaking verification)
- **Endpoint shape / parameter:** OTP verification request during checkout/order placement. Parameters: `otp`, session code. (Exact endpoint not specified in records — identify the OTP-check request in the flow and replay it.)
- **Payload that actually fired:** No crafted payload — submit a random/wrong OTP value. The server's *error response* returns the session code, which is the OTP itself.
- **Root cause:** The OTP validation endpoint echoes internal session state (the session code doubles as the OTP) in the failure response. Verbatim root cause: "The OTP error message echoes the session code (which is the OTP)."
- **Impact:** Attacker reads the OTP from the error, re-submits it as a valid OTP, completes phone verification, and places the order. The final order-placement request could additionally be tampered with to place **N orders**.
- **Exemplar:** id=142221 (Eternal, ajaysenr).

### 2. OTP not bound to the identity it was issued for (cross-account OTP reuse)
- **Endpoint shape / parameter:** `POST` email verification on a customer portal (portal.test.cloud.mattermost.com). Parameters: `otp`, `email`.
- **Payload that actually fired:** The OTP emailed to the *victim's* address, submitted in the *attacker's* email-verification request (intercepted and replayed). Verbatim: "OTP sent to the victim's email entered on the attacker's email verification."
- **Root cause:** Two defects combined: (a) the OTP is not bound to the email address it was issued for, so any account can consume it; (b) the flow does not re-validate the OTP at subsequent steps.
- **Impact:** Attacker completed email verification on their own account using the victim's OTP and proceeded past the **payment step** to use the account normally — i.e., paid-tier access without paying.
- **Exemplar:** id=1443211 (Mattermost, ajaysenr).

### 3. Skippable OTP verification step (verification is optional client-side)
- **Endpoint shape / parameter:** `POST` place order on a food-delivery flow (Zomato). Parameter: `otp`.
- **Payload:** payload not stated — the bypass did not require a crafted value.
- **Root cause:** "OTP verification required when placing a restaurant order could be bypassed." The verification step is enforced only in the client flow, not server-side on the final action.
- **Impact:** Placed a restaurant order with no valid OTP at all.
- **Exemplar:** id=247158 (Eternal, ajaysenr).

### 4. State persisted before verification completes (verify-after-write)
- **Endpoint shape / parameter:** `POST /settings/auth/setup_account_recovery` (HackerOne). Parameter: `phone_number`.
- **Payload:** N/A — a plain phone-number value (the victim's number) in the recovery-setup request; no OTP needed to make the write stick.
- **Root cause:** "Account recovery phone change stores the number before OTP verification completes." The server commits the phone number on submission; OTP verification is a later, separate step that can be skipped.
- **Impact:** Attacker stored another person's phone number as the recovery number without verifying the SMS OTP. Recovery OTPs were then delivered to the victim's number — confirmed by observing a 2FA recovery attempt send the code to the victim's phone. This enables ongoing harassment/account-state pollution and positions the attacker's flow around the victim's identity.
- **Exemplar:** id=2501984 (HackerOne, ajaysenr).

## Bypass / chain notes
- **Wrong-OTP oracle (pattern 1):** The chain is: intercept the OTP verification request → submit a random/wrong OTP → parse the error response for the session code → replay the request with the correct (leaked) OTP. The "failure" response is the vulnerability; always read full error bodies, not just status codes.
- **Cross-account consumption (pattern 2):** Chain: create a victim account and an attacker account → trigger OTP send to the victim's email → in the attacker's verification request, intercept and substitute the victim's OTP → verification completes → proceed past payment. Test whether the OTP's `otp`/`email` pair is cross-checked; also test whether later steps re-validate.
- **Skip-by-navigation (pattern 4):** Chain: change recovery phone number to the victim's number → skip OTP verification by **refreshing the page or navigating back** → the number is already stored and recovery OTPs flow to the victim's number. Where a flow writes state before verification, skipping the verification screen (refresh, back, direct API call to the next step) often suffices.
- **Post-bypass tampering (pattern 1):** Once verification is satisfied, the downstream placement request was malleable — the final request could be modified to place N orders. After a bypass, always probe the *next* request for missing server-side constraints.
- **Impact confirmation technique (pattern 4):** The stored-number effect was verified by triggering a 2FA recovery attempt and observing the OTP land on the victim's number — a clean, non-destructive proof method worth reusing.

## Gotchas / what NOT to do
- Don't assume an OTP field is only brute-forceable. All four records are logic flaws — none required guessing codes. Test binding, ordering, and skip paths before brute force (and brute force often gets you rate-limited/blocked anyway).
- Don't stop at the verification response. Pattern 2's real impact (past the payment step) and pattern 1's real impact (N orders) were both downstream of the bypass itself.
- Don't ignore error message content. Pattern 1 lives entirely in an error response echoing the session code.
- Don't verify only the "happy path" ordering. Pattern 4's server commits state *before* verification — flows that look correct in the UI's order are often inverted server-side.
- Don't test these against real victims' accounts carelessly: pattern 2 and 4 involve third-party phone numbers/emails. Use accounts you control (two self-owned accounts) to demonstrate cross-account OTP reuse, as the Mattermost methodology does.
- Pattern 3's records give no payload — don't over-assume the exact bypass mechanism (client-side skip vs. direct API call); report what you can demonstrate.

## Real-world impact examples
- **Eternal (id=142221):** Random OTP submission during order placement leaked the session code (= the OTP) in the error message; attacker verified a phone number without a valid OTP, placed the order, and tampered the final request to place **N orders**.
- **Mattermost (id=1443211):** OTP sent to the victim's email completed email verification on the attacker's account; attacker **proceeded past the payment step** and used the account normally.
- **Eternal / Zomato (id=247158):** OTP verification on restaurant order placement bypassed entirely — order placed with no valid OTP.
- **HackerOne (id=2501984):** Another person's phone number stored as an account-recovery number without SMS verification; recovery OTPs confirmed delivered to the victim's number via a live 2FA recovery attempt.