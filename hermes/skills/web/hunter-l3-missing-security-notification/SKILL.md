---
name: hunter-l3-missing-security-notification
description: "Use when hunting Missing Security Notification on a target. Loads the L3 technique sheet: This class covers security-sensitive account actions that complete successfully but fail to trigger the notification email the platform promises (or that a user would reasonably expect)."
domain: cybersecurity
subdomain: web
tags:
- web
- missing-security-notification
- hunting
- l3
version: '1.0'
---

# Missing Security Notification — Technique Sheet

## Overview

This class covers security-sensitive account actions that complete successfully but fail to trigger the notification email the platform promises (or that a user would reasonably expect). It pays when an attacker with temporary access — or an attacker who has compromised a session/reset link — can pivot the account (payout method, password, email) while the legitimate owner receives zero signal. It is also testable without any special tooling: perform the sensitive action, watch the mailbox, and compare against the "normal path" behavior. All four records below were filed by the same reporter against HackerOne and GitLab, and all four are notification-suppression gaps on high-value account state changes.

## Distinct sub-patterns

### 1. Payout method add/change fires silently (no email, no password re-auth)

- **Endpoint shape:** HackerOne → Payout Methods page → "Add payout method" (the payout management flow, distinct from the regular payout-change flow).
- **Payload:** payload not stated (pure UI/state-flow bug; no injection payload involved).
- **Root cause:** The platform has two code paths that mutate payout settings. The "regular change flow" sends a notification email and requires password verification; the "Add Payout Method" path on the Payout Methods page does neither. The security controls are bound to one flow, not to the state mutation itself.
- **Impact proven:** An attacker (or a session hijacker) can add or swap the payout method silently — payout redirection occurs with no email to the account holder and no password check, so stolen sessions convert directly into diverted bounties/payments.
- **Exemplars:** HackerOne report 240083.

### 2. Password reset on a DISABLED account sends no notification

- **Endpoint shape:** POST password reset flow (request reset link → set new password), executed against a disabled/deactivated account. Parameter in scope: `password` (the new password set via the reset link).
- **Payload:** payload not stated.
- **Root cause:** Notification delivery is gated on account status. Disabled accounts are excluded from the email-send path even though the reset link still functions and changes their password. The alerting exists, but the recipient filter suppresses it exactly when the account is in its most sensitive state.
- **Impact proven:** The attacker reset a disabled user's password via the reset link and no notification email was sent — the intended password-change alert was defeated, and the disabled account could be silently re-taken.
- **Exemplars:** HackerOne report 279914.

### 3. Password change via RESET LINK path skips the change-notification

- **Endpoint shape:** POST /profile/password on the normal profile-change path vs. the password reset link flow (two paths, one missing control). No parameter required.
- **Payload:** payload not stated.
- **Root cause:** Same structural flaw as sub-pattern 1, on a different resource: the password-change email notification is wired into the "change password from the profile page" handler only. The "set new password via reset link" handler does not enqueue the notification. Coverage is per-code-path, not per-event.
- **Impact proven:** A password changed through the reset link produced no notification email, so an attacker who obtains/forces a reset and immediately re-sets the password leaves the owner with no detection signal — the compromised-account change goes undetected.
- **Exemplars:** HackerOne report 38343.

### 4. Email change to an already-verified linked address suppresses the "Email Changed" mail

- **Endpoint shape:** POST /profile (GitLab profile update). Parameter: `user[email]`.
- **Payload:** payload not stated; the triggering condition is the value pattern — set `user[email]` to an address that is (a) already linked to the account and (b) already verified. Any pre-verified secondary email qualifies.
- **Root cause:** The notification logic deduplicates against verification state: because the target email is already "verified" in the system, the change is treated as a non-event and the 'Email Changed' notification to the previous/primary owner email is skipped. Trust in the destination address suppresses the alert about the source address losing control.
- **Impact proven:** Switching the login email to a linked verified email sent no 'Email Changed' notification to the previous owner email — the primary owner remains unaware that login control has moved.
- **Exemplars:** GitLab report 801973.

## Bypass / chain notes

- The recurring "bypass" is path enumeration, not payload craft: for every sensitive state change, enumerate ALL flows that mutate it (profile settings page, reset-link flow, alternate add/manage page, API equivalents if exposed) and test notification behavior on each. In these records the unmonitored path was always a secondary/alternate flow (Add Payout Method page; reset-link password set; disabled-account reset; linked-email swap).
- Condition-based suppression is itself the bypass vector: (a) account status (disabled ⇒ no mail, record 279914) and (b) destination verification state (already-verified linked email ⇒ no mail, record 801973). Look for other conditional gates — muted users, unconfirmed accounts, alias emails — that drop notification recipients.
- Chain potential with account takeover: each of these is silent only in combination with some initial access (stolen session, phished reset link, insider re-activating a disabled account). No record in this set documents an explicit multi-step chain, but the payout-redirection case (240083) is the natural monetization endpoint for session hijacking.

## Gotchas / what NOT to do

- Do not test against your own primary account in a way that leaves it in a modified state (e.g., actually changing payout to attacker-controlled details). Use throwaway accounts and observe your own mailboxes.
- Do not report "no notification" for cosmetic/low-value actions (profile bio, display name). All four accepted records target authentication credentials (password), identity (login email), or money (payout method) — the impact argument rests entirely on the sensitivity of the mutated state.
- Do not assume the notification is missing just because it was delayed or spam-filtered. These reports are credible because the reporter demonstrated the same action on the normal path DID send mail while the alternate path did not — build that comparison before submitting.
- Disabled-account testing (279914): the point is that the reset link still WORKS on a disabled account while notifications are suppressed. If reset is properly blocked for disabled accounts, there is no bug.
- Do not invent payloads — this class is flow/behavioral, not injection. A report with a fake "payload" field weakens it.

## Real-world impact examples

- HackerOne 240083: payout method added/changed via the Payout Methods page with no email notification and no password verification — enabling payout redirection entirely unnoticed by the account holder.
- HackerOne 279914: a disabled user's password was changed via reset link with zero notification, defeating the platform's password-change alert for the account state where silent takeover matters most.
- HackerOne 38343: password set through a reset link produced no change notification, so a compromised account's credential rotation by an attacker is invisible to the owner.
- GitLab 801973: login email switched to an already-verified linked email with no 'Email Changed' mail to the previous owner — identity/ownership migration of the account leaves no audit trail in the owner's inbox.