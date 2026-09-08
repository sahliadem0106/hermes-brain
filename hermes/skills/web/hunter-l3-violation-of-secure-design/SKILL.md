---
name: hunter-l3-violation-of-secure-design
description: "Use when hunting Violation of Secure Design on a target. Loads the L3 technique sheet: This class covers bugs where no injection, no overflow, and no logic trick is required — the application simply *lacks a security control that should exist by design*: a missing verification step, a m"
domain: cybersecurity
subdomain: web
tags:
- web
- violation-of-secure-design
- hunting
- l3
version: '1.0'
---

# Violation of Secure Design — Technique Sheet

## Overview
This class covers bugs where no injection, no overflow, and no logic trick is required — the application simply *lacks a security control that should exist by design*: a missing verification step, a missing notification, a missing network restriction. These are found by walking security-sensitive flows end-to-end (account changes, payout settings, infrastructure perimeter) and asking "what should happen here that doesn't?" They pay because they are often architecturally embarrassing to fix, but individual rewards are usually low-to-moderate unless tied to financial flows.

## Distinct sub-patterns

### 1. Unverified addition of a payout/financial destination (no email verification, no notification to the added address)
- **Endpoint shape:** `Settings > Payment Methods > Add payment method (PayPal)` — the `email` field of the newly added PayPal payout destination.
- **Payload that actually fired:** none required (payload not stated — the attack is purely a missing-control flow).
- **Root-cause pattern:** The application accepts an arbitrary email as a PayPal payout method and does **both** of the following incorrectly: (a) it never sends a verification challenge to the added address, and (b) it never sends any notification to that address that it was added. The address owner therefore has zero opportunity to detect or object.
- **Impact proven:** An attacker can silently point a victim's (or any user's) payout stream at an attacker-controlled PayPal address. In a bounty context, this means bounty funds could be deposited to an unapproved address — a direct financial-impact finding, not a theoretical one.
- **Exemplar:** HackerOne #307424 (ajaysenr).
- **How to hunt it:** Add a payment method / payout destination using an email you control, then check *both* mailboxes: does the added address receive a verification link? A "you were added" notice? If neither fires, that's the bug. Repeat the same probe against other payout providers (Stripe, crypto addresses, bank forms) on the same platform — the missing-control pattern is often systemic across payment rails.

### 2. Origin server directly reachable, bypassing CDN/WAF (no origin-lockdown)
- **Endpoint shape:** Direct HTTP to origin IPs discovered outside the CDN range — e.g. `http://54.69.218.2/login` (AWS IP serving an app normally fronted by Cloudflare).
- **Payload that actually fired:** none (payload not stated); the "payload" is a direct connection to `54.69.218.2` hitting a login page.
- **Root-cause pattern:** Origin servers accept traffic from the entire internet rather than restricting ingress to the CDN's IP ranges (no firewall/security-group allowlist of Cloudflare IPs, no mTLS/Cloudflare-AUTH between edge and origin). DNS-history and range-scanning reveal origins behind the CDN, and they answer requests directly.
- **Impact proven:** Full bypass of Cloudflare protections — WAF rules, rate limiting, bot mitigation, and IP-level bans all become irrelevant because an attacker can talk straight to the origin. An insecure login page was served directly at the origin IP.
- **Exemplar:** Coalition, Inc. #315838 (ajaysenr).
- **How to hunt it:** Collect historical DNS (SecurityTrails, DNSdumpster, censys/Shodan reverse-DNS and cert transparency for the origin), pull ASN ranges of the hosting provider, and port-scan for the application. Success signal: the origin serves the same app (especially a login/auth path) without the CDN's headers or challenge pages.

### 3. Security-relevant profile change with no account-change notification (inconsistent notification coverage)
- **Endpoint shape:** `settings/profile/edit` — the `country` field of the profile edit form.
- **Payload that actually fired:** none (payload not stated — simply submitting a Country change).
- **Root-cause pattern:** Other profile fields trigger a transactional email ("Your profile was recently changed") to the account owner; the Country field was omitted from that notification list. The notification control exists but is inconsistently applied — a classic secure-design gap where the control's coverage, not its existence, is the defect.
- **Impact proven:** An attacker who has some level of access to the account (e.g. a hijacked session) can change Country without generating the alert email the victim would otherwise receive — removing the victim's detection signal during an account takeover, and enabling attacker-favored tax/jurisdiction settings to be flipped silently.
- **Exemplar:** HackerOne #961841 (ajaysenr).
- **How to hunt it:** Enumerate every editable field on settings pages (profile, email, password, 2FA, language, country, timezone, notification prefs). Change each one individually on a test account and diff which changes produce an alert email. Any field that changes security or payout posture without triggering the standard "your account was changed" email is a finding — severity climbs if the field is one an attacker would change during an ATO.

## Bypass / chain notes
- **Silence compounds:** sub-patterns 1 and 3 share a root property — the *absence of a notification* is itself the vulnerability. These pair naturally with an account takeover chain: ATO → silently change payout email (no verification to added address) → silently change country/locale (no alert email) → victim's recovery and detection paths are both degraded.
- **CDN bypass chains:** a directly reachable origin (sub-pattern 2) is typically used as the delivery step for exploits the WAF would otherwise block (SQLi payloads, SSRF gadget abuse, auth bypass with tampered headers). On its own it may be accepted-info; chain it with a demonstrated WAF-defeating exploit or expose an insecure auth page (as in #315838) to prove impact.

## Gotchas / what NOT to do
- **Never add a payment method to someone else's account using their real payout flow, and never attempt to actually divert funds.** Demonstrate with your own test accounts and clearly attacker-controlled addresses; the impact argument ("funds could be deposited to an unapproved address") is made on paper, not executed.
- **Origin scanning: stay in scope.** Only test IPs/assets the program's scope covers (in-scope wildcard domains, their ASN ranges per program rules). Directly hitting origin IPs outside scope is out-of-bounds testing even if the origin is "the same site."
- **Missing-notification bugs are frequently duped or triaged as informational.** Before reporting, change *every other* field on the same form to prove the inconsistency ("fields X, Y, Z trigger the email; country does not") — the differential is what elevates it from "feature request" to a secure-design violation.
- **Don't assume the added-address silence is the only gap — check for verification on *your own* changes too.** The strongest form of sub-pattern 1 is "no verification AND no notification," not just one of the two.

## Real-world impact examples
- **#307424 (HackerOne):** An arbitrary PayPal payout email could be added with zero verification of, and zero notification to, that address — meaning bounty funds could be silently redirected to an unapproved PayPal account.
- **#315838 (Coalition, Inc.):** Origin at 54.69.218.2 served `http://54.69.218.2/login` directly — an insecure login page reachable without any of the Cloudflare-layer protections the company relied on.
- **#961841 (HackerOne):** A Country change on settings/profile/edit produced no "Your profile was recently changed" email while every other profile-field change did — removing the account owner's only detection signal for that change.