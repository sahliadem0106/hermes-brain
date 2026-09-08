---
name: hunter-l3-improper-restriction-of-authentication-attempts
description: "Use when hunting Improper Restriction of Authentication Attempts on a target. Loads the L3 technique sheet: This class covers any endpoint that accepts a secret (password, credential pair) but fails to limit how many guesses an attacker can make."
domain: cybersecurity
subdomain: web
tags:
- web
- improper-restriction-of-authentication-attempts
- hunting
- l3
version: '1.0'
---

# Improper Restriction of Authentication Attempts — Technique Sheet

## Overview
This class covers any endpoint that accepts a secret (password, credential pair) but fails to limit how many guesses an attacker can make. It pays when you can demonstrate unlimited attempts against a live authentication or authorization gate — no lockout, no rate limit, no throttling — turning a weak-credential problem into full account takeover. It is one of the simplest bug classes to test and one of the most consistently accepted, because the impact (ATO) is direct and provable.

## Distinct sub-patterns

### Sub-pattern 1: Unthrottled login endpoint (brute-force credential stuffing)
- Endpoint shape: `POST /signin` (classic session login form; here on hotornot.com, Bumble's properties use this shape for credential login).
  - Template: `POST https://<domain>/signin` with body parameter `credentials` (username + password pair).
- Payload that fired: payload not stated — the demonstration was Burp Intruder sending unlimited brute-force login requests against the endpoint.
- Root-cause pattern: the login endpoint has no rate limiting, no attempt throttling, and no account lockout. Every request is processed regardless of volume, so an attacker can iterate an entire wordlist against a single account.
- Impact that was proven: unlimited brute-force requests accepted with no lockout, enabling account takeover and privacy violation (access to the victim's dating account data).
- Exemplar report: id=744692 [ajaysenr] (Bumble).

### Sub-pattern 2: Unthrottled "current password" field on password change
- Endpoint shape: the password-change flow — Profile > Password page, where changing your password requires re-entering the current password.
  - Template: the authenticated "change password" request whose body carries a `current password` parameter alongside the new password.
- Payload that fired: payload not stated — the tester used a payload list of 100+ candidate passwords against the current-password field.
- Root-cause pattern: the current-password verification step is not rate limited. Even though the attacker is already logged in (their own session), the field that gates the change is a secret check with unlimited guesses — so guessing someone's current password unlocks the ability to set a new one.
- Impact that was proven: successfully brute-forced an account's current password from a 100+ password list and could then change the password — full account takeover.
- Exemplar report: id=827484 [ajaysenr] (Acronis).
- Why this is valuable: this sub-pattern is often overlooked because the endpoint is authenticated. But if an attacker obtains a victim's session (cookie theft, shared machine, XSS elsewhere), an unlimited-guess current-password field converts a low-value foothold into permanent ATO.

### Sub-pattern 3: Exposed network authentication service with no brute-force protection
- Endpoint shape: `SSH :22` on a hostname reachable from the internet.
  - Template: `<vendor-domain>:22` — here `store.greenhouse.io:22`, a third-party vendor's host.
- Payload that fired: payload not stated — the finding is the exposed service itself, susceptible to brute force.
- Root-cause pattern: an open SSH port on an internet-reachable third-party host with no brute-force protection (no fail2ban / lockout / key-only auth enforced).
- Impact that was proven: exposed SSH susceptible to brute force. Note: resolved as informative because the host belonged to a third-party vendor outside Greenhouse's direct control.
- Exemplar report: id=897556 [ajaysenr] (Greenhouse.io).
- Lesson: the technique is valid, but triage depends on asset ownership — for third-party/vendor-hosted infrastructure, expect reduced severity or informative unless you can show the vendor is in scope.

## Bypass / chain notes
- No multi-step chains appear in these records (all three stand alone).
- Practical notes consistent with the records:
  - The Bumble and Acronis findings both needed only a single tool (Burp Intruder / a password list) — no bypass was required because no control existed at all.
  - The "current password" sub-pattern (Acronis) effectively chains session-level access + unlimited guessing into ATO; treat any authenticated secret-verification field (current password, 2FA backup code, security answer) as a candidate for the same test.

## Gotchas / what NOT to do
- Do not brute force accounts you don't own against third-party/vendor assets and expect full credit — the Greenhouse SSH report was resolved as informative because the host belonged to a third-party vendor.
- Do not stop at "no rate limit observed" without demonstrating impact: both accepted reports (Bumble, Acronis) proved a concrete outcome — a password list actually run and ATO demonstrated, not just a slow-response observation.
- Scale your payload list to the demo need (Acronis used 100+ passwords) — enough to prove no lockout exists, not enough to actually lock or DoS the account.
- Distinguish the two test surfaces: unauthenticated login (`POST /signin`) vs authenticated current-password check. They look similar but the second requires an existing session and is more commonly missed by programs.

## Real-world impact examples
- Bumble (id=744692): unlimited Burp Intruder login attempts on hotornot.com/signin with no lockout — direct path to account takeover and privacy violation of victim accounts.
- Acronis (id=827484): brute-forced an account's current password with a 100+ password payload list through the unthrottled password-change flow, then changed the password — full account takeover.
- Greenhouse.io (id=897556): open, brute-forceable SSH on store.greenhouse.io — technically valid finding, but triaged informative due to third-party vendor ownership.