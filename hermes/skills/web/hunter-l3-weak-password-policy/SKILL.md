---
name: hunter-l3-weak-password-policy
description: "Use when hunting Weak Password Policy on a target. Loads the L3 technique sheet: Weak Password Policy bugs are validation gaps in registration, password-change, and password-reset flows that let a user (or attacker) set trivially guessable or policy-violating credentials: password"
domain: cybersecurity
subdomain: web
tags:
- web
- weak-password-policy
- hunting
- l3
version: '1.0'
---

# Weak Password Policy — Technique Sheet

## Overview
Weak Password Policy bugs are validation gaps in registration, password-change, and password-reset flows that let a user (or attacker) set trivially guessable or policy-violating credentials: password == username, `123456`, single characters, whitespace-only strings, or reuse of the previous password. Individually they are usually Low/Medium severity; they pay when paired with a brute-force/credential-stuffing chain, when the weak credential unlocks a privileged/root account, or when the vendor's stated security policy (NIST 800-63B, OWASP ASVS) is violated. Almost every record here was found on the same flows: `POST /register`, `POST /accounts/register/`, `POST /accounts/password/` (change), `POST /accounts/password/reset/`, and settings change-password endpoints.

## Distinct sub-patterns

### 1. Password identical to username (or email)
- Endpoint shape: registration or profile update; no dedicated endpoint shape — any flow that sets credentials. Exemplar payload: `username=pentest123@&password=pentest123@` (Eternal, 115036). Also WakaTime signup accepted password equal to the email (246042).
- Root cause: no check comparing password against username/email field; no credential blacklist.
- Impact: accounts trivially guessable — an attacker who knows the identifier knows the password.
- Exemplars: 115036 (Eternal), 246042 (WakaTime).

### 2. No complexity enforcement at registration — pure-digit/top-list passwords
- Endpoint shape: `POST /accounts/register/` (Weblate 223374, payload `123456`), `signup` (Infogram 280504, payload `123123`; WakaTime `POST /signup` with `123456`, payload not stated).
- Root cause: registration validates only length (or nothing); no digit/letter/symbol mixture requirement and no common-password blacklist (top-N list would catch both payloads).
- Impact: account created with a password from the most-common-passwords list; guessing is one spray away.
- Exemplars: 223374, 280504, 246042.

### 3. No complexity enforcement at password change / master password
- Endpoint shape: `POST /accounts/password/` (Weblate), ownCloud password change (276123, payload `q`), Khan Academy password change (255708, payload `abcdefgh`), Tor Browser `about:preferences#security` master password (280282, payload `123` and a single space).
- Root cause: the change-password form applies weaker validation than the policy claims. Two specific flavors in the records:
  - Single-character acceptance: ownCloud accepted the one-character password `q` (276123).
  - Rule partially enforced: Khan Academy stated a "mixture of numbers and symbols" rule but only the length rule was actually enforced, so all-alphabetic `abcdefgh` passed (255708).
- Impact: single-char or brute-forceable passwords set on existing accounts; for Tor, the master password (which protects saved passwords/certs) could be `123` or one space.
- Exemplars: 276123, 255708, 280282.

### 4. Whitespace padding to defeat minimum-length checks
- Endpoint shape: `POST /accounts/password/` (Weblate change-password).
- Payloads (verbatim, whitespace-padded):
  - Six spaces: `      ` (223618) — passed because length check counts characters.
  - Six spaces + one letter: `      a` (223851) — effective one-character password.
- Root cause: validator checks character count and only added an all-whitespace rejection *after* the first report; no trimming/normalization, no non-whitespace character requirement. 223851 is explicitly chained to bypass the fix shipped for 223618.
- Impact: passwords with a single effective character, indistinguishable to the length check from strong ones.
- Exemplars: 223618, 223851.

### 5. No minimum length enforcement at all
- Endpoint shape: `POST /register` (Paragon Initiative Enterprises, 148903).
- Payload: `test` (4 chars, accepted at account creation).
- Root cause: initial account creation accepted weak passwords with no validation.
- Impact: root account created with password `test` — severity boosted because the weak credential landed on a privileged account.
- Exemplar: 148903.

### 6. No password-history check — reuse via change-password flow
- Endpoint shape: change-password on the account (Weblate `POST /accounts/password/` style flow on demo.weblate.org, 229577; WakaTime `POST /settings/change-password`, 255034; Legal Robot password change, 262140).
- Root cause: no storage/comparison of previous password hashes, so the new password may equal the old one (229577, 255034) or be *near-identical* to the current one (262140 — "similar to current" not restricted).
- Impact: an attacker with temporary access (or a victim reverting) can cycle credentials back to a known/leaked value; near-identical reuse (262140) means a compromised account stays accessible to the original attacker after the user "changes" their password.
- Exemplars: 229577, 255034, 262140.

### 7. No password-history check — reuse via reset flow
- Endpoint shape: `POST /accounts/password/reset/` (Weblate, 223362; AWS VDP `POST` password reset, 3514122 — payload not stated).
- Root cause: reset flow doesn't compare the new password against the last 3–5 historical passwords. The reset link — the one flow an attacker is most likely to steer a victim through — is the weakest credential-set point.
- Impact: user sets the same old (possibly leaked) password again. The AWS record (3514122) was accepted as a security-policy violation of NIST 800-63B and OWASP even without demonstrated compromise.
- Exemplars: 223362, 3514122.

### 8. Weak signup policy with proven account takeover
- Endpoint shape: signup / password change (Stripo Inc, 985367 — payload not stated).
- Root cause: signup password policy permits weak passwords.
- Impact: escalated beyond "policy gap" to actual **account takeover** of affected accounts via brute-forcing weak credentials. This is the severity ceiling for the class: demonstrate compromise, not just acceptance.
- Exemplar: 985367.

## Bypass / chain notes
- Fix-bypass chain (best-documented): report 223618 (six-space password) → vendor patched by rejecting all-whitespace passwords → report 223851 resubmits `      a` (spaces + one letter) to slip past the new check. Lesson: when a validator blacklists one degenerate form, test the minimal perturbation around it.
- Rule-vs-enforcement gap: Khan Academy's stated "mixture of numbers and symbols" rule was not enforced client- or server-side — always test the *documented* policy, not just obvious weak passwords (255708).
- Compromise-persistence chain: Legal Robot (262140) — an attacker who knew the old password can keep access after a "rotation" by setting a near-identical new password. Pairs with any temporary-access scenario.
- No records in this set required filter bypasses beyond whitespace padding; the class is almost entirely about missing server-side validation, so client-side-only enforcement (if present) is bypassable with a direct POST.

## Gotchas / what NOT to do
- Do not test only `123456`. The records show distinct validator gaps: whitespace padding, single characters, whitespace+letter mixes, username-identical, near-identical reuse. Rotate through all of them.
- Don't ignore the change-password and reset flows — half the records (223362, 229577, 255034, 262140, 276123, 223851) fired there, not at signup. Registration and change flows often have different validators.
- Don't stop at "the form accepted it" — capture the actual response/state proving the password was set (e.g., re-login with the weak password), and note when no compromise was shown (246042 was explicitly logged as "no account compromise shown").
- A single-character password like `q` (276123) is a stronger finding than `123456` because it proves zero enforcement rather than a weak blacklist — lead with the most degenerate payload you can set.
- Reusing your own old password (229577) may be dismissed as low; frame it via brute-force resistance / leaked-credential reuse, or chain it to a takeover demonstration (985367) for severity.
- Whitespace payloads are fragile to copy-paste — leading/trailing spaces are often stripped by editors; construct them programmatically and verify the exact bytes were submitted.

## Real-world impact examples
- Root account with password `test` created at signup (Paragon Initiative Enterprises, 148903) — weak policy directly yielding a privileged credential.
- Account takeover of affected Stripo accounts achieved purely through weak signup password policy enabling brute force (985367).
- Tor Browser master password set to `123` or a single space (280282) — the credential protecting the browser's password store/certificates.
- Effective one-character password (`      a`) on Weblate change-password (223851); bare six-space password accepted before the patch (223618).
- Single-char password `q` accepted by ownCloud's change-password flow (276123).
- Password reset flow accepting reuse of the current/recent password on AWS VDP (3514122) — accepted and addressed as a NIST 800-63B / OWASP policy violation without needing exploitability proof.
- Passwords identical to username (`pentest123@`/`pentest123@`, 115036) and to email (246042) — guessable in one attempt for anyone who knows the identifier.