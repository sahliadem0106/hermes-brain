---
name: hunter-l3-validation-bypass
description: "Use when hunting Validation Bypass on a target. Loads the L3 technique sheet: Validation bypass is the class of bugs where server-side input validation — required fields, paired-field checks, blacklist/suffix filters, extension checks — can be circumvented without triggering the intended rejection."
domain: cybersecurity
subdomain: web
tags:
- web
- validation-bypass
- hunting
- l3
version: '1.0'
---

# Validation Bypass — Technique Sheet

## Overview

Validation bypass is the class of bugs where server-side input validation — required fields, paired-field checks, blacklist/suffix filters, extension checks — can be circumvented without triggering the intended rejection. The three verified records here show two distinct flavors: client-side-only or asymmetric form validation on profile updates, and null-byte truncation at the database adapter layer defeating Ruby-side string checks. Individually these are usually low severity (they pay modestly on programs like Legal Robot and Ruby on Rails), but the Rails null-byte pattern is the important one to internalize — the same adapter-level truncation generalizes to blacklist and extension checks in file upload and routing contexts, where impact escalates quickly.

## Distinct sub-patterns

### 1. Paired-field validation bypass via both-fields-blank submission

- **Endpoint shape / parameter:** Profile update form. `POST` to the profile edit endpoint on `app.legalrobot.com`, parameters `first_name` and `last_name` (the same form also carried `job_title`).
- **Payload that actually fired (verbatim):** `first_name=&last_name=`
- **Root-cause pattern:** The validation logic only enforced the first/last-name requirement when *one* of the two fields was filled — i.e., it checked the pairing ("if you supply a first name you must supply a last name," or vice versa) but had no check for the both-blank state. Submitting both fields empty fell through every branch and was accepted. This is a classic asymmetric/conditional validation gap: the validator handles the "partial data" case and the "full data" case, but not the "empty data" case.
- **Impact that was proven:** The attacker updated their own profile with both first and last name left blank, fully bypassing the paired-field validation. Note the report explicitly scoped impact to the attacker's own account — no cross-user access — which is why this stayed a low/accepted-severity validation finding rather than escalating.
- **Exemplar report IDs:** 255474, 164687 (both by ajaysenr, Legal Robot; 164687 is the same profile form's validation being bypassed across `first_name`, `last_name`, and `job_title` fields, though its specific payload is not stated in the record).

### 2. Null-byte truncation at the DB adapter defeating application-side string checks

- **Endpoint shape / parameter:** Not a single HTTP endpoint — the vulnerable surface is Ruby code using the ActiveRecord query builder, with the validated parameter being a user-controlled string, e.g. a `title` field. Concretely: anywhere a Ruby-side check (blacklist match, suffix/extension comparison, keyword filter) runs on a string that is *also* interpolated into a SQL query via ActiveRecord.
- **Payload that actually fired (verbatim):** `test title\0suffix` — and as demonstrated in the report, a value like `test\0dummy` equals `test` in the generated SQL.
- **Root-cause pattern:** The PostgreSQL adapter truncates the string at the null byte (`\0`) when interpolating it into SQL, silently dropping everything after `\0`. So the application validates the *full* Ruby string — `test title\0suffix` — against its blacklist/suffix check, the check fails to match (because the "bad" part is after the null byte and the validator compares against the disallowed pattern), but the value that actually reaches PostgreSQL is just `test`. The string the validator saw and the string the database stored/acted on are different. The validation is performed on one representation of the input; the database acts on another.
- **Impact that was proven:** Demonstrated that `test\0dummy` is treated as `test` in generated SQL, meaning any suffix check, extension check, or blacklist validation performed on the Ruby side can be bypassed for a suffix appended after a null byte. In the recorded report the impact is stated as validation bypass capability (not a chained RCE or file overwrite), but the primitive is exactly the one that historically escalates: e.g. an `allowed_extensions` or filename-blacklist check where `file.php\0.jpg`-style input validates as `.jpg` on the Ruby side.
- **Exemplar report IDs:** 394253 (ajaysenr, Ruby on Rails program).

## Bypass / chain notes

- No multi-step chains appear in these records; all three are single-request (or single-code-path) bypasses. That is itself a signal: the winning technique in each was exploiting a **representation mismatch or missing validation state**, not a filter evasion requiring encoding gymnastics.
- For sub-pattern 2, the implicit "bypass recipe" is: take any Ruby-side string check (blacklist, ends_with?/suffix, extension allowlist), append the payload that must evade the check *after* a literal `\0` byte, and prepend benign content that passes. The validator sees the benign-plus-suffix string; PostgreSQL sees only the benign prefix. Test both `value\0suffix` and `value%00suffix` (URL-encoded form) at the HTTP layer.
- For sub-pattern 1, the bypass is state-space reasoning rather than payload crafting: enumerate the four states of a paired-field validator (both filled, A only, B only, both blank) and submit each. Validators frequently only guard the "A only" and "B only" states.

## Gotchas / what NOT to do

- **Do not claim cross-user impact you didn't demonstrate.** Report 255474 explicitly notes "no other user's data accessed" — the finding was validated on the reporter's own profile only. Overclaiming account-wide impact on a both-blank-names bug is a fast way to lose credibility with triage; scope it honestly as "can set own profile to empty required fields."
- **Don't assume form-level (client-side) validation is the bug.** Confirm the server accepts the invalid state. In 164687/255474 the accepted request proves the server-side validation gap; if the server rejects and only the client complained, it's not a finding.
- **For the null-byte pattern, don't stop at theoretical equivalence.** 394253 proved the equivalence (`test\0dummy` == `test` in generated SQL) — that's the bar. A report that only says "null bytes might bypass something" without showing a specific validator actually evaded will likely be closed as informative.
- **Null bytes can be rejected upstream.** Many web servers, frameworks, and WAFs reject or strip `\0` before it reaches application code. Verify the byte survives to the ActiveRecord layer (e.g., by observing the truncation effect in stored output) before assuming the primitive works.
- **Severity expectations:** both-blank profile fields are low severity on their own. They become reportable primarily when the blanked field is genuinely security- or integrity-relevant, or when the program's policy treats required-field enforcement as in-scope logic. Read the program policy before submitting.

## Real-world impact examples (from records)

- **Legal Robot (255474):** Attacker successfully saved their own profile with `first_name` and `last_name` both empty — required-name validation completely bypassed via `first_name=&last_name=`.
- **Legal Robot (164687):** Form validation for `first_name`, `last_name`, and `job_title` on the edit-profile form was bypassed while editing a user profile (specific payload not stated in the record).
- **Ruby on Rails (394253):** `test title\0suffix` submitted through ActiveRecord resulted in PostgreSQL storing/acting on `test title` — proving a Ruby-side suffix/extension/blacklist check can be evaded by hiding the disallowed suffix after a null byte, since the PG adapter truncates at `\0` during SQL interpolation.