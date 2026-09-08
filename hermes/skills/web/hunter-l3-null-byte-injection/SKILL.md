---
name: hunter-l3-null-byte-injection
description: "Use when hunting Null Byte Injection on a target. Loads the L3 technique sheet: Null byte injection exploits a server's failure to reject or sanitize the `%00` byte (and other control characters) in user-supplied input."
domain: cybersecurity
subdomain: web
tags:
- web
- null-byte-injection
- hunting
- l3
version: '1.0'
---

# Null Byte Injection — Technique Sheet

## Overview

Null byte injection exploits a server's failure to reject or sanitize the `%00` byte (and other control characters) in user-supplied input. Historically it truncates strings at the C-library level (bypassing extension checks, path validation, or token verification), but in modern web apps it most commonly manifests as a validation-gap indicator: if `%00` survives input validation, storage, and reflection, the app's sanitization layer is broken — and that same gap often accepts more dangerous payloads (XSS, path traversal, SQLi). It pays on programs that run legacy stacks (notably .NET, Rails, PHP) where null bytes interact badly with server-side validation, and it is frequently accepted as a P4/P3 "sanitization missing" finding even when direct exploitation is limited.

## Distinct sub-patterns

### Sub-pattern 1: Null byte in an authentication/invitation token — validation bypass + reflection

- **Endpoint shape:** `GET /users/sign_in?invitation_token=<token><payload>` (Ruby on Rails sign-in flow, invitation-token verification)
- **Payload that fired (verbatim):**
  ```
  eda8fca985bc4d4ef21f269ed2a24951%00"><img src=x onerror=prompt(1) x=
  ```
  Note the structure: a **valid-format token prefix** (32 hex chars, matching the real token format), followed by `%00`, then an XSS attempt payload. The null byte is the wedge; the trailing HTML/JS probes whether reflection is escaped.
- **Root cause:** The server validated the token by string-matching against known valid tokens, but the null byte terminated comparison/truncation so the check "passed" (or failed softly) without rejecting the request outright. The injected value was then reflected into the `Back to invitation` link on the rendered login page with no null-byte rejection.
- **Impact proven:** A request with an *invalid* token containing a null byte returned **HTTP 200 with the login page and a reflected `Back to invitation` link**, instead of the expected 404/invalid-token error. Null byte injection confirmed. The link value was HTML-escaped, so the XSS attempt did **not** fire — impact stayed at "null byte accepted + reflected," not stored/reflected XSS.
- **Exemplars:** HackerOne report id=116189 (ajaysenr), program HackerOne.

### Sub-pattern 2: Null/control characters accepted into stored profile fields

- **Endpoint shape:** `POST /account/edit-profile` — payload applied to **all profile fields** (name, bio, etc.), then viewed via the profile render pages.
- **Payload that fired (verbatim):** `%00`
- **Root cause:** Profile update fields accept null/control characters with no server-side filtering. The value is persisted to the database and rendered back to the client unfiltered — a round-trip failure: input validation → storage → output encoding chain all miss the control byte.
- **Impact proven:** Control characters (e.g. `%00`) were **saved server-side and rendered client-side** in every Edit Profile field. This is a stored, persistent injection point — the null byte lives in the profile data and is emitted on every profile view.
- **Exemplars:** HackerOne report id=255125 (ajaysenr), program Legal Robot.

### Sub-pattern 3: Null byte in the URL path against a .NET application

- **Endpoint shape:** `GET /%2F%20<arbitrary text>%00` — payload embedded directly in the **URL path**, not a parameter.
- **Payload that fired (verbatim):**
  ```
  https://.../%2F%20This%20website%20is%20vulnerable%20to%20NULL%20BYTE%20INJECTION%00
  ```
  Note the encoded leading `%2F` (slash), the space-delimited text in the middle (used as a marker to identify where the payload lands in any response/error), and the terminating `%00`.
- **Root cause:** The Microsoft .NET application fails to sanitize user-supplied data containing null bytes in the URL path. .NET's URL normalization/request validation does not strip the encoded null byte before it reaches application-level processing.
- **Impact proven:** Null-byte injection confirmed on the target. Impact framed as: an attacker can exploit it to **access sensitive information that may aid further attacks** (e.g., path/request handling quirks that leak internal state or enable traversal against a mis-sanitizing handler). Demonstrated as a sanitization gap rather than a fully weaponized exploit.
- **Exemplars:** HackerOne report id=709072 (ajaysenr), program U.S. Dept Of Defense.

## Bypass / chain notes

- **Token-format prefix + `%00`** (sub-pattern 1): appending the null byte after a *well-formed* token prefix is what slips past format validation — validators that check "does it look like a token" pass the prefix, while the null byte defeats exact-match/lookup logic. Use this combined shape rather than a bare `%00` when testing token parameters.
- **Reflection probe stacking:** In id=116189, the `%00` was chained inline with an XSS probe (`"><img src=x onerror=prompt(1) x=`) in a single request. The null byte tests sanitization; the trailing payload tests output encoding in one shot. Expect the XSS leg to fail when the framework escapes — the finding then rests on the null byte acceptance itself (which is exactly what happened there).
- **Encoded null (`%00`) vs raw `\0`:** All three records used the **URL-encoded** form `%00` (or full-URL-encoding of the whole path). Always send `%00` encoded — a raw null byte in a URL is typically rejected by the HTTP stack before reaching the app.
- **Path markers for confirmation** (sub-pattern 3): placing recognizable human-readable text inside the payload (`%2F%20This website is vulnerable...%00`) lets you confirm exactly where and how the payload is reflected or mishandled when reading responses/errors.
- **No escalation chains were present in the records.** All three findings stand alone as null-byte acceptance; none chained into XSS, traversal, or auth bypass with proven higher impact. Do not overstate — in id=116189 the XSS was explicitly escaped.

## Gotchas / what NOT to do

- **Null byte acceptance is usually the finding, not the exploit.** In these records, the XSS attempt after `%00` did not execute (output was escaped). Report the sanitization gap honestly; don't claim RCE/XSS you didn't achieve.
- **Test round-trip persistence, not just reflection** (sub-pattern 2): the Legal Robot bug's strength was that `%00` was *saved and re-rendered*. A one-off reflected null byte that never persists is a weaker finding — submit `%00` to a profile field, then re-load the profile to verify storage.
- **Cover all fields, not one:** in id=255125 the payload was submitted to **all profile fields** simultaneously — parameters validated individually may share one missing filter, and breadth strengthens the report.
- **Target legacy/stack-specific apps:** the confirmed .NET case (id=709072) and the Rails case (id=116189) both ride stack-specific handling of null bytes. Modern frameworks that reject `%00` at the router will return 400 before you can test anything — recognize the dead end quickly.
- **Expected-behavior delta matters:** the HackerOne finding's core evidence was *200 + reflected link where 404 was expected*. Always articulate what the correct rejection behavior should have been.
- **Don't confuse with path truncation payloads** (`%00.jpg`, `/etc/passwd%00`) — none of the records used filename/extension truncation; those classic patterns are not supported by this data set.

## Real-world impact examples

1. **HackerOne (id=116189):** Invalid invitation token with trailing `%00` + XSS probe returned HTTP 200 and the login page with the payload reflected in the `Back to invitation` link, instead of 404 — proving the token validity check is bypassable via null byte (XSS itself was escaped, so impact = validation bypass + reflection).
2. **Legal Robot (id=255125):** `%00` submitted via `POST /account/edit-profile` was persisted server-side and rendered back to the client in every Edit Profile field — a stored, persistent acceptance of control characters with no server-side filtering.
3. **U.S. Dept of Defense (id=709072):** `%2F%20This%20website%20is%20vulnerable%20to%20NULL%20BYTE%20INJECTION%00` in the URL path of a .NET app confirmed null-byte injection; potential lever for accessing sensitive information supporting further attacks.