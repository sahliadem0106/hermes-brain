---
name: hunter-l3-input-validation
description: "Use when hunting Input Validation on a target. Loads the L3 technique sheet: Input validation bugs are failures to constrain what a field, parameter, or protocol field will accept: missing length limits, missing character-set/encoding validation, unescaped metacharacters, and "
domain: cybersecurity
subdomain: web
tags:
- web
- input-validation
- hunting
- l3
version: '1.0'
---

# Input Validation — Technique Sheet

## Overview

Input validation bugs are failures to constrain what a field, parameter, or protocol field will accept: missing length limits, missing character-set/encoding validation, unescaped metacharacters, and (at the protocol level) missing structural validation of wire fields. Individually they look like low-severity noise, but they pay when they produce a concrete demonstrable failure — accepted invalid emails, control-character injection enabling impersonation, server 500s, broken client-side JS, account/username squatting on reserved values, or memory/protocol desync in C code. They are ideal early-career and low-effort findings: single-request reproductions with a payload and a screenshot.

## Distinct sub-patterns

### 1. Null byte / control character injection into email fields
- **Endpoint shape:** `PUT /settings/email` (account email-change form)
- **Payload that fired (verbatim):** `████%00` (email address with a URL-encoded null byte `%00` appended)
- **Root cause:** The email-change handler accepted a null byte appended to the email address without validating the character set of the submitted value.
- **Impact proven:** An email address containing a null byte was accepted and set as the user's account email on the platform.
- **Exemplars:** HackerOne #3991

### 2. Meta-character injection into profile fields (impersonation / identity hiding)
- **Endpoint shape:** `POST /profile` — params `full_name`, `bio`
- **Payload that fired (verbatim):** `%0a` (records also reference `%00` in the same fields)
- **Root cause:** Name and bio fields do not filter control/meta characters such as null bytes and newline (`%0a`); server-side sanitization is absent rather than just client-side.
- **Impact proven:** Attacker could register a display name and bio containing meta characters, enabling impersonation of other users or hiding of real identity within the application.
- **Exemplars:** Legal Robot #274013

### 3. Special/invalid characters accepted in email and free-text fields
- **Endpoint shape:** `POST /signup` and account profile edit — params `email`, `name`, `job title`, `company name`
- **Payload that fired (verbatim):** `hacker~%@gmail.com` for email; special characters `$`, `%`, `~`, `!`, `{}` in name/job title/company fields
- **Root cause:** Sign-up and profile fields lack character-validation entirely — no whitelist or regex on email format or free-text fields.
- **Impact proven:** The invalid email was accepted at signup AND a verification email was actually sent to it (proving server-side acceptance, not just a form bug). Special characters persisted in profile fields.
- **Exemplars:** Legal Robot #254927

### 4. Missing length validation on email/username (RFC-limit violation)
- **Endpoint shape:** account email-add form (Gratipay); `POST /contact/?t=account` and account save (Weblate demo)
- **Payload that fired (verbatim):** a 100+ character local part: `aaaa…aaa@example.com` (a's repeated); 255+ character email addresses on Gratipay
- **Root cause:** No character-length restriction enforced on email, username, or other account fields. RFC 5321 caps the local part at 64 octets and the whole address at 320 (practically 254); none of that was enforced.
- **Impact proven:** Demonstrated adding an email exceeding the RFC maximum (255+ chars); submitted arbitrarily long strings in email/username fields without restriction or error.
- **Exemplars:** Gratipay #127995, Weblate #229796

### 5. Unescaped user input breaking client-side JavaScript
- **Endpoint shape:** `GET /?s=` (blog search parameter)
- **Payload that fired (verbatim):** `test\` (search string ending in a trailing backslash)
- **Root cause:** The trailing backslash is interpolated into the page's JavaScript (inside a JS string literal) without escaping, so it escapes the closing quote and produces a syntax error.
- **Impact proven:** Page threw a JavaScript error when searching for any string ending in `\` — a client-side DoS of the search feature. Payload is one character.
- **Exemplars:** Yelp #179732

### 6. Missing unicode validation causing server errors
- **Endpoint shape:** Weblate account save (account fields)
- **Payload:** not stated (certain unicode characters in account fields)
- **Root cause:** Server-side validation of unicode characters in account fields is missing; certain code points reach backend code that errors on them.
- **Impact proven:** Triggered a 500/server error when saving the account — a reliable, reproducible server crash from an ordinary user profile form.
- **Exemplars:** Weblate #229483

### 7. Reserved-token bypass in username validation (list-based blocklist failure)
- **Endpoint shape:** GET (visiting) `/{username}` — claiming a reserved username; the validation is in the signup/claim flow
- **Payload that fired (verbatim):** `1.0-payout` as the username
- **Root cause:** The username restriction list failed to block the reserved pattern `1.0-payout` (a value meaningful to the app's own routing/versioning), so the reserved path could be claimed.
- **Impact proven:** Reserved username claimed with a live profile at `https://gratipay.com/1.0-payout/` — attacker-controlled content on a path that collides with application-reserved space.
- **Exemplars:** Gratipay #128121

### 8. Missing structural validation of protocol fields (binary-level input validation)
- **Endpoint shape:** MQTT PINGRESP/DISCONNECT handling in `lib/mqtt.c` (`mqtt_doing`), curl's MQTT client
- **Payload that fired (verbatim):** `0xD0 0x02 0x00 0x00` — PINGRESP fixed header `0xD0` with a lying `remaining_length` of `0x02` plus two trailing bytes
- **Root cause:** The state machine never validates that control packets with no variable part (PINGRESP `0xD0`, DISCONNECT `0xE0`) have `remaining_length == 0`. A malicious broker can therefore dispatch the trailing bytes to the stale `mqtt->nextstate` handler.
- **Impact proven:** curl accepted the malformed PINGRESP and consumed the two trailing bytes as the start of the next expected message (the variable header of a PUBLISH), enabling PUBLISH payload injection, fake SUBACK/CONNACK, or protocol-state desync.
- **Chain (verbatim steps):** ["malicious broker completes CONNECT/CONNACK and SUBSCRIBE/SUBACK", "broker sends PINGRESP fixed header 0xD0 0x02 0x00 0x00 (claims remaining_length=2…"] — i.e., complete a normal handshake first, then smuggle the malformed PINGRESP so the leftover bytes are reinterpreted as the next packet.
- **Exemplars:** curl #3702718

## Bypass / chain notes

- **Null byte and percent-encoding bypass:** `%00` and `%0a` in URL-encoded form slip through validators that only check the decoded "looks like an email/name" shape at one layer. If a WAF or form blocks raw control characters, send them URL-encoded; the record payloads are all percent-encoded.
- **Character-class mixing for maximum validity-window confusion:** the Legal Robot records show `%@gmail.com`-style emails and `$%~!{}` in text fields being accepted — try a small vocabulary of special characters rather than full fuzzing; one accepted character proves the finding.
- **Protocol smuggling chain (curl MQTT):** this is the one true multi-step chain in the records: (1) complete CONNECT/CONNACK and SUBSCRIBE/SUBACK normally so the client's `nextstate` expects a PUBLISH variable header, (2) send the malformed PINGRESP `0xD0 0x02 0x00 0x00`, (3) the claimed remaining_length causes trailing bytes to be consumed as the next packet's start. The validation gap only becomes exploitable in a specific protocol state — always chain structural-validation bugs to the state where the unvalidated field gets consumed.
- **Reserved-name + content injection:** claiming a reserved path (`/1.0-payout`) is more impactful when you can populate the profile with content; combine with sub-pattern 2 (meta characters in profile fields) where the same platform allows both.

## Gotchas / what NOT to do

- **Prove server-side acceptance, not client-side pass-through.** The strongest record here (Legal Robot #254927) shows the server sent a verification email to `hacker~%@gmail.com`. "The form let me type it" is not a bug; "the server stored it / acted on it / errored" is.
- **Don't stop at accepted input with no consequence.** Records that paid had: a server error (#229483), broken JS on a core page (#179732), an actual null-byte email granted (#3991), a live squatting profile (#128121), or a memory/protocol desync (#3702718). If your long email is accepted but truncated safely, there is likely no report.
- **Demonstrate the RFC limit with a real request, not a citation.** Gratipay #127995 added an actual 255+ char email; citing RFC 5321 alone would have been rejected as theoretical.
- **Keep payloads minimal and reproducible.** `test\` is one character. `hacker~%@gmail.com` is one email. A 500 from a specific unicode char should pin the exact code point in the report.
- **For binary/protocol targets, build a malicious counterpart.** The curl MQTT bug required controlling the broker side (a malicious MQTT broker) — a plain "curl crashed" without the crafted packet sequence `0xD0 0x02 0x00 0x00` and the handshake chain wouldn't demonstrate the desync.
- **Length bugs: vary the field.** If email length is capped, try username, name, bio, contact-form fields — the Weblate records show the same missing-length root cause across multiple endpoints, filed as separate findings per endpoint.
- **Don't assume blocklists are complete.** Reserved-username lists are maintained by hand; version-like and route-like strings (`1.0-payout`, `api`, `admin`, path segments) are the classic misses.

## Real-world impact examples (from records)

- **Null byte email granted:** A HackerOne user successfully set an account email containing `%00`, demonstrating that identity-adjacent fields could carry binary control data (#3991).
- **Identity impersonation via profile metacharacters:** `%00`/`%0a` in `full_name`/`bio` on Legal Robot let an attacker craft display identities that impersonate other users or conceal their own (#274013).
- **Verification email to an invalid address:** Legal Robot's signup pipeline fully accepted `hacker~%@gmail.com` and dispatched a real verification email — end-to-end proof of absent validation in a production mail flow (#254927).
- **Reserved path squatting:** A live attacker profile at `https://gratipay.com/1.0-payout/` occupied a reserved, app-meaningful URL path (#128121).
- **RFC-limit violation:** 255+ character email address successfully added to a Gratipay account (#127995).
- **Client-side DoS:** Any Yelp blog search ending in `\` (`?s=test\`) broke the page's JavaScript (#179732).
- **Server 500 from a profile save:** Certain unicode characters in Weblate account fields crashed the save operation (#229483).
- **Protocol smuggling in a widely deployed C library:** Malformed `0xD0 0x02 0x00 0x00` PINGRESP from a malicious broker caused curl's MQTT client to desync its state machine, allowing injected PUBLISH payloads and forged SUBACK/CONNACK (#3702718).