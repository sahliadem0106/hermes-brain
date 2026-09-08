---
name: hunter-l3-ldap-injection
description: "Use when hunting LDAP Injection on a target. Loads the L3 technique sheet: LDAP injection happens when user-controlled input is concatenated into an LDAP search filter without escaping, letting an attacker alter the filter's logic to enumerate users, extract directory attrib"
domain: cybersecurity
subdomain: web
tags:
- web
- ldap-injection
- hunting
- l3
version: '1.0'
---

# LDAP Injection — Technique Sheet

## Overview

LDAP injection happens when user-controlled input is concatenated into an LDAP search filter without escaping, letting an attacker alter the filter's logic to enumerate users, extract directory attributes (including password hashes and keys), or break authentication flows. In bug bounties it pays in two settings: exposed identity/SSO infrastructure (ForgeRock OpenAM, Active Directory-backed web apps) where a single unauthenticated blind-injection primitive can leak session tokens, private keys, or password hashes; and ordinary web forms whose inputs are passed to LDAP lookups, where error-based proof alone can demonstrate directory compromise. The classic tell is LDAP-specific errors (e.g. 0x80005000) or status-code differences in user-existence responses.

## Distinct sub-patterns

### 1. CVE-2021-29156 — OpenAM webfinger blind LDAP injection (full data extraction)

- **Endpoint shape / parameter:** The ForgeRock OpenAM `/webfinger` (WebFinger JRD) endpoint, where the `resource`/user identity parameter value is interpolated into an LDAP filter. Concretely, a request like `GET /openam/oauth2/realms/root/realms/dc/handler?id=<candidate-value>&_schema=chrome` style webfinger lookups where the username portion of the resource URI is attacker-controlled. (Exact URL was not stated in the records; the vulnerable input is the username in the webfinger resource.)
- **Payload that actually fired:** payload not stated in the records. The class of payload is a webfinger username starting with a candidate value plus LDAP filter metacharacters to truncate the filter (the CVE-2021-29156 pattern — injecting into the LDAP filter built from the webfinger resource).
- **Root cause:** OpenAM constructs an LDAP search filter from the unauthenticated webfinger resource parameter. Special characters in the resource value are not escaped, so an attacker closes the legitimate filter condition and appends arbitrary filter logic (CVE-2021-29156).
- **Impact proven:** Unauthenticated, character-by-character retrieval of password hashes; retrieval of a session token or private key from the directory (generic CVE impact as documented in the record).
- **Exemplar report:** id=1278050 (U.S. Dept Of Defense, ajaysenr).

### 2. CVE-2021-29156 — OpenAM webfinger user enumeration via status-code oracle

- **Endpoint shape / parameter:** Same OpenAM webfinger endpoint; the same vulnerable username/resource field, used purely as a boolean oracle instead of for extraction.
- **Payload that actually fired:** payload not stated. Technique as recorded: craft a webfinger username that starts with the candidate value (the injected filter matches on a prefix rather than an exact match), then observe the response code.
- **Root cause:** Because the injected filter is a prefix match, an existing user returns HTTP 200 OK while a non-existent user returns 404 — a clean yes/no oracle requiring no error output.
- **Impact proven:** Enumerated a valid username via 200-vs-404 status differences; the response also disclosed the internal OpenAM instance address. Password enumeration through the same oracle was also possible.
- **Exemplar report:** id=1278891 (U.S. Dept Of Defense, ajaysenr).

### 3. Error-based LDAP injection via unsanitized registration field

- **Endpoint shape / parameter:** `POST /Registration/Home/New` — parameter `first_name` (a free-text form field on a self-registration page).
- **Payload that actually fired (verbatim):** `"` (a single double-quote character).
- **Root cause:** User registration input (first name) is stored without sanitization, so a double quote reaches the LDAP backend and breaks the filter — the application builds an LDAP filter like `(firstName="<input>"...)` and the raw quote terminates the string mid-filter.
- **Impact proven:** The server returned LDAP fatal error `0x80005000`, proving unsanitized attacker data reached the directory. Per the record, this demonstrated the attacker could enumerate the domain, exfiltrate data, and — notably — bypass the manual user-activation approval process (the application gates new accounts behind a manual review; controlling the LDAP query lets that gate be circumvented).
- **Exemplar report:** id=359290 (U.S. Dept Of Defense, ajaysenr).

## Bypass / chain notes

- **Status-code oracle as a blind bypass:** When direct data extraction output isn't reflected, the 1278891 technique shows the same injection primitive works as a binary oracle: submit a candidate username as the *prefix* of the injected filter value and diff 200 vs 404. This converts a blind injection into a reliable enumeration channel and can be scripted character-by-character or candidate-list-wise.
- **Multi-step chain from the records (verbatim steps):**
  1. Craft webfinger username starting with candidate value
  2. Observe 200 OK vs 404 to confirm valid username
- **Error-to-exfiltration chain:** In the registration case, the double-quote error was not the end goal — the record frames it as step one of a chain: the same unsanitized field could be used for domain enumeration and data exfiltration, and specifically to bypass the manual user-activation approval process. Treat "LDAP error in response" as evidence the whole directory query is attacker-controlled, not just as an informational bug.
- **Escalation via directory contents:** For OpenAM/CVE-2021-29156, the documented ceiling is severe: the LDAP directory holds password hashes, and OpenAM's own session tokens and private keys can be attributes in the tree — extraction of any of these converts a "filter injection" into full authentication bypass.

## Gotchas / what NOT to do

- **Don't dismiss a lone double-quote error as low severity.** Error 0x80005000 from a registration form is proof of unsanitized input reaching LDAP; the winning reports frame it as a path to domain enumeration and approval-flow bypass, not as "broken error handling."
- **Don't only test exact-match user lookups.** The enumeration oracle works because the injected filter is a *prefix* match — if your payload forces an exact comparison you lose the 200/404 differential.
- **Don't overlook non-obvious endpoints.** None of the three findings were on a login form. Two are on webfinger (a rarely-audited discovery endpoint on SSO products), one on a registration form. Identity-product discovery/dispatch endpoints (`/webfinger`, handler endpoints) are high-yield for this class.
- **Don't forget second-order impact.** In the registration case the input is *stored* without sanitization — the LDAP query may fire later (during activation/approval), so a payload can be a second-order injection even if the immediate response looks clean.
- **Check the instance-address disclosure.** The OpenAM enumeration response leaked the internal OpenAM instance address — a secondary info disclosure worth including in the report even when the primary issue is enumeration.
- **Payload not stated caveats:** For both OpenAM records the records do not preserve the verbatim injection string; when reproducing, you must derive the filter-closing payload from the target's product version (CVE-2021-29156, ForgeRock AM) rather than copying a known string — validate against the version in the advisory first.

## Real-world impact examples

- **Full authentication-material extraction (id=1278050):** Via CVE-2021-29156 in the OpenAM webfinger endpoint, unauthenticated retrieval character-by-character of password hashes, or direct retrieval of a session token or private key — no credentials required at any step.
- **Valid-user enumeration + internal address leak (id=1278891):** Same endpoint, same CVE: a valid username confirmed by a 200 OK vs 404 differential on unauthenticated requests, plus disclosure of the OpenAM instance address in the response; the record notes password enumeration was possible through the same oracle.
- **Directory access + approval bypass (id=359290):** Submitting `"` as `first_name` on `POST /Registration/Home/New` triggered LDAP fatal error 0x80005000, proving unsanitized input reached the directory and enabling domain enumeration, data exfiltration, and circumvention of the manual user-activation approval gate — i.e., an attacker could get accounts past human review.