---
name: hunter-l3-cookie-injection
description: "Use when hunting Cookie Injection on a target. Loads the L3 technique sheet: Cookie Injection covers bugs where attacker-controlled data is stored and replayed as cookies outside the attacker's intended scope — either by injecting cookies into a victim's browser via an unencod"
domain: cybersecurity
subdomain: web
tags:
- web
- cookie-injection
- hunting
- l3
version: '1.0'
---

# Cookie Injection — Technique Sheet

## Overview
Cookie Injection covers bugs where attacker-controlled data is stored and replayed as cookies outside the attacker's intended scope — either by injecting cookies into a victim's browser via an unencoded `Set-Cookie` echo, or by exploiting parser/handle-state flaws in HTTP clients (curl/libcurl) that mis-scope or mis-clone cookie state. It pays when the injected or mis-scoped cookies can fixate sessions, bypass CSRF protections, cause client-side DoS (cookie bombs), or leak cookies across trust boundaries between unrelated origins. Note that this record set includes library-level CVEs (curl), so the class spans both web-app response-header injection and HTTP-client cookie handling flaws.

## Distinct sub-patterns

### Sub-pattern 1: Set-Cookie injection via unencoded parameter echo
- Endpoint shape / parameter: `GET /` with a parameter such as `?coupon=...` whose value is reflected into the response's `Set-Cookie` header (any reflected parameter that lands in a `Set-Cookie` header fits this shape).
- Payload that actually fired (verbatim): `HERE;+Cookie1=XXXXX;+Cookie2=WWWWWWW;+Cookie3=EOF`
  - The `;` delimiters terminate the first cookie and introduce new `name=value` pairs. The `+` characters stand in for spaces in the header value, producing multiple attacker-defined cookies (`Cookie1`, `Cookie2`, `Cookie3`).
- Root-cause pattern: The semicolon in the `coupon` parameter was not URL-encoded (and not sanitized/stripped) before being echoed into the `Set-Cookie` response header. Since `;` is the cookie attribute/pair delimiter in `Set-Cookie`, the attacker fully controls the cookie list and attributes emitted to their own or a victim's browser.
- Impact that was proven: Arbitrary attacker-controlled cookies injected via `Set-Cookie`, enabling: session fixation, cookie bomb / client-side DoS (filling the cookie jar to evict or block legitimate cookies), and CSRF protection bypass (overwriting or injecting CSRF-token cookies).
- Exemplar report IDs: 806577 (program: Nord Security, author ajaysenr).

### Sub-pattern 2: Cookie scope escape via trailing-dot TLD in the client's cookie parser
- Endpoint shape / parameter: `curl` cookie jar / HTTP response handling; parameter is the `Domain` attribute of `Set-Cookie`.
- Payload that actually fired (verbatim): `header("Set-Cookie: a=b; Domain=.me.");`
  - The key detail is the trailing dot inside the Domain attribute: `Domain=.me.` (TLD + trailing dot).
- Root-cause pattern: curl's cookie parser rejects cookies scoped to a bare TLD (`Domain=.me`), but fails to reject a TLD written with a trailing dot (`Domain=.me.`). It accepts, stores, and replays the cookie under the `.me.` scope — an effective TLD+dot scope that matches hostnames rendered with trailing dots (FQDN form).
- Impact that was proven: Cookie `a=b` was set for scope `.me.` and subsequently sent to unrelated `domain.me.` hosts accessed with a trailing dot. This enables cookies from one arbitrary site to leak to unrelated sites sharing the TLD — a cross-origin cookie leakage/scope-confusion bug. Assigned CVE-2022-27779.
- Exemplar report IDs: 1553301 (program: curl, author ajaysenr).

### Sub-pattern 3: Cookie-enable state retained but cookies not cloned on handle duplication (libcurl)
- Endpoint shape / parameter: library-level — `curl_easy_duphandle` in libcurl; parameter is the cookie file / cookie source state.
- Payload that actually fired: payload not stated (no HTTP payload; the bug is triggered by calling `curl_easy_duphandle` on a handle with cookies enabled).
- Root-cause pattern: A duplicated easy handle retains the cookie-*enable* state but does not clone the actual cookies, and the duplicated handle's cookie source filename defaults to the literal string `none`. If conditions are met (a crafted readable file named `none` exists in the program's working directory), the duplicate handle reads cookie data from that attacker-influenceable file.
- Impact that was proven: An attacker can insert cookies into a running program that uses libcurl, under the conditions above. Assigned CVE-2023-38546.
- Exemplar report IDs: 2215578 (program: Internet Bug Bounty, author ajaysenr).

## Bypass / chain notes
- Parser-differential bypass (Sub-pattern 2): the core "bypass" is a validation gap — the check `is this a TLD scope?` rejects `Domain=.me` but not `Domain=.me.`. Any cookie-scoping validator that string-compares against the TLD without normalizing trailing dots is vulnerable to the same trick. Test both `Domain=.tld` and `Domain=.tld.` variants.
- Attribute-injection primitive (Sub-pattern 1): once a raw `;` reaches a `Set-Cookie` header, you are not limited to adding cookies — everything after the first `;` is header content under your control, including per-cookie attributes (`Path`, `Domain`, `Secure`, `HttpOnly` absence, `SameSite`), which is what makes session fixation and CSRF-bypass chains practical. The record's payload chain (semicolon-terminated first pair, then additional pairs) demonstrates the multi-cookie expansion in one request.
- No explicit multi-step chains were present in the records (all three list `chain: (none)`); impacts above were proven directly from the single injection/parser step.

## Gotchas / what NOT to do
- Don't assume a server that "handles" `;` in one parameter context is safe — the injection only needs one parameter echoed into `Set-Cookie` without encoding (Sub-pattern 1 fired on a `coupon` parameter, not an obvious cookie-related one).
- When testing client-side cookie scoping, remember the FQDN trailing-dot form (`host.tld.`) is a legitimate resolution path — a cookie scoped to `.tld.` is not inert; it will be replayed to trailing-dot hostnames (Sub-pattern 2). Do not dismiss trailing-dot scopes as unreachable.
- In Sub-pattern 3, impact is conditional: it requires the crafted readable `none` file in the working directory of the affected program. A report asserting arbitrary cookie insertion without establishing those conditions will overstate impact.
- Payloads must survive URL decoding and header assembly intact — the `+` for space in the recorded payload indicates the value passes through form-decoding before header reflection; test both `+` and `%20` encodings.
- Preserve cookie name values verbatim from your PoC when reporting; the demonstrated ability to set multiple attacker-named cookies (`Cookie1`, `Cookie2`, `Cookie3`) is what establishes the full primitive, not merely reflecting a value back.

## Real-world impact examples
- CVE-2022-27779 (curl, record 1553301): `Set-Cookie: a=b; Domain=.me.` resulted in cookie `a=b` being stored under `.me.` and sent to unrelated `domain.me.` hosts using trailing dots — cross-site cookie leakage between arbitrary unrelated sites sharing a TLD.
- CVE-2023-38546 (libcurl, record 2215578): a duplicated easy handle defaulted its cookie source to the filename `none`, allowing an attacker who can place a readable `none` file in the program's working directory to insert cookies into a running libcurl-based program.
- Nord Security (record 806577): reflecting `HERE;+Cookie1=XXXXX;+Cookie2=WWWWWWW;+Cookie3=EOF` from the `coupon` parameter into `Set-Cookie` injected three attacker-controlled cookies, with proven escalation to session fixation, cookie bomb / client-side DoS, and CSRF protection bypass.