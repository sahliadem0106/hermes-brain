---
name: hunter-l3-http-header-injection
description: "Use when hunting HTTP Header Injection on a target. Loads the L3 technique sheet: HTTP header injection (CRLF injection) occurs when user-controlled input containing carriage-return/line-feed sequences (`%0d%0a` or literal `\\r\\n`) is echoed into HTTP response headers — or, less com"
domain: cybersecurity
subdomain: web
tags:
- web
- http-header-injection
- hunting
- l3
version: '1.0'
---

# HTTP Header Injection — Technique Sheet

## Overview

HTTP header injection (CRLF injection) occurs when user-controlled input containing carriage-return/line-feed sequences (`%0d%0a` or literal `\r\n`) is echoed into HTTP response headers — or, less commonly, into request headers via vulnerable library APIs. It pays when it lets you set attacker-chosen cookies on a target domain (session fixation), control the `Location` of redirects (open redirect / phishing), or smuggle whole extra headers. All three verified records here stem from the same root: unsanitized CRLF in an input that gets placed into a header context, plus one library-level case where no validation existed at all.

## Distinct sub-patterns

### Sub-pattern 1: CRLF in URL path → injected Set-Cookie on a parent domain

- Endpoint shape: `GET /%0d%0a<injected headers>` — no parameters needed, the payload lives in the raw URL path.
- Payload (verbatim):
  ```
  /%0d%0aset-cookie%20%3amycookie%3dmyvalue;%20%44omain%20%3d.hackerone.com
  ```
  Decoded, this is `/` + CRLF + `set-cookie :mycookie=myvalue; Domain =.hackerone.com`.
- Root cause: CRLF bytes in the URL path are not sanitized before the request is processed and the path is reflected into response headers, so the injected line becomes a full `Set-Cookie` header in the 200/3xx response.
- Key bypass inside this record: a space was placed **after** `Domain` (`Domain =` / `%44omain%20%3d`) — some parsers/implementations that would reject or strip an injected `Domain=.hackerone.com` attribute accept `Domain =` with trailing whitespace, so the cookie still binds to the main domain instead of being scoped down or dropped. Note also `%44omain` (uppercase-hex-encoded `D`) was used.
- Impact proven: in Internet Explorer, `Set-Cookie: mycookie=myvalue; Domain=.hackerone.com` actually landed — the cookie was set on the main `hackerone.com` domain. That is attacker-settable cookie territory on a primary apex domain: session fixation, forcing victim state, chaining into auth logic.
- Exemplar report: id=97292 [ajaysenr], HackerOne program.

### Sub-pattern 2: URL-decoded parameter reflected into the `Location` response header

- Endpoint shape: `POST /login.cgi` with a `uri` parameter — a redirect-handling parameter on a login form (classically post-auth redirect targets).
- Payload (verbatim):
  ```
  /admin.cgi
  NewHeader:Value
  ```
  i.e. `uri=/admin.cgi%0d%0aNewHeader:Value` — the newline characters are URL-encoded in transmission and the attacker supplies them URL-encoded so they survive the POST.
- Root cause: the `uri` parameter is URL-decoded server-side and then placed directly into the `Location` response header of the 302 without any sanitization of control characters. URL-decoding happens *after* input filtering (if any), so `%0d%0a` sails through any blocklist checking for literal `\r\n`.
- Impact proven: injected a fully attacker-controlled custom response header `NewHeader: Value` into the 302 login response. Demonstrated capability includes redirecting the login flow to an attacker-controlled location (open redirect via `Location` control) and arbitrary additional header injection on authenticated-flow responses.
- Exemplar report: id=203673 [ajaysenr], Ubiquiti Inc. program.
- Why this shape is worth hunting: login/logout/cgi endpoints with a `uri`, `next`, `returnTo`, `url`, `redirect` parameter that land in `Location` are the highest-yield target — the redirect flow guarantees your input hits a response header on every request.

### Sub-pattern 3: User-controlled input into library request-header API with no validation

- Endpoint shape: not an HTTP endpoint — `httplib`/`urllib`'s `HTTPConnection.putheader()` in Python, where the attacker controls the header *name* and/or *value* (e.g. an application passing user input as a header name or value).
- Payload (verbatim):
  ```
  X-Custom: 1
  X-Injected: 1
  ```
  i.e. a putheader() call whose value (or name) contains a newline, causing an extra header `X-Injected: 1` to be emitted on the outgoing request.
- Root cause: `putheader()` performed no validation of header names/values, so any embedded `\r\n` produced additional request headers. Applications that flow user input into these calls (forwarding headers, building proxied requests) become injection vectors. This was fixed as CVE-2016-5699 in the Python standard library itself.
- Impact proven: injection of additional attacker-controlled headers into outbound requests made by applications using user-controlled header input — request-side smuggling/splitting primitive against any downstream server.
- Exemplar report: id=165102 [ajaysenr], Internet Bug Bounty program (Python stdlib — paid as an IBB because the vulnerable component is shared infrastructure, not a single program's site).

## Bypass / chain notes

- **Encoding survives input filters:** in both web records the CRLF was URL-encoded (`%0d%0a`) in the request and only became literal newline bytes after server-side URL-decoding. If a WAF or app filter blocks literal `\r\n` or `%0d%0a`, try double-encoding, but the verified technique in these records is: encode the CRLF, decode happens server-side after validation.
- **Whitespace-after-attribute-name bypass:** `Domain =.hackerone.com` (space before `=`) defeated the mechanism that would otherwise prevent the injected cookie from binding to the parent domain. Variants worth trying when the plain form is stripped: spaces around `=`, and hex-encoding letters of the attribute name (`%44omain`). The record confirms the space-after-`Domain` variant specifically bypassed the domain restriction.
- **Set-Cookie via header injection is the strongest single-header target:** a `Location` header alone gives an open redirect; a `Set-Cookie` header gives you a persistent, attacker-defined value on the victim's browser scoped to a domain you name. Prefer proving the cookie actually lands (record 97292 verified it in IE — browser-specific cookie parsers accept malformed attributes differently, so test multiple browsers if one rejects it).
- **Request-side vs response-side:** the library sub-pattern (165102) is request-side — the injected headers go out to a backend/downstream server, enabling request splitting against that server. The other two are response-side, directly exploitable in the victim's browser.
- No multi-step chains beyond the two-hop CRLF→Set-Cookie→domain-binding chain in record 97292 appear in the records.

## Gotchas / what NOT to do

- Don't inject a `Set-Cookie` and assume scope — cookies injected without a valid `Domain` attribute will bind to the path/host serving the response, not the parent domain. Record 97292's impact depended entirely on making the cookie bind to `.hackerone.com`; without that it's a much weaker bug.
- Browser behavior differs: the Set-Cookie injection in the records was proven in Internet Explorer specifically. If Chrome/Firefox reject your injected cookie, don't conclude the bug is unexploitable — document per-browser results.
- Don't send literal raw newlines in the request body/URL where encoding is required — the working payloads here all use URL-encoded CRLF (`%0d%0a`) so they pass through proxies and survive to the server-side decode step.
- The library-level pattern (165102) requires *user-controlled* header input reaching `putheader()` — a wrapper function that sanitizes input, or an app that only passes constants, kills it. Confirm the data flow before reporting.
- When you get header injection, don't stop at an arbitrary header like `NewHeader: Value` as the final claim — that proves the primitive; pair it with a concrete downstream impact (cookie on parent domain, redirect to attacker host) the way records 97292 and 203673 did.
- Not stated in the records: server-side `X-` header injection as a final impact, request smuggling chains, or response-splitting with two full responses — no record demonstrates these, so don't claim them from this sheet.

## Real-world impact examples

- **HackerOne (id=97292):** a single crafted GET request to `/` with `/%0d%0aset-cookie%20%3amycookie%3dmyvalue;%20%44omain%20%3d.hackerone.com` set a cookie scoped to the main `hackerone.com` apex domain in the victim's (IE) browser — attacker-controlled cookies on the primary domain, verified end-to-end in the report.
- **Ubiquiti (id=203673):** `POST /login.cgi` with `uri=/admin.cgi%0d%0aNewHeader:Value` produced a 302 whose `Location` and header block were attacker-controlled, enabling redirect of the login flow to an attacker-chosen location plus arbitrary response-header injection.
- **Internet Bug Bounty (id=165102):** Python's `httplib`/`urllib` `HTTPConnection.putheader()` accepted newlines in header names/values, so any app forwarding user-controlled data as request headers emitted attacker-defined extra headers — fixed as CVE-2016-5699 and rewarded through IBB because it affected the shared standard library.