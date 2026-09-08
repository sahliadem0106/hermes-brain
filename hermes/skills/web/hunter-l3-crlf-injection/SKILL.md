---
name: hunter-l3-crlf-injection
description: "Use when hunting CRLF Injection on a target. Loads the L3 technique sheet: CRLF injection (HTTP response splitting / header injection) is the injection of carriage-return (`%0d`) and line-feed (`%0a`) bytes into parts of an HTTP response the server builds from user input — m"
domain: cybersecurity
subdomain: web
tags:
- web
- crlf-injection
- hunting
- l3
version: '1.0'
---

# CRLF Injection — Technique Sheet

## Overview

CRLF injection (HTTP response splitting / header injection) is the injection of carriage-return (`%0d`) and line-feed (`%0a`) bytes into parts of an HTTP response the server builds from user input — most commonly the URL path reflected into a `Location` header on a 301/302/307 redirect, but also arbitrary reflected parameters, client library headers (undici, curl, libcurl), and URL parsers. The classic, highest-yield pattern is the **redirect-header reflection**: request `/path%0d%0aSet-Cookie:foo=bar` and the server emits your bytes verbatim as response headers. It pays because each individual "set one header" proof chains into cookie injection, session fixation, CSRF bypass, XSS, cache poisoning, and response splitting with attacker-controlled bodies. It rewards testing with raw HTTP/1.1 (curl) since browsers and many proxies normalize or block CRLF in request URIs.

## Distinct sub-patterns

### 1. Path reflected into `Location` header on 301/302/307 redirect (the dominant pattern)

- **Endpoint shape:** `GET https://target/{path}` where the path is echoed into `Location:` of a redirect response. Variants: `GET /dashboard/{path}`, `GET /__session_start__/{injected}`, `GET /advanced`, `GET /{encoded CRLF}`.
- **Payloads that actually fired (verbatim):**
  - `%0D%0ASet-Cookie:crlfinjection=crlfinjection` (GSA, id=1038594)
  - `/dashboard/%0d%0aContent-Type: text/html%0d%0aHTTP/1.1 200 OK%0d%0aSet-Cookie: oauth2_sid="..."%0d%0a%0d%0a%3Chtml%3EHacker Content%3C/html%3E...` (Uber, id=125984 — full response splitting)
  - `%0dSet-Cookie:crlf=injection%3bdomain=.ubnt.com%3b` (Ubiquiti, id=145128)
  - `%0aSet-Cookie:malicious_cookie1` (Snapchat, id=237357)
  - `%0D%0ASet-Cookie:test2=test;domain=.████` (DoD, id=245485)
  - `/%0d%0a%09headername:%20headervalue` (HackerOne, id=217058 — note the leading TAB after CRLF)
  - `%0D%0Avirus:%20value` (Clario, id=730788 — LF-only injection worked)
- **Root cause:** Server concatenates the request path into the `Location` header without stripping CR/LF; the redirect layer (nginx rewrite, app framework, SSO) trusts the raw bytes.
- **Impact proven:** Arbitrary `Set-Cookie` on the apex domain (`domain=.ubnt.com`, `domain=.myshopify.com`, `domain=.owncloud.org`), full response splitting with attacker HTML/JS body (Uber), arbitrary custom headers (HackerOne, Clario).
- **Exemplars:** id=1038594 (GSA), id=217058 (HackerOne).

### 2. Same reflection on dedicated redirect/SSO endpoints

- **Endpoint shape:** `GET /page/in-context-localization?email=...` (Khan Academy — non-path parameter reflected into a response header); Buildbot login: `/login?next=%0d%0aX-Injected:%20true` (MariaDB, CVE-2019-7313); 307 redirect endpoint behind nginx (Mars, id=1943013).
- **Payloads (verbatim):** `%0d%0a%20InjectedBy:BigBear` (Khan Academy); `Set-Cookie: CRLF_Injection_By_ze2pac` (Mars).
- **Root cause:** Any user-controlled value (query param, `next`/`redirect` URL) interpolated into a header without CRLF stripping — not just the path.
- **Impact proven:** Custom header injection (Khan Academy), header/body injection via login redirect (MariaDB), Set-Cookie injection enabling XSS/open redirect/response splitting (Mars).
- **Exemplars:** id=13314 (Khan Academy), id=481512 (MariaDB buildbot).

### 3. Encoded query delimiter / rewrite-rule edge cases

- **Endpoint shape:** Path or query containing an *encoded* special character (`%23` for `#`, encoded `?`) that the server decodes late, letting CRLF ride along into the response.
- **Payload:** `https://api.owncloud.org/%23%0dSet-Cookie:crlf=injection2;domain=.owncloud.org;` (ownCloud, id=154306); encoded question mark variant on downloads.mariadb.org (id=490997, payload not stated).
- **Root cause:** Rewrite rules / late URL decoding process the fragment/query marker after sanitization, so CRLF sequences adjacent to encoded delimiters reach the response headers.
- **Impact proven:** Cookie injection on `*.owncloud.org`; cookie injection, response splitting, and session fixation across mariadb domains.
- **Exemplars:** id=154306 (ownCloud), id=476257 (MariaDB, `/%0d%0aSet-Cookie:test=1` on a rewrite rule).

### 4. CRLF → Set-Cookie → CSRF token override (chained)

- **Endpoint shape:** `GET http://gratipay.com/%0dSet-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;`
- **Root cause:** CRLF reflected into response headers (as above), but chained: the injected cookie overwrites the server-issued CSRF token cookie.
- **Chain:** (1) Inject `Set-Cookie: csrf_token=attacker_value` via CRLF in the redirect path; (2) use the known cookie value to bypass CSRF protection and forge a `statement.json` POST.
- **Impact proven:** Working CSRF bypass on a state-changing POST.
- **Exemplar:** id=79552 (Gratipay). This is the model chain for turning a "just a header" proof into account-level impact.

### 5. Full HTTP response splitting with attacker body (double-response smuggling)

- **Endpoint shape:** `GET /dashboard/{path}` (Uber, id=125984); `GET /email-prospect{suffix}?requesturl=...` (Starbucks, id=858650).
- **Payload (Starbucks, verbatim):**
  `curl -i 'https://www.starbucks.com/email-prospecttg9wh%0d%0aset-cookie:foo%0d%0a%0d%0a4t6uf?requesturl=/responsibility/global-report/policies' -d 'newsletter_signup_email=&newsletter_signup_zipcode=&newsletter_signup_placement=footer' --http1.1`
- **Root cause:** Injected `%0d%0a%0d%0a` (double CRLF) terminates the headers early, so everything after becomes the response *body*. In the Uber payload, a full fake second response (`HTTP/1.1 200 OK` + body) was injected into the 302.
- **Impact proven:** Uber — attacker HTML/JS served in the 302; cookies not Secure/HttpOnly, so JS exfiltration + session fixation. Starbucks — arbitrary headers incl. injected CORS headers stealing authenticated info, plus DoS via long cookies. 8x8 (id=413115) — response splitting via LF in a URL parameter (payload not stated).
- **Exemplars:** id=125984 (Uber), id=858650 (Starbucks).

### 6. Client-side HTTP library header injection (undici / Node.js)

- **Endpoint shape:** Application code calling `undici.request()` with attacker-influenced option values.
- **Payloads (verbatim):**
  - content-type: `'application/json\r\n\r\nGET /foo2 HTTP/1.1'` — one call performed two requests (id=1664019, request smuggling).
  - host: `12 \r\n\r\naaa:aaa` / `12 \n\naaa:aaa` — injected extra headers because `processHeader` never runs `headerCharRegex` on the `host` value (ids=1820955, 1878489, CVE-2023-23936, undici ≤5.14.0).
- **Root cause:** Library trusts option values as header content without the per-character validation applied elsewhere.
- **Impact proven:** Arbitrary header injection, request smuggling inside a single `request()` call; CVE issued.
- **Exemplars:** id=1664019, id=1878489.

### 7. URL-parser hostname truncation → whitelist bypass

- **Endpoint shape:** SSRF/redirect-validator code using legacy `url.parse().hostname` (Node.js).
- **Payload (verbatim):** `http://test1.com\ntest2.com` — `url.parse().hostname` returns `test1.com` (truncated at the newline) while the actual request goes to `test2.com`.
- **Root cause:** Legacy `url.parse()` does not strip CRLF from hostnames; a whitelist validated against the parsed hostname but the connection used the full value.
- **Impact proven:** Hostname whitelist bypass, exploited in a real penetration test.
- **Exemplar:** id=771596 (Node.js). Apply this when auditing SSRF/redirect allowlists that use `url.parse`.

### 8. CLI/library option CRLF injection (curl family)

- **Endpoint shapes / payloads (verbatim):**
  - `--proxy-header $'X-Test: hello\r\nX-Evil: owned'` → two headers on the wire to the proxy (id=3133379).
  - `CURLOPT_HAPROXY_CLIENT_IP = "1.2.3.4\nPROXY TCP4 127.0.0.1 10.0.0.1 1234 80"` → a complete second PROXY protocol line injected; spoof source IP, bypass IP-based access controls (id=3823932).
  - `CURLOPT_RTSP_STREAM_URI` containing `\r\nTEARDOWN /camera-A RTSP/1.0` → a single SETUP smuggled a TEARDOWN that killed an unrelated party's active camera session (victim PLAY returned `454 Session Not Found`) (id=3963494).
- **Root cause:** Option values interpolated unescaped into request headers/protocol lines with no CRLF validation (only length checks).
- **Impact proven:** Splitting one client operation into multiple independent requests (HTTP and RTSP), access-control bypass, destruction of other users' state.
- **Exemplars:** id=3133379, id=3963494.

### 9. CRLF in content to break display-vs-target equivalence (link spoofing)

- **Endpoint shape:** `POST /1.1/dm/new.json` / tweet creation with params `text,status`.
- **Payload (verbatim):** `fakewebsite.tw%0ditter.com`
- **Root cause:** The newline breaks the URL-parsing/linkification logic but not the display rendering, so displayed text and actual hyperlink target diverge.
- **Impact proven:** Displayed URL `fakewebsite.twitter.com` actually hyperlinked to attacker-controlled domains — phishing.
- **Exemplar:** id=712979 (X/Twitter). Remember CRLF can attack *content rendering*, not only headers.

## Bypass / chain notes

- **Encoding variants:** `%0d%0a` (standard), bare `%0d` (Ubiquiti, Vimeo, Gratipay), bare `%0a` LF-only (Snapchat, Shopify `%0a`, Clario `%0D%0A`, 8x8 LF-only) — always test both individually; some stacks strip only one.
- **TAB after CRLF:** `/%0d%0a%09headername:%20headervalue` (HackerOne) — a leading tab makes the injected line an obs-fold continuation, which some header parsers accept when a plain `headername:` would be rejected.
- **Double CRLF for body control:** `%0d%0a%0d%0a` ends the header block; anything after it becomes the response body (Uber, Starbucks). This upgrades header injection to full response splitting.
- **Second-response smuggling:** Uber's payload embedded a complete fake `HTTP/1.1 200 OK` + headers + HTML body inside the 302 — intermediate clients parse it as a second response.
- **Set-Cookie scoping:** append `;domain=.apex.com;` to land the cookie on every subdomain (Ubiquiti, ownCloud, Shopify, Vimeo, DoD) — cross-subdomain cookies unlock session fixation and Double-Submit CSRF bypass (Ubiquiti explicitly cited Double-Submit Cookie CSRF bypass).
- **Chains observed:** CRLF → Set-Cookie `csrf_token` → CSRF bypass on POST (Gratipay); CRLF → Set-Cookie + HTML body → cookie exfiltration via JS (cookies not HttpOnly/Secure) + session fixation (Uber); CRLF → injected CORS headers → theft of authenticated info (Starbucks); CRLF → request smuggling via client lib (undici, curl RTSP).

## Gotchas / what NOT to do

- **Browser dependence matters:** the Airbnb finding (id=197279) worked in IE only, not Firefox/Chrome — modern browsers sanitize CRLF in the request URI, so test with `curl -i --http1.1` (as in the Starbucks repro), not just the browser.
- **Platform normalization:** some servers decode `%0d`/`%0a` in some positions but not others — a `%0d`-only payload succeeded where `%0d%0a` variants were used elsewhere; don't conclude "not vulnerable" after one encoding.
- **Context differs:** this class isn't just redirect Location headers — it fired in client-library options (undici, curl, libcurl RTSP/HAProxy), URL parsers, and even text/linkification (Twitter). Audit each injection sink for its own CRLF validation.
- **Library bugs are the program's bug:** undici/curl findings were accepted against the library (CVEs issued), not the application — scope your report to the component that lacks validation.
- **Don't stop at "injected a header":** the accepted reports almost always added impact reasoning — cookie scoping, session fixation, CSRF override, XSS via split body, or CORS header injection. A lone benign header is the starting point, not the report.
- Several records show the payload only reflected on specific paths (`/%23%0d...`, `/__session_start__/...`, `/advanced`) — the vulnerable reflection point may be a single route/rewrite rule; enumerate paths rather than testing only `/`.
- Unrelated records in the set (VK missing-`hash`, Legal Robot `tokenExpires` cookie) are different bug classes — don't shoehorn them into CRLF reports.

## Real-world impact examples

- **Uber (id=125984):** full response splitting on `/dashboard/` — arbitrary headers, attacker `Set-Cookie` including an `oauth2_sid` session cookie value, and attacker HTML/JS in the 302 body; JS cookie theft and session fixation possible because cookies lacked Secure/HttpOnly.
- **Gratipay (id=79552):** CRLF-injected `Set-Cookie: csrf_token=...` directly bypassed CSRF protection on `statement.json` POST — money-moving state change.
- **Starbucks (id=858650):** verified response splitting via curl with injected CORS headers enabling theft of authenticated information, plus application DoS via oversized cookies.
- **Shopify / Ubiquiti / ownCloud / Vimeo (ids=66386, 145128, 154306, 39181):** `Set-Cookie` injection scoped to the apex domain (`*.myshopify.com`, `.ubnt.com`, `*.owncloud.org`, `.vimeopro.com`) — session fixation and Double-Submit CSRF bypass primitives on major programs.
- **curl RTSP (id=3963494):** a single `SETUP` smuggled a `TEARDOWN` that terminated another party's live camera session — confirmed with `454 Session Not Found` on the victim's subsequent `PLAY` (curl 8.21.0).
- **Node.js `url.parse` (id=771596):** hostname whitelist bypass via CRLF, exploited in a real-world penetration test.
- **Twitter (id=712979):** displayed-URL spoofing at scale in tweets/DMs — direct phishing enabler.
- **CVEs issued:** CVE-2023-23936 (undici host header), CVE-2019-7313 (Buildbot login redirect) — CRLF injection at library/framework level gets CVEs and affects every downstream consumer.