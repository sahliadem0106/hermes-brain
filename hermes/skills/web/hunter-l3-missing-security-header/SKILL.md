---
name: hunter-l3-missing-security-header
description: "Use when hunting Missing Security Header on a target. Loads the L3 technique sheet: This class covers responses that omit well-known defensive HTTP headers — HSTS, X-Content-Type-Options, X-XSS-Protection, and similar."
domain: cybersecurity
subdomain: web
tags:
- web
- missing-security-header
- hunting
- l3
version: '1.0'
---

# Missing Security Header — Technique Sheet

## Overview

This class covers responses that omit well-known defensive HTTP headers — HSTS, X-Content-Type-Options, X-XSS-Protection, and similar. The bugs are verified by inspecting response headers (typically with `curl -I` or browser devtools) and require no exploitation payload. It is a low-severity, high-volume class: most programs accept it as Low or Informational, but it reliably pays on programs that explicitly list these headers in policy, and it is a common first accepted submission for new hunters. Check the program's policy first — some programs (e.g. historically Imgur) explicitly welcome header-hygiene reports; others mark them N/A.

## Distinct sub-patterns

### 1. Missing Strict-Transport-Security (HSTS)

- Endpoint shape: any TLS-served site; check the root document `GET /` (and ideally a subresource or two) over HTTPS.
- Payload that actually fired: none — detection is purely `curl -sI https://target/` and observing the `Strict-Transport-Security:` header is absent.
- Root-cause pattern: the server/CDN config never emits the HSTS header, so the browser has no policy forcing HTTPS on subsequent visits. First-visit and explicit-HTTP-visit connections can be downgraded or MITM'd by an on-path attacker (sslstrip-style).
- Impact proven: site served over TLS without HSTS, leaving connections potentially downgradable/interceptable. Reported and accepted as a security finding.
- Exemplar: id=1498 [ajaysenr] (Secret program).

### 2. Missing X-Content-Type-Options: nosniff

- Endpoint shape: all HTTP responses (site-wide). Verified on the root page and on any response serving user-influenced content.
- Payload that actually fired: none — verbatim check is that the response header set lacks `X-Content-Type-Options: nosniff`.
- Root-cause pattern: without `nosniff`, browsers may MIME-sniff responses and interpret e.g. a text/plain or attacker-influenced response as JavaScript/HTML, enabling content-type confusion (and blocking protections like CORB). Two independent reports show this is consistently accepted across programs.
- Impact proven:
  - Content (MIME) sniffing possible due to the missing header (Localize, id=8059).
  - Confirmed responses lack `X-Content-Type-Options: nosniff`, allowing browsers to sniff content/encoding type — described as "undesired behavior" and accepted on a major program (Imgur, id=91366).
- Exemplars: id=8059 [ajaysenr] (Localize); id=91366 [ajaysenr] (Imgur).

### 3. Missing X-XSS-Protection header

- Endpoint shape: root domain responses, `GET /` on the primary site (weblate.org in the record).
- Payload that actually fired: none — header simply absent from responses.
- Root-cause pattern: responses never set `X-XSS-Protection`, so legacy-browser XSS-auditor protection was not enabled. Note: this header is deprecated in modern browsers and many programs no longer accept its absence — but the record shows it was accepted on a real program.
- Impact proven: responses from weblate.org lack `X-XSS-Protection`; accepted as a finding (header-hygiene severity).
- Exemplar: id=223723 [ajaysenr] (Weblate).

## Bypass / chain notes

No filter bypasses or multi-step chains appear in the records — all four are standalone single-request findings with no chained exploit. That is the norm for this class: impact is the *absence* of a defense, demonstrated by header inspection alone. If you want to strengthen the report, the records suggest framing: state what an on-path attacker could do (downgrade for HSTS) or what browser behavior is enabled (sniffing for nosniff), rather than claiming exploitable XSS/RCE you did not demonstrate.

## Gotchas / what NOT to do

- Do not send this to programs whose policy marks security-header issues as N/A out of hand — severity is Low/Info, so a duplicate or out-of-scope submission is pure reputation cost. (Imgur accepting it, id=91366, shows some majors do take them.)
- Verify across responses, not just one: the Imgur report (id=91366) checked "all HTTP responses" — a header present on `/` but missing on an app route is a weaker (often rejected) claim, and a header missing on `/` only can be a mis-test.
- Do not claim concrete exploitation you did not perform; all four accepted records describe the *enabling condition* (sniffing possible, downgrade possible), not a proven XSS or MITM.
- Do not test over plain HTTP and conclude about HSTS — HSTS is only meaningful on HTTPS responses; inspect the HTTPS response specifically.
- Modern-context caveat: X-XSS-Protection is obsolete in current browsers; expect some triagers to push back. Lead with the header-verification evidence (verbatim response headers) and the program's own scope wording.

## Real-world impact examples

- Secret (id=1498): site delivered over HTTPS with no `Strict-Transport-Security`, meaning first-time or coerced-HTTP visits could be downgraded/intercepted by a network attacker. Accepted on this basis alone.
- Imgur (id=91366): all responses lacked `X-Content-Type-Options: nosniff`, confirmed site-wide; browser MIME/encoding sniffing enabled — accepted as a valid finding on a large program.
- Localize (id=8059): missing `nosniff` permitted content sniffing; accepted.
- Weblate (id=223723): `X-XSS-Protection` unset on weblate.org responses; accepted.

Practical takeaway: this class is won by breadth and precision — enumerate which headers the program cares about, verify their absence on every response class (root, app routes, static/user content) with captured headers pasted into the report, and scope impact claims exactly to what the missing header enables.