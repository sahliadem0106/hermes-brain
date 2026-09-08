---
name: hunter-l3-mixed-content
description: "Use when hunting Mixed Content on a target. Loads the L3 technique sheet: Mixed content is the class of bugs where a page served over HTTPS loads subresources (images, scripts, logos, avatars) over plain HTTP."
domain: cybersecurity
subdomain: web
tags:
- web
- mixed-content
- hunting
- l3
version: '1.0'
---

# Mixed Content — Technique Sheet

## Overview

Mixed content is the class of bugs where a page served over HTTPS loads subresources (images, scripts, logos, avatars) over plain HTTP. It pays in two tiers: **active mixed content** (scripts/XHR over HTTP, which browsers block but the flaw still shows a hijackable request in the page source) and **passive mixed content** (images over HTTP, which many programs accept as valid because the requests are observable and replaceable by a network attacker). The recurring bounty-winning shape is trivially simple: open the browser console on an HTTPS page, find `http://` resource URLs, screenshot the console error, and articulate the MITM scenario. All four verified records here were found by the same reporter (ajaysenr) against ownCloud, Gratipay, Lyst, and FanDuel — proof this is a low-skill, high-repeatability class when the report is written well.

## Distinct sub-patterns

### Sub-pattern 1: HTTP-loaded first-party assets (images) on an HTTPS host

- **Endpoint shape / parameter:** None — the vulnerable asset is referenced from the root page of a subdomain. Exemplar: `GET /` on `https://stats.owncloud.org`, where the HTML references `http://stats.owncloud.org/misc/user/logo.png` (same host, downgraded scheme).
- **Payload that actually fired (verbatim):**
  ```
  http://stats.owncloud.org/misc/user/logo.png
  ```
- **Root-cause pattern:** A template or config hardcodes the `http://` scheme (or uses a scheme-relative default in a server-side URL builder) for a static asset. Because the resource is on the same host, the fix is trivially upgrading to HTTPS — which makes the report easy for the triager to accept. The browser emits a mixed-content error in the console, which is the artifact of proof.
- **Impact that was proven:** The HTTPS page produced a mixed-content error in the browser console. A MITM could rewrite the HTTP response and inject malicious JavaScript to steal user credentials. Note the escalation logic: even though a logo is "just an image," the attacker controls the HTTP response body, so script injection into the response is the plausible attack — articulate this explicitly.
- **Exemplar report IDs:** 108692 (ownCloud).

### Sub-pattern 2: HTTP-loaded third-party assets (Gravatar avatars) in `<img>` tags

- **Endpoint shape / parameter:** None — embedded in rendered HTML of the HTTPS root page: `<img src="http://www.gravatar.com/...">`.
- **Payload that actually fired:** payload not stated in the record beyond the observed tag shape: an `<img>` element pointing at `http://www.gravatar.com/...` (Gravatar over plain HTTP).
- **Root-cause pattern:** The application builds the avatar URL from a third-party service using the unencrypted scheme — typically because the code predates or ignores `https` availability on the third party, or the developer wrote the absolute URL with `http://` instead of leaving the scheme relative (`//www.gravatar.com/...`) or omitting it. This is the classic "third-party avatar/pixel hardcoded to http" pattern.
- **Impact that was proven:** The request URLs travel unencrypted and can be observed on the network — i.e., a passive network observer learns which pages the user visits (avatar requests leak page context). Privacy-level impact rather than script injection, but accepted as valid.
- **Exemplar report IDs:** 185835 (Gratipay).

### Sub-pattern 3: Dead conditional-comment branches that still emit insecure script URLs

- **Endpoint shape / parameter:** None — the flaw lives in the HTML source of `https://www.lyst.com` pages: an IE conditional comment intended only for IE<9 contained an `http://` JavaScript include.
- **Payload that actually fired:** payload not stated; the mechanism was an erroneous conditional comment for IE<9 causing an insecure (`http://`) JavaScript load on an HTTPS page. The referenced script did not even exist (a 404), yet the insecure *request* itself was the bug.
- **Root-cause pattern:** Legacy-browser-compatibility cruft. The conditional comment guards a script include that modern browsers never fetch — but IE<9 clients (or any client where the guard is bypassed/misparsed) issue a plain-HTTP script request. The key insight: **the request being hijackable is the bug, not whether it succeeds.** A non-existent script still means an attacker on the network can answer the request with a 200 and inject script.
- **Impact that was proven:** The insecure, non-existent JS request over certain HTTPS requests could technically be hijacked. Fix was simply removing the comment; the page no longer serves that request.
- **Exemplar report IDs:** 207329 (Lyst).

### Sub-pattern 4: Passive mixed content — HTTP images on a production HTTPS site

- **Endpoint shape / parameter:** `GET https://www.fanduel.com/press` — a content-heavy editorial/marketing page. Images on the page were referenced over plain HTTP.
- **Payload that actually fired:** payload not stated (record documents the class of image URLs on the /press page, not a specific URL).
- **Root-cause pattern:** CMS-authored content (press pages are typically written via a CMS/editor that pastes or stores absolute `http://` image URLs) — the page shell is HTTPS but embedded media URLs were authored insecurely.
- **Impact that was proven:** Images loaded over unencrypted HTTP, allowing a man-in-the-middle attacker to sniff traffic, replace images, and infer the pages a user visits. This is the canonical three-part passive-mixed-content impact statement: (1) sniff, (2) replace/deface, (3) page-visit inference.
- **Exemplar report IDs:** 437800 (FanDuel).

## Bypass / chain notes

- No multi-step chains appear in these records — all four were single-request findings. That is itself a signal: mixed content is a first-request, first-screenshot bug class.
- The implicit "bypass" in this class is against browser blocking behavior, not filters:
  - **Active vs. passive framing:** Browsers block HTTP *scripts* on HTTPS pages (so the flaw can't be live-exploited in a modern browser), but the records show two accepted framings — for Lyst (207329) the report hinged on the *hijackable request* existing at all, and for ownCloud (108692) the MITM-response-rewrite scenario was accepted even though the resource was an image. If a browser blocks the load, pivot the impact narrative to "the network attacker answers before the browser can block" and to legacy clients (IE<9 explicitly cited in 207329).
  - **Passive content still pays:** FanDuel (437800) and Gratipay (185835) were accepted purely as passive mixed content (images). Don't assume images-only findings are triaged as informational — the privacy/visit-inference impact statement was enough.
- Scheme-relative opportunity worth flagging when writing these reports (all four records would have been fixed this way): replace `http://host/...` with `//host/...` or `https://host/...`. Confirming the HTTPS version of the resource *exists* (200 over HTTPS) makes the fix recommendation concrete and reduces triage friction.

## Gotchas / what NOT to do

- **Don't report only "console shows a warning"** — every accepted record paired the console error with an explicit MITM consequence (credential theft via response rewrite, image replacement, page-visit inference). The impact narrative is what converts a warning into a bounty.
- **Don't skip checking whether the HTTP resource exists.** Lyst (207329) was a 404 script and still got fixed — but note the record says impact was only "technically" hijackable; expect weaker bounty or pushback on non-existent resources. When the resource does exist, the finding is stronger.
- **Don't confuse first-party vs. third-party blame.** ownCloud/FanDuel loaded their *own* hosts over HTTP (clean fix: serve over HTTPS). Gratipay loaded a *third party* (gravatar.com) over HTTP — check whether the third party supports HTTPS before writing the fix recommendation, otherwise the triager may reject with "third-party issue, out of scope."
- **Don't waste time on legacy-browser-only vectors unless the source actually emits them.** The Lyst bug fired only via an IE<9 conditional comment — it was reportable because the source literally contained the insecure request. A hypothetical you can't see in the page source is not a finding.
- **Don't claim script injection when only an image is loaded — claim the right impact tier.** For passive content the proven impacts in the records were: sniff traffic, replace images, infer visited pages. For anything where the attacker controls the response body of an HTTP subresource, response-rewriting-to-script is the accepted escalation (ownCloud, 108692) — but ground it in the MITM model, not in the page directly executing.
- **Verify the parent page is HTTPS and the subresource is HTTP on the *live* site**, and screenshot both the page source (or DevTools Network tab) and the console error. All four records were verified against production URLs — no staging, no hypotheticals.

## Real-world impact examples

- **ownCloud (108692):** `https://stats.owncloud.org` loaded `http://stats.owncloud.org/misc/user/logo.png`, producing a browser-console mixed-content error; a MITM could rewrite the HTTP response to inject malicious JavaScript and steal user credentials. Fixed by serving the asset over HTTPS.
- **Gratipay (185835):** An HTTPS page embedded `<img src="http://www.gravatar.com/...">`, so avatar request URLs (and therefore which page the user was viewing) were visible to any network observer.
- **Lyst (207329):** An erroneous IE<9 conditional comment on `www.lyst.com` caused an insecure, non-existent JavaScript load on HTTPS pages — hijackable on the wire by any network attacker despite being dead code for modern browsers. Fixed by removing the comment entirely.
- **FanDuel (437800):** `https://www.fanduel.com/press` loaded images over plain HTTP, giving a MITM the ability to sniff traffic, replace images, and infer which pages a user visits.