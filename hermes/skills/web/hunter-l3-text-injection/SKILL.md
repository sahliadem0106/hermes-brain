---
name: hunter-l3-text-injection
description: "Use when hunting Text Injection on a target. Loads the L3 technique sheet: Text injection is the ability to make attacker-chosen plain text appear inside a trusted site's page content — most commonly the 404/error page reflecting the requested URL path, or a landing/parameter-driven page echoing a query value."
domain: cybersecurity
subdomain: web
tags:
- web
- text-injection
- hunting
- l3
version: '1.0'
---

# Text Injection — Technique Sheet

## Overview
Text injection is the ability to make attacker-chosen plain text appear inside a trusted site's page content — most commonly the 404/error page reflecting the requested URL path, or a landing/parameter-driven page echoing a query value. It carries no HTML or JS execution, so impact is limited to phishing, defacement-via-shared-link, and user trapping — but on a main domain, that trust is exactly what makes the phishing convincing. It pays when the injected text appears on the target's own domain with the target's branding, or in trusted locations like the page title or authenticated-area error pages.

## Distinct sub-patterns

### 1. 404 path reflection on the main domain
- **Endpoint shape:** `GET /{arbitrary path}` — the requested path is echoed verbatim into the rendered 404 page.
- **Payload that fired:** `https://www.algolia.com/test/%2f../It%20has%20been%20changed%20by%20a%20new%20one%20https://www.crowdcurity.com%20so%20go%20to%20the%20new%20one%20since%20this%20one` (same shape used against withinsecurity.com, owncloud.help, and the wp-admin path on withinsecurity.com).
- **Root cause:** The 404 error page reflects the requested path back into the page without sanitization instead of using a static 404 page.
- **Impact:** Arbitrary attacker text injected into the 404 page of the primary domain (www.algolia.com, blog.algolia.com, withinsecurity.com, owncloud.help), usable for phishing — the injected page claims the site has moved to a new URL.
- **Exemplars:** 106348 (Algolia), 112304 (ownCloud), 106350 (withinsecurity).

### 2. 404 path reflection in an authenticated/admin path prefix
- **Endpoint shape:** `GET /wp-admin/test/%2f../{text}` — a protected path prefix (wp-admin) whose error page still reflects the path.
- **Payload that fired:** `/test/%2f../It%20has%20been%20changed%20by%20a%20new%20one%20https://www.Attacker.com%20so%20go%20to%20the%20new%20one%20since%20this%20one`
- **Root cause:** Same reflection root cause; the extra angle is that injection inside an admin path increases user-trapping credibility — victims browsing admin-adjacent URLs see attacker text inside what looks like the admin surface.
- **Impact:** Reflected attacker text on withinsecurity.com's error page, enabling user trapping.
- **Exemplar:** 111860 (withinsecurity).

### 3. 404 reflection on a mobile-app backend / embedded webview
- **Endpoint shape:** `GET /{path}` on the app's companion domain, e.g. `http://hack.whocoronavirus.org/{text}`.
- **Payload:** `TextInjection` (any non-existent path segment).
- **Root cause:** 404 page reflects the requested path without sanitization — but here Google's 404 handling sanitizes the inputs, so no compromise of the page content was possible.
- **Impact:** Text injected into the 404 page; explicitly judged low/no compromise because the underlying 404 renderer sanitized input.
- **Exemplar:** 1065830 (WHO COVID-19 Mobile App). Note: this is a good example of a text-injection report being accepted as a valid-but-low finding — worth probing app companion domains, but expect reduced impact where a hardened renderer (e.g., Google-hosted error pages) is in play.

### 4. Query-parameter reflection on a landing page
- **Endpoint shape:** `GET /?c={url}` — a query parameter whose value is echoed into the page.
- **Payload that fired:** `https://media.hboeck.de/?c=http://www.example.com`
- **Root cause:** The `c` parameter value is reflected into the page output without sanitization.
- **Impact:** A crafted URL causes attacker content to be displayed on the web app — defacement via a shared link.
- **Exemplar:** 434670 (Hanno's projects).

### 5. Text reflection on a dedicated landing/OTP-style endpoint
- **Endpoint shape:** `GET /check-otp` on get.uber.com (parameter unspecified in the record).
- **Payload:** reflected attacker text (not stated verbatim).
- **Root cause:** A landing page reflects attacker-controlled text with no HTML/JS — pure text injection.
- **Impact:** Confirmed text injection in a landing page on get.uber.com.
- **Exemplar:** 126235 (Uber). Lesson: check the reflection on transactional/verification endpoints (OTP, login redirects), not just 404 pages — they're shared with victims in real flows.

### 6. Text injection into the page `<title>` (post-fix regression)
- **Endpoint shape:** Not an endpoint — the website's title element on Gratipay.
- **Payload that fired:** `<script>alert(1)</script>` (submitted as probe; accepted as text injection, not XSS).
- **Root cause:** An incomplete fix of prior report #115284 still allowed text injection into the website title.
- **Impact:** Attacker text injected into the title — highly visible in browser tabs and link previews.
- **Exemplar:** 128764 (Gratipay). Re-testing previously fixed issues is valuable: partial fixes often close the body injection but leave the title or another render context open.

### 7. Text reflection in an auth-flow error page
- **Endpoint shape:** The auth flow's "problem"/error page on urbandictionary.com (endpoint/payload not stated in the record).
- **Root cause:** Auth-flow pages inject/reflect attacker-supplied text into the page without validation.
- **Impact:** Text injection on the Auth problem page confirmed and fixed.
- **Exemplar:** 189356 (Urban Dictionary). Auth error pages are a distinct hotspot: they take user input (usernames, emails, redirect messages) and render it in error states.

## Bypass / chain notes
- The recurring URL shape `/{anything}/%2f../{text}` was used consistently across programs (Algolia, withinsecurity, ownCloud). The `%2f..` (`/..`) segment appears to serve as a spacer so the trailing attacker text lands as a distinct reflected segment on the error page. If a plain non-existent path doesn't render the text, try the `/%2f../` separator form.
- URL-encode everything in the injected text (spaces as `%20`, slashes as `%2f`) so the full sentence survives routing/normalization and arrives intact at the 404 renderer.
- Chain angle used in the wild: injected text was crafted as "It has been changed by a new one https://www.attacker-domain.com so go to the new one since this one" — i.e., the injection itself IS the phishing lure, redirecting trust to an attacker domain. No multi-step technical chain is needed; the shared link is the chain.
- Diversify render contexts when one is blocked: records show reflection landing in page body (404), page `<title>` (Gratipay), and auth-flow error pages (Urban Dictionary). A fix in one context doesn't cover others — test each.
- Known limiter: on the WHO app domain, Google's 404 page sanitized inputs, so reflection there yielded text injection only with no compromise — identify whose error page stack serves the 404 before estimating impact.

## Gotchas / what NOT to do
- Do not claim XSS. Every payload here is plain text/HTML-stripped. Injecting `<script>alert(1)</script>` and seeing it render as text is a text-injection report, not a cross-site scripting finding (Gratipay #128764).
- Don't assume all 404 reflections pay equally. The WHO record (1065830) was explicitly noted as no-compromise because inputs were sanitized — scope your impact claims to what the render context allows.
- Impact must be framed around abuse of trust (phishing, defacement via link, user trapping), not code execution. The accepted reports here all framed it that way ("claims the site moved to X", "enabling defacement via a shared link", "enabling user trapping").
- Don't stop at one path format: the records show three working shapes — bare non-existent path (`/{text}`), the `/%2f../{text}` spacer form, and protected-prefix forms (`/wp-admin/...`).
- Watch for regressions after fixes. Gratipay's issue was a failed fix of #115284 — if a program fixed a related injection, retest all render contexts (title, body, error pages).
- Fill gaps yourself: several records lack a verbatim payload (Uber #126235 "reflected-attacker-text", Urban Dictionary #189356 none). When reproducing this class, document the exact URL and rendered output — programs triage these faster with a copy-pasteable POC URL.

## Real-world impact examples
- **Algolia (106348):** A crafted 404 URL on www.algolia.com and blog.algolia.com rendered the attacker's sentence claiming the site had moved to crowdcurity.com — a fully on-domain phishing page under the target's brand.
- **withinsecurity (111860):** Injection under the `/wp-admin/` prefix enabled user trapping — victims landing on an admin-looking URL saw attacker-controlled text inside the error page.
- **ownCloud (112304):** The identical `/%2f../` payload rendered attacker text on owncloud.help's 404 page, usable for phishing.
- **Hanno's projects (434670):** `?c=http://www.example.com` reflected attacker-supplied content into the page, enabling defacement of the app's appearance for anyone clicking the shared link.
- **Uber (126235):** Text injection confirmed on a get.uber.com landing page — demonstrating the class pays on high-value, high-traffic domains even without HTML execution.