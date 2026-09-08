---
name: hunter-l3-web-cache-deception
description: "Use when hunting Web Cache Deception on a target. Loads the L3 technique sheet: Web Cache Deception (WCD) tricks a cache (CDN/proxy) into storing a victim's authenticated, personalized page under a URL that looks like a static asset."
domain: cybersecurity
subdomain: web
tags:
- web
- web-cache-deception
- hunting
- l3
version: '1.0'
---

# Web Cache Deception — Technique Sheet

## Overview
Web Cache Deception (WCD) tricks a cache (CDN/proxy) into storing a victim's authenticated, personalized page under a URL that looks like a static asset. The attacker sends the victim a link whose path is decorated with a static-file extension (`.css`, `.js`), the origin happily renders the dynamic/authenticated response for that path, and the cache stores it because the extension says "static." Anyone — including an unauthenticated attacker in incognito — can then fetch that exact URL and read the victim's private page contents. It pays when the cached page embeds sensitive data: profile info, CSRF tokens, API keys, or auth tokens, all retrievable with no cookies at all.

## Distinct sub-patterns

### 1. Path-extension spoofing with `.css` on a documentation/help site (Shopify)
- **Endpoint shape:** `GET /es/manual/your-account/copyright-and-trademark/{random-string}.css`
  - Template: take any authenticated page URL, append `/` + arbitrary junk + `.css`.
- **Payload (verbatim):** `https://help.shopify.com/es/manual/your-account/copyright-and-trademark/abcdefg.css`
- **Root cause:** The cache server classified the response as cacheable based on the `.css` extension in the URL, while the origin returned an authenticated 404 page that contained user data. The mismatch — extension-based cacheability vs. origin rendering a personalized (even 404) body — is the whole bug. Notably the victim's own error page is the leak vehicle.
- **Impact proven:** The attacker retrieved the authenticated user's cached 404 page containing first/last name, username, email, profile picture, and a valid CSRF token — all without needing any cookies. A variant on `hatchful.shopify.com` leaked the authenticated user's API key.
- **Exemplar:** id=1271944 (ajaysenr, Shopify).

### 2. Static extension `.js` mapping onto a personalized content route (Chaturbate)
- **Endpoint shape:** `GET /my_collection/min.js`
  - Here the suffix isn't a trailing arbitrary string but a fake asset filename (`min.js`) appended to an existing personalized path, mimicking a common bundle filename.
- **Payload (verbatim):** `https://chaturbate.com/my_collection/min.js`
- **Root cause:** The server serves the personalized `/my_collection/` content for `/my_collection/min.js` and the cache stores it as a static `.js` asset. The origin has no strict route matching — any suffix resolves to the dynamic handler — so the private page becomes publicly retrievable under a cacheable-looking name.
- **Impact proven:** In an incognito browser with no authentication, visiting `/my_collection/min.js` returned all account details and token information of the logged-in user who had been lured to the URL.
- **Exemplar:** id=397508 (ajaysenr, Chaturbate).

### 3. `.css` suffix on a post-registration confirmation page (Semrush)
- **Endpoint shape:** `GET /en/register/confirmation/success/none.css`
  - Template: append `.css` (here as `none.css`) to the last path segment of a personalized authenticated page.
- **Payload:** payload not stated (the report is the suffix pattern itself; the trigger URL is the endpoint above).
- **Root cause:** The cache serves the dynamic personalized page when a static-looking `.css` path is appended, caching the private content publicly. Same extension-vs-origin mismatch as the Shopify case, applied to a transient but authenticated confirmation page.
- **Impact proven:** An unauthenticated attacker visiting the cached `/success/none.css` URL saw the earning state information (and token info) of an authenticated user's account.
- **Exemplar:** id=439021 (ajaysenr, Semrush).

**Cross-pattern observation:** all three records are the same core exploit with different delivery surfaces — (a) authenticated 404 body (Shopify), (b) route suffix laxness with a bundle-style filename (Chaturbate), (c) plain suffix on a confirmation page (Semrush). The extension used is `.css` or `.js` in every case; no header-based (e.g., `Accept: text/css`) or delimiter-based variants (`;`, `?`, `//`, `%0A`) appear in these records — stick to what fired.

## Bypass / chain notes
The standard 3-step chain seen in all records:
1. **Lure:** get a logged-in victim to visit the decorated URL (random string + static extension appended to an authenticated path). The random segment (e.g., `abcdefg`) ensures a fresh cache key the attacker controls and that no legit asset collides with it.
2. **Poison/deposit:** the origin renders the authenticated/personalized content for the decorated path; the cache classifies it as static (via the extension) and stores it publicly under that URL.
3. **Retrieve:** the unauthenticated attacker simply GETs the decorated URL and receives the victim's page — names, email, username, profile picture, CSRF tokens, API keys, or account/token info, depending on the target.

Delivery notes: the victim must actually visit the URL while authenticated for that cache key to be populated; the attacker's retrieval needs no session. On Shopify, the leaked CSRF token is directly reusable (no cookies needed to exploit it), and the `hatchful.shopify.com` variant escalates the same primitive to full API-key disclosure.

## Gotchas / what NOT to do
- Don't append the extension to arbitrary paths blindly — it must be a path where the origin returns the *victim's personalized content* (even a personalized 404 works at Shopify; a generic unauthenticated 404 leaks nothing).
- Don't reuse an extension/path that the origin normalizes or strips before rendering — the origin must serve dynamic content at the decorated URL for the cache to be poisoned with anything useful. (Chaturbate only worked because `/my_collection/min.js` resolved to the personalized handler.)
- Don't assume the response is sensitive just because the page is authenticated — the pay-off depends on what's embedded in the body. In these records the wins were CSRF token, API key, and account/token details; confirm the body actually contains exploitable data before reporting.
- Use a unique random segment per test (e.g., `abcdefg.css` style); a predictable or pre-existing path may hit an existing cached asset instead of caching the victim's response.
- The victim interaction is required — you cannot self-poison from an unauthenticated position in these patterns; the cache entry must be created by a logged-in user.

## Real-world impact examples
- **Shopify (id=1271944):** cached authenticated 404 page exposed first/last name, username, email, profile picture, and a **valid CSRF token** to anyone; variant on hatchful.shopify.com exposed the **user's API key**.
- **Chaturbate (id=397508):** `/my_collection/min.js` served from cache in an incognito browser returned **all account details and token information** of the logged-in victim.
- **Semrush (id=439021):** cached `/en/register/confirmation/success/none.css` revealed the victim's **earning state information and token info** to an unauthenticated visitor.