---
name: hunter-l3-web-cache-poisoning
description: "Use when hunting Web Cache Poisoning on a target. Loads the L3 technique sheet: Web cache poisoning is a response-manipulation class where an attacker gets malicious or malformed content stored in a shared cache (CDN, reverse proxy, revalidation cache), so that the poisoned response is served to other, unrelated users."
domain: cybersecurity
subdomain: web
tags:
- web
- web-cache-poisoning
- hunting
- l3
version: '1.0'
---

# Web Cache Poisoning — Technique Sheet

## Overview

Web cache poisoning is a response-manipulation class where an attacker gets malicious or malformed content stored in a shared cache (CDN, reverse proxy, revalidation cache), so that the poisoned response is served to other, unrelated users. It pays when a cache accepts attacker-controlled input (unkeyed headers or URL components) that is reflected into the cached response, or when the cache key omits user-authentication state. Because the payload persists in the cache and hits every subsequent visitor of that URL, impact scales far beyond a self-reflected bug — DoS, stored XSS, credential/token leakage, and link hijacking are all proven outcomes in the records.

## Distinct sub-patterns

### 1. Unkeyed port header reflection (X-Forwarded-Port / X-Forwarded-URL + URL params)

- Endpoint shape: `GET /zh-cn/careers/` (localized marketing/careers pages behind a CDN)
- Parameters: `x-forwarded-port` (header), `x-forwarded-url` (header), arbitrary URL query params
- Payload (verbatim): `x-forwarded-port: zwrtxqvas9lm4kzkia` sent together with a cache-buster `yig1bt7ai4` query param
- Root cause: the CDN built its cache key without these unkeyed inputs (forwarded-port/url headers and URL params), while the application reflected them into the response — so a crafted request's output got cached and served to other visitors
- Impact: poisoned cached page served to all visitors of `/zh-cn/careers/`; enables DoS or distribution of malicious code if reflected XSS is present
- Exemplar: id=1010858 (Acronis)

### 2. Host header poisoning with port manipulation (Host used in page content)

- Endpoint shape: `GET /` on a themes/marketplace subdomain (e.g. `themes.shopify.com`)
- Parameter: `Host` header
- Payload (verbatim): `Host: themes.shopify.com:1337` with cache-buster `?g4mm4=hitthecache`
- Root cause: the Host header is reflected into the page (the canonical link) and is part of the cache key, so a single crafted request poisons the shared entry for the homepage — every subsequent visitor gets the :1337 variant
- Impact: homepage served canonical/asset URLs with port `:1337`, breaking images, CSS, and links for all visitors (cache-wide DoS)
- Exemplar: id=1096609 (Shopify)
- Chain as reported: (1) send request with `Host: themes.shopify.com:1337` plus a cache-buster query to poison the cache; (2) all visitors to the homepage receive the poisoned response

### 3. X-Forwarded-Host reflection into cached pages (arbitrary host → XSS/defacement/malware hosting)

- Endpoint shape: `GET /` (community/forum homepage, e.g. help.nextcloud.com)
- Parameter: `X-Forwarded-Host` header
- Payload (verbatim): `cyberjutsu.io/#`
- Root cause: the application reflected `X-Forwarded-Host` into cached responses with no validation — attacker-controlled host is baked into the cached page
- Impact: attacker host reflected in cached pages for all users → stored XSS, defacement, and malware hosting potential
- Exemplar: id=429747 (Nextcloud)
- Chain as reported: (1) send requests with `X-Forwarded-Host: cyberjutsu.io/#` to cache the page; (2) cached page reflects the attacker host to all users

### 4. X-Forwarded-Host revalidation-cache poisoning → victim token leakage

- Endpoint shape: `GET /s/smule_groups/user_groups/{username}` (per-user profile page)
- Parameter: `X-Forwarded-Host` header
- Payload (verbatim): `X-Forwarded-Host: localhost`
- Root cause: the page reflects `X-Forwarded-Host` into its links and responses are cached (revalidate-type caching) — a poisoned response causes a victim's subsequent requests to go to the attacker-controlled host
- Impact: disclosure of the victim's CSRF token and other sensitive information, enabling CSRF attacks against the victim
- Exemplar: id=504514 (Smule)
- Chain as reported: (1) request the page with `X-Forwarded-Host` pointing to an attacker host; (2) poisoned response is cached (revalidate-type caching); (3) victim loads the page and their browser sends requests (carrying the CSRF token) to the attacker's host

### 5. Auth-state-blind cache key → cross-user session/page disclosure

- Endpoint shape: `GET /shop/trends/{category}` with a junk path suffix, e.g. `https://www.lyst.com/shop/trends/mens-dress-shoes/blahblah.css`
- Parameter: URL path (attacker-controlled `.css`-suffixed suffix used as a cache-buster)
- Payload (verbatim): `https://www.lyst.com/shop/trends/mens-dress-shoes/blahblah.css`
- Root cause: the server caches personalized pages keyed only by URL, not by authentication state — a logged-in user's response gets stored under that URL key
- Impact: a non-logged-in / private-mode visitor was shown as LOGGED IN on the cached page and saw the logged-in user's email, name, and member id — direct PII disclosure via the cache
- Exemplar: id=631589 (Lyst)

### 6. X-Forwarded-Host reflection into page links / share buttons

- Endpoint shape: `GET /partners/blog/{slug}` (blog posts under /partners/)
- Parameter: `X-Forwarded-Host` header
- Payload (verbatim): `X-Forwarded-Host: your_hackerz_site.com`
- Root cause: the `X-Forwarded-Host` value is reflected into the page and cached without URL cache keys, so links in the cached page are rewritten to the attacker's domain
- Impact: poisoned cached page so its links (e.g. the Facebook share button) point to the attacker's domain — link hijacking / traffic redirection
- Exemplar: id=977851 (Shopify)

## Bypass / chain notes

- Cache-busters are used to target a fresh cache entry without poisoning the live homepage during testing: arbitrary query params (`?g4mm4=hitthecache`, `yig1bt7ai4`) or junk path suffixes (`/blahblah.css`). Test on a buster first, then demonstrate on the real URL once impact is proven.
- Header-family testing pattern seen across records: try the whole forwarded-header family — `X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-URL`, and the raw `Host` header (including non-standard ports). Three of six records fired on `X-Forwarded-Host` alone.
- Chain (Smule, id=504514): reflection → revalidate-type caching → victim's browser makes subresource requests to the attacker host → CSRF token exfiltration. Poisoning plus reflection into links converts a "cosmetic" header reflection into credential theft.
- Chain (Shopify themes, id=1096609): Host reflected into canonical link + included in cache key means a single request poisons the whole homepage cache — asset URLs with a dead port break every visitor's page render.
- Payload normalization trick (Nextcloud, id=429747): appending `#` to the host (`cyberjutsu.io/#`) trims/reframes how the reflected host renders into URLs — useful when reflection lands mid-URL.

## Gotchas / what NOT to do

- Don't poison the production homepage URL during initial testing — use cache-busters (query param or path suffix) so you don't break the site for real users. Poisoning `themes.shopify.com` with `:1337` broke images/CSS/links for everyone; demonstrate impact, then report immediately rather than letting a destructive payload linger in the cache.
- Don't assume only `Host` matters — `X-Forwarded-Host`, `X-Forwarded-Port`, and `X-Forwarded-URL` are separate unkeyed inputs and each may be reflected and cached independently (Acronis fired on port/url; Shopify and Smule fired on forwarded-host).
- Don't report header reflection alone as poisoning — you must show the response actually gets cached and served to another user/session (the Acronis, Nextcloud, Smule, and Shopify records all demonstrate the poisoned response being served to other visitors).
- Don't overlook the URL path itself as a poisoning/keying surface (Lyst): the bug there wasn't a header — it was the cache key omitting auth state, found via a junk `.css` path suffix.
- Watch the local-vs-remote distinction in impact: `X-Forwarded-Host: localhost` (Smule) still caused cross-victim token leakage — the payload host doesn't need to be a public attacker domain for the bug to count.

## Real-world impact examples

- Acronis (id=1010858): a poisoned cached `/zh-cn/careers/` page was served to other visitors — DoS or malicious-code distribution vector.
- Shopify themes.shopify.com (id=1096609): every homepage visitor received canonical/asset URLs with port `:1337`, breaking images, CSS, and links site-wide (cache-wide DoS).
- Nextcloud help site (id=429747): attacker host `cyberjutsu.io/#` baked into cached pages for all users — stored XSS, defacement, malware hosting.
- Smule (id=504514): victim's CSRF token and sensitive info disclosed via poisoned revalidation cache → CSRF attacks.
- Lyst (id=631589): anonymous/private-mode visitor served a logged-in user's page showing their email, name, and member id — direct PII disclosure through the cache.
- Shopify partners blog (id=977851): cached blog page's links (Facebook share button) rewritten to the attacker's domain.