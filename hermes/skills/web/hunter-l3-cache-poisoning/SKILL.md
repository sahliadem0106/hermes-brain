---
name: hunter-l3-cache-poisoning
description: "Use when hunting Cache Poisoning on a target. Loads the L3 technique sheet: Cache poisoning abuses discrepancies between how an origin/CDN builds its cache key and how it processes a request, letting an attacker store a malicious or harmful response that is then served to every other user under a legitimate key."
domain: cybersecurity
subdomain: web
tags:
- web
- cache-poisoning
- hunting
- l3
version: '1.0'
---

# Cache Poisoning — Technique Sheet

## Overview
Cache poisoning abuses discrepancies between how an origin/CDN builds its cache key and how it processes a request, letting an attacker store a malicious or harmful response that is then served to every other user under a legitimate key. It pays when the poisoned resource is broadly requested (homepage assets, shared JS bundles, patch notes, embed endpoints) and the cache layer (Cloudflare, Fastly, Varnish, Squid, Akamai) honors attacker-controlled but unkeyed inputs. Impact ranges from full XSS/content-injection in the target origin's context to site-wide DoS by caching error/empty responses. The recurring fingerprint is "the cache stores a response that differs from what the origin would serve to a normal user."

## Distinct sub-patterns

### 1. Unkeyed header on a non-versioned route → cached 404 (Fastify/Accept-Version)
- **Endpoint shape:** `GET /` (any valid Fastify route that is NOT registered as versioned)
- **Payload (verbatim):** `Accept-version: tada`
- **Root cause:** Fastify's default versioned-route behavior returns 404 for any request carrying an `Accept-Version` header when the target route is non-versioned. Responses are not `Vary`-tagged on this header, so a CDN can key the response only on the URL and store the 404.
- **Impact:** `curl -v -H 'Accept-version: tada' http://localhost:9000` returned HTTP 404 for a fully valid route; behind a default Fastly/Varnish config an attacker caches the 404 in place of the functional URL (CVE-2020-7764).
- **Exemplars:** 1025575 (Node.js third-party modules / Fastify)

### 2. Unkeyed junk header → cached malformed error response (CDN misses header in key)
- **Endpoint shape:** `GET /patches/gtaiv/notes_title_update_6/GTAIVPC_TU6_Patch_Notes_FR.txt?donotpoisoneveryone=1` (Host: updates.rockstargames.com)
- **Payload (verbatim):** request line + `Host: updates.rockstargames.com` + header `trailer: 1`
- **Root cause:** The CDN did not include the `trailer` header in its cache key. A header value the origin mishandled produced a malformed 400, which the cache then stored under the normal URL key.
- **Impact:** Legitimate users requesting the patch-notes file received the cached malformed 400 — effective DoS on that content.
- **Exemplars:** 1219038 (Rockstar Games)

### 3. Non-standard HTTP methods + rewrite headers on CDN-cached static assets
- **Endpoint shape:** `GET /webpack-runtime-{hash}.js?cachebust=exodus` (Cloudflare-cached static JS/CSS on www.exodus.com)
- **Payload (verbatim):**
  ```
  ERROR /webpack-runtime-d5cfa86b8e358efc5db3-v2.js?cachebust=exodus HTTP/1.1
  Host: www.exodus.com
  ```
  and
  ```
  GET /webpack-runtime-d5cfa86b8e358efc5db3-v2.js?cachebust=exodus HTTP/1.1
  Host: www.exodus.com
  x-rewrite-url: /root
  ```
- **Root cause:** Cloudflare cached the static assets, but the origin/CDN combo responded to (a) non-standard HTTP methods (`ERROR`) and (b) `x-rewrite-url` / `x-original-url` headers without keying on them, so mismatched responses landed under the canonical asset key.
- **Impact:** Cached webpack-runtime JS replaced with a "501 Not Implemented" response, breaking core functionality for all users; the rewrite headers also triggered the Exodus firewall.
- **Exemplars:** 1581454 (Exodus)

### 4. Path-traversal segment confusion in URL-parsing regex → cross-product cache key collision
- **Endpoint shape:** no fixed endpoint; crafted link URL: `https://amazon.ca/dp/[VICTIM-PRODUCT-ID]/../[ATTACKER-PRODUCT-ID]`
- **Payload (verbatim):** `https://amazon.ca/dp/[VICTIM-PRODUCT-ID]/../[ATTACKER-PRODUCT-ID]`
- **Root cause:** The URL-parsing regex for Amazon affiliate links (used by Linkpop) did not normalize `..` path segments. The crafted URL normalized to the attacker's product on the origin side but was cached under the victim product's cache key.
- **Impact:** When a victim added their legitimate Amazon product to Linkpop, the attacker-controlled product was displayed and linked instead; the victim's page's link button led to the attacker's product (content swap on the victim's page).
- **Exemplars:** 1848940 (Shopify / Linkpop)

### 5. HTTP-method-override header honored → cached empty 200
- **Endpoint shape:** `GET https://addons.allizom.org/static-server/img/addon-icons/default-64.d144b50f2bb8.png?dontpoisoneveryone=1` (Mozilla addons stage; static resources pattern)
- **Payload (verbatim):** `curl -H "X-HTTP-Method-Override: HEAD" https://addons.allizom.org/static-server/img/addon-icons/default-64.d144b50f2bb8.png?dontpoisoneveryone=1`
- **Root cause:** The origin honored `X-HTTP-Method-Override: HEAD` and returned an empty 200 body, which the cache stored under the normal GET key (the override header was not in the key and the empty-body response wasn't rejected).
- **Impact:** A homepage image and a JS file became unavailable to all users after the attacker requested them with the override header.
- **Exemplars:** 2860983 (Mozilla)

### 6. Unsanitized parameter reflected into cached JS (persisted JS injection / null-byte DoS)
- **Endpoint shape:** `GET /embed/job_board/js?for={customer_key}`
- **Payload (verbatim, abbreviated):** `for=surveymonkey%00%00%00...(thousands of NULL bytes)...00654321&token=1234567`
- **Root cause:** The `for` parameter was copied verbatim into the generated JS (`Grnhse.Settings` — boardURI/applicationURI) without sanitization, and the generated JS file was cached, persisting the injection for all subsequent visitors.
- **Impact:** Arbitrary strings and thousands of NULL bytes injected into the cached JS; the oversized applicationURI made job-application iframes fail with `ERR_CONNECTION_CLOSED`, denying service to customer job boards.
- **Exemplars:** 334709 (Greenhouse.io)
- **Note:** "token=1234567" was included in the payload; the report did not state its exact role. Payload beyond the abbreviation above is not stated verbatim (the report indicates thousands of `%00` bytes).

### 7. Cache-key normalization flaw in a proxy (URL userinfo decoding) → cross-origin key collision
- **Endpoint shape:** `GET ftp://` (or `https://`) requests through a Squid proxy
- **Payload (verbatim):** `GET ftp://hackerone.com%2f%3f@192.168.122.1:8080/payload HTTP/1.1`
- **Root cause:** Squid decoded the URL userinfo (`%2f`→`/`, `%3f`→`?`) when building the cache key, so differently-encoded URLs — spanning different domains — mapped to the same cache entry. The attacker poisons the entry under their own domain, and victims requesting the real domain hit it.
- **Impact:** Requests to legitimate domains (e.g. hackerone.com) returned attacker-controlled content (confirmed via `X-Cache: HIT`), including JS executing in the target domain's context — full content spoof/XSS-class impact.
- **Chain (from record):** (1) Insert encoded `%2f%3f` in the userinfo before `@`; (2) poison the cache key for the attacker-controlled domain; (3) victim requests the real domain and receives poisoned content.
- **Exemplars:** 824753 (Internet Bug Bounty / Squid)

## Bypass / chain notes
- **Cache-busting query strings** appear in two payloads (`?donotpoisoneveryone=1` on Rockstar, `?cachebust=exodus` on Exodus, `?dontpoisoneveryone=1` on Mozilla) — a safety/courtesy convention to make the poisoned entry visibly testable and avoid poisoning the live production key while demonstrating the technique. Note these still share the key if the cache ignores the query param; in the Mozilla case the query was part of the demonstration URL.
- **Method confusion:** two independent records (Exodus `ERROR` method; Mozilla `X-HTTP-Method-Override: HEAD`) show that anything that makes the origin produce a non-canonical response body — a bogus method or a body-stripping override — becomes poison if the cache doesn't key on or reject it.
- **Unkeyed header classes seen:** `Accept-Version` (Fastify), `trailer` (Rockstar), `x-rewrite-url` / `x-original-url` (Exodus). The test method is uniform: send the header on a cached URL and re-request without it; a different response on replay = poisoning.
- **Multi-step chains observed:** Squid userinfo collision (attacker domain → victim domain, 3 steps, record 824753); Fastify Accept-Version (request → 404 → CDN stores, record 1025575).
- **Key-collision mindset:** two records exploit the key side rather than unkeyed inputs — path `..` normalization (Shopify/Linkpop) and userinfo decoding (Squid). If the origin normalizes a URL differently than the cache, the cache key and the served content diverge.

## Gotchas / what NOT to do
- Do NOT poison production cache keys without mitigation: every record here uses a clearly-labeled cache-bust parameter (`donotpoisoneveryone=1`, `dontpoisoneveryone=1`, `cachebust=exodus`) or a staging host (`addons.allizom.org` is Mozilla's staging domain). Copy this convention.
- Do NOT assume the header is unkeyed from one response — verify by replaying the clean URL and checking for the poisoned response (`X-Cache: HIT` was the confirmation in record 824753).
- Do NOT spray thousands of NULL bytes without bounding the test — record 334709 caused real connection failures (`ERR_CONNECTION_CLOSED`) for job applicants; scope and document.
- The Exodus record shows cache-poisoning probes can trip the target firewall (`x-rewrite-url` triggered it) — expect WAF noise and report accordingly.
- A response that is only different for *you* (e.g., personalized, Set-Cookie'd, or `Vary`-tagged correctly) is not a finding — every confirmed record here produced a response shared across users.

## Real-world impact examples
- **DoS via cached 400:** Rockstar patch-notes file (1219038) — all users got a malformed 400.
- **Core JS broken site-wide:** Exodus webpack-runtime replaced with 501 (1581454); Mozilla homepage image + JS unavailable (2860985 → 2860983).
- **Content/product swap:** Shopify Linkpop victims saw and linked the attacker's Amazon product instead of their own (1848940).
- **JS injection persistence:** Greenhouse `for` param injection persisted in the cached embed JS, breaking application iframes (334709).
- **Cross-domain content injection / JS in target origin context:** Squid userinfo collision served attacker content with `X-Cache: HIT` on hackerone.com (824753) — the highest-severity pattern in the set.
- **Framework-level CVE:** Fastify `Accept-Version` 404 caching (1025575, CVE-2020-7764) — poisoned 404 replaces a functional URL behind default Fastly/Varnish.