---
name: hunter-l3-cache-poisoning-dos
description: "Use when hunting Cache Poisoning (DoS) on a target. Loads the L3 technique sheet: Cache Poisoning (DoS) is a class where an attacker manipulates a request element that reaches the origin but is NOT part of the cache key (typically an unkeyed header), forcing the origin to generate "
domain: cybersecurity
subdomain: web
tags:
- web
- cache-poisoning-dos
- hunting
- l3
version: '1.0'
---

# Cache Poisoning (DoS) — Technique Sheet

## Overview

Cache Poisoning (DoS) is a class where an attacker manipulates a request element that reaches the origin but is NOT part of the cache key (typically an unkeyed header), forcing the origin to generate an error response (301 loop, 404, or a CORS-breaking response) that the cache then stores and serves to all subsequent users. Unlike classic cache poisoning (which injects malicious content for XSS), the payload here is purely destructive — the goal is denial of service of a specific resource or entire page. It pays when the target sits behind a CDN/edge cache (Cloudflare, Fastly, etc.) and any backend behavior varies on unkeyed request headers.

## Distinct sub-patterns

### 1. Unkeyed scheme header → cached self-referential 301 redirect loop

- Endpoint shape: `GET /assets/static/js/{num}.chunk.js` (any cached static asset)
- Param: `x-forwarded-scheme` header (unkeyed)
- Payload (verbatim):
  ```
  GET /assets/static/js/8.9572d249.chunk.js?hackerone=poc HTTP/2
  Host: hackerone.com
  x-forwarded-scheme: http
  ```
- Root cause: The backend respects `x-forwarded-scheme` and issues a 301 redirect to the `http://` version of the same URL. The cache stores that 301 as the cached response for the URL. Subsequent requests get the cached 301 pointing back to the same URL → permanent redirect loop.
- Impact: With a cache-buster, demonstrated the JS chunk becomes a permanent 301 loop and is inaccessible. Same technique works on any cached static file — pages depending on those assets lose availability (partial DoS).
- Exemplars: HackerOne #1181946 (hackerone.com).

### 2. Unkeyed forwarded-host header → backend error → cached 404

- Endpoint shape: `GET /` on the target site (e.g. developer.mozilla.org)
- Param: `X-Forwarded-Host` header (unkeyed)
- Payload: `X-Forwarded-Host: invalid.local`
- Root cause: An attacker-supplied `X-Forwarded-Host` value causes a backend error, producing a 404 response. The cache keys on URL only (host is forwarded, not keyed) and stores the 404, then serves it to all users.
- Impact: Persistent 404 for the page for all users — developer.mozilla.org effectively inaccessible indefinitely.
- Exemplars: Mozilla #1976449 (developer.mozilla.org).

### 3. Internal routing header → forced 404 cached at the edge

- Endpoint shape: `GET /?cb={num}` (cache-buster query param on the root page)
- Param: `X-CF-APP-INSTANCE` header
- Payload: `X-CF-APP-INSTANCE: xxx:1`
- Root cause: A malformed `X-CF-APP-INSTANCE` header (Cloud Foundry gorouter routing header) forces the gorouter to return 404; the fronting web cache stores that 404 as the cached response for the URL.
- Impact: Cache-poisoned 404 served to new users (cache keyed on Cookie) → denial of service; the error also leaked an internal hostname (info disclosure bonus).
- Exemplars: GSA Bounty #728664.

### 4. Origin-echoing JSON API cached without Origin in the key → CORS DoS

- Endpoint shape: `GET /wp-json/` (WordPress REST API root)
- Param: `Origin` header (unkeyed but reflected)
- Payload: `fetch('https://en.instagram-brand.com/wp-json/')` with an arbitrary Origin header
- Root cause: The `wp-json` endpoint echoes the request `Origin` into `Access-Control-Allow-Origin`, but the edge cache does not key on the Origin value. An attacker's arbitrary Origin gets baked into the cached CORS response headers.
- Impact: Cached response carries a mismatched `Access-Control-Allow-Origin`, so legitimate cross-origin consumers of wp-json fail the CORS check and are denied service (client-side DoS of the API for third-party origins).
- Exemplars: Automattic #921704 (en.instagram-brand.com).

## Bypass / chain notes

- Cache-buster query param (`?cb={num}`, `?hackerone=poc`) is required to target a fresh cache entry when demonstrating — append an arbitrary unused param so the poisoned entry maps to a URL the target actually requests (or in the H1 case, to prove the mechanism without breaking the real asset for everyone immediately).
- Cache-key mismatch is the universal enabler in all four records: the offending header (scheme, forwarded host, CF app instance, Origin) influences the origin's response but is excluded from the cache key. Look for reflected/unkeyed headers with `param miner`-style tooling or by observing response variation.
- Bonus leakage from the same primitive: the GSA case leaked an internal hostname in the cached error — check error bodies of induced responses for internal infrastructure names.
- No multi-step chains were present in these records; each is a single-request poison. The "chain" impact comes from the cache's long TTL serving the bad response indefinitely.

## Gotchas / what NOT to do

- Do not poison a production cache entry for a real, un-busted URL on a live target without program guidance — the impact is that every user gets the broken response until the cache expires or is purged. Use a cache-buster during testing and be explicit about it in the report (as the H1 report did).
- A "no real DoS was demonstrated" caveat matters: showing the mechanism on a busted URL is usually sufficient evidence; crashing the actual asset for all users is disproportionate.
- Don't assume every header that changes the response is exploitable — the header must NOT be part of the cache key. If it's keyed, each variation is cached separately and only the attacker is affected.
- Origin-echo (sub-pattern 4) is client-side DoS of CORS consumers, not server-side — don't oversell it as full-site outage; frame it as denial of service to legitimate cross-origin API consumers.
- Header names vary by backend: `x-forwarded-scheme` (scheme handling), `X-Forwarded-Host` (host reconstruction), `X-CF-APP-INSTANCE` (Cloud Foundry gorouter), `Origin` (CORS echo). Test the header class relevant to the target's stack, not all blindly.

## Real-world impact examples

- hackerone.com (#1181946): a single request with `x-forwarded-scheme: http` turned a production JS chunk into an infinite 301 loop for any cached fetch — any cached static file was vulnerable, threatening availability of every page depending on those assets.
- developer.mozilla.org (#1976446 / #1976449): `X-Forwarded-Host: invalid.local` caused the homepage to be cached as a 404, making the site inaccessible to all users indefinitely.
- GSA (#728664): `X-CF-APP-INSTANCE: xxx:1` poisoned the root page into a cached 404 for new users, plus disclosed an internal hostname in the error.
- en.instagram-brand.com (#921704): cached arbitrary-Origin CORS headers on `/wp-json/` broke legitimate cross-origin API consumers via failed CORS checks.