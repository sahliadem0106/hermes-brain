---
name: hunter-l3-forced-browsing
description: "Use when hunting Forced Browsing on a target. Loads the L3 technique sheet: Forced browsing is directly requesting URLs/directories/endpoints that exist on the server but are not linked in the normal UI, because access controls or publishing logic assume \"not linked = not rea"
domain: cybersecurity
subdomain: web
tags:
- web
- forced-browsing
- hunting
- l3
version: '1.0'
---

# Forced Browsing — Technique Sheet

## Overview
Forced browsing is directly requesting URLs/directories/endpoints that exist on the server but are not linked in the normal UI, because access controls or publishing logic assume "not linked = not reachable." It pays when the app ships predictable paths (framework directory conventions, Rails-style REST routes, deep-link handlers) or when a feature is time-gated rather than access-gated. All three records here were found by ajaysenr, and all three are essentially "the blocklist stops one level short" or "the gate checks the wrong thing."

## Distinct sub-patterns

### 1. Path-prefix bypass via `../` in a mobile deep link (mobile forced navigation)
- Endpoint shape: Android intent routed through an `android.intent.action.VIEW` deep-link handler, restricted to a `/admin` path prefix on the app's webview domain:
  `https://{shop}.myshopify.com/admin/...`
- Payload (verbatim):
  ```
  am start -W -a android.intent.action.VIEW -d "https://ravel17.myshopify.com/admin/collections/../../"
  ```
  (via `adb shell`)
- Root cause: The deep-link handler validates that the URI begins with `/admin/`, but does not re-validate the resolved path after normalization. `collections/../../` normalizes to `/`, so the prefix check passes while the webview actually loads the site root — and from there, any attacker-chosen URL. The app webview had JavaScript enabled and the EASDK bridge attached.
- Impact proven: Arbitrary/external URLs loaded in the Shopify Android app webview; JavaScript execution in that context; and via the EASDK bridge, `EASDK.redirect` to `file:///data/data/com.shopify.mobile/shared_prefs/notification_ids.xml` — reading app-sandbox files (shared_prefs contents leak).
- Exemplar report: 1087744 (Shopify)
- Chain (as recorded): (1) create a partner app pointing at a malicious server URL, (2) craft a VIEW intent with `../` to bypass the `/admin` path prefix, (3) arbitrary URL loads in the trusted webview, (4) JS + EASDK bridge gives sandbox file read.

### 2. Directory blocklist misses deeper sibling directories (incomplete deny rule)
- Endpoint shape: static asset tree on the target:
  `GET /static/cm/mode/` plus subdirectories `GET /static/cm/mode/xml/` and `GET /static/cm/mode/django/`
- Payload: none stated — this was discovered by directly requesting unlinked directory paths, not by injecting content.
- Root cause: Access controls explicitly blocked `/static/` and `/static/cm/`, but the deny rules did not extend to `/static/cm/mode/` or its children (`xml/`, `django/` — this is the CodeMirror editor's mode directory, a well-known framework path). The rule set was enumerated by path, not enforced by default-deny.
- Impact proven: Directories that should have been forbidden returned HTTP 200 and their contents were directly accessible.
- Exemplar report: 220150 (Ubiquiti Inc.)
- Hunter heuristic visible in the record: when a path is blocked, enumerate one and two levels deeper with known directory suffixes — the deny list often names parents but not the full subtree.

### 3. Time-gated content at a predictable REST path (route exists before gate opens)
- Endpoint shape: Rails-style route derived from the existing challenge page URL:
  `GET /{challengeName}/scope_versions`
  e.g. `https://hackerone.com/{challengeName}/scope_versions`
- Payload (verbatim, as the record gives it): `https://hackerone.com/{challengeName}/scope_versions`
- Root cause: The scope page `/challengeName` correctly hides scope before a challenge begins, but a sibling route (`/scope_versions`) exposes the same data and was never gated by the challenge start time. Access control was applied to the page, not to the data behind sibling routes.
- Impact proven: Hidden in-scope assets and full scope history of an upcoming HackerOne challenge were viewable before the challenge was announced — an intel advantage over all other participants during a time-boxed contest.
- Exemplar report: 565736 (HackerOne)
- Hunter heuristic visible in the record: once a feature exists in the UI, enumerate its sibling/nested routes (`/scope_versions`, `_history`, `_revisions` style paths) and check whether the gate that protects the primary page was applied to all of them.

## Bypass / chain notes
- `../` suffix is a general-purpose bypass for deep-link / webview allowlists that do a string prefix match instead of comparing the normalized URL. One `../`-laden segment inside an allowed prefix is enough (record 1087744).
- The deep-link finding chained into something much larger than a webview redirect: a partner app + arbitrary URL = attacker-controlled JS inside an app-trusted origin, and the EASDK bridge then converted webview access into local file read (`file:///data/data/com.shopify.mobile/shared_prefs/...`). Forced-navigation → JS execution → sandbox read is the chain worth hunting for on any Android app with an embedded JS bridge.
- Directory findings (record 220150) are about *enumeration depth*: `/static/cm/mode/` succeeded where its parents failed. Extend the blocked path itself by appending known children rather than starting over.
- The scope_versions finding (record 565736) is a route-enumeration bypass of a temporal gate — no filter bypass was needed, just requesting a route the developers forgot to gate.

## Gotchas / what NOT to do
- Don't assume a parent directory being blocked means its children are. Equally, don't assume the UI-visible gate covers sibling routes — check both directions.
- On mobile deep links, a prefix check on the raw string is not a security boundary; test normalization (`../`, and by extension URL-encoded variants) rather than only testing whether the handler opens at all.
- In record 220150, payload and impact were purely read-only directory access — don't oversell "HTTP 200 on a directory" without showing what was exposed or that it should have been forbidden.
- Respect program rules when reading pre-release data: the scope_versions leak's value is as a pre-announcement info leak in a live challenge program; the report was about the gate failing, not about using the intel.
- Payload availability varies: for 220150 and 565736 the records contain no injection-style payload — the "payload" is the unlinked URL itself. Don't fabricate a magic string; forced browsing findings are often just correct URL construction.

## Real-world impact examples
- Shopify (1087744): `am start` with `"https://ravel17.myshopify.com/admin/collections/../../"` loaded attacker URLs in the Shopify Android webview with JS enabled, and EASDK.redirect read `file:///data/data/com.shopify.mobile/shared_prefs/notification_ids.xml` from the app sandbox.
- Ubiquiti (220150): `/static/cm/mode/`, `/static/cm/mode/xml/`, and `/static/cm/mode/django/` returned HTTP 200 despite `/static/` and `/static/cm/` being blocked.
- HackerOne (565736): `https://hackerone.com/{challengeName}/scope_versions` revealed the hidden scope and scope history of an upcoming challenge before it began.