---
name: hunter-l3-hsts-bypass
description: "Use when hunting HSTS Bypass on a target. Loads the L3 technique sheet: HSTS (HTTP Strict Transport Security) bypass bugs live in two places: the client-side enforcement logic (notably curl's HSTS cache implementation) and server-side header emission (malformed/duplicate "
domain: cybersecurity
subdomain: web
tags:
- web
- hsts-bypass
- hunting
- l3
version: '1.0'
---

# HSTS Bypass — Technique Sheet

## Overview

HSTS (HTTP Strict Transport Security) bypass bugs live in two places: the client-side enforcement logic (notably curl's HSTS cache implementation) and server-side header emission (malformed/duplicate `Strict-Transport-Security` headers that cause browsers to ignore the policy). The payoff class is real but mostly low-to-moderate severity: the proven impact is a victim being downgraded from HTTPS to cleartext HTTP (MITM position required for full exploitation), or a client's HSTS database being silently wiped. These bugs pay in "client software" (curl via Internet Bug Bounty) and in web programs where header handling is broken (Uber).

## Distinct sub-patterns

### 1. Trailing-dot hostname not matched against the HSTS cache (client, curl)

- Endpoint shape / parameter: any HTTP URL whose host carries a trailing dot; curl with `--hsts` enabled or built with HSTS support. Template: `http://<host>.` (note the final dot after the TLD).
- Payload that actually fired (verbatim): `http://accounts.google.com.`
- Root cause: the HSTS cache lookup performs an exact hostname string match and does not canonicalize away the trailing dot. `accounts.google.com.` does not match the cached entry for `accounts.google.com`, so the mandatory HTTPS upgrade is skipped and the request goes out in cleartext. The same class of mismatch applies when the URL and the cached entry differ only by the trailing dot.
- Impact proven: HSTS bypassed — an HTTP request to `accounts.google.com.` is served over HTTP and not upgraded to HTTPS. This was filed against curl (CVE-2022-30115 covers the source-code-level trailing-dot mismatch where curl continues using insecure cleartext HTTP instead of HTTPS).
- Exemplar report IDs: 3574928 (curl program), 1565622 (Internet Bug Bounty, CVE-2022-30115).

### 2. HSTS state not carried across serial transfers on one curl command line

- Endpoint shape / parameter: curl CLI with `--hsts`, multiple URLs on the same command line executed serially. Shape: `curl --hsts <file> https://<host> http://<same-host>`.
- Payload that actually fired (verbatim): `curl --hsts "" https://curl.se http://curl.se`
- Root cause: HSTS state learned from the first transfer (the response's `Strict-Transport-Security` header) is not persisted/loaded into the cache that the second, serial transfer consults. The second HTTP URL is therefore never upgraded to HTTPS even though the same host just returned HSTS policy.
- Impact proven: demonstrated that the first URL returns HSTS info which the second URL fails to use — the subsequent HTTP request is not upgraded. Reporter notes no exploit known; it is a bypass of the intended security control.
- Exemplar report ID: 1874715.

### 3. Parallel transfers overwrite the HSTS cache file, losing state for earlier hosts

- Endpoint shape / parameter: curl CLI with `--hsts <file>` combined with `--parallel`, multiple URLs to different hosts. Shape: `curl --hsts <file> --parallel https://<hostA> https://<hostB>`.
- Payload that actually fired (verbatim): `curl --hsts hsts.txt --parallel https://curl.se https://example.com`
- Root cause: with parallel transfers, each completed transfer writes the HSTS cache file independently; the most recently completed transfer's write overwrites the file wholesale, clobbering the HSTS entries learned by earlier-finishing transfers. State for earlier hosts is lost.
- Impact proven: after parallel transfers, a later HTTP-only request to an earlier host is not upgraded to HTTPS because its cache entry was erased (cache overwritten) — bypass of the intended control.
- Exemplar report ID: 1874716.

### 4. Duplicate HSTS headers make the browser ignore the policy (server-side)

- Endpoint shape / parameter: response headers on the root page — `GET /` on a subdomain serving HSTS; here `business.uber.com`. Check for two or more `Strict-Transport-Security` headers in one response.
- Payload that actually fired: payload not stated (no request payload; the finding is purely the duplicated response header observed on `GET /` of business.uber.com).
- Root cause: when a response contains duplicate `Strict-Transport-Security` headers, Firefox ignores the HSTS policy for that host entirely rather than honoring one of them. The domain therefore never enters the browser's HSTS cache.
- Impact proven: demonstrated that duplicate HSTS headers cause Firefox to ignore HSTS on business.uber.com, enabling a temporary HTTPS-to-HTTP downgrade of a targeted user. Requires the user to click an attacker-supplied link (i.e., active attacker + user interaction); rated low impact.
- Exemplar report ID: 221955 (Uber).

### 5. Oversized HSTS cache filename triggers temp-file rename failure that wipes the database

- Endpoint shape / parameter: curl CLI, `--hsts <filename>` where the filename parameter itself is the attack surface. Shape: `curl --hsts <filename longer than 243 bytes> <url>`.
- Payload that actually fired (verbatim): a filename of 256 `a` characters (`aaaa…`, 256 bytes — the report gives the literal 256-char string).
- Root cause: `Curl_fopen` builds the temporary file name as `<filename>.<randomsuffix>.tmp`. When the HSTS filename exceeds 243 bytes, the composed temp name exceeds the 255-byte filesystem limit; the rename/write fails, and the failure path leaves the HSTS cache file truncated/emptied.
- Impact proven: with an HSTS filename longer than 243 bytes, curl truncated the cache file from 179 bytes to 0 bytes, erasing the entire HSTS database — the host's previously pinned HTTPS-only state is destroyed, enabling HSTS bypass (CVE-2023-46219).
- Exemplar report ID: 2236133 (curl program).

## Bypass / chain notes

- No multi-step chains appear in the records — all six findings are single-step bypasses. The chains are implicit, though: each bypass assumes a network attacker (MITM) positioned to exploit the cleartext downgrade.
- Boundary-value attacks on HSTS machinery are a recurring theme: two of the six findings are triggered purely by name/length edge cases (trailing dot; filename > 243 bytes pushing `.<randomsuffix>.tmp` past the 255-byte FS limit). When auditing HSTS implementations, test hostnames with trailing dots and pathological path/filename lengths, not just normal values.
- State-machine gaps in curl's HSTS handling: both the serial-transfer (1874715) and parallel-transfer (1874716) bugs are cache-propagation failures — state learned in one transfer isn't visible to another. Any client that persists HSTS across transfers is a candidate for the same class of bug; test one host's HSTS response against a second request to the same host in the same invocation, and multiple hosts under `--parallel`.
- Server-side: the Uber case shows the bypass needs no crypto at all — a malformed header emission (duplicates) turns off the control in Firefox. Header-duplication checks are cheap and worth running on every in-scope domain.

## Gotchas / what NOT to do

- Do not overrate standalone severity. The Uber duplicate-header finding (221555/221955) was low impact because exploitation requires the targeted user to click a link and an active MITM; reports that claim more than "temporary downgrade of a user who clicks my link" will not match the proven record.
- curl's own team notes on 1874715 that "no exploit is known" — demonstrating the control is bypassed (second request not upgraded) is a valid finding, but don't fabricate a forced-downgrade scenario the tool can't produce.
- Distinguish the two curl filename bugs clearly: 1874716 is a logic bug in `--parallel` cache writing; 2236133 is a filesystem-length bug in the temp-name construction triggered by the cache filename length, not by parallelism.
- The trailing-dot payload ends with a literal dot after the TLD (`http://accounts.google.com.`) — don't strip it or the bypass doesn't fire.
- Filename-length payloads must actually exceed 243 bytes for the temp-name suffix `.<randomsuffix>.tmp` to push past the 255-byte limit; a shorter name won't reproduce CVE-2023-46219.
- These are client-implementation bugs (curl) or server-configuration bugs (Uber) — generic advice like "just send the HSTS header" or "use preload lists" is not in scope for this class and doesn't match any record.

## Real-world impact examples

- CVE-2022-30115 (curl, via Internet Bug Bounty): curl's HSTS check bypassed via trailing-dot host mismatch, tricking curl into continuing to use insecure cleartext HTTP instead of HTTPS (record 1565622; concretely demonstrated in 3574928 with `http://accounts.google.com.`).
- CVE-2023-46219 (curl): HSTS database erased entirely — cache file truncated from 179 bytes to 0 bytes when the `--hsts` filename exceeded 243 bytes, wiping all pinned HTTPS-only hosts (record 2236133).
- Uber (business.uber.com): Firefox ignored HSTS due to duplicate `Strict-Transport-Security` headers, enabling a temporary HTTPS-to-HTTP downgrade of a targeted user who clicks a link (record 221955).
- curl CLI state-loss bugs: HSTS info returned by one transfer not applied to a later serial request to the same host (1874715), and cache file overwritten under `--parallel` so a later HTTP-only request to an earlier host is not upgraded (1874716).