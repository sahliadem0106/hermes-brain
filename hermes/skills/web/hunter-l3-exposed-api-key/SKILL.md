---
name: hunter-l3-exposed-api-key
description: "Use when hunting Exposed API Key on a target. Loads the L3 technique sheet: This class covers API keys, tokens, and secrets that are exposed outside their intended secret store — hardcoded in mobile APKs, committed to public Git history, or over-permissioned public tokens — a"
domain: cybersecurity
subdomain: web
tags:
- web
- exposed-api-key
- hunting
- l3
version: '1.0'
---

# Exposed API Key — Technique Sheet

## Overview
This class covers API keys, tokens, and secrets that are exposed outside their intended secret store — hardcoded in mobile APKs, committed to public Git history, or over-permissioned public tokens — and that remain valid at the time of testing. It pays because many programs treat leaked-but-never-rotated keys as valid P1/P2 (financial damage, account access, supply-chain overwrite), and the hunt is almost entirely non-intrusive: extract, enumerate, verify against the live API, report. The recurring failure is not leakage alone but absence of restrictions/rotation — the fix is always scoped key restrictions or revocation, so demonstrating live validity is what converts a "finding" into a bounty.

## Distinct sub-patterns

### 1. Unrestricted Google Maps API key hardcoded in an Android APK
- Endpoint shape: APK `app.<package>` — e.g. package `app.zenly.locator`; key is a static string resource / manifest value inside the decompiled APK. Live-usable target is the Google Static Map API: `https://maps.googleapis.com/maps/api/staticmap?...key=<LEAKED_KEY>`
- Payload that actually fired: payload not stated (the key itself was extracted from the APK; no request body involved). Verification consisted of successfully querying the Google Static Map API with the extracted key.
- Root-cause pattern: The Google Maps API key is stored in plain text in the APK (unavoidable for client-side Maps SDK usage) AND the key was missing restrictions — no API restriction (limiting which Google APIs the key can call), no application restriction (binding to package name + signing cert SHA-1). An unrestricted client-side key is fully equivalent to a free-for-all server key.
- Impact proven: Unrestricted key retrievable by anyone from the APK and usable by anyone to query the Google Static Map API — billing abuse / quota exhaustion against the victim's Google Cloud billing (financial damage / DoS). Restrictions were later enforced as the fix.
- Exemplar report: id=1093667 [ajaysenr] — Zenly.

### 2. API key committed to public GitHub history and never revoked
- Endpoint shape: `GET https://api.rs2.usw2.rockset.com/v1/orgs/self/users/self/apikeys` — a management-plane endpoint that enumerates the authenticated org's API keys, used as the liveness oracle for the leaked secret.
- Payload that actually fired (verbatim): `api_key = "skZMJRZSXLZZj5HAdBjNxUfZbarWV5dLqfVO6U623zW5KROzfY0vNRa22ToZfRRe"` — supplied as the authentication credential against the API (Bearer-style key auth), not as a parameter.
- Root-cause pattern: A Rockset API key (note the `sk` prefix — a recognizable, greppable secret format) was committed in an old public GitHub commit and never revoked. The leak itself was historical (an old commit, not HEAD), so scanners/rotation sweeps that only diff recent commits missed it; the key stayed valid for the entire period.
- Impact proven: Verified via the live API that the leaked key was still valid and not revoked — authenticated successfully and listed API keys, confirming one with `created_at 2019-10-22T06:08:37Z` (proving it was the long-lived original, live for years post-leak).
- Exemplar report: id=1094151 [ajaysenr] — Rockset.

### 3. Public API token over-permissioned to full access (privilege misconfiguration, not just exposure)
- Endpoint shape: N/A — a public build API (Ubiquiti's nightly-build API for UniFi firmware). No secret extraction needed: the token is *public by design*; the bug is its permission set.
- Payload that actually fired: n/a (no payload; the write operations were performed with the legitimately public token).
- Root-cause pattern: A public API token was mistakenly granted full-access permission. Exposure of a low-privilege public token is expected in this design; granting it create/overwrite authority turned a public read artifact into a write-capable credential.
- Impact proven: An attacker could create and overwrite nightly builds of UniFi firmware — a firmware supply-chain overwrite primitive (anyone on the build channel could be served attacker-controlled images).
- Exemplar report: id=179986 [ajaysenr] — Ubiquiti Inc.

## Bypass / chain notes
- No multi-step chains were present in the records — all three were single-hop findings. The "chain" in this class is conceptual: leak (APK / git history / public token) → liveness verification (call a benign authenticated endpoint) → impact framing (billing abuse, key enumeration, build overwrite).
- Historical-commit technique: the Rockset key sat in an old commit, not the current tree. Digging through git history (not just HEAD) is what surfaces long-lived unrevoked keys; the 2019 `created_at` timestamp vs. report date is the proof of staleness.
- Liveness-verification pattern: rather than performing a destructive action, authenticate with the leaked key and hit a read-only enumeration endpoint (`/v1/orgs/self/users/self/apikeys`) — this proves validity, scope, and provenance (`created_at`) in one safe call.
- For APK keys: extraction is guaranteed (plain text in the APK is a fact of Android packaging), so the entire bounty hinges on demonstrating the key is *unrestricted* — i.e., a successful API call that a properly restricted key would reject.

## Gotchas / what NOT to do
- Do not report an APK-embedded Google Maps key as a bug if it is properly restricted (API-restricted + app-restricted to package/SHA-1). The bug is the missing restrictions, not the presence of the key. Check restriction status before writing the report.
- Do not exfiltrate data or make destructive writes to prove validity. In the Rockset case, listing API keys was sufficient; a benign authenticated read beats a risky write both ethically and for report acceptance.
- Do not stop at "key found in git" — a dead/rotated key is a non-finding. You must verify the key is still valid against the live service before reporting.
- Do not treat a *public* token as automatically vulnerable: the Ubiquiti bug was the full-access permission grant on a token that was meant to be public. Exposure with correct scoping is not a finding.
- Key formats matter for hunting: greppable prefixes (e.g. `sk`) make secret-scanning in repos/commits tractable; opaque keys in APK resources require decompilation instead.

## Real-world impact examples
- Zenly (1093667): Unrestricted Google Maps API key pulled from the `app.zenly.locator` APK, usable by anyone to hit Google Static Map API — direct billing/quota damage (financial DoS) to Zenly's Google Cloud account; remediated by enforcing restrictions.
- Rockset (1094151): A key leaked in an old public commit authenticated successfully years later, enumerating org API keys including one created 2019-10-22T06:08:37Z — proving org-management-level credential exposure persisted indefinitely.
- Ubiquiti (179986): A public build-API token with mistakenly granted full access allowed creating and overwriting nightly UniFi firmware builds — attacker-controlled firmware distribution to the build channel.