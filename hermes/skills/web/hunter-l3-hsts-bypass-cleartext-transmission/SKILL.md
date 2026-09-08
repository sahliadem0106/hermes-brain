---
name: hunter-l3-hsts-bypass-cleartext-transmission
description: "Use when hunting HSTS Bypass (Cleartext Transmission) on a target. Loads the L3 technique sheet: This class covers bugs in which HTTP Strict Transport Security (HSTS) state — the client-side cache entry that forces a hostname to be reached only over HTTPS — is stored, matched, or applied incorrec"
domain: cybersecurity
subdomain: web
tags:
- web
- hsts-bypass-cleartext-transmission
- hunting
- l3
version: '1.0'
---

# HSTS Bypass (Cleartext Transmission) — Technique Sheet

## Overview

This class covers bugs in which HTTP Strict Transport Security (HSTS) state — the client-side cache entry that forces a hostname to be reached only over HTTPS — is stored, matched, or applied incorrectly, allowing a subsequent request to be sent in cleartext over HTTP. Unlike server-side HSTS misconfigurations (missing `Strict-Transport-Security` headers, short `max-age`, missing `includeSubDomains`), all patterns in this record set are **client-side cache-handling bugs in curl**, a tool installed on billions of machines (and embedded in phones, TVs, CI runners, and countless applications via libcurl). When a client fails to honor HSTS it has legitimately learned, any MITM on the network path can strip HTTPS and capture or modify traffic that the user was told was pinned to TLS.

When it pays: curl accepts client-side HSTS state via `--hsts <file>` (read on startup, written on exit) and maintains an in-memory cache during a session. Any divergence between "what got stored" and "what gets matched" — keyed on the wrong representation of a hostname, scoped incorrectly to a single invocation, or lost to concurrent overwrites — is a bounty-worthy cleartext transmission bug. All three exemplar reports were filed by the same researcher (ajaysenr) against curl / Internet Bug Bounty, which tells you this is a fruitful vein for *source-level review of a single target's HSTS cache implementation* rather than wide bug-class scanning: one careful reader found three distinct defects in the same subsystem. The playbook generalizes to any client or library that persists HSTS state (browsers, mobile SDKs, package managers).

## Distinct sub-patterns

### Sub-pattern 1: IDN key-mismatch — HSTS stored under one encoding, looked up under another

- **Endpoint shape / parameter:** No HTTP endpoint involved; the "parameter" is the hostname representation. The trigger is a hostname whose dot separator is a Unicode ideographic full stop U+3002 (`。`) instead of ASCII `.` — a legitimate internationalized-domain-name (IDN) label separator that browsers and curl accept as equivalent to a dot.
- **Payload that actually fired (verbatim):**
  ```
  curl --hsts hsts.txt https://curl%E3%80%82se
  curl --hsts hsts.txt http://curl%E3%80%82se
  ```
  (`%E3%80%82` is the percent-encoded UTF-8 form of `。`, i.e. the host `curl。se`, which normalizes to `curl.se`.)
- **Root-cause pattern:** curl stores the HSTS cache entry keyed by the **IDN-encoded** (punycode/ACE) form of the hostname, but performs the lookup on the **IDN-decoded (ASCII/Unicode) name**. Because the storage key and the lookup key are different string representations of the same logical host, the cache never matches — the HSTS state is written but can never be read. The result is a complete functional bypass of HSTS for that host: the entry is effectively invisible.
- **Impact that was proven:** Demonstrated that the second request is sent in cleartext over HTTP despite valid, previously-established HSTS state for the host. Confidential data transmitted in that second request goes over the wire unencrypted, exactly as an active network attacker would want.
- **Exemplar report IDs:** 1813831 (Internet Bug Bounty), 1813864 context (curl).
- **Chain (as recorded):** First request to the IDN host (UTF-8 U+3002 instead of `.`) establishes HSTS stored under the IDN-encoded name; second request uses the ASCII-decoded form, misses the cache entry, and proceeds over HTTP.

### Sub-pattern 2: Same-invocation state gap — HSTS learned on request 1 not applied to request 2 in one command line

- **Endpoint shape / parameter:** No endpoint; the parameter is the **multi-URL command-line invocation shape**: `curl --hsts "" <https-url> <http-url>` — two URLs in a single curl process, with an in-memory-only HSTS cache (`--hsts ""` disables persistence to a file, isolating the bug from disk caching).
- **Payload that actually fired (verbatim):**
  ```
  curl --hsts "" https://hsts.example.com http://hsts.example.com
  ```
- **Root-cause pattern:** Within a single curl invocation, HSTS state learned from the first request is **not applied to subsequent requests on the same command line**. The in-memory cache updated after request 1 completes is not consulted (or is consulted as stale/absent) when the second URL's scheme is decided. This is a lifecycle/scope bug: the session cache exists, but the read happens before or instead of the write from the earlier transfer in the same process.
- **Impact that was proven:** Demonstrated that the second request is performed over HTTP even though the first request returned a valid HSTS header. Two fetches of the same host in one command — a completely ordinary usage pattern (e.g. fetch headers, then fetch body) — yield a cleartext request for the second.
- **Exemplar report ID:** 1813864 (curl).
- **Chain (as recorded):** First URL establishes HSTS via the HSTS header; second URL in the same invocation is checked against stale/absent in-memory HSTS state; second request goes over HTTP.

### Sub-pattern 3: `--parallel` cache-write race — concurrent transfers clobber each other's HSTS entries

- **Endpoint shape / parameter:** No endpoint; the parameter is the **parallel transfer mode**: multiple URLs to distinct hosts in one invocation with `--parallel` and a shared `--hsts` cache file.
- **Payload that actually fired (verbatim):**
  ```
  curl --parallel --hsts hsts.txt https://site1.tld  https://site2.tld https://site3.tld
  ```
- **Root-cause pattern:** With `curl --parallel`, concurrent HSTS processing causes **concurrent writes that overwrite each other's entries** in the shared cache, so only one of the contacted sites ends up recorded. The cache-update logic is not serialized or merged across the parallel transfer pool — last-writer-wins, and the losers are silently dropped.
- **Impact that was proven:** Only one of the parallel sites gets an entry in `hsts.txt`. Connections to the other sites are not protected — future requests to those hosts (which the user believes are HSTS-pinned, since the tool was told to persist HSTS state) can be downgraded to cleartext.
- **Exemplar report ID:** 1814333 (curl).
- **Chain (as recorded):** Issue parallel HTTPS requests to multiple sites with a shared HSTS cache; concurrent writes overwrite each other's HSTS cache entries; only one entry survives.

### Sub-pattern taxonomy note

All three defects share one abstract root cause — **the HSTS cache write path and the HSTS cache read path disagree about identity, timing, or atomicity** — but they are three independent, individually reportable bugs:

| # | Dimension that breaks | Variant |
|---|---|---|
| 1 | Identity | Key mismatch: stored under IDN-encoded name, matched against decoded name |
| 2 | Timing/scope | Learned state not visible to later requests in the same process |
| 3 | Atomicity | Concurrent writes lose entries (no serialization/merge) |

## Bypass / chain notes

- **The attacker never touches the client.** These bugs require no adversarial payload in the classical sense — the "exploit" is the client misbehaving on benign input. The exploitability chain in the wild is: (1) victim runs curl (or an app embedding libcurl) and receives a valid HSTS header; (2) cache is populated wrongly or not at all due to one of the three defects; (3) an active network attacker (rogue Wi-Fi, on-path router) strips the HTTPS redirect on the *next* request to the same host, which the client now sends in cleartext because it believes no HSTS entry exists.
- **IDN normalization as an amplifier (record 1813831):** the U+3002 trick works because IDN label separators are valid alternate dot forms. This generalizes to any pipeline where a hostname is normalized in one component and cached/matched in another — the bypass requires only that the two representations diverge. The verification method is purely two curl commands: first establish the entry, then re-request and observe the scheme. Nothing is installed; the cleartext request in the recorded transcript *is* the proof.
- **In-memory isolation as a control (record 1813864):** `--hsts ""` was used to disable the cache file, proving the bug exists in the *session* cache handling itself and is not an artifact of file persistence. Use this technique in your own PoCs to pin down which layer (session cache vs. on-disk cache) the defect lives in.
- **Parallelism as a lossiness multiplier (record 1814333):** the demonstrated loss is "all but one entry" on a three-host run. With N parallel hosts, worst case is one surviving entry out of N — the failure rate scales with the batch, which matters for tooling that fetches many hosts concurrently (mirroring tools, dependency fetchers, fleet scripts).

## Gotchas / what NOT to do

- **This is a client-side class.** None of these records involve a server misconfiguration — don't go testing random websites' HSTS headers under this sheet. The target is the client's HSTS cache implementation (curl here; the same review lens applies to other HSTS-persisting clients).
- **Don't claim the entry "wasn't stored."** In record 1813831 the entry *is* stored — it's stored under a key the lookup never uses. Distinguish "write missing" (records 2 and 3) from "read misses a valid write" (record 1); the root-cause and fix are different, and imprecise claims weaken reports.
- **Don't test IDN variants with a plain ASCII host.** Sub-pattern 1 only fires when the hostname is expressed with an IDN label separator (`%E3%80%82`); the same hostname typed with `.` behaves normally. The divergence is the bug.
- **Single-URL invocations won't reproduce records 2 and 3.** Sub-pattern 2 needs ≥2 URLs in one command line; sub-pattern 3 needs `--parallel` with ≥2 distinct hosts and a shared cache file. Reproducing with separate invocations just exercises the normal file-cache path and will look like a false negative.
- **Don't rely on a single run for the parallel case.** Sub-pattern 3 is a race; a one-off run may happen to keep more than one entry. The recorded impact ("only one of the parallel sites gets an entry") is the demonstrated worst case — verify across repeated runs and check the resulting `hsts.txt` contents directly, not just connection behavior.
- **Scope the impact claim to cleartext transmission.** The proven impact in all three records is that requests are sent over HTTP despite HSTS state — i.e., confidentiality/integrity loss on the network path. Don't over-claim (e.g., don't assert server-side compromise or cookie theft) beyond what the demonstration shows.

## Real-world impact examples

- **Record 1813831 (Internet Bug Bounty):** Two sequential curl invocations against `curl%E3%80%82se` (=`curl.se` via U+3002): the HTTPS request establishes HSTS in `hsts.txt`; the immediately-following HTTP request to the same host is sent in cleartext. Confidential data can be transmitted unencrypted on a connection the HSTS policy was supposed to force onto TLS — demonstrable by any on-path observer.
- **Record 1813864 (curl):** `curl --hsts "" https://hsts.example.com http://hsts.example.com` — the first response carries a valid HSTS header, yet the second URL in the very same command line is fetched over HTTP. Every user who fetches the same host twice per invocation (an extremely common scripting pattern) silently loses HSTS protection for the second fetch.
- **Record 1814333 (curl):** `curl --parallel --hsts hsts.txt https://site1.tld https://site2.tld https://site3.tld` — after the run, `hsts.txt` contains an entry for only one of the three sites. The other two sites have no persisted HSTS protection, so any future connection to them (including from subsequent normal runs that read the cache) can be downgraded to cleartext by a network attacker, indefinitely, because the user's tooling believes it recorded HSTS state and will not re-establish or enforce it.