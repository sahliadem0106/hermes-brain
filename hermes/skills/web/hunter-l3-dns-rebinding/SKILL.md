---
name: hunter-l3-dns-rebinding
description: "Use when hunting DNS Rebinding on a target. Loads the L3 technique sheet: DNS rebinding is a browser- and server-side trust attack: a hostname you control first resolves to an attacker IP (to pass any \"must not be a remote/attacker address\" check), then re-resolves to a private/loopback target (e.g."
domain: cybersecurity
subdomain: web
tags:
- web
- dns-rebinding
- hunting
- l3
version: '1.0'
---

# DNS Rebinding — Technique Sheet

## Overview

DNS rebinding is a browser- and server-side trust attack: a hostname you control first resolves to an attacker IP (to pass any "must not be a remote/attacker address" check), then re-resolves to a private/loopback target (e.g. 127.0.0.1) so a victim's browser — or an application's own DNS resolution — silently talks to internal-only services. It pays whenever an application validates *hostnames* rather than resolved IPs, has a TOCTOU gap between validation and use, or exposes unauthenticated local services (debuggers, local HTTP servers) reachable via a browser. In the records it yielded full RCE via the Node.js inspector, a CTF flag via a localhost check bypass, and cross-origin disclosure of a user's torrent downloads.

## Distinct sub-patterns

### 1. TOCTOU target-check bypass via dual-IP rebinding (rbndr.us)

- **Endpoint shape / parameter:** `GET /attack-box/launch` with parameter `payload` — a base64 JSON blob of the form:
  `{"target":"<hostname>","hash":"<md5 hex>"}`
- **Payload that actually fired (verbatim):**
  ```
  eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyIK
  ```
  which decodes to target `7f000001.c0a80001.rbndr.us`. The rbndr.us convention: hex-encoded A records alternating between the two IPs — here `7f000001` = 127.0.0.1 and `c0a80001` = 192.168.0.1, flipping per resolution.
- **Root-cause pattern:** The attack authorization hash was `md5(salt+target)` with a dictionary-crackable salt, and the "is this a local target" check was a classic TOCTOU — the hostname is validated at one moment (or one DNS answer) and used at another, so a re-binding hostname passes validation yet resolves to localhost when actually fetched.
- **Impact proven:** Attacker cracked the hash salt (`mrgrinch463`) by brute-forcing `md5(salt+target)` against rockyou.txt with a custom Go script, then used the rebinding domain to pass the IP check and hit localhost, retrieving `flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`.
- **Exemplars:** h1-ctf record id=1068434.
- **Chain as observed:** (1) brute-force md5(salt+target) salt with custom Go script vs rockyou.txt; (2) use DNS-rebinding domain resolving to an external IP (record truncated at this step — remainder not stated).

### 2. Hostname-whitelist bypass where whitelisted names resolve over DNS (Node.js inspector)

- **Endpoint shape / parameter:** `GET http://localhost6:9229/json` — the Node.js `--inspect` debugger's JSON discovery endpoint, param `hostname` = `localhost6`.
- **Payload that actually fired (verbatim):** `http://localhost6:9229/json`
- **Root-cause pattern:** The `--inspect` host whitelist included the literal string `localhost6`. Unlike `localhost` (hardcoded to loopback in /etc/hosts), `localhost6` is not guaranteed an /etc/hosts entry, so it goes through normal DNS resolution — attacker-controlled DNS can rebind it to 127.0.0.1. This bypassed the CVE-2018-7160 fix, which had only blocked the DNS-rebinding of ordinary `localhost`-style names.
- **Impact proven:** Full attacker access to the Node.js debugger WebSocket → complete control of the process, i.e. remote code execution. Assigned **CVE-2021-22884**.
- **Exemplars:** Node.js record id=1069487.
- **Chain as observed:** (1) attacker page loads `http://localhost6:9229`, which resolves via attacker-controlled DNS; (2) DNS-rebind `localhost6` to 127.0.0.1 with a short TTL; (3) page (chain truncated in record — continues into debugger WebSocket takeover).
- **Why this generalizes:** anywhere a product whitelists *strings* that are assumed safe but are actually DNS-resolvable (any name not pinned in /etc/hosts, or that the vendor doesn't force-resolve to a literal IP), rebinding converts the whitelist into an open door.

### 3. Unauthenticated local HTTP server with no Host validation (WebTorrent)

- **Endpoint shape / parameter:** `http://127.0.0.1:{port}` — the WebTorrent client's local server on a random port; no dedicated parameter; "payload" is simply the poc HTML page hosted by the attacker that performs the rebinding and then reads responses.
- **Payload that actually fired:** `poc.html` (local HTTP server content) — i.e., an attacker-hosted HTML page driving the rebinding; no special request payload, the attack is purely hostname-based.
- **Root-cause pattern:** The local HTTP server does not validate the requesting `Host` header / hostname at all. No Origin/Host check means any website that can get its own hostname to resolve to 127.0.0.1 (via rebinding) can script a cross-origin read of the local server's responses.
- **Impact proven:** A malicious website can discover what files the user has downloaded via WebTorrent — private file-list disclosure on the victim's machine, purely by visiting the page.
- **Exemplars:** Brave Software record id=663729.
- **Chain as observed:** (1) WebTorrent serves downloaded files on a random local port; (2) malicious site uses DNS rebinding to reach the local server; (3) site reads the downloaded-file content (chain truncated in record).

## Bypass / chain notes

- **Hex-encoded dual-A-record domains are the canonical tooling.** `7f000001.c0a80001.rbndr.us` encodes both IPs in the label itself (big-endian hex: `7f000001` → 127.0.0.1, `c0a80001` → 192.168.0.1). You can substitute any two hex IPs. rbndr.us alternates answers per query, which is what defeats the "check once, use later" flow.
- **Auth-layer chain first, rebinding second:** in record 1068434 the rebinding domain alone wasn't enough — the target string is inside a signed/authorized payload (`md5(salt+target)`), so the salt had to be cracked first (custom Go script vs rockyou.txt; salt `mrgrinch463`). Lesson: when a rebinding candidate endpoint requires an HMAC/hash over the hostname, attack the hash's secret before anything else.
- **Pick a target with real teeth behind it.** The strongest outcome in the records came from rebinding into a *debugger* (`localhost6:9229` → `/json` → DevTools WebSocket) — local services that assume loopback == trusted are the highest-value rebinding destinations. Simplest impactful targets: anything on 127.0.0.1 that serves data with no Host/Origin validation (WebTorrent's random-port file server).
- **Short TTL is the enabling mechanism** in every record: the attacker's DNS answers must expire fast so the browser re-queries between the validation fetch and the sensitive fetch.
- **Non-obvious loopback-adjacent names are the bypass surface:** `localhost6` worked precisely because it was whitelisted as a string but not pinned as an IP. Any whitelist entry that isn't hard-resolved is a rebinding candidate.
- **No-parameter attacks exist:** the WebTorrent case required no crafted request body — the browser itself is the delivery vehicle; only the attacker page and DNS matter.

## Gotchas / what NOT to do

- **Don't assume a hostname whitelist means the name is safe.** Conversely, don't test only `localhost`/`127.0.0.1` — many programs block those literally (the CVE-2018-7160 fix did) but leave DNS-resolvable aliases like `localhost6` open.
- **Don't use long TTLs or cached resolutions** — rebinding depends on the resolver returning a different answer on the second lookup; standard TTL answers or the browser's DNS cache will kill the flip.
- **Don't skip the auth check analysis.** In 1068434, spending effort on rebinding before cracking the `md5(salt+target)` salt would have dead-ended; the payload must be constructable before rebinding is even reachable.
- **Don't expect the local service to validate anything for you** — but do check whether it *does*: the difference between the WebTorrent bug (no Host validation → exploitable) and a patched app (validates Host/Origin) is the entire finding. Test the Host header explicitly.
- **Random local ports are a constraint, not a blocker** — WebTorrent bound a random port; the attacker page still found it (port-scan-from-browser / discovery step implied; the record's chain is truncated here — do not assume a fixed port works).
- **Fix-side reminder (what programs patched):** validate resolved IPs, not hostname strings; pin loopback names to literal IPs; validate Host/Origin on local servers; eliminate the validate-then-use gap (TOCTOU) on target checks.

## Real-world impact examples

1. **Remote code execution (CVE-2021-22884, Node.js):** rebinding `localhost6` to 127.0.0.1 gave an attacker's webpage access to the `--inspect` debugger WebSocket on port 9229, granting full control of the Node process. Report id=1069487.
2. **Local-target RCE-ish bypass in a CTF/hackathon app (h1-ctf):** cracked salt `mrgrinch463` from `md5(salt+target)`, then `7f000001.c0a80001.rbndr.us` passed the IP check and pinged localhost → flag `flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`. Report id=1068434.
3. **Cross-origin privacy leak (Brave / WebTorrent):** a malicious website read the WebTorrent local server (random port on 127.0.0.1) via DNS rebinding and learned the user's downloaded files — no payload beyond a `poc.html` page. Report id=663729.