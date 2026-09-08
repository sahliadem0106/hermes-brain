---
name: hunter-l3-weak-tls-configuration-sweet32
description: "Use when hunting Weak TLS Configuration (SWEET32) on a target. Loads the L3 technique sheet: SWEET32 (CVE-2016-2183) is a birthday-bound attack against legacy block ciphers with small 64-bit block sizes — in practice, 3DES (3DES-EDE-CBC) cipher suites in TLS."
domain: cybersecurity
subdomain: web
tags:
- web
- weak-tls-configuration-sweet32
- hunting
- l3
version: '1.0'
---

# Weak TLS Configuration (SWEET32) — Technique Sheet

## Overview
SWEET32 (CVE-2016-2183) is a birthday-bound attack against legacy block ciphers with small 64-bit block sizes — in practice, 3DES (3DES-EDE-CBC) cipher suites in TLS. When a server still negotiates 3DES-CBC, an attacker who can keep a long-lived TLS session alive (or induce enough traffic across it, ~2^32 blocks ≈ tens of GB) can recover plaintext cookies or other secrets crossing the connection. It pays on programs with older infrastructure, legacy load balancers, or default cipher configs that were never hardened after 2016.

## Distinct sub-patterns

### Sub-pattern 1: Server advertises/accepts 3DES-CBC cipher suites
All three records in this set are the same core finding — the only sub-pattern present in the data.

- Endpoint shape / parameter: Not an HTTP endpoint. The "endpoint" is the TLS listener on the target's primary domain — yelp.com, Legal Robot's main site, and nextcloud.com. Detection target is the server's cipher-suite list on port 443 (TLS handshake, no HTTP path or parameter involved).
- Payload that actually fired: payload not stated — there is no exploit payload in these records. The finding is demonstrated by the TLS handshake evidence: the server's offered cipher list includes a 3DES-CBC suite (e.g. 3DES-EDE-CBC family). The proof is cipher negotiation capability, not a successful decryption.
- Root-cause pattern: The server's TLS configuration still enables 3DES-CBC cipher suites. 3DES uses a 64-bit block, so after ~2^32 blocks encrypted under the same connection, CBC collisions leak plaintext (the SWEET32 birthday attack). This typically survives because: a default/stale cipher config on the load balancer or web server, backwards-compatibility cipher lists for old clients, or never applying 2016+ hardening guidance.
- Impact that was proven: Confirmed support of SWEET32-vulnerable 3DES-CBC ciphers (CVE-2016-2183). The proven impact in all three reports is cipher-suite support itself, with the accepted risk statement that long TLS sessions could let an attacker decrypt customer data. No records show a completed decryption.
- Exemplar report IDs: 199436 (Yelp), 199438 (Legal Robot), 199445 (Nextcloud) — all by researcher ajaysenr.

## Bypass / chain notes
- No chains were recorded: all three reports are single-step findings (chain: none).
- The attack chain implied by the root cause (man-in-the-middle position + a long-running TLS session such as a browsing session or a large file download to accumulate ~2^32 blocks, then CBC collision recovery of an authentication cookie) was asserted as the risk rationale but not demonstrated in any record. Do not represent it as proven.
- Practical trigger observed across the records: the same researcher (ajaysenr) reported the identical finding pattern across multiple programs (Yelp, Legal Robot, Nextcloud) in the same period — this is a sweepable, tool-detectable misconfiguration, not a target-specific logic bug.

## Gotchas / what NOT to do
- This is a configuration/parity finding, not a working exploit: none of the three records shows decrypted data. Report it as "server supports 3DES-CBC (SWEET32/CVE-2016-2183)" with the handshake/cipher-scan evidence, not as "decrypted customer data."
- Don't invent an HTTP endpoint or parameter — there is none. The test surface is the TLS listener on the main domain.
- Don't skip the impact framing: the accepted justification across these reports is that LONG TLS sessions enable decryption. A brief TLS session with minimal traffic is not realistically exploitable, so triagers may argue likelihood — lead with session-length/traffic-volume reasoning.
- Detection is cheap and identical across targets; don't expect novelty bounty. These were accepted as cipher misconfiguration reports, but the same finding repeated across three programs means many programs will mark it out-of-scope as a known/scanner finding — check program policy for "weak cipher" exclusions before submitting.
- Payload not stated in any record — don't fabricate a "payload" section for your report; the cipher-suite scan output IS the evidence.

## Real-world impact examples
- Yelp (id=199436): yelp.com confirmed to support 3DES-CBC cipher suites vulnerable to SWEET32 (CVE-2016-2183); long TLS sessions could allow an attacker to decrypt customer data.
- Legal Robot (id=199438): same confirmed 3DES-CBC support with the same customer-data-decryption exposure.
- Nextcloud (id=199445): nextcloud.com — same confirmed 3DES-CBC support (CVE-2016-2183) and the same long-session decryption risk.

All three are the researcher ajaysenr; all three were reported with identical root cause, impact wording, and no exploit payload — a template of one scan finding applied across multiple programs.