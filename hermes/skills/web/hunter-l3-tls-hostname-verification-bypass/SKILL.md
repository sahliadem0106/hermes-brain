---
name: hunter-l3-tls-hostname-verification-bypass
description: "Use when hunting TLS Hostname Verification Bypass on a target. Loads the L3 technique sheet: This class covers bugs where a TLS client or server fails to bind the certificate identity to the intended hostname — either by skipping hostname verification entirely under permissive-but-intended-li"
domain: cybersecurity
subdomain: web
tags:
- web
- tls-hostname-verification-bypass
- hunting
- l3
version: '1.0'
---

# TLS Hostname Verification Bypass — Technique Sheet

## Overview

This class covers bugs where a TLS client or server fails to bind the certificate identity to the intended hostname — either by skipping hostname verification entirely under permissive-but-intended-limited configurations, or by exploiting inconsistent hostname normalization between the resolver (which decides "who am I connecting to") and the TLS verifier (which decides "does this certificate match"). It also covers protocol-level issues like TLS session resumption that skips identity re-verification. These pay best in widely-deployed libraries and runtimes (Node.js, curl/libcurl backends) where a single flaw silently downgrades security for thousands of downstream applications. The most reliable finding shape is a differential test: run the same connection through a known-good backend (OpenSSL) and a suspect backend and compare results.

## Distinct sub-patterns

### Sub-pattern 1: TLS session reuse bypasses identity re-verification (Node.js)

- Endpoint shape / parameter: TLS connection establishment in Node.js where a session (ticket/ID) is reused. The attacker-controlled parameter is `servername` (the SNI/hostname) supplied to the TLS client when resuming a cached session.
- Payload: none stated in the record (the report describes the mechanism rather than a concrete request string).
- Root-cause pattern: When a TLS session is resumed, Node.js fails to re-verify that the identity in the resumed session matches the new `servername`. The verifier trusts the cached session's identity without re-checking the host bound to it, so presenting a session obtained from host A while connecting with `servername` of host B skips certificate validation for the new connection.
- Impact proven: Attacker can bypass certificate validation to establish unauthorized connections. Details beyond that were not disclosed in the report.
- Exemplars: 3649802 (Node.js program, ajaysenr)

### Sub-pattern 2: Unicode dot separator normalization mismatch — wildcard depth bypass (Node.js)

- Endpoint shape / parameter: Node.js TLS client/server hostname verification. The parameter is `hostname` as supplied to the client and matched against a wildcard certificate's SAN/CN.
- Payload (verbatim concept from record): hostname containing the unicode dot separator U+FF0E (fullwidth full stop) in a wildcard-certificate context — e.g. craft a hostname where a U+FF0E occupies a label-boundary position that the verifier's wildcard depth check miscounts.
- Root-cause pattern: Two independent components normalize the hostname differently. The resolver accepts a hostname containing U+FF0E (treating it like a dot), but the TLS verifier normalizes or compares it differently, so the wildcard depth comparison (`*.example.com` matching only one label deep) can be bypassed — the verifier either over-matches or mis-parses label boundaries. The security boundary relies on both sides agreeing on what constitutes a "dot"; they don't.
- Impact proven: TLS wildcard-depth authentication bypass via unicode dot separator, enabling confidentiality impact or bypass of the intended security boundary under affected configurations. Affected versions: Node.js 22, 24, 26.
- Exemplars: 3688064 (Node.js program, ajaysenr)
- Chain from record: (1) Craft hostname with unicode dot separator accepted by resolver but normalized differently by verifier; (2) resolver and verifier hostname normalization disagree, breaking the wildcard depth check.

### Sub-pattern 3: Verifier disabling cascades — permissive option silently kills hostname checking (curl/libcurl, mbedTLS/wolfSSL/rustls backends)

- Endpoint shape / parameter: libcurl with TLS backends mbedTLS, wolfSSL, or rustls. The parameter is `CURLOPT_SSL_VERIFYPEER`. The finding shape: setting `CURLOPT_SSL_VERIFYPEER=0` (a documented, deliberately permissive configuration where the app intends only to skip CA-chain validation) also disables hostname verification on those backends.
- Payload: none needed — no crafted certificate or name trickery; an attacker holding ANY certificate (wrong CN, not from a trusted CA) suffices.
- Root-cause pattern: On OpenSSL/GnuTLS/Schannel the flag set for "verify peer" and "verify host" are separate knobs, so turning off peer verification leaves hostname checking intact. The mbedTLS/wolfSSL/rustls backends instead clear the entire certificate-verify flag set (mbedTLS: `*flags=0`) or install an unconditional verify-none verifier. The hostname check is a bit in that same flag set, so it is silently dropped as collateral damage.
- Impact proven: A MITM holding any certificate (wrong CN) fully impersonates the HTTPS target. Tested result: mbedTLS/wolfSSL/rustls returned `rc=0` and served HTTP 200, while the OpenSSL control returned `rc=60` (peer certificate cannot be authenticated) — proving the discrepancy is backend-specific, not the documented behavior. Enables interception of `Authorization` headers, `Cookie` headers, and POST bodies.
- Exemplars: 3826199 (curl program, ajaysenr)

## Bypass / chain notes

- Normalization-differential chains (3688064): the only documented chain is the two-step resolver-vs-verifier disagreement — find an input accepted (and resolved) under one normalization but verified under another. Generalize: any place where two security components (DNS resolver, IDNA/punycode conversion, hostname canonicalizer, TLS verifier) each independently process the same user-controlled hostname is a candidate for this class. Dot-like separators (U+FF0E fullwidth, and by extension other unicode "dot" variants) are the demonstrated family.
- Flag-cascade chains (3826199): no multi-step chain needed — the bug is that a legitimate configuration flag has wider blast radius than documented. The practical "chain" is exploitation posture: position as MITM (network adjacency, ARP spoofing, malicious Wi-Fi, BGP/DNS reroute), present any self-signed cert, and harvest `Authorization`, `Cookie`, and POST-body credentials from applications that set VERIFYPEER=0 assuming hostname is still checked.
- Session-reuse chains (3649802): no chain disclosed; the bypass is intrinsic to resumption + `servername` mismatch.

## Gotchas / what NOT to do

- Do not report "VERIFYPEER=0 disables everything" as a universal curl bug — it is backend-specific. The OpenSSL/GnuTLS/Schannel control behaving correctly (rc=60) is exactly what makes this a real, differentiated finding; without the differential you have no evidence the documented behavior was exceeded.
- Do not test unicode normalization mismatches against a random endpoint — you need a wildcard certificate context for the depth-comparison bypass to matter, and you must know the affected runtime version (here Node.js 22/24/26). Verify the target runs an affected version before claiming.
- Don't conflate "server accepted my connection" with "verification bypassed" — capture the actual return codes / handshake outcomes as proof. The curl finding is strong precisely because it documents `rc=0` + HTTP 200 on vulnerable backends vs `rc=60` on the control.
- For session-reuse findings, ensure the session actually belongs to a different identity than the `servername` used — a same-identity resumption failure is not a bypass.
- These are library/runtime vulnerabilities, not per-target web bugs: scope them to the correct program (Node.js, curl) rather than trying to claim them against an arbitrary in-scope web property.

## Real-world impact examples

- id=3826199 (curl): Proven end-to-end MITM. A man-in-the-middle holding any certificate with a wrong CN impersonated the HTTPS target against libcurl built with mbedTLS, wolfSSL, or rustls — `rc=0`, HTTP 200 served — while the OpenSSL control correctly failed with `rc=60`. Impact: interception of `Authorization` headers, `Cookie` headers, and POST bodies (i.e., full credential and data theft from any app using those backends with VERIFYPEER=0).
- id=3688064 (Node.js): TLS wildcard-depth authentication bypass via U+FF0E fullwidth full stop in the hostname, exploitable against Node.js 22, 24, and 26 — a confidentiality impact / security-boundary bypass affecting all apps on those runtimes whose verifier and resolver disagree on dot normalization.
- id=3649802 (Node.js): Attacker bypasses certificate validation entirely by reusing a TLS session with a different `servername` — unauthorized connections to hosts whose identity was never re-verified on resumption.