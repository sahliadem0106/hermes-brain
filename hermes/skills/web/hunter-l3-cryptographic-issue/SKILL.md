---
name: hunter-l3-cryptographic-issue
description: "Use when hunting Cryptographic Issue on a target. Loads the L3 technique sheet: This class covers broken or misapplied cryptography in TLS stacks, crypto libraries, and protocol implementations — weak DH parameters, Montgomery arithmetic bugs, padding oracles, cipher renegotiation gaps, and misuse of AEAD nonces."
domain: cybersecurity
subdomain: web
tags:
- web
- cryptographic-issue
- hunting
- l3
version: '1.0'
---

# Cryptographic Issue — Technique Sheet

## Overview
This class covers broken or misapplied cryptography in TLS stacks, crypto libraries, and protocol implementations — weak DH parameters, Montgomery arithmetic bugs, padding oracles, cipher renegotiation gaps, and misuse of AEAD nonces. In practice it pays almost exclusively through two routes: (1) finding implementation flaws in core open-source crypto (OpenSSL) via the Internet Bug Bounty, where deep source-level analysis of assembly and bignum routines is rewarded, and (2) spotting servers with legacy protocol/cipher configuration (SSLv2, SSLv3, EXPORT ciphers, non-safe-prime DH) where known cross-protocol attacks apply. Impact is rarely "information disclosure from one endpoint" — it is key recovery or session decryption, which is why these carry critical-level bounties.

## Distinct sub-patterns

### 1. Small-subgroup key recovery via non-safe-prime DH + reused private exponents
- Endpoint shape: OpenSSL server DH parameter handling; specifically when `SSL_OP_SINGLE_DH_USE` is NOT set, so the same DH private exponent is reused across handshakes. Parameters come from X9.42 / RFC 5114 (non-safe primes with small subgroups).
- Payload that fired: none needed at the protocol level — the attack is completing multiple handshakes with crafted DH public values. Payload not stated beyond that; the attack math is small-subgroup confinement.
- Root cause: RFC 5114 primes have small subgroups (~160 bits). If the server reuses its private exponent (static DH or cached), an attacker who sends subgroup elements can solve for the exponent modulo each subgroup and CRT them together.
- Impact proven: Recovery of the peer's private DH exponent (CVE-2016-0701), exposing the TLS session key material.
- Exemplars: 113288 (Internet Bug Bounty).

### 2. Incorrect Montgomery squaring on x86_64 (carry bug)
- Endpoint shape: OpenSSL `BN_mod_exp` path — the x86_64 Montgomery squaring procedure (`bn_sqr8x_mont` family). Test shape: pick modulus/inputs where the assembly path is taken and compare `BN_mod_exp` assembly output against generic C implementation output.
- Payload that fired: none stated; the "payload" is a specific input pair to `BN_mod_exp` that diverges between implementations. Payload not stated in the record.
- Root cause: A carry-propagating bug in the x86_64 Montgomery squaring routine produced wrong modular-exponentiation results for certain inputs (CVE-2015-3193, OpenSSL 1.0.2, fixed 1.0.2e).
- Impact proven: Incorrect results in RSA and Diffie-Hellman computations — demonstrated as BN_mod_exp mismatch; signature/secret-validity verification can be bypassed and private keys can be recovered in some configurations.
- Exemplars: 128169.

### 3. Montgomery squaring overflow with 512-bit moduli
- Endpoint shape: OpenSSL `rsaz_512_sqr` (x86_64, openssl source), used for exponentiation with 512-bit moduli. Affects OpenSSL 1.1.1 and 1.0.2 (CVE-2019-1551).
- Payload that fired: payload not stated.
- Root cause: Overflow bug in the 512-bit Montgomery squaring routine — the result overflows for certain input ranges.
- Impact proven: Breaking DH512 is "just feasible" IF the DH key is reused. Attacks on 2-prime RSA1024 / 3-prime RSA1536 / DSA1024 assessed as very difficult — note the honest scoping, which is part of why the report was accepted: the DH512-reuse case alone carried the impact.
- Exemplars: 2449038.

### 4. DROWN — SSLv2 EXPORT ciphers as a Bleichenbacher oracle (cross-protocol)
- Endpoint shape: any TLS server that shares an RSA key/certificate with a server that supports SSLv2 + EXPORT-grade ciphers. Probe shape: connect to port 443 and also to any other port/service (SMTP, etc.) offering SSLv2 with the same key.
- Payload that fired: payload not stated; the attack is the standard DROWN workload — thousands of SSLv2 connections and ~2^50 computation for the special variant.
- Root cause: SSLv2 servers with EXPORT ciphersuites leak RSA padding-oracle responses; the oracle decrypts check bytes of the TLS RSA premaster secret even though the TLS server never speaks SSLv2 (CVE-2016-0800, confirmed by OpenSSL).
- Impact proven: Decryption of captured TLS sessions for the shared-key server.
- Exemplars: 166629.

### 5. SSLv2 cipher renegotiation bypass (disabled ciphers still negotiable)
- Endpoint shape: servers that believe SSLv2 is "disabled" — but where the admin disabled specific ciphers rather than the protocol (i.e., without `SSL_OP_NO_SSLv2`).
- Payload that fired: payload not stated; the demonstration is a malicious client negotiating SSLv2 ciphersuites that were disabled server-side.
- Root cause: SSLv2 does not block disabled ciphers unless the protocol itself is disabled (CVE-2015-3197). Cipher-level configuration does not stop negotiation at the protocol layer.
- Impact proven: Server is left vulnerable to DROWN even though the operator believed SSLv2 ciphers were off.
- Exemplars: 166634.
- Practical note: this is the configuration-verification sub-pattern — test whether SSLv2 handshake completes at all, not whether particular ciphers are rejected.

### 6. Legacy SSL protocol exposure (POODLE/BLEED)
- Endpoint shape: any production HTTPS endpoint; check supported protocol versions (SSLv3) and DTLS/heartbeat exposure (BLEED). Concrete case: `app.relateiq.com` (RelateIQ program).
- Payload that fired: payload not stated; standard POODLE/BLEED detection (protocol downgrade + CBC padding oracle; heartbeat request for BLEED).
- Root cause: The server still supported SSL protocols vulnerable to POODLE/BLEED — i.e., SSLv3 with CBC-mode ciphers, and OpenSSL heartbeat enabled.
- Impact proven: TLS traffic decryption/attack against the production app endpoint.
- Exemplars: 31415.

### 7. AEAD nonce-handling flaw — unauthenticated nonce bytes
- Endpoint shape: OpenSSL ChaCha20-Poly1305 AEAD API (the `EVP_aead`/ChaCha20-Poly1305 custom interface), parameter = the nonce. OpenSSL accepted up to 16-byte nonces.
- Payload that fired: use of a 16-byte nonce. Verbatim from the record: "OpenSSL accepts up to 16-byte nonces but discards the first 4 bytes per the AEAD spec."
- Root cause: For nonces longer than 12 bytes, the first 4 bytes are used only for key derivation and not covered by the Poly1305 authentication tag — so those 4 nonce bytes are unauthenticated. Applications that treat the nonce as fully authenticated (or that can be driven into nonce reuse) are exploitable.
- Impact proven: Tampering with the first 4 nonce bytes goes undetected, and nonce reuse allows complete decryption of sensitive data.
- Exemplars: 506040.

## Bypass / chain notes
- Cross-protocol is the recurring bypass theme: you never attack the TLS endpoint directly. DROWN works because the TLS key is shared with a weaker SSLv2 endpoint (other ports/services); the disabled-cipher bug (166634) works because admins disable ciphers, not protocols — always probe at the protocol layer.
- Key reuse is the multiplier in every DH/arith bug: small-subgroup attack (113288) requires reused private exponents (no `SSL_OP_SINGLE_DH_USE`); the rsaz_512_sqr overflow (2449038) is only "just feasible" against DH512 with a reused key. A code-level arithmetic bug is much weaker impact on ephemeral keys — frame reports around reuse scenarios.
- Configuration-vs-implementation: sub-patterns 4–6 are purely misconfiguration (SSLv2/SSLv3/EXPORT still enabled) and are the easiest to find at scale — scan all exposed ports, not just 443, for SSLv2/SSLv3 support and cert reuse.
- No chains were recorded across these reports — each stands alone; but DROWN-style findings implicitly chain (cert-sharing discovery → SSLv2 oracle → captured-traffic decryption).

## Gotchas / what NOT to do
- Don't report raw arithmetic bugs without scoping impact honestly: 2449038 explicitly narrowed impact to DH512-with-reuse and marked RSA1024/DSA1024 attack "very difficult." Overclaiming kills credibility.
- Don't test non-safe-prime DH against servers using ephemeral keys — the subgroup attack needs exponent reuse; verify `SSL_OP_SINGLE_DH_USE` (or equivalent) is absent first.
- Don't conclude "SSLv2 is disabled" from a single rejected handshake: per CVE-2015-3197, server cipher configuration can look like a disable while the protocol still negotiates. Test a full SSLv2 handshake with allowed ciphers.
- These are mostly library-level findings (5 of 7 went through Internet Bug Bounty against OpenSSL itself, not a target app). Only sub-patterns 6 (POODLE/BLEED) and parts of 4/5 are hunt-able against arbitrary bounty targets; fuzzing OpenSSL internals requires deep C/x86_64 assembly and bignum knowledge — don't attempt this class with scanners alone.
- DROWN-class testing generates thousands of connections against production servers — coordinate with the program; don't run oracle workloads blindly.
- For the AEAD nonce bug (506040), the flaw is in the API contract (16-byte nonces with 4 unauthenticated bytes), not a payload you can fire against a random host — exploitation requires an application that mishandles the nonce. Identify the consuming application's nonce handling before claiming exploitability.

## Real-world impact examples
- CVE-2016-0701 (113288): private DH exponent recovery from handshake observations — TLS key material exposure on servers reusing DH exponents with RFC 5114 parameters.
- CVE-2015-3193 (128169): BN_mod_exp returned wrong results for certain inputs in OpenSSL 1.0.2, affecting RSA and DH; fixed in 1.0.2e.
- CVE-2016-0800 / DROWN (166629): decryption of TLS sessions of servers sharing RSA keys with an SSLv2+EXPORT-capable server; ~2^50 computation and thousands of connections; confirmed by OpenSSL.
- CVE-2015-3197 (166634): malicious client negotiated SSLv2 ciphers the server admin had disabled — servers believing SSLv2 was off were DROWN-vulnerable anyway.
- CVE-2019-1551 (2449038): overflow in x86_64 rsaz_512_sqr; DH512 breakable when keys reused; OpenSSL 1.1.1/1.0.2 affected.
- 31415 (RelateIQ): app.relateiq.com vulnerable to POODLE/BLEED — decryption/attack of production TLS traffic; paid on a real company target.
- 506040 (Internet Bug Bounty): unauthenticated first 4 bytes of a 16-byte ChaCha20-Poly1305 nonce in OpenSSL — tampering undetected; nonce reuse → complete decryption of sensitive data.