---
name: hunter-l3-certificate-validation-bypass
description: "Use when hunting Certificate Validation Bypass on a target. Loads the L3 technique sheet: Certificate validation bypass bugs occur when a client (desktop app, CLI tool, library backend) connects over TLS but fails to enforce some part of the certificate verification contract — trust chain,"
domain: cybersecurity
subdomain: web
tags:
- web
- certificate-validation-bypass
- hunting
- l3
version: '1.0'
---

# Certificate Validation Bypass — Technique Sheet

## Overview
Certificate validation bypass bugs occur when a client (desktop app, CLI tool, library backend) connects over TLS but fails to enforce some part of the certificate verification contract — trust chain, revocation status (OCSP), or key-usage extensions. They pay in two distinct markets: (1) rich/desktop clients with custom server settings, where a MITM can capture user credentials and data in plaintext; (2) curl and similar libraries, where a logic flaw in the verification path (session caching, missing EKU checks) turns a properly "verified" connection into an impersonation or revocation-bypass primitive. Impact is typically demonstrated by standing up an attacker-controlled TLS endpoint and showing the client hand over sensitive data or accept a certificate it must reject.

## Distinct sub-patterns

### 1. Client-side app skips trust-chain validation on user-supplied custom server host
- **Endpoint shape:** Not a web endpoint — the target is the desktop client's "custom server / self-hosted URL" feature. The attacker controls any TLS listener, e.g. `ncat --ssl -l <port>` on an attacker host, and points the client's server-host setting at it.
- **Payload that actually fired:** No request payload required. The attack payload is an on-the-fly self-signed certificate presented by the attacker's `ncat` listener. The client then sent, over the attacker's TLS session, a live `ExchangeServicesClient` SOAP `FindItem` request (Exchange web-services call carrying user email data).
- **Root cause:** The client does not validate the SSL certificate trust chain for the user-supplied custom server host. The connection is encrypted but not authenticated — the client accepts any certificate, including a self-signed one generated at connection time.
- **Impact proven:** Full MITM demonstration: attacker-controlled server received the client's SOAP request containing user email data with zero certificate validation. In a hostile network this means credential and mail-data capture against anyone who can influence the connection (ARP spoofing, DNS hijack, malicious Wi-Fi).
- **Exemplar:** id=16568 (RelateIQ)

### 2. OCSP verify-status bypass via TLS session-ID caching (library logic flaw)
- **Endpoint shape:** N/A — this is a library-level TLS handshake logic bug, not an endpoint. The "target" is any curl transfer where the user/caller requested certificate-status checking (OCSP stapling, e.g. `curl --cert-status` or `CURLOPT_SSL_VERIFYSTATUS`).
- **Payload that actually fired:** No HTTP payload. The "payload" is a two-connection sequence:
  1. First connection to a host fails the OCSP verify-status check (e.g. bad/unavailable stapled OCSP response) — but curl caches the TLS session ID anyway.
  2. Second transfer to the same hostname within the session-cache freshness window reuses the cached session and skips the verify-status check entirely.
- **Root cause:** curl cached the SSL session ID even when the OCSP verify-status check failed. On session resumption (TLS 1.2, OpenSSL backend), the verify-status check is not re-evaluated, so a transfer that must be gated on revocation status sails through on a session established by a failed check.
- **Impact proven:** OCSP stapling verification could be bypassed entirely via TLS session reuse, allowing transfers to a host whose OCSP status had failed verification. Assigned CVE-2024-0853 under the Internet Bug Bounty program.
- **Exemplar:** id=2341063 (Internet Bug Bounty)

### 3. Missing Extended Key Usage (serverAuth) enforcement — clientAuth-only certificate accepted
- **Endpoint shape:** HTTPS TLS handshake via curl's GnuTLS backend. Any HTTPS URL fetched with `curl_easy_perform()` when built against GnuTLS.
- **Payload that actually fired (verbatim from record):** a leaf certificate crafted with:

  ```
  extendedKeyUsage = critical, clientAuth
  ```

  i.e. a certificate whose EKU is critically marked as client-auth-only. Presented as the server certificate on an attacker-controlled HTTPS endpoint.
- **Root cause:** curl's GnuTLS verify path checks trust chain, validity time, and hostname, but never enforces the TLS server Extended Key Usage (`serverAuth`) on the leaf certificate. Every other verification gate passes, so a certificate minted for client authentication is accepted in the server role.
- **Impact proven:** `curl_easy_perform` returned 0 (success) and curl logged `SSL certificate verified by GnuTLS` against the clientAuth-only leaf — demonstrating HTTPS server impersonation to affected clients. Any attacker who can obtain a legitimate clientAuth certificate (e.g. from an internal PKI, mTLS-issuing CA, or any CA whose certs chain to a trusted root with clientAuth EKU) can impersonate an arbitrary HTTPS server.
- **Exemplar:** id=3752567 (curl)

## Bypass / chain notes
- **Session-resumption chain (id=2341063):** the only multi-step chain in the records — (1) first connection fails OCSP verify-status but the session ID is cached; (2) second transfer to the same hostname within cache freshness reuses the session; (3) the verify-status check is skipped on resumption, so the transfer succeeds despite the failed revocation check. The bypass lives entirely in the cache/reuse interaction — a single-connection test will not reproduce it.
- **PKI-role confusion (id=3752567):** the practical exploitation path is obtaining or minting a certificate with a *different* EKU (clientAuth) that chains to a trusted root. Hostname and trust checks pass by design; only the missing EKU check makes the certificate usable in the wrong role. Marking the EKU extension `critical` was part of the proof — the presence of a critical, non-serverAuth EKU should make rejection mandatory, and the client still accepted it.
- **Custom-host MITM (id=16568):** no filter bypass needed — validation is simply absent. The compounding factor is that the custom-server feature gives the attacker a legitimate reason for the client to connect to attacker-chosen infrastructure; the MITM only needs network positioning (same LAN, DNS control) to complete the chain.

## Gotchas / what NOT to do
- **Not all "cert validation" bugs are the same check.** These three records hit three different gates: trust-chain validation (id=16568), revocation/OCSP status (id=2341063), and key-usage enforcement (id=3752567). Testing only "does it accept a self-signed cert" will miss the OCSP-cache and EKU classes.
- **Don't test OCSP-cache bugs with a single connection.** The id=2341063 bug requires a failed first connection followed by a resumed session; a one-shot `curl --cert-status` against a bad-OCSP host should fail and tells you nothing about the resumption path.
- **Don't assume backend parity in curl.** The EKU gap (id=3752567) is GnuTLS-backend-specific — the same curl version against OpenSSL may enforce EKU correctly. Always note the TLS backend in your report.
- **Don't test library bugs against public targets.** id=2341063 and id=3752567 are library vulnerabilities reported through curl / Internet Bug Bounty — the correct target is the library itself (via its bounty program), not a bug-bounty program's web assets that happen to use curl.
- **For desktop-client MITM bugs, demonstrate with live data.** The accepted proof (id=16568) was not "the client connected" but "the client transmitted a real SOAP `FindItem` request containing user email data to my ncat server." Connection success alone is a weaker report.
- **Payload not stated caveat:** none of the three records contain an HTTP-level payload — these are TLS-layer bugs. Do not pad the report with invented request payloads; the certificate properties and connection sequence *are* the payload.

## Real-world impact examples
- **id=16568 (RelateIQ):** An attacker-controlled `ncat --ssl` listener with an on-the-fly self-signed certificate received a live `ExchangeServicesClient` SOAP `FindItem` request carrying user email data, with no certificate validation performed by the client. Direct credential/data exposure via network-positioned MITM.
- **id=2341063 (curl, CVE-2024-0853):** A host whose OCSP stapled response failed verification could still be contacted successfully via a reused TLS 1.2 session, meaning a revoked or otherwise rejected server could serve content to curl users who explicitly requested revocation checking. Widely deployed library → broad downstream exposure; issued a CVE.
- **id=3752567 (curl/GnuTLS):** A `extendedKeyUsage = critical, clientAuth` leaf certificate was accepted as an HTTPS server certificate — curl returned success and logged `SSL certificate verified by GnuTLS`. Any holder of a clientAuth-only certificate chaining to a trusted root could impersonate any HTTPS server to affected curl builds.