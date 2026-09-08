---
name: hunter-l3-cryptographic-issues
description: "Use when hunting Cryptographic Issues on a target. Loads the L3 technique sheet: This class covers failures in how a target implements, configures, or deploys cryptography — weak or guessable signing keys used for session integrity, weak TLS/SSL configurations on endpoints, and in"
domain: cybersecurity
subdomain: web
tags:
- web
- cryptographic-issues
- hunting
- l3
version: '1.0'
---

# Cryptographic Issues — Technique Sheet

## Overview
This class covers failures in how a target implements, configures, or deploys cryptography — weak or guessable signing keys used for session integrity, weak TLS/SSL configurations on endpoints, and insecure default crypto paths or plaintext-fallback behaviors in infrastructure tooling. It pays when an application trusts a cryptographic artifact (session cookie, TLS channel, config file) that the attacker can forge, downgrade, or intercept. In practice, disclosed records in this class split into two clusters: (1) weak/guessable secret keys in application frameworks, and (2) TLS/crypto misconfiguration or downgrade surface in server and tooling deployments.

## Distinct sub-patterns

### Sub-pattern 1: Weak/guessable framework SECRET_KEY → forged session cookies
- **Endpoint shape / parameter:** Any Flask (or similar) application that issues itsdangerous-signed session cookies. Target shape: `GET /` on the app, inspect the session cookie in the response/`Set-Cookie`. Parameter: the session cookie itself.
- **Payload that actually fired (verbatim):** `eyJfcGVybWFuZW50Ijp0cnVlfQ.YX-V3g.NET76NNJbweb_qagyfYl2_7TDJg` (a Flask itsdangerous session token in `header.timestamp.signature` format).
- **Root-cause pattern:** The application (Elekto, a Kubernetes elections tool) had its Flask `SECRET_KEY` configured to the weak literal string `'N/A'`. Flask session cookies are signed, not encrypted — anyone who recovers or guesses the signing key can mint arbitrary sessions.
- **Impact that was proven:** Using `flask-unsign` to brute-force the cookie's signature, the key `'N/A'` was recovered after 8192 attempts. With the key in hand, arbitrary session manipulation was possible — including cross-origin request forgery against the voting/authentication flows of the target.
- **Exemplar report IDs:** 1387366 (Kubernetes program), by ajaysenr.

### Sub-pattern 2: Weak TLS protocol / cipher suite configuration on the web server
- **Endpoint shape / parameter:** TLS listeners (nginx or equivalent) on production domains. Detection surface: TLS handshake parameters, not application endpoints. Confirm with SSL Labs scan shape: `https://www.ssllabs.com/ssltest/analyze.html?d=<domain>&s=<server-IP>`.
- **Payload that actually fired:** Payload not stated (configuration issue — no request payload). For the Airbnb record the submitted artifact was the SSL Labs scan link: `https://www.ssllabs.com/ssltest/analyze.html?d=airbnb.pt&s=23.203.215.81`.
- **Root-cause pattern:** Two concrete variants in the records:
  - TLS 1.0 enabled alongside weak cipher suites in nginx TLS configuration (Gratipay).
  - General weak SSL configuration on a specific production host (`www.airbnb.pt`) identified via SSL Labs analysis (Airbnb).
- **Impact that was proven:**
  - TLS 1.0 exposure = vulnerable to BEAST-class attacks and PCI non-compliance after 30 June 2018 (Gratipay, report 244070).
  - Confirmed SSL configuration weaknesses on `airbnb.pt` (Airbnb, report 49537).
- **Exemplar report IDs:** 244070 (Gratipay), 49537 (Airbnb).

### Sub-pattern 3: Insecure default crypto config path accessible to non-admin users
- **Endpoint shape / parameter:** Not a web endpoint — a filesystem/deployment pattern. Node.js reads `openssl.cnf` from a default build path (`/home/iojs/build/...`) instead of the system location `/etc/ssl` on macOS/Linux.
- **Payload that actually fired:** Payload not stated (vulnerability report on Node.js core behavior; CVE-2022-32222).
- **Root-cause pattern:** The application runtime loads its OpenSSL configuration from a user-writable default path rather than a root-owned system path. A non-admin user who can write to that path can inject a weakened crypto configuration that Node.js then honors.
- **Impact that was proven:** Default config path accessible to a non-admin user enables weakened crypto configuration (CVE-2022-32222). Note: no concrete data compromise was proven in this record — it was accepted as a Node.js core vulnerability via the Internet Bug Bounty program.
- **Exemplar report ID:** 1888758 (Internet Bug Bounty), by ajaysenr.

### Sub-pattern 4: Missing authentication/integrity on a secondary protocol (plaintext MITM injection)
- **Endpoint shape / parameter:** A service's non-HTTP protocol handler — in the records: the Burp Collaborator SMTP server. The weakness is in the protocol implementation itself, not TLS config.
- **Payload that actually fired:** Payload not stated (MITM injection of a plaintext Collaborator interaction ID during SMTP exchange).
- **Root-cause pattern:** A non-standard SMTP implementation accepted a plaintext collaborator ID from an active man-in-the-middle. The protocol lacked integrity/authenticity guarantees on that interaction channel, so injected identifiers were treated as legitimate.
- **Impact that was proven:** An active MITM could inject a collaborator ID to steal the victim's Collaborator SMTP interactions — potentially obtaining user credentials delivered through those interactions.
- **Exemplar report ID:** 953219 (PortSwigger Web Security), by ajaysenr.

## Bypass / chain notes
- **Brute-force the key, not the cookie:** where a framework signs sessions with a shared secret, the attack path is key recovery from a sample token (`flask-unsign` brute-forced `'N/A'` in 8192 attempts). Once the key is known, every session field is attacker-controlled — no per-user bypass needed.
- **Scan-link as evidence chain:** for TLS config findings, the record used an external verification artifact (SSL Labs URL with both domain and server IP) rather than an exploit — the "chain" is report + standardized third-party test result.
- **MITM is the chain:** the Collaborator finding required no exploit chain in the traditional sense — the attacker position (active MITM) plus the protocol's plaintext acceptance *was* the chain, converting a protocol quirk into credential theft potential.
- No multi-step application chains (e.g., forged session → privilege escalation → RCE) appear in these records; the session-forgery finding stopped at cross-origin request forgery against auth/voting flows as the demonstrated impact.

## Gotchas / what NOT to do
- **Weak TLS alone is often low-severity:** the Gratipay report succeeded because it anchored impact to a concrete standard (BEAST exploitability class + PCI non-compliance deadline), not just "TLS 1.0 is old." A bare "weak cipher" claim without a compliance/exploitability anchor is likely to be closed as informational.
- **Validate scope before reporting config-path issues:** the Node.js finding (1888758) landed via the Internet Bug Bounty program — a core-software channel, not a normal web bug bounty. Don't expect ordinary web programs to accept runtime/library crypto-path findings; route them to the vendor's program (IBB, GitHub, Node.js) instead.
- **Don't confuse signed ≠ encrypted:** Flask session cookies are readable by the client by design — the bug is only the forgeability from the weak key. Reporting "sensitive data exposure" because the cookie decodes is wrong; the finding is the key brute-force.
- **Confirmation of a weakness ≠ demonstrated compromise:** both the Airbnb SSL Labs report (49537) and the Node.js CVE (1888758) were accepted without proven data compromise. But treat that as program-dependent — most consumer bug bounty programs will demand a concrete attack path, not a scanner result.
- **Keep the brute-force cheap and bounded:** the successful key recovery took 8192 attempts because the key was a trivial literal. If a reasonable wordlist fails, the key is likely strong — don't burn compute on long brute-forces; move on.

## Real-world impact examples
- **Kubernetes (1387366):** Flask `SECRET_KEY = 'N/A'` on elections.k8s.io recovered via `flask-unsign` (8192 attempts) from cookie `eyJfcGVybWFuZW50Ijp0cnVlfQ.YX-V3g.NET76NNJbweb_qagyfYl2_7TDJg` → arbitrary session forgery → cross-origin request forgery against the voting/authentication flows of a Kubernetes governance tool.
- **Gratipay (244070):** TLS 1.0 + weak ciphers on nginx → BEAST-class attack exposure and PCI non-compliance after 30 June 2018 — accepted on compliance-anchored impact.
- **Airbnb (49537):** Weak SSL configuration on `www.airbnb.pt` confirmed via SSL Labs analysis (`d=airbnb.pt&s=23.203.215.81`).
- **PortSwigger (953219):** Non-standard Collaborator SMTP implementation → active MITM injects plaintext collaborator ID → steals victim's Collaborator SMTP interactions → potential user credential theft. This is the highest-consequence pattern in the set: a protocol implementation quirk escalated to credential compromise.
- **Internet Bug Bounty (1888758):** Node.js default `openssl.cnf` path under `/home/iojs/build/` writable by non-admins → attacker-controlled weakened crypto config (CVE-2022-32222), accepted as core vuln despite no proven data compromise.