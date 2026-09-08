---
name: hunter-l3-improper-certificate-validation
description: "Use when hunting Improper Certificate Validation on a target. Loads the L3 technique sheet: This class covers any failure to correctly verify a TLS/SSL peer: skipping certificate validation entirely, failing to check hostnames (CN/SAN mismatches, wildcards, IDN punycode, IP literals), accept"
domain: cybersecurity
subdomain: web
tags:
- web
- improper-certificate-validation
- hunting
- l3
version: '1.0'
---

# Improper Certificate Validation — Technique Sheet

## Overview

This class covers any failure to correctly verify a TLS/SSL peer: skipping certificate validation entirely, failing to check hostnames (CN/SAN mismatches, wildcards, IDN punycode, IP literals), accepting bad OCSP stapling responses, mishandling verification error paths, and breaking certificate comparison primitives. It pays almost exclusively in client-side and library bugs — desktop apps, mail clients, HTTP clients (curl, Node/Undici, Ruby, OpenSSL, libcurl backends) — reported through wide-scope programs (Acronis, Nextcloud, curl, Node.js, Ruby, Internet Bug Bounty / PortSwigger). Impact is almost always MITM interception/modification of otherwise "secure" traffic, and CVEs are routinely issued.

## Distinct sub-patterns

### 1. Client skips TLS certificate validation entirely
- Endpoint shape: desktop/app client TLS connections, no HTTP surface. E.g. "Acronis True Image / Cyber Protect Home Office client TLS connection".
- Payload: none — demonstrated by terminating the client's connection at a MITM proxy and observing it connect anyway.
- Root cause: the client never calls certificate verification on the server cert at all.
- Impact: full MITM interception/modification of client-server traffic (CVE-2021-32581). Programs often note no exploitation seen — the vulnerability stands on its own.
- Exemplars: 1056144 (Acronis), 1070533 (Acronis — hostname not checked on the login TLS connection specifically, letting a MITM impersonate the login server).

### 2. Certificate signature never verified (E2EE / key exchange)
- Endpoint shape: not an endpoint — the client-device enrollment/E2EE key exchange. E.g. "N/A (client-server E2EE key exchange)" for Nextcloud.
- Payload: none.
- Root cause: clients never verify that the certificate returned to them is signed by the server's public key during initial setup or device addition.
- Impact: a compromised server can hand each client a different public key undetected (theoretical; reporter confirmed the missing check without accessing data).
- Exemplar: 1192470 (Nextcloud).

### 3. Config value `undefined` disables verification (language-runtime default bug)
- Endpoint shape: any code path using `tls.connect` options.
- Param: `rejectUnauthorized`.
- Payload (verbatim):
  ```js
  const https = require('https');
  const request = https.get('https://expired.badssl.com', { rejectUnauthorized: undefined });
  request.on('error', (e) => console.log('Request failed:', e.message));
  request.on('response', (e) => console.log('Request succeeded'));
  ```
- Root cause: in `tls.connect`, an explicit `undefined` for `rejectUnauthorized` is treated as `false`, disabling verification contrary to documentation.
- Impact: request to `expired.badssl.com` succeeds when it must fail; any code passing `undefined` silently does no TLS validation.
- Exemplar: 1278254 (Node.js).

### 4. Mishandled verification return values inside TLS libraries
- Endpoint shape: library handshake internals, e.g. `SSL_connect` / `SSL_do_handshake` (OpenSSL 3.0.0), and `ossl_x509name_cmp` (Ruby).
- Payload (Ruby, verbatim):
  ```ruby
  a = OpenSSL::X509::Name.new([["CN", "www.example.com"]]); b = OpenSSL::X509::Name.new([["CN", "www.example.co"]]); a == b  #=> true
  ```
- Root cause variants:
  - OpenSSL: a negative return from `X509_verify_cert()` mishandled → `SSL_get_error` returns unexpected `SSL_ERROR_WANT_RETRY_VERIFY`; crafted chains cause crashes, infinite loops, or incorrect behavior (1455411).
  - Ruby: `ossl_x509name_cmp` uses threshold `result > 1` instead of `result > 0`, so distinct X509 Names compare equal — enabling acceptance of an illegitimate certificate in signing/encryption checks (CVE-2018-16395, 387250).
- Exemplars: 1455411 (Internet Bug Bounty), 387250 (Ruby).

### 5. ProxyAgent never verifies the upstream certificate (HTTP proxy ≠ CONNECT tunnel)
- Endpoint shape: `GET https://self-signed.badssl.com/` routed via `Undici ProxyAgent http://localhost:8118`; also Node's global `fetch` through `Undici.ProxyAgent` with HTTP or HTTPS proxy URLs.
- Payload: none stated (proxy + `self-signed.badssl.com` is the harness).
- Root cause: Undici's ProxyAgent sends absolute URLs to the proxy instead of opening a CONNECT tunnel, so the upstream server's certificate is never verified; HTTP proxy URLs additionally downgrade nominally-HTTPS requests to plaintext.
- Impact: request to `self-signed.badssl.com` via the proxy returned 200 instead of failing; all request/response data exposed to the proxy and network path — full MITM read/modify.
- Exemplars: 1583680, 1599063 (Node.js / Internet Bug Bounty).

### 6. IDN / punycode wildcard-matching failure
- Endpoint shape: libcurl TLS hostname verification (`lib/vtls/hostcheck.c`), wildcard SAN matching.
- Payload (verbatim): `curl https://%E3%81%82.example.local  --cacert server.crt`
- Root cause: `hostmatch()` checks the cert pattern for the "xn--" IDN prefix instead of the hostname, so wildcard matching is not disabled for IDN hostnames; equivalently, curl's private wildcard SAN matcher converts IDN hostnames to punycode (always `xn--`-prefixed) but still lets patterns like `x*` match.
- Impact: TLS connection succeeds with a mismatched wildcard certificate that should fail (CVE-2023-28321).
- Exemplars: 1950627, 1991427 (curl / Internet Bug Bounty).

### 7. Error path in TLS setup returns success (skips verification setup)
- Endpoint shape: `curl --http3-only` QUIC/TLS with wolfSSL backend; also plain QUIC (libcurl/wolfSSL).
- Param: `--curves` (also bad `tls13-ciphers` / `cafile`).
- Payload (verbatim):
  ```
  ./curl -v --http3-only 'https://example.com/' -o /dev/null -s --resolve example.com:443:192.168.1.24 --curves blah
  ```
- Root cause: CVE-2024-2379 — in `curl_wssl_init_ctx`, an error from bad tls13-ciphers/curves/cafile triggers `goto out` with `result` still holding the success value from `ctx_setup`, so certificate verification setup is skipped and the function returns success.
- Impact: curl skipped certificate verification and connected over HTTP/3 to a self-signed MITM server **without `--insecure`** (verified against the same request failing with a cert error under a control). Confirmed bypass on QUIC connections generally.
- Exemplars: 2410774 (curl), 2437050 (Internet Bug Bounty).

### 8. Verification skipped when the URL host is an IP address
- Endpoint shape: TLS connections to IP-address hosts under libcurl/mbedTLS (HTTPS, FTPS, IMAPS, SMTPS); also curl's own hostcheck treating an IP literal as a plain string.
- Payload: none stated (IP-literal URL + mismatched cert is the harness).
- Root cause variants:
  - libcurl skips the server certificate check entirely when the hostname is an IP address under mbedTLS (CVE-2024-2466, 2435482).
  - curl matches an IP literal in the URL against an IP string in the certificate **Common Name** instead of requiring a numeric `iPAddress` SAN entry (715413) — contrary to RFC 2818 server identity requirements.
- Impact: unverified or wrongly-matched certs accepted for IP hosts → MITM.
- Exemplars: 2435482, 715413, 2437050-adjacent.

### 9. OCSP stapling checks accept any response (or are skipped)
- Endpoint shape: `curl --cert-status` (GnuTLS backend); `curl --cert-status` with `CURLOPT_SSL_VERIFYSTATUS` under Apple SecTrust builds.
- Payload: none stated.
- Root cause variants:
  - GnuTLS: `gnutls_ocsp_status_request_is_checked()` returns non-zero for *any* existing stapled response, so 'unknown'/'unauthorized' statuses are accepted as success. A connection to a test site whose OCSP status returned 'unauthorized' was established without error (OpenSSL correctly errors) — 2669852.
  - Apple SecTrust: when SecTrust verifies the chain, curl skips OpenSSL's `verifystatus()` OCSP check, and SecTrust only processes a staple when one is present — so no OCSP enforcement occurs. `curl --cert-status --ca-native` exited 0 against a server with no staple (control build failed with exit 91) — 3694390.
- Impact: documented OCSP guarantees silently violated; revoked/unauthorized certs accepted.
- Exemplars: 2669852, 3694390 (curl).

### 10. SSH host-key verification silently skipped (SFTP/SCP)
- Endpoint shape: `sftp://{host}`.
- Payload (verbatim): `curl --user foo sftp://localhost:2222`
- Root cause: curl does not fail or prompt when the SSH host is absent from `known_hosts` — silently proceeding like `StrictHostKeyChecking accept-new` even without `--insecure`.
- Impact: a fake server captured credentials ("Authenticated username foo password bar"); enables MITM content tampering, upload/data leak, and credential theft.
- Exemplar: 2961050 (curl).

### 11. Hostname checked but signature/issuer not (partial verification)
- Endpoint shape: `Net::SMTP` TLS on port 465 / STARTTLS.
- Payload (verbatim):
  ```ruby
  require 'net/smtp'
  smtp = Net::SMTP.new("smtp.example", 465)
  smtp.enable_tls
  smtp.start
  ```
- Root cause: Net::SMTP verifies only the certificate hostname — not the signature or issuer — accepting self-signed or fake-CA-signed certs with a matching CN.
- Impact: TLS SMTP connection succeeded against a self-signed forged certificate matching the hostname; MITM can intercept TLS SMTP.
- Exemplar: 980249 (Ruby).

### 12. Mail/app clients not validating hostname-vs-CN
- Endpoint shape: Nextcloud Mail app's IMAP/SMTP TLS connections.
- Payload: none stated.
- Root cause: the app connected to IMAP/SMTP servers without verifying that the server hostname matched the certificate CN.
- Impact: app could be forced to connect to an insecure server (CVE-2020-8156).
- Exemplar: 803734 (Nextcloud).

### 13. Certificate revocation state as a phishing aid
- Endpoint shape: `GET https://support.theendlessweb.com` (and `jira.theendlessweb.com`) — checking organizational Let's Encrypt certs affected by the CAA rechecking incident.
- Payload: none.
- Root cause: org's certs required reissuance due to the Let's Encrypt CAA rechecking incident and would be revoked.
- Impact: confirmed the certs would become invalid — useful for phishing infrastructure credibility attacks.
- Exemplar: 813279 (Endless Group). Note: this is the only record in the set that is a revocation/lifecycle issue rather than a code bug.

### 14. License/cryptographic binding not enforced (adjacent — validation of a token, not a cert)
- Endpoint shape: Burp Suite offline license activation.
- Param: license key.
- Root cause: activation did not bind the key to a specific version or device; an older version accepted the same key.
- Impact: activated a latest-version (v1.7.29) key on older v1.7.17, enabling one license to be shared by multiple users.
- Exemplar: 294794/294891 (PortSwigger). Include only if the program's scope covers licensing logic; it's an "improper validation" cousin, not TLS.

## Bypass / chain notes

- **Error-path-as-success is the richest chain primitive**: a deliberately bad user-supplied option (`--curves blah`, bad `tls13-ciphers`, bad `cafile`) flips a `goto out` cleanup path into returning the stale success value from an earlier setup call (2410774). The chain: bogus option value → error branch → `result` never overwritten → verification setup skipped → handshake completes against a self-signed MITM server with no `--insecure` flag.
- **Proxy downgrade chains**: an "HTTPS" URL configured through an HTTP proxy URL under Undici.ProxyAgent becomes plaintext on the wire — the proxy URL scheme itself is the downgrade (1599066/1599063). No cert work needed at all; the tunnel is never built.
- **Missing-host-key chain**: SFTP connect → no known_hosts entry → no failure or prompt → client hands credentials to the attacker's fake server (2961050).
- **badssl.com as the universal test harness**: `expired.badssl.com`, `self-signed.badssl.com` appear repeatedly as the guaranteed-failing peer; stand up a local MITM listener (e.g. proxy on `http://localhost:8118`) to capture the success-instead-of-failure proof.
- **Partial-verification gaps chain with hostname lookalikes**: when only CN/hostname is checked (Net::SMTP, Nextcloud Mail), a self-signed cert with the right CN is sufficient — no CA compromise needed.

## Gotchas / what NOT to do

- Don't report "no exploitation observed" as a weakness of the finding — several accepted reports (Acronis CVE-2021-32581) explicitly note no exploitation seen; the missing check itself is the vulnerability.
- Don't assume hostname verification implies signature verification. The Ruby Net::SMTP and Nextcloud Mail bugs show clients that check the CN but happily accept self-signed/fake-CA certs (980249, 803734).
- Don't test IDN/wildcard issues with plain ASCII hostnames — the bug only fires on `xn--` punycode paths (`https://%E3%81%82.example.local`).
- Don't forget the backend matters: identical curl code paths behave differently under GnuTLS vs OpenSSL vs wolfSSL vs Apple SecTrust (2669852, 3694390, 2410774). Always state the backend and show a control build/config that fails correctly.
- Don't test IP-host verification against a domain cert with SANs only — mbedTLS-libcurl skips the check entirely for IP hosts, and curl's string-match bug needs a cert whose CN *contains the IP string* (2435482, 715413).
- Don't rely on the tool printing an error: in the `goto out` class the tool returns exit 0 / success — verify by whether the handshake *completed*, not by absence of error messages.
- Distinguish scope: library/runtime bugs (Node, Ruby, OpenSSL, curl, Undici) go through umbrella programs like Internet Bug Bounty; end-product client bugs (Acronis, Nextcloud, Endless) go through the vendor program.
- The revocation-status pattern (813279) and the license-key pattern (294891) are edge cases in this set — don't stretch them into generic "TLS is misconfigured" reports; they were accepted for specific, provable lifecycle/binding failures.

## Real-world impact examples

- **Full MITM of "secure" desktop backup traffic** — Acronis True Image clients with no cert validation (CVE-2021-32581): an attacker on the network can intercept and modify all client↔server traffic including login (1056144, 1070533).
- **Global fetch MitM in Node** — Undici.ProxyAgent never verifies upstream certs; request to `self-signed.badssl.com` via the proxy returned **200**; all HTTPS request/response data readable and modifiable by the proxy or anyone on the path (1583680, 1599063).
- **One-line code bug = zero TLS security** — `rejectUnauthorized: undefined` treated as `false` in Node's `tls.connect`; `expired.badssl.com` request succeeded (1278254).
- **Verification bypass without `--insecure`** — curl HTTP/3 + wolfSSL with `--curves blah` connected to a self-signed MITM server; verified working vs. a control that fails with a cert error (CVE-2024-2379, 2410774).
- **Credential capture** — curl SFTP to a host absent from known_hosts silently sent `foo`/`bar` to the attacker's fake server, enabling content tampering and data theft (2961050).
- **Cross-protocol MITM** — libcurl/mbedTLS skipped cert checks for IP hosts across HTTPS, FTPS, IMAPS, SMTPS (CVE-2024-2466, 2435482).
- **Accepting revoked status** — GnuTLS-backed curl established a connection to a server whose OCSP status was 'unauthorized' (2669852); Apple SecTrust builds ignored `--cert-status` entirely (3694390).
- **Identity confusion at the crypto-primitive level** — Ruby `X509::Name#==` returning true for `www.example.com` vs `www.example.co` (CVE-2018-16395, 387250); curl accepting a wildcard cert for an IDN hostname (CVE-2023-28321, 1950627/1991427).
- **Forged-cert SMTP interception** — Net::SMTP accepted a self-signed cert with matching CN, letting a MITM read TLS-protected mail (980249).