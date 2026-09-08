---
name: hunter-l3-cleartext-transmission
description: "Use when hunting Cleartext Transmission on a target. Loads the L3 technique sheet: Cleartext Transmission bugs are cases where data that should travel over TLS travels over plain HTTP — either because a link/URL was constructed with an `http://` scheme, a server fails to redirect HT"
domain: cybersecurity
subdomain: web
tags:
- web
- cleartext-transmission
- hunting
- l3
version: '1.0'
---

# Cleartext Transmission — Technique Sheet

## Overview
Cleartext Transmission bugs are cases where data that should travel over TLS travels over plain HTTP — either because a link/URL was constructed with an `http://` scheme, a server fails to redirect HTTP→HTTPS, or because a client/library silently downgrades a connection it already holds instead of upgrading or reconnecting. As a bug class it sits at the "low-hanging but real" tier: standalone instances (a single HTTP page) often rate only low severity, but the class pays when (a) sensitive input (credentials, addresses, tokens) is transmitted on the cleartext channel, or (b) the flaw lives inside a library, where it silently violates a security guarantee for every downstream user.

## Distinct sub-patterns

### 1. Generated share/outbound links hardcoded to HTTP
- **Endpoint shape / parameter:** A social-sharing button on a public site. Template: the "Share to Facebook" action on any project page — `GET https://<host>/projects/<project>/<component>/<lang>/` → the button's `href` points to a Facebook share URL whose `u=` parameter is `http://<host>/projects/...` instead of `https://`.
  - Exemplar: `GET https://demo.weblate.org/projects/hello/master/en_GB/`, param: N/A (Share to Facebook button).
- **Payload that actually fired (verbatim):** `https://demo.weblate.org/projects/hello/master/en_GB/` (the page URL; the generated share link itself was the HTTP-scheme artifact).
- **Root-cause pattern:** The Share-to-Facebook link is generated over HTTP instead of HTTPS — a template/config default (`http://` hardcode) rather than an open redirect or TLS misconfig on the page itself.
- **Impact proven:** Confirmed the Facebook share link used by the Share button is served over HTTP, not HTTPS — visitors clicking Share leak the browsing URL in cleartext to the network.
- **Exemplar report IDs:** 225769 (Weblate).

### 2. Sensitive form input on an HTTP-only page with no HTTPS redirect
- **Endpoint shape / parameter:** A login or data-submission page served at `http://` with no 301/302 upgrade. Two shapes in the records:
  - `GET http://translate.kromtech.com/user/login` — login page (credential entry).
  - `POST http://rinkeby.chain.link/` (submit testnet address) — param: testnet address.
- **Payload that actually fired:** payload not stated for both records (576288, 741549); the "payload" is simply the natural use of the page — submitting the login form / the testnet address.
- **Root-cause pattern:** The page is served over plain HTTP without TLS, and there is no HTTPS redirect (576288 explicitly confirms "no HTTPS redirect"). Nothing forces the browser onto TLS before the user types.
- **Impact proven:**
  - 576288 (Chainlink): captured the user's testnet address in cleartext via Wireshark during transmission — on-path capture demonstrated, not just theorized.
  - 741549 (Clario): accessed the Kromtech login page unencrypted without SSL/TLS, allowing credentials/interception in transit.
- **Exemplar report IDs:** 576288 (Chainlink), 741549 (Clario).

### 3. Library bug: protocol-selection logic fails to disable plaintext (curl `--proto`)
- **Endpoint shape / parameter:** The curl CLI `--proto` option. Template: any invocation that *only removes* protocols, e.g. `--proto -all,-http` (negation list that disables everything then disables http again, without adding a safe set back).
- **Payload that actually fired (verbatim):** `curl --proto -all,-http http://curl.se`
- **Root-cause pattern:** Protocol-removal logic error: when a selection disables all protocols without adding any, the default set remains allowed. The removal-only expression is interpreted such that the default protocol set stays enabled instead of resolving to "nothing allowed."
- **Impact proven:** Confirmed a request was sent over plaintext http even though that protocol was explicitly disabled.
- **Exemplar report IDs:** 2437131 (Internet Bug Bounty / curl).

### 4. Library bug: connection-reuse bypasses a later TLS requirement (curl mail protocols)
This is the highest-value sub-pattern in the records — a pooled-connection downgrade. Two variants share one root cause:

- **Endpoint shape / parameter:** libcurl connection reuse on cleartext-upgrade mail schemes: `imap://`, `pop3://`, `smtp://`, with the second transfer setting `CURLOPT_USE_SSL` (CLI: `--ssl-reqd`). Template:
  - Transfer 1: `smtp://host` (no TLS).
  - Transfer 2 (same handle, `--next`): `smtp://host --ssl-reqd`.
  - Verbatim repro (3770979): `"$CURL_BIN" -sv "smtp://127.0.0.1:$PORT" --user alice:secret --mail-from alice@example --mail-rcpt bob@example -T msg1.txt --next "smtp://127.0.0.1:$PORT" --ssl-reqd --user alice:secret --mail-from alice@example --mail-rcpt bob@example -T msg2.txt`
- **Payload that actually fired:** verbatim command above; 3621851 itself notes payload (none) — the repro is the two-transfer sequence.
- **Root-cause pattern:** Connection reuse for cleartext-upgrade mail protocols does not account for the later transfer's `CURLOPT_USE_SSL`. In the 3770979 regression, same-scheme connection matching no longer enforces `url_match_ssl_use()`, so a later `--ssl-reqd` request reuses a pooled clear-text `smtp://` session without running STARTTLS.
- **Impact proven:**
  - 3621851: verified — a later TLS-required (`--ssl-reqd`) mail transfer is sent over a previously established plaintext connection, contrary to the TLS requirement.
  - 3770979: confirmed — the second `--ssl-reqd` transfer printed `Reusing existing smtp: connection`, the server saw only one TCP connection, and STARTTLS never ran, so a TLS-required message was sent in cleartext (credentials and message body included, since `--user alice:secret` was on the same reused session).
- **Exemplar report IDs:** 3621851, 3770979 (both curl).

## Bypass / chain notes
- **Reuse-the-pool chain (3621851)**, the one explicit multi-step chain in the records:
  1. Open plaintext mail connection (e.g. `imap://host` with no SSL).
  2. Make a second transfer with `--ssl-reqd` on the same easy/multi handle.
  3. Connection is reused as plaintext; STARTTLS is not enforced — the TLS-required transfer completes in the clear.
  Generalize: any stateful client that pools connections and matches them on scheme/host/port *without* matching the security level (plain vs. upgraded) is a downgrade candidate. The matching predicate must include "TLS required/used."
- **Negation-only `--proto` bypass (2437131):** a selection consisting solely of removals (`-all,-http`) fails closed-to-default instead of closed-to-none. The bypass is that "explicitly disabled" silently means "still enabled." Test removal-only expressions against any protocol-selection UI.
- **No-redirect gap (576288):** the HTTP page + absence of an HTTPS redirect means even TLS-available apps leak: nothing in the stack forces the upgrade before first keystroke.

## Gotchas / what NOT to do
- Don't report a single HTTP-served page as high severity on its own — 225769, 741549-style findings are low/medium tier. Severity comes from what crosses the wire (credentials, addresses) or from the library's broken guarantee.
- Wireshark/on-path proof is what elevates a "page is HTTP" report (576288 captured the actual testnet address in transit) — demonstrate interception, don't just screenshot the http:// URL.
- Don't conflate "no HSTS" with "cleartext transmission" — the records' accepted bugs are about actual cleartext data flow or actual cleartext sends, not missing headers.
- For connection-reuse bugs, the tell is on the wire: one TCP connection where the policy demands TLS, and no STARTTLS in the session. Verifying "server saw only one TCP connection" (3770979) is the confirmation step; client-side logs alone ("Reusing existing connection") support but don't prove cleartext send.
- Negation-only protocol selections are a footgun worth testing but also a footgun to avoid in your own repro tooling: `--proto -all,-http` did NOT disable http in the buggy versions — check your own curl's behavior before trusting it.

## Real-world impact examples
- **Chainlink (576288):** a user's Rinkeby testnet address, submitted at `http://rinkeby.chain.link/`, was captured in cleartext via Wireshark mid-transmission — a demonstrated on-path read of user-supplied data.
- **Clario/Kromtech (741549):** `http://translate.kromtech.com/user/login` served the login flow unencrypted, so credentials were interceptable in transit.
- **Weblate (225769):** every visitor clicking Share to Facebook on `https://demo.weblate.org/projects/hello/master/en_GB/` emitted the share link over HTTP — silent URL leakage at scale.
- **curl (3621851, 3770979):** a transfer explicitly requiring TLS (`--ssl-reqd`) — mail with authenticated credentials (`--user alice:secret`) and message body — was delivered over a reused plaintext `smtp://` connection with STARTTLS never executed; the client even announced the reuse (`Reusing existing smtp: connection`) while the server observed a single unencrypted TCP session.
- **curl / Internet Bug Bounty (2437131):** `curl --proto -all,-http http://curl.se` sent the request over plaintext http despite the protocol being explicitly disabled — a library-level violation of the user's stated security policy affecting every version shipping the faulty selection logic.