---
name: hunter-l3-insecure-transport
description: "Use when hunting Insecure Transport on a target. Loads the L3 technique sheet: Insecure Transport covers failures to enforce TLS across an application's attack surface: plaintext HTTP endpoints that remain reachable, forms that submit credentials without an automatic HTTPS upgra"
domain: cybersecurity
subdomain: web
tags:
- web
- insecure-transport
- hunting
- l3
version: '1.0'
---

# Insecure Transport — Technique Sheet

## Overview
Insecure Transport covers failures to enforce TLS across an application's attack surface: plaintext HTTP endpoints that remain reachable, forms that submit credentials without an automatic HTTPS upgrade, cookies leaked before a redirect, and backend storage (e.g. S3 buckets) that serve objects over unencrypted HTTP. Individually these are often classified as low-to-medium, but they prove that sensitive data — credentials, session cookies, webhook payloads, uploaded files — traverses the network in cleartext and can be sniffed by an on-path attacker. They pay best on programs that handle auth or confidential user data, and they are cheap to find: re-scheme a known URL and observe whether you get a 200 or a redirect.

## Distinct sub-patterns

### 1. Plaintext HTTP webhook endpoints
- Endpoint shape: `POST /webhooks` registered with an `http://` (not `https://`) URL. No special parameter; the weakness is the scheme accepted for the callback target.
- Payload that fired: payload not stated (the finding is about the transport of webhook deliveries, not a crafted body).
- Root-cause pattern: the application performs no scheme validation (or no enforcement of HTTPS) on the webhook URL supplied by the user. Any `http://` callback is accepted, so all subsequent event deliveries — which typically contain secrets, customer data, or API tokens — go over plaintext HTTP where a network observer reads or tampers with them.
- Impact proven: webhook payloads can be delivered over plaintext HTTP and intercepted/read on the network. The program accepted the finding and added warnings rather than outright blocking HTTP endpoints — a valid alternative outcome to note when reporting.
- Exemplar: 158541 (Moneybird).

### 2. HTTP login form with no automatic HTTPS upgrade
- Endpoint shape: `POST http://legalrobot.com/` — the root/login form reachable and submittable over HTTP.
- Payload that fired: payload not stated; the PoC was requesting the HTTP origin and observing behavior.
- Root-cause pattern: two failures compound — (a) the HTTP origin serves `200 OK` instead of a `301`/`302` redirect to HTTPS, and (b) no HSTS / no automatic upgrade means the browser happily submits the form (username + password) over the plaintext connection.
- Impact proven: `http://legalrobot.com` served 200 instead of 301, and the login form could submit credentials in the clear — credentials sniffable by an on-path attacker (coffee-shop/MITM scenario).
- Exemplar: 164419 (Legal Robot).

### 3. Cookies transmitted before the HTTPS redirect on outbound links
- Endpoint shape: `GET /events/2017/06/12/ICAIL/` — an internal content page containing external links; the `url` parameter carries the outbound destination.
- Payload that fired: payload not stated; the proof was observing request headers on the initial HTTP hop.
- Root-cause pattern: external links on the page are initially rendered/served over HTTP. The application issues cookies without the `Secure` flag, so when the browser follows the link (even if the server then redirects to HTTPS), the session cookie is already sent over the plaintext hop — it hits the wire before any redirect upgrades the connection.
- Impact proven: cookies were transmitted over the network before the HTTPS redirect on external links — session tokens exposed to passive sniffing despite the app "using HTTPS."
- Exemplar: 272863 (Legal Robot).

### 4. Backend object storage that doesn't enforce HTTPS
- Endpoint shape: `GET https://hackerone-attachments.s3.amazonaws.com/production/{path}` — S3-hosted attachments fetched with the `http://` scheme instead.
- Payload that fired: payload not stated; the PoC was swapping the scheme on a known attachment URL and fetching it over HTTP.
- Root-cause pattern: the S3 bucket (and any frontend generating links to it) does not enforce HTTPS — S3 serves both schemes by default unless the bucket policy / CDN config requires it. If the main app hands out or tolerates `http://` attachment URLs, sensitive uploads are fetched over unencrypted connections even though the main site is fully HTTPS.
- Impact proven: uploaded screenshots (private report attachments) were accessible over plain HTTP at `http://hackerone-attachments.s3.amazonaws.com/...`, meaning user content moved over only partially encrypted, sniffable connections.
- Exemplar: 43280 (HackerOne).

## Bypass / chain notes
The records contain no multi-step chains (all four are single-hop findings), but note these common assessment angles implicit in them:

- Scheme-swapping is the core "bypass": take any known HTTPS URL (webhook target, attachment link, login form action) and change `https://` → `http://`. A 200 response, a delivered webhook, or a fetched object = finding.
- The cookie-leak pattern (272863) is effectively a chain of two root causes: cookies missing the `Secure` attribute + links rendered as plain HTTP before an application-level redirect. Fixing either alone stops the leak — report both halves.
- The webhook pattern (158541) chains naturally with any feature that lets users register callbacks: if HTTP callbacks are accepted, an attacker-controlled `http://` host on a network the victim's server talks to can capture third-party data passively.

## Gotchas / what NOT to do
- Don't report plain "site supports HTTP" without proving sensitive data moves over it. All four accepted findings tied the plaintext transport to something concrete: credentials, cookies, webhook payloads, or private uploads. A 301 redirect alone, with no data over HTTP, is not a finding.
- Test with a clean HTTP client (curl / fresh browser profile), not a browser that already has HSTS state cached — HSTS will mask a missing server-side redirect (the exact failure in 164419).
- For the cookie-pre-redirect bug, you must capture the actual request headers on the HTTP hop to prove the cookie hit the wire; "it probably sends cookies" is not evidence.
- For S3-style findings, verify the object actually returns over HTTP with the same path — some buckets block HTTP via policy; a hypothetical isn't a report.
- Programs may accept these with mitigations instead of fixes (Moneybird added warnings to HTTP webhook URLs rather than rejecting them). Frame impact to show why silent acceptance of HTTP is still exploitable, and don't re-report after a warning-only mitigation unless it's demonstrably ineffective.

## Real-world impact examples
- Legal Robot login (164419): an on-path attacker could passively capture usernames and passwords from the login form submitted over `http://legalrobot.com/` — full account takeover material, obtained with no active attack beyond network position.
- Legal Robot cookie leak (272863): session cookies for logged-in users were broadcast in cleartext before any HTTPS redirect when following external event links, enabling session hijacking via passive sniffing.
- HackerOne attachments (43280): private bug-report screenshots — often containing internal URLs, tokens, or sensitive customer data in test cases — were downloadable over plain HTTP from the S3 bucket, exposing triage-confidential content to network observers.
- Moneybird webhooks (158541): financial/accounting event payloads delivered to user-registered HTTP endpoints could be intercepted and read in transit, exposing business data carried by the webhook system.