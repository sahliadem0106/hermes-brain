---
name: hunter-l3-security-misconfiguration
description: "Use when hunting Security Misconfiguration on a target. Loads the L3 technique sheet: Security Misconfiguration is the catch-all class for servers and applications that ship in a state less hardened than intended: missing or weak security headers, insecure cookie flags, weak or antiqua"
domain: cybersecurity
subdomain: web
tags:
- web
- security-misconfiguration
- hunting
- l3
version: '1.0'
---

# Security Misconfiguration — Technique Sheet

## Overview
Security Misconfiguration is the catch-all class for servers and applications that ship in a state less hardened than intended: missing or weak security headers, insecure cookie flags, weak or antiquated authentication transport on exposed endpoints, and admin/debug interfaces (xmlrpc.php, wp-admin) left reachable by anonymous users. Individually each finding is often low severity; the class pays when you chain a misconfiguration into credential brute-force, MIME-sniffing drive-by attacks, or session hijacking — and it pays reliably because misconfigs are trivially verifiable (one request, one header check) and frequently missed in legacy code paths. These findings came from HackerOne programs (GoCD, Nextcloud, X/xAI, HackerOne itself, Ian Dunn, Stellar.org), all by the same reporter, which tells you something: header/flag auditing is a repeatable, high-volume hunting style.

## Distinct sub-patterns

### 1. Missing X-Content-Type-Options: nosniff on authentication-sensitive responses
- Endpoint shape: `GET /go/auth/login` (GoCD). Applicable to any response that renders attacker-influenceable content — login pages, file download endpoints, API responses with `Content-Type` that browsers might sniff.
- Payload that fired: none needed — the finding is the *absence* of a header. Confirm with:
  `curl -sI https://target/go/auth/login | grep -i x-content-type-options`
- Root cause: the server (GoCD's embedded Jetty, in this case) does not emit `X-Content-Type-Options: nosniff`. Without it, IE (and historically Chrome for certain content types) perform MIME sniffing: a response served as one content type can be reinterpreted as HTML/JS if the sniffed type differs, enabling stored-XSS-via-sniffing and drive-by downloads of user-uploaded files.
- Proven impact: confirmed the login response lacks the header, leaving IE/Chrome users vulnerable to MIME-sniffing attacks including drive-by download exposure. Report ID: **151786** (GoCD).
- Hunting note: check *every* response class, not just the homepage — auth endpoints and file-serving routes are the ones where a sniffing bug actually chains into something.

### 2. HTTP Basic authentication on direct file URLs (Base64 transport weakness)
- Endpoint shape: `GET /remote.php/webdav/Photos/{filename}` (Nextcloud). Any endpoint that fronts raw file access with Basic auth: WebDAV, direct file share links, app-store endpoints, router admin panels.
- Payload that fired: payload not stated. The observation is that responses require `Authorization: Basic <base64(user:pass)>`.
- Root cause: direct file URLs are protected with HTTP Basic auth whose credentials are merely Base64-encoded (not encrypted at rest in any meaningful sense, trivially decoded, and — depending on client behavior — re-sent on every request to the realm). This makes offline decoding and automated brute-force against the endpoint materially easier than form-based auth with rate limiting, because generic tooling (`hydra`, `ffuf` with a wordlist) works directly against the 401 challenge.
- Proven impact: confirmed direct file URLs use Basic Authentication with Base64-encoded username/password in the header, easing brute-force attacks against user accounts. Report ID: **151847** (Nextcloud).
- Hunting note: enumerate file paths (Photos, templates, shares) to discover the Basic-auth-protected route; then demonstrate the brute-force *feasibility* — many programs want evidence like a captured `Authorization` header plus the decoded credentials format.

### 3. Session cookies set without the Secure flag
- Endpoint shape: `GET /` on an investor relations portal — `investor.twitterinc.com` (X / xAI). Applies anywhere a session cookie is issued over a domain that also accepts plain HTTP.
- Payload that fired: none — the finding is a cookie attribute. Cookie names observed: `AMDA452F526X_SESSION`, `AMDA452F526X_BRIEFCASE`, `AMDA452F526X_PREVIEW`.
- Root cause: the `Set-Cookie` headers for the session cookies omit `Secure`, so the browser will transmit them over plaintext HTTP. Any network MITM (open Wi-Fi, corporate proxy) or an HTTP→HTTPS downgrade opportunity can capture the session.
- Proven impact: confirmed three session cookies (`_SESSION`, `_BRIEFCASE`, `_PREVIEW`) are set without `Secure`, exposing them to transmission over plain HTTP. Report ID: **15232** (X / xAI).
- Hunting note: the `PREVIEW` cookie name hints at a preview/staging surface — check whether the same portal serves content over HTTP at all; demonstrating an actual HTTP-served page that would receive the cookie strengthens severity.

### 4. HSTS max-age below policy threshold
- Endpoint shape: response headers of `https://hackerone.com` — the `Strict-Transport-Security` header itself is the parameter surface.
- Payload that fired (verbatim): `max-age=2678400; includeSubdomains`
- Root cause: the site serves HSTS with a `max-age` of 2678400 seconds (~31 days), which is flagged TOO SHORT by ssllabs.com (their policy expects ≥ 180 days). A short max-age narrows the window in which the browser enforces HTTPS, weakening downgrade protection for infrequent visitors.
- Proven impact: observed header `Strict-Transport-Security: max-age=2678400; includeSubdomains` flagged TOO SHORT by ssllabs.com. Report ID: **3709** (HackerOne).
- Hunting note: this is an accepted-report existence proof for "policy-compliance" findings on a top program — but note it was accepted on HackerOne's own program years ago; on modern programs this is frequently informational/NA. Cite the ssllabs grading as third-party evidence in your report.

### 5. XML-RPC enabled on WordPress (system.listMethods disclosure)
- Endpoint shape: `POST /wordpress/xmlrpc.php` with a body param `methodName`.
- Payload that fired (verbatim):
  `<methodName>system.listMethods</methodName>`
  (i.e., a full XML-RPC request wrapping this element; the response enumerates every exposed method.)
- Root cause: `xmlrpc.php` ships enabled by default in WordPress installs and is commonly forgotten. It exposes (a) method enumeration via `system.listMethods`, (b) credential brute-force via `wp.getUsersBlogs` (one request tests many passwords with no login rate limit), and (c) pingback-based amplification for DDoS.
- Proven impact: xmlrpc.php responded with all available methods via `system.listMethods`, enabling brute-force / amplified-DDoS abuse. The reporter did not exploit further — full impact was not demonstrated in the report. Report ID: **371550** (Ian Dunn program).
- Hunting note: even a methods list alone was accepted here. `wp.getUsersBlogs` POST with candidate credentials is the standard severity-escalation follow-up; `pingback.ping` to an external host demonstrates amplification.

### 6. Anonymous-reachable admin panel with server information disclosure
- Endpoint shape: `GET /wp-admin/` (Stellar.org). Any admin path (`/wp-admin/`, `/admin`, `/manager/html`, `/console`) reachable without authentication.
- Payload that fired: none — unauthenticated GET is the whole finding.
- Root cause: the WordPress admin panel is reachable by anonymous users (no redirect to login, no IP restriction, no auth wall), and the response leaks server version and operating-system details (banner/headers/error pages). Combined, this gives an attacker both a target surface and reconnaissance for targeted brute force of admin credentials.
- Proven impact: anonymous access to `/wp-admin/` plus exposed server version/OS information, enabling targeted brute force of admin credentials. Report ID: **376563** (Stellar.org).
- Hunting note: distinguish "wp-admin redirects to login" (normal) from "wp-admin renders admin operations/panels" (finding). The information disclosure (version/OS) is what turns a 200-on-login-page into a real report.

## Bypass / chain notes
Records show no multi-step chains (all `chain: (none)`), but the records' own impact statements define the canonical escalation paths:
- Missing `nosniff` → chain with a user-controlled file-serving endpoint → MIME confusion → XSS / drive-by download (stated impact of 151786).
- Basic-auth over Base64 → direct credential brute force with generic tooling (stated impact of 151847).
- Cookie without `Secure` → MITM over plain HTTP → session capture (stated impact of 15232).
- XML-RPC `system.listMethods` → `wp.getUsersBlogs` credential brute force / pingback amplification (stated impact of 371550).
- Anonymous wp-admin + version/OS disclosure → targeted admin brute force (stated impact of 376563).
The pattern across all: a config weakness alone is low severity; pair it with the attacker capability it unlocks and demonstrate that capability's feasibility (a captured header, a methods list, an ssllabs grade) without fully exploiting.

## Gotchas / what NOT to do
- Do not report a missing header on a page with no attacker-influenced content — nosniff findings need a sniffing-possible response to have teeth.
- Do not assume Basic auth = vulnerability by itself; the accepted Nextcloud finding hinged on the Base64/brute-force angle on direct file URLs, not merely "Basic auth exists."
- Secure-flag findings need the domain to actually accept HTTP; if everything 301s to HTTPS instantly, severity collapses.
- HSTS max-age findings are frequently rejected as informational on modern programs — 3706-era acceptance is not a guarantee; check program policy first.
- XML-RPC: enumerating methods is an accepted finding, but do not run actual brute force against production accounts without explicit program permission — stop at the methods list.
- Anonymous /wp-admin/ access that merely shows a login redirect is NOT a finding — verify you can reach admin operations or information disclosure, and document what specifically leaks.
- All six records were single-request, header/flag observations with no exploit chain — don't fabricate deeper exploitation than the config evidence supports; state "impact not further exploited" where true.

## Real-world impact examples (concrete, from records)
- GoCD (151786): login endpoint confirmed missing `X-Content-Type-Options`, exposing IE/Chrome users to MIME sniffing and drive-by download scenarios.
- Nextcloud (151847): confirmed `Authorization: Basic` with Base64-encoded credentials protecting direct file URLs (`/remote.php/webdav/Photos/{filename}`), easing brute force of user accounts.
- X/xAI (15232): confirmed `AMDA452F526X_SESSION`, `AMDA452F526X_BRIEFCASE`, `AMDA452F526X_PREVIEW` cookies issued without `Secure` on investor.twitterinc.com — session tokens transmittable over plain HTTP.
- HackerOne (3709): live HSTS header `max-age=2678400; includeSubdomains` graded TOO SHORT by ssllabs (below the 180-day policy threshold).
- Ian Dunn (371550): xmlrpc.php returned the full method list to `<methodName>system.listMethods</methodName>` — brute-force and amplification-DDoS surface confirmed.
- Stellar.org (376563): unauthenticated `/wp-admin/` access with server version/OS disclosure, enabling targeted admin credential brute force.