---
name: hunter-l3-host-header-injection
description: "Use when hunting Host Header Injection on a target. Loads the L3 technique sheet: Host Header Injection is a server-side flaw where the application trusts client-supplied routing headers — `Host`, `X-Forwarded-Host`, `Forwarded`, and occasionally `Referer` — when generating URLs, l"
domain: cybersecurity
subdomain: web
tags:
- web
- host-header-injection
- hunting
- l3
version: '1.0'
---

# Host Header Injection — Technique Sheet

## Overview

Host Header Injection is a server-side flaw where the application trusts client-supplied routing headers — `Host`, `X-Forwarded-Host`, `Forwarded`, and occasionally `Referer` — when generating URLs, links, redirects, or emails, instead of validating them against the canonical domain. Because the Host header decides "which site am I?", frameworks and reverse proxies routinely propagate it into link generation, password reset emails, invitation emails, and `301 Location` headers. It pays when the poisoned value reaches a *second* victim (reset/invitation emails, cached responses), turning a self-inflicted curl test into account takeover or site-wide cache poisoning.

## Distinct sub-patterns

### 1. Password reset poisoning via Host header

- **Endpoint shape:** `POST /password_reset` (or equivalent reset-request flow); the poisoned value is embedded in the reset link emailed to the user.
- **Payload:** `Host: attacker.example.com` (Concrete CMS, id=301592); `Host: evil.com` (Kartpay, id=1098948).
- **Root cause:** Reset link built from the Host header without canonical-host enforcement.
- **Impact:** Reset link points to the attacker's host; attacker intercepts the token in the link and hijacks the reset flow — full account takeover.
- **Exemplars:** id=301592 (Concrete CMS), id=1098948 (Kartpay).

### 2. Reset token exfiltration via Host header on link click

- **Endpoint shape:** Password reset request, then the *victim opens* the emailed reset link on their machine.
- **Payload:** `Host: evil.com` set when requesting the reset (Shopify, id=1092831).
- **Root cause:** The application leaks the reset token in the Host header of a subsequent request, which is sent to third-party sites — i.e., the token ends up transmitted to a domain the attacker controls.
- **Impact:** Reset token observed leaking to a third-party site in the Host header; the third-party site's owner can use the token to reset the user's password.
- **Exemplar:** id=1092831 (Shopify).

### 3. Invitation / onboarding email link injection via X-Forwarded-Host

- **Endpoint shape:** `POST /invitation` (email invite flow).
- **Payload:** `X-Forwarded-Host: example.com` (Logitech, id=1072277).
- **Root cause:** Application trusts `X-Forwarded-Host` to build invitation links, letting the attacker control the host in emails sent to users.
- **Impact:** Invitation emails contain attacker-controlled links, enabling phishing and account theft (email spoofing).
- **Exemplar:** id=1072277 (Logitech).
- **Note:** Direct Host header tampering on this target returned 403 — the bypass via `X-Forwarded-Host` was required (see Bypass notes).

### 4. Reflected Host in 301 redirect Location (open redirect)

- **Endpoint shape:** `GET /` or any route that issues a redirect, e.g. `GET /themes/search` (WordPress).
- **Payloads (verbatim):**
  - `Host: google.com` + `Host: anymalicioussite.com` → `301 Location: https://google.com/` (IRCCloud, id=13286)
  - `Host: heroku.com` → `301 Location: https://www.heroku.com/` (Gratipay, id=158482)
  - `Host: www.google.com` → `301 Moved Permanently, Location: https://google.com/` (Homebrew, id=221908)
  - `Host: z.xss.ro` → redirect to `https://z.xss.ro/themes/search/` (WordPress, id=273726)
  - `Host: crowdshield.com` → 301 to that domain (Whisper, id=94637)
- **Root cause:** Application reflects the attacker-controlled Host header into the 301 redirect `Location` without validation.
- **Impact:** Host-header-based open redirect on the target domain; on Gratipay explicitly demonstrated poisoning the browser cache so further requests to the legitimate site redirect to the attacker's site.
- **Exemplars:** id=13286 (IRCCloud), id=158482 (Gratipay), id=221908 (Homebrew), id=273726 (WordPress), id=94637 (Whisper).

### 5. DNS/web cache poisoning via X-Forwarded-Host (cached redirect)

- **Endpoint shape:** `GET /` on the main site, where the response is cached.
- **Payload:** `X-Forwarded-Host: evil.com` (HackerOne, id=487; no Host/param noted in the record beyond the payload).
- **Root cause:** App trusts `X-Forwarded-Host` to build redirect URLs, and the poisoned result gets cached.
- **Impact:** After a crafted request, visiting hackerone.com instantly redirected to evil.com (DNS cache poisoning) — every subsequent visitor hitting the cached entry was affected.
- **Exemplar:** id=487 (HackerOne).

### 6. Infrastructure-host takeover of routing (Fastly/CDN edge)

- **Endpoint shape:** `GET /` behind a CDN (Fastly in the RubyGems case).
- **Payload:** `Host: www.google.com` → "Domain Not Found"; `Host: www.newrelic.com` (a Fastly-hosted domain) → attacker-influenced `301` to `http://newrelic.com/` (RubyGems, id=180196).
- **Root cause:** The target trusts the HTTP Host header for routing/link generation; when the supplied Host matches a domain also routed on the shared CDN, the edge routes into that other customer's config, producing an attacker-influenced redirect.
- **Impact:** Controlled Host changed routing behavior; enabled cache poisoning / password-reset abuse.
- **Exemplar:** id=180196 (RubyGems).
- **Takeaway:** Host values of *other domains on the same CDN* are valid test inputs, not just your own attacker domain.

### 7. Forwarded header (RFC 7239) injection

- **Endpoint shape:** `GET /` on a redirecting route.
- **Payload:** `Forwarded: host=evil.com` (RubyGems, id=2627221).
- **Root cause:** Application trusts the `Forwarded` header's `host=` value for building redirects without validation.
- **Impact:** Redirected users to an attacker-controlled domain; phishing and potential web cache poisoning.
- **Exemplar:** id=2627221 (RubyGems).
- **Note:** Many hunters stop at Host/X-Forwarded-Host; the standardized `Forwarded` header is a distinct injection surface that reached a real redirect here.

### 8. Framework-level redirect helper trusting X-Forwarded-Host (Rails)

- **Endpoint shape:** Any Rails action using `redirect_to`, e.g. `GET redirect_to`.
- **Payload:** attacker IP as `X-Forwarded-Host` / `HTTP_HOST` (Ruby on Rails core, id=888176).
- **Root cause:** Rails `_compute_redirect_to_location` builds the Location header from `request.host_with_port`, which trusts `X-Forwarded-Host`; critically, **IP hosts bypass the configured host allowlist check**.
- **Impact:** Attacker IP reflected into the redirect Location; enables password-reset poisoning and web-cache poisoning.
- **Exemplar:** id=888176 (Ruby on Rails).
- **Takeaway:** If a host allowlist blocks your domain, try a raw IP in X-Forwarded-Host.

### 9. Referer reflection into outbound email links

- **Endpoint shape:** `POST` newsletter signup on the main site (www.starbucks.com).
- **Payload:** `Referer: https://r1otnetsec.herokuapp.com/` (Starbucks, id=229498).
- **Root cause:** Newsletter signup reflects the Referer into the "Welcome to Starbucks" email links without validation.
- **Impact:** *All* links in the welcome email (including the Starbucks logo image link) redirected to the attacker-controlled domain — credential phishing at brand scale.
- **Exemplar:** id=229498 (Starbucks).
- **Note:** This is a sibling technique — the same "control what URL-builder trusts" idea, but via Referer rather than Host.

## Bypass / chain notes

- **403 on Host → X-Forwarded-Host:** On Logitech (id=1072277), direct Host tampering returned 403; adding `X-Forwarded-Host: example.com` succeeded and the invitation email linked to the attacker domain. Always try proxy-derived headers when raw Host is blocked.
- **Host allowlist → raw IP:** Rails (id=888176) shows configured host checks bypassed entirely by supplying an IP address instead of a hostname.
- **Host → Forwarded:** RubyGems had Host/X-Forwarded-Host issues (id=180196) *and* a separate `Forwarded: host=evil.com` injection (id=2627221) — test the full header family: `Host`, `X-Forwarded-Host`, `Forwarded: host=`, and `Referer`.
- **Multi-step poisoning chains in the records:**
  - Concrete CMS (id=301592): submit reset with poisoned Host → reset link points to attacker host → attacker intercepts and uses the link.
  - Shopify (id=1092831): request reset → victim opens link → token leaks via Host header to third-party site → site owner resets the password. The victim's click does the exfiltration; no interactive attacker step on the server side.
  - HackerOne (id=487): single poisoned request → response cached → subsequent organic visitors redirected to evil.com. The cache is the multiplier.
- **CDN co-tenancy:** Use hosts of other domains on the target's CDN/edge as Host values (RubyGems/Fastly, id=180196).

## Gotchas / what NOT to do

- A self-inflicted redirect (your curl gets a 301 to your domain) is usually the *floor*, not the report. WordPress (id=273726) was explicitly framed as "self-inflicted open redirect" with impact contingent on internal config; the strong reports proved victim reach — email injection (Logitech, Starbucks, Concrete CMS), token leakage (Shopify), or cache poisoning (HackerOne, Gratipay).
- Redirect Location reflection alone still paid on several programs (Homebrew, Whisper, IRCCloud, Gratipay) — but frame it as cache poisoning/phishing potential plus demonstrated Location control, not just "open redirect."
- "Domain Not Found" style responses (RubyGems, id=180196) are signal, not failure — they show Host controls routing; vary the Host value (e.g., a co-located CDN domain) rather than concluding the app ignores Host.
- Don't stop at `Host` when it's filtered — every successful injection in these records lives on at least one of `X-Forwarded-Host`, `Forwarded`, or `Referer`.
- Test email-generating flows (invite, reset, newsletter) specifically — they convert host control into victim-delivered attacks, which is where the proven account-takeover impact came from.

## Real-world impact examples

- **HackerOne (id=487):** One crafted request with `X-Forwarded-Host: evil.com`; afterwards, visiting hackerone.com redirected to evil.com due to cached poisoned response — sitewide redirect for real visitors.
- **Shopify (id=1092831):** Password reset token observed leaking in the Host header to a third-party site when the victim opened the reset link; the third party could use the token to reset the user's password.
- **Logitech (id=1072277):** `X-Forwarded-Host: example.com` on `POST /invitation` made invitation emails link to the attacker's domain — direct phishing/account-theft vector despite a 403 on raw Host tampering.
- **Starbucks (id=229498):** Referer injection made *every link in the official welcome email* — including the Starbucks logo — redirect to the attacker's Heroku app, a high-fidelity credential phishing email from the brand itself.
- **Gratipay (id=158482):** `Host: heroku.com` produced `301 Location: https://www.heroku.com/`; browser cache poisoning meant subsequent gratipay.com visits redirected to the attacker's site.
- **Concrete CMS (id=301592):** `Host: attacker.example.com` embedded the attacker's host into the generated password reset link, enabling full reset-flow hijack.