---
name: hunter-l3-misconfiguration
description: "Use when hunting Misconfiguration on a target. Loads the L3 technique sheet: Misconfiguration findings are exactly that: a service, DNS record, or endpoint left in its default or forgotten state."
domain: cybersecurity
subdomain: web
tags:
- web
- misconfiguration
- hunting
- l3
version: '1.0'
---

# Misconfiguration — Technique Sheet

## Overview

Misconfiguration findings are exactly that: a service, DNS record, or endpoint left in its default or forgotten state. No injection payload is required — the bug is the configuration itself, and the hunt is driven by enumeration of third-party integrations (Mailgun, GitHub Apps, Spring Boot Actuator, Confluence), DNS record hygiene, and exposed management surfaces. They pay well when the misconfig grants a trust boundary: email interception, account takeover via re-claimable integrations, or credential leakage from unauthenticated admin endpoints. Low-hanging variants (broken links on 404 pages, missing DMARC, dangling program URLs) are valid but often get triaged as informational — the real money is in takeover-grade and data-exposure sub-patterns.

## Distinct sub-patterns

### 1. Unclaimed Mailgun subdomain (CNAME → mailgun.org) — email interception

- **Endpoint shape / parameter:** DNS lookup on email-related subdomains: `email.{domain}`, `email.mg.{domain}`. Check CNAME and MX records.
  - Exemplars: `email.mg.gitlab.com`, `email.bitwarden.com`
  - Diagnostic signature: `CNAME email.mg.gitlab.com → mailgun.org`, with inherited Mailgun MX records (`MX 10 mxa.mailgun.org`, `10 mxb.mailgun.org`-style records point to Mailgun infrastructure).
- **Payload:** (none stated) — the "payload" is the account action: sign up for your own Mailgun account, add the victim subdomain as a sending/receiving domain, pass Mailgun's DNS verification (which succeeds because the CNAME already exists).
- **Root cause:** A CNAME pointing to mailgun.org was provisioned (for transactional email) but the subdomain was never claimed in any Mailgun account — or the account that owned it lapsed. Mailgun's domain-verification flow accepts the domain as long as the DNS records resolve correctly, so the first person to claim it wins. The MX records inherited via the CNAME mean all mail to that subdomain is routed to whichever Mailgun account holds it.
- **Impact proven:**
  - GitLab (id=174983): claimed `email.mg.gitlab.com` in attacker's Mailgun account, created the mailing list address `postmaster@email.mg.gitlab.com`, and received emails sent to it in the attacker's inbox — full email snooping on that subdomain, plus exposure of the DV (domain-verified) postmaster alias.
  - Bitwarden (id=272357): claimed `email.bitwarden.com` under DNS verification (report scope was the claim itself).
- **Exemplar report IDs:** 174983 (GitLab), 272357 (Bitwarden).

### 2. Abandoned third-party OAuth/App integration — re-registerable app takeover

- **Endpoint shape / parameter:** Documentation pages linking to third-party app installs. Template: `https://docs.{domain}/docs/<integration-name>` containing an install link like `https://github.com/apps/<app-name>`.
  - Exemplar: `https://docs.doppler.com/docs/github-actions` → GitHub App install link.
- **Payload:** (none stated) — the action is re-registering a GitHub App with the same name as the abandoned one, so the existing install URL now points to attacker-controlled registration.
- **Root cause:** The vendor referenced a GitHub App in their docs but later abandoned/unregistered it without updating the docs. GitHub App names are first-come-first-served; anyone can register the name, and every user who clicks the documented install link installs the attacker's app instead.
- **Impact proven (Doppler, id=2399386):** Anyone installing the taken-over app grants the attacker access to their repositories and GitHub Actions workflows. This is repo-read (and potentially secrets-via-Actions) impact against every customer following the docs.
- **Exemplar report ID:** 2399386 (Doppler).

### 3. Publicly exposed Spring Boot Actuator on a custom path

- **Endpoint shape / parameter:** Actuator endpoints mounted on a non-default base path (so naive scans for `/actuator/...` miss them). Endpoints observed:
  - `GET /heapdump`
  - `GET /env`
  - Note: both on a **custom path**, not `/actuator/heapdump` — assume the app remapped `management.endpoints.web.base-path`.
- **Payload:** (none stated) — plain unauthenticated GET requests to the two endpoints.
- **Root cause:** Spring Boot Actuator `/heapdump` and `/env` endpoints were publicly accessible without access controls (no `management.endpoint...enabled=false`, no auth on the management port, and a custom base path that evaded standard discovery).
- **Impact proven (LY Corporation, id=862589):** Leaked JVM heap data via `/heapdump` exposing **admin credentials and user tokens/cookies**, with maximum demonstrated impact of **takeover of random LINE Official Accounts**. `/env` corroborates by leaking property values (potential secrets) directly.
- **Exemplar report ID:** 862589 (LY Corporation).

### 4. Support-system misconfiguration exposing internal documentation

- **Endpoint shape / parameter:** `GET /{path}` — an externally reachable path belonging to (or proxied into) an internal support system. The path itself was the misconfiguration trigger; no auth required.
- **Payload:** (none stated)
- **Root cause:** HackerOne's support stack was configured such that an externally exposed route reached their internal Confluence instance — internal documentation not intended for public viewing was addressable from the internet.
- **Impact proven (id=3113398):** Access to HackerOne's internal Confluence documentation, **plus the ability to view and modify limited content** within the instance — i.e., not just read exposure but authenticated-ish write on a limited scope.
- **Exemplar report ID:** 3113398 (HackerOne).

### 5. Missing DMARC record — sender spoofing

- **Endpoint shape / parameter:** DNS TXT record query at the apex domain: `_dmarc.{domain}` (exemplar: `brave.org`).
- **Payload:** (none stated)
- **Root cause:** No DMARC TXT record published, so receivers have no policy (`p=none` or better) for unauthenticated mail claiming to be from the domain. SPF/DKIM alone don't stop third parties from putting the domain in the `From:` header.
- **Impact proven (id=491753, Brave Software):** Enables spoofed `From:` addresses at the domain and reputational damage (phishing in the brand's name). Typically this is the "floor" severity for this sub-pattern unless the spoofing can be demonstrated against a concrete victim flow.
- **Exemplar report ID:** 491753 (Brave Software).

### 6. Broken/non-functional links on error pages (business-impact misconfig)

- **Endpoint shape / parameter:** `https://{domain}/{path}` — any URL that renders the site's 404 error page (exemplar: `https://sifchain.finance/{path}`).
- **Payload:** (none stated)
- **Root cause:** The 404 page template rendered six social-media icons whose links did not resolve to their intended targets (dead/incorrect hrefs in the template).
- **Impact proven (id=1186926, Sifchain):** On the 404 page, all social media buttons were non-functional, preventing users from contacting the team. Business impact only — no data or access.
- **Exemplar report ID:** 1186926 (Sifchain).

### 7. Unconnected/abandoned program URL — claimable web property

- **Endpoint shape / parameter:** The program's own advertised URL (exemplar: `http://sifchain.finance`), which pointed at hosting that was never connected (Wix).
- **Payload:** (none stated)
- **Root cause:** The public URL pointed to an unconnected Wix site (Wix's "domain not connected" state), i.e., the domain/hosting registration was orphaned from the actual deployment.
- **Impact claimed (id=1187018, Sifchain):** An attacker could claim the URL/hosting and serve a fake site to phish researchers' credentials. Note: **the phishing impact was asserted, not proven** — the accepted finding was the dangling/claimable URL itself.
- **Exemplar report ID:** 1187018 (Sifchain).

## Bypass / chain notes

- **Custom-path Actuator is itself a bypass of scanner expectations** (id=862589): scanning `/actuator/heapdump` on a host returns 404 while `/heapdump` (remapped base path) is fully open. When Actuator is suspected, try default paths, `/actuator/*`, and brute forced short top-level paths for `/env`, `/heapdump`, `/health`, `/info`.
- **CNAME-to-mailgun.org is the pivot, MX is the proof** (ids 174983, 272357): the CNAME alone isn't the impact — the inherited MX records are what route mail to the attacker's claimed account. Demonstrate the full loop: claim domain → create a list/alias (e.g., `postmaster@…`) → receive a real email to the claimed address. That end-to-end receipt is what justified acceptance at GitLab.
- **Takeover chains live in documentation** (id=2399386): the vulnerable link was in product docs, not on the main site. Crawl `docs.*`, help centers, READMEs, and setup guides for `github.com/apps/`, Slack app URLs, Intercom, Zendesk, Statuspage, and similar integrations, then check each for liveness/claimability.
- **Support/internal-tool exposure** (id=3113398) chained nothing — the external path reached Confluence directly. Where a support widget or SSO flow references an internal hostname, resolve and probe it directly from outside; misrouted reverse proxies can expose the whole instance including write capabilities.
- **Missing DMARC + any other email vector compounds**: no DMARC (id=491753) is weak alone, but if you also hold or can influence a mail path to the domain (e.g., a claimed Mailgun subdomain), spoofed-from phishing becomes a concrete, demonstrable chain rather than a theoretical one.

## Gotchas / what NOT to do

- **Don't claim a domain you don't own without care** — Mailgun takeover reports work because the claim is reversible and demonstrated to the vendor; do not send mail from the claimed domain or set up a live phishing page. Impact statements like "could phish researchers" (id=1187018) were accepted, but the phishing itself was never executed — keep unproven impact clearly labeled as potential.
- **Don't report the CNAME as the bug** — the bug is that the vendor's subdomain is claimable in *your* account. Show the claim succeeding and, where possible, mail actually landing in your inbox (the GitLab report did exactly this with `postmaster@email.mg.gitlab.com`).
- **Don't stop at "no DMARC"** — missing DMARC alone (id=491753) tends to be low severity. Strengthen it by showing SPF/DKIM gaps that make spoofing trivially deliverable, or a concrete spoof scenario. Note this record shows the domain-level check; don't assume subdomains are covered by an org-level record.
- **Don't scan only default Actuator paths** — the highest-impact record in this set used a custom base path. Default `/actuator/*` misses it.
- **Don't treat broken links as security bugs** — id=1186926 (broken social icons on the 404 page) is a real, accepted finding but purely business impact. Expect low severity and possible N/A at security-focused programs; frame it as user-trust/contact disruption, not a vulnerability.
- **Verify app-name claimability before reporting** — for GitHub App takeover (id=2399386), confirm the documented URL 404s or points to an unregistered app, and that the name is actually re-registrable. A live app owned by the vendor is not a bug.
- **Respect write-access boundaries on exposed internal tools** — id=3113398 included limited *modify* capability in Confluence. Prove it minimally (e.g., a draft or harmless test change in a sandbox space) and disclose immediately; do not exfiltrate real internal documentation contents in the report.

## Real-world impact examples

1. **Email interception at GitLab scale (id=174983):** Claiming `email.mg.gitlab.com` in a personal Mailgun account let the researcher create `postmaster@email.mg.gitlab.com` and receive emails sent to that address in their own inbox — silent mail snooping on a GitLab-owned email subdomain.
2. **LINE Official Account takeover via heap dump (id=862589):** Public `/heapdump` on a custom Actuator path leaked JVM heap containing admin credentials and user tokens/cookies; demonstrated maximum impact was takeover of random LINE Official Accounts — credentials straight out of process memory.
3. **Repo + workflow access via abandoned GitHub App (id=2399386):** Re-registering the app referenced at `docs.doppler.com/docs/github-actions` meant every customer clicking the documented install link granted the attacker access to their repositories and GitHub Actions workflows.
4. **Internal Confluence exposed with write access (id=3113398):** An external `GET /{path}` reached HackerOne's internal Confluence, yielding both read access to internal documentation and limited content-modification ability.
5. **Bitwarden email subdomain claim (id=272357):** `email.bitwarden.com`, CNAME'd to mailgun.org and unclaimed, was added to the researcher's Mailgun account and passed DNS verification — pre-positioning for the same mail-interception impact as the GitLab case.