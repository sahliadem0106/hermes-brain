---
name: hunter-l3-domain-takeover
description: "Use when hunting Domain Takeover on a target. Loads the L3 technique sheet: Domain takeover is claiming control of a domain or its DNS/content because some resource referencing it was abandoned: a deleted hosted zone, an expired subscription, or a dangling pointer to a claima"
domain: cybersecurity
subdomain: web
tags:
- web
- domain-takeover
- hunting
- l3
version: '1.0'
---

# Domain Takeover — Technique Sheet

## Overview
Domain takeover is claiming control of a domain or its DNS/content because some resource referencing it was abandoned: a deleted hosted zone, an expired subscription, or a dangling pointer to a claimable third-party service (GitHub Pages, etc.). It pays when the domain still receives traffic or is trusted by users of the target brand — the attacker can serve arbitrary content, receive email, or run phishing from a legitimate-looking property. Verification is usually a benign TXT record (e.g. `faberge@wearehackerone`) or a claim on the target service.

## Distinct sub-patterns

### 1. Deleted authoritative hosted zone on a registrar/DNS provider
- **Endpoint shape:** the domain's DNS itself — `DOMAIN. IN TXT/ANY` — where DOMAIN's zone should exist at a provider (here Reg.ru). No web endpoint or parameter involved.
- **Payload that fired (verbatim):**
  ```
  reddit.ru.		86400	IN	TXT	"faberge@wearehackerone"
  ```
- **Root cause:** The authoritative hosted zone for reddit.ru had been deleted from Reg.ru while the domain still pointed there / remained brand-associated. With no zone, anyone with a Reg.ru account could re-create the hosted zone for the domain and become authoritative for all its records.
- **Impact proven:** Full DNS control of reddit.ru — attacker created the missing zone, set the proof TXT record, and could create associated email addresses (i.e. receive mail on the domain) and serve arbitrary content.
- **Exemplar:** report id=1226891 (Reddit, ajaysenr).

### 2. Domain pointing to a claimable service endpoint (service-side takeover)
- **Endpoint shape:** `GET /` on the affected domain — a domain whose DNS record (A/CNAME) targets a third-party hosting service where the underlying resource is unclaimed.
- **Payload:** not stated.
- **Root cause:** 3hopify.media pointed to a claimable service endpoint — the service-side resource was unclaimed, so an attacker registered/claimed it and thereby took over the domain's served content.
- **Impact proven:** Attacker took over 3hopify.media and could host arbitrary content, enabling scams against users who trusted the Shopify-associated domain.
- **Exemplar:** report id=1344982 (Shopify, ajaysenr).

### 3. Acquired domain left pointing at an unclaimed hosting page
- **Endpoint shape:** the acquired domain itself, resolved via its hosting provider (GitHub Pages in this record — i.e. DNS pointing at GitHub Pages without a verified custom domain claim).
- **Payload:** not stated.
- **Root cause:** A domain acquired by the company still pointed to an unclaimed GitHub page. GitHub Pages custom domains are claimable by anyone who adds the domain to a repo when the original owner's claim lapsed — classic dangling-pointer takeover on an acquisition asset.
- **Impact proven:** Attacker successfully claimed/took over the obviousengine.com GitHub page and controlled what it served.
- **Exemplar:** report id=392785 (Snapchat, ajaysenr).

### 4. Expired domain/subscription takeover
- **Endpoint shape:** the DoD domain itself (redacted) — no web parameter; the weakness is in the domain's registration lifecycle.
- **Payload:** not stated.
- **Root cause:** The subscription for the domain had expired, leaving the domain (or its service subscription) available for anyone to re-register/claim.
- **Impact proven:** Any attacker could take over the domain and conduct phishing attacks against a U.S. Dept of Defense audience — a high-trust context where a lapsed asset is maximally dangerous.
- **Exemplar:** report id=804080 (U.S. Dept Of Defense, ajaysenr).

## Bypass / chain notes
- No filter-bypass or multi-step chains appear in these records — all four were direct single-step takeovers. The "chain" concept here is implicit: takeover → arbitrary content/email → phishing or scam, which is exactly how impact was framed in 1344982 and 804080.
- Proof-of-control technique seen: instead of defacing, set a benign TXT record containing the program's verification handle (`faberge@wearehackerone` for HackerOne) — demonstrates control without violating rules.

## Gotchas / what NOT to do
- Do not host real content or deface the domain. The accepted proof in the Reddit case was a single harmless TXT record naming the researcher handle.
- Don't stop at "NXDOMAIN" or "site down" — the paying insight is why: deleted zone (Reg.ru), unclaimed GitHub Pages, expired subscription. Check the DNS provider and hosting service, not just HTTP status.
- Acquisition targets are takeover gold: when a company acquires a product (Snapchat/obviousengine), audit whether the acquired domain's old hosting pointers were cleaned up. They often aren't.
- Match the domain to a program's scope before touching it — brand lookalikes (3hopify.media) counted for Shopify because of the association, but out-of-scope domains are a waste and a risk.
- Emails matter: DNS zone control implies ability to receive mail on the domain (noted in 1226891) — report that capability as impact, but don't actually intercept third-party mail.

## Real-world impact examples
- **Reddit (id=1226891):** Re-created the deleted Reg.ru hosted zone for reddit.ru and set TXT `faberge@wearehackerone`, proving full DNS/content control plus the ability to create email addresses on reddit.ru.
- **Shopify (id=1344982):** Took over 3hopify.media via its claimable service endpoint; arbitrary content hosting possible for user-facing scams.
- **Snapchat (id=392785):** Claimed the unclaimed GitHub Pages site on acquired domain obviousengine.com, taking control of served content.
- **U.S. Dept Of Defense (id=804080):** Expired domain subscription allowed takeover of a DoD domain, directly enabling phishing against a government audience.