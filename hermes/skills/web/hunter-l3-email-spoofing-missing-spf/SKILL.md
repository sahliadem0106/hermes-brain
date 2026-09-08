---
name: hunter-l3-email-spoofing-missing-spf
description: "Use when hunting Email Spoofing (Missing SPF) on a target. Loads the L3 technique sheet: This class covers domains that fail to publish — or publish too weak — a Sender Policy Framework (SPF) TXT record, allowing an attacker to send email that appears to originate from the target's domain."
domain: cybersecurity
subdomain: web
tags:
- web
- email-spoofing-missing-spf
- hunting
- l3
version: '1.0'
---

# Email Spoofing (Missing SPF) — Technique Sheet

## Overview

This class covers domains that fail to publish — or publish too weak — a Sender Policy Framework (SPF) TXT record, allowing an attacker to send email that appears to originate from the target's domain. It is a pure DNS-configuration finding: no application endpoint, no parameter, no exploit payload in the traditional sense. It pays consistently but modestly (typically low severity unless the domain is used in security-sensitive email like password resets or security alerts), and is found by a single DNS lookup — making it one of the fastest recon checks to run across all of a program's domains, including retired/legacy ones.

## Distinct sub-patterns

The records contain two distinct sub-patterns: a fully absent SPF record (7 of 8 records) and a soft-fail (`~all`) policy that still permits spoofing (1 record).

### Sub-pattern 1: No SPF TXT record published at all

- **Endpoint shape / parameter:** Not an HTTP endpoint — the "target" is the DNS zone. Template: `TXT` record lookup on the bare domain or subdomain:
  - `dig TXT <domain> +short` (expect: empty / no `v=spf1` record)
  - Domains seen in records: `paragonie.com` (apex), `localize.im` (apex), `trycourier.app` (retired domain), `myshopify.com` (subdomain-owned wildcard domain, distinct from `shopify.com`)
- **Payload that actually fired:** payload not stated. The "payload" in this class is the verification itself, not a message body: a DNS query confirming the record is absent. One record (id=12836, Localize) explicitly used **mxtoolbox** to confirm no valid SPF TXT record exists. One record (id=93157, Gratipay) shows the closest thing to a verbatim payload: the spoofed sender header `From: security@agratipay.com`.
- **Root-cause pattern:** The domain's DNS zone simply contains no `v=spf1` TXT record. Receiving mail servers therefore have no sender-verification mechanism for that domain and cannot reject or flag mail with a forged `MAIL FROM`/header From. Notably, in the Shopify case (id=54779) the parent domain `shopify.com` *did* have SPF while the tenant/wildcard domain `myshopify.com` did not — a classic gap where infrastructure teams secure the corporate zone but miss the customer-facing subdomain zone. In the Courier case (id=1416701) the domain was **retired** (`trycourier.app`), meaning legacy/decommissioned zones are a fruitful hunting ground.
- **Impact that was proven:** Ability to send spoofed email from the target domain, enabling impersonation and phishing:
  - paragonie.com: "easy to spoof the domain's e-mail address" (4 separate reports: 115214, 115294, 115315, 115390 — all accepted by the program, showing the same finding on the same domain was repeatedly reported/valid).
  - localize.im: confirmed missing SPF via mxtoolbox, allowing spoofing of the domain's email address (12836).
  - trycourier.app: spoofed email sent from the retired domain, enabling impersonation/phishing (1416701).
  - myshopify.com: spam/phishing could originate from the myshopify.com domain (54779).
- **Exemplar report IDs:** 115214 (Paragon Initiative Enterprises), 54779 (Shopify — the parent-vs-subdomain variant), 1416701 (Courier — the retired-domain variant).

### Sub-pattern 2: SPF present but soft-fail (`~all`)

- **Endpoint shape / parameter:** Same DNS surface, but the record *exists* and is insufficient: a TXT record ending in `~all` (soft-fail) rather than `-all` (hard-fail).
- **Payload that actually fired:** verbatim from the record: `From: security@agratipay.com` — i.e., a spoofed sender address in the security@ namespace of the target domain, the most credible-looking sender a phisher could choose.
- **Root-cause pattern:** With `~all`, receiving servers are only instructed to mark non-matching mail as "soft fail" (typically delivered but tagged/spam-foldered), not rejected. Spoofed mail from the domain still gets through in many receiving configurations, so attacker-controlled email can plausibly appear to come from the domain.
- **Impact that was proven:** Spoofed email from `security@gratipay.com` could be sent for phishing purposes (id=93157). Note the record's payload references `agratipay.com` while the impact states `gratipay.com` — the report demonstrates the spoofed `From:` on the Gratipay domain despite the soft-fail policy.
- **Exemplar report IDs:** 93157 (Gratipay).

## Bypass / chain notes

- No multi-step chains appear in the records (all 8 have `chain: (none)`). The attack is single-step: confirm weak/absent SPF → send spoofed mail.
- The practical "bypass" in this class is **coverage bypass**: the secured zone is the apex, the weak one is a sibling. Check every zone the company controls, not just the main domain — `myshopify.com` was missable precisely because `shopify.com` looked protected (54779).
- **Retired-domain bypass:** decommissioned domains (`trycourier.app`, 1416701) often lose their SPF records when mail infrastructure is torn down but the DNS zone is kept alive for redirects. These are still trusted names to users and are the easiest wins.
- The `security@` sender choice (93157) is an impact amplifier, not a technical bypass — pairing the spoof with a security-themed pretext maximizes phishing believability.

## Gotchas / what NOT to do

- **Do not report DMARC-only gaps without checking SPF first.** All 8 accepted records hinge specifically on SPF absence or `~all`. Verify with `dig TXT <domain> +short` and quote the exact result (or its absence) — the Localize report (12836) was accepted on the strength of a mxtoolbox confirmation, so include third-party verification output.
- **Do not confuse `~all` with "protected"** — soft-fail is reportable (93157), but be aware some triagers treat it as lower severity than a missing record; frame impact as "spoofed mail still delivered/accepted by many receivers."
- **The same finding on the same domain may be re-reportable** — Paragon accepted four separate reports (115214/115294/115315/115390) all describing the identical missing-SPF condition on paragonie.com. This suggests the program treated each submission as valid, but do not assume this generalizes; most programs will dupe the second report.
- **No HTTP payload = no exploit PoC needed, but evidence is mandatory.** Every accepted record here rests on a DNS verification screenshot/output. A claim of "no SPF" without the lookup output is not actionable.
- **Don't stop at the apex domain.** Enumerate subdomain zones and historical/retired domains before concluding a program has no SPF findings.
- **Don't claim delivery of an actual phishing email if you only proved the DNS condition** — the records prove spoofability (and one spoofed `From:` header); none demonstrate a completed phish, and sending one is typically out of scope.

## Real-world impact examples

- **Shopify (54779):** `myshopify.com`, the domain stamped on every merchant's storefront, had no SPF record while `shopify.com` did — spam and phishing could originate directly from a Shopify-owned domain that merchants and customers inherently trust.
- **Courier (1416701):** the retired `trycourier.app` domain had no SPF, so attackers could send convincing phishing email purporting to come from Courier's former app domain — targeting users who still recognize the name.
- **Gratipay (93157):** despite an existing (soft-fail) SPF policy, spoofed mail with `From: security@agratipay.com` / presented as `security@gratipay.com` could be sent — spoofing the *security team's* address, the highest-trust sender a phisher can impersonate.
- **Paragon Initiative Enterprises (115214, 115294, 115315, 115390):** paragonie.com — a security company's own domain — had no SPF record, making its email trivially spoofable; the program accepted four reports establishing this.
- **Localize (12836):** localize.im had no valid SPF TXT record (confirmed via mxtoolbox), allowing full spoofing of the domain's email address.