---
name: hunter-l3-spf-misconfiguration
description: "Use when hunting SPF Misconfiguration on a target. Loads the L3 technique sheet: SPF misconfiguration is a DNS-based email security weakness where a domain's `v=spf1` TXT record either fails to exist, fails to validate, or uses a policy that does not hard-reject unauthorized senders."
domain: cybersecurity
subdomain: web
tags:
- web
- spf-misconfiguration
- hunting
- l3
version: '1.0'
---

# SPF Misconfiguration — Technique Sheet

## Overview
SPF misconfiguration is a DNS-based email security weakness where a domain's `v=spf1` TXT record either fails to exist, fails to validate, or uses a policy that does not hard-reject unauthorized senders. When SPF is absent, invalid, or soft-failing, an attacker can send email that appears to originate from the target domain — enabling phishing of employees, users, and customers under a trusted brand. It typically pays out quickly (low-skill check, clear impact proof via a spoofing tool) but only in programs that accept subdomain/parent-domain spoofing reports; always check the program's policy on email spoofing before testing.

## Distinct sub-patterns

### 1. Soft-fail (`~all`) with third-party includes — permissive policy
- **Endpoint shape:** DNS TXT record at the domain apex, `infogram.com`
- **Payload that actually fired (verbatim):**
  ```
  v=spf1 include:_spf.google.com include:spf.mandrillapp.com include:mailgun.org ~all
  ```
- **Root-cause pattern:** The record is syntactically valid but terminates with `~all` (SOFTFAIL) instead of `-all` (FAIL). Combined with broad third-party includes (Google, Mandrill, Mailgun), any sender not in those providers is only marked soft-fail — receiving mail servers are advised, not required, to reject. The researcher demonstrated exploitation via an external spoofing service (emkei.cz) that is outside all included providers.
- **Impact proven:** Could send email to anyone on behalf of infogram.com using external services such as emkei.cz — full domain spoofing for phishing.
- **Exemplar report:** 280408 (Infogram, ajaysenr)

### 2. Missing SPF record entirely
- **Endpoint shape:** DNS TXT record for a subdomain, here `prow.k8s.io` (a single-label subdomain of a larger org domain — an easy one to overlook)
- **Payload:** not stated (the check itself is the payload: query the TXT record and confirm no `v=spf1` entry exists)
- **Root-cause pattern:** No valid SPF record published for the domain/subdomain. With no policy at all, receiving servers have no authorization framework for the domain, and any host on the internet can send with `MAIL FROM` at that domain. Subdomains and infrastructure domains (CI systems, build tooling, internal services exposed publicly) frequently lack SPF even when the apex domain has one.
- **Impact proven:** Attacker could send forged/fake email spoofing the domain for phishing.
- **Exemplar report:** 775531 (Kubernetes, ajaysenr)

### 3. SPF record exceeding the 10-DNS-lookup limit → PermError
- **Endpoint shape:** DNS TXT record at the apex, `owncloud.com`
- **Payload that actually fired (verbatim):**
  ```
  v=spf1 a:mx.owncloud.com a:kerio.owncloud.com a:schaltsekun.de a:m.hive01.com include:cmail1.com include:email.influitive.com include:google.com ~all
  ```
- **Root-cause pattern:** Per RFC 7208, SPF evaluation is capped at 10 DNS lookups — each `include:`, `a`, `mx`, `ptr`, `exists`, and `redirect=` mechanism consumes lookups (nested includes count too). This record chains multiple `a:` mechanisms plus multiple `include:` mechanisms (each of which expands to its own nested lookups, e.g. `include:google.com` expands to several nested includes), blowing past the limit. When the limit is exceeded, evaluation terminates with a **PermError ("Too many DNS lookups")** — meaning the SPF check *fails entirely* for the domain. A PermError is not a pass and not a soft-fail; many receivers either ignore SPF or treat it inconsistently, so the record that was meant to protect the domain provides no protection at all.
- **Impact proven:** SPF validation returns PermError "Too many DNS lookups", effectively allowing spoofed/spam email to originate from the domain.
- **Exemplar report:** 83578 (ownCloud, ajaysenr)

## Bypass / chain notes
- All three records end in `~all` rather than `-all` — in two of three cases the soft-fail is the direct enabler; in the PermError case it is moot because evaluation never reaches `all`.
- Third-party `include:` entries (google.com, mandrillapp.com, mailgun.org, cmail1.com, email.influitive.com, email.outflank-style ESPs) broaden the authorized-sender set: any compromise or account at those providers can send as the domain. In the Infogram case, includes were present but the exploit came from *outside* them (emkei.cz), proving the `~all` was the weak link.
- Chains seen: none in the records. None of the three findings chained into DKIM/DMARC attacks; impact was demonstrated as standalone spoofing.

## Gotchas / what NOT to do
- Don't report `~all` alone without demonstrating impact. Two of the three records here also had `~all`, but the accepted finding showed a working spoof (emkei.cz). Many programs treat soft-fail as a self-XSS-style informational issue unless you prove deliverable spoofed mail.
- Don't confuse an SPF record with the absence of DMARC. These records all lack any stated DMARC alignment story, but the reported weakness class is SPF itself (missing / invalid / soft-fail). Read the program policy — some triagers bounce "SPF/DMARC misconfiguration" entirely.
- Check subdomains, not just the apex. The Kubernetes finding (775531) is a subdomain (`prow.k8s.io`) with no record — a much more common find than a missing apex record.
- Count the lookups, don't eyeball the length. A record can look short but still exceed 10 lookups once nested `include:` expansion is counted (`include:google.com` alone costs multiple nested lookups). Use `dig TXT domain` plus a lookup-counting tool to verify PermError rather than guessing.
- Verify the PermError is real before reporting: `dig TXT owncloud.com` shows the record, but you must simulate/verify evaluation terminates with "Too many DNS lookups" (e.g. via an SPF validator) — that's what makes the impact credible.

## Real-world impact examples
- **Infogram (280408):** researcher sent email to anyone on behalf of infogram.com via emkei.cz, enabled by the `~all` soft-fail in a record that included Google, Mandrill, and Mailgun. Brand-trusted phishing at scale.
- **Kubernetes (775531):** `prow.k8s.io` (Kubernetes' CI/testing infrastructure domain) had no SPF record at all — anyone could forge mail as the domain. Infrastructure/tooling domains are high-value spoof targets because employees are conditioned to trust mail "from" CI and build systems.
- **ownCloud (83578):** the published SPF record at owncloud.com exceeded RFC 7208's 10-lookup cap, producing PermError "Too many DNS lookups". A record that *looks* protective (7 explicit mechanisms, plus nested includes) actually guarantees SPF evaluation failure — effectively equivalent to no protection, allowing spoofed/spam email from the domain.

## Recon checklist (derived directly from these records)
1. `dig TXT <domain>` and `dig TXT <subdomain>` for apex + notable infra subdomains — look for absence of `v=spf1` (pattern 2).
2. If present, check the qualifier: `~all` = candidate soft-fail finding (pattern 1) — but you must demonstrate a working spoof to sell it.
3. Count DNS lookups across all mechanisms including nested `include:` expansion — >10 means PermError (pattern 3), which is a strong finding regardless of `~all`/`-all` because the record never evaluates successfully.
4. Prove impact with a controlled spoofing send (e.g. emkei.cz as used in the records) before reporting a soft-fail.