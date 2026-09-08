---
name: hunter-l3-broken-link-hijacking
description: "Use when hunting Broken Link Hijacking on a target. Loads the L3 technique sheet: Broken link hijacking is the takeover of dead external links published on a target's own properties: when a website links out to a third-party resource (GitHub, Twitter/X, LinkedIn, Calendly, Confluen"
domain: cybersecurity
subdomain: web
tags:
- web
- broken-link-hijacking
- hunting
- l3
version: '1.0'
---

# Broken Link Hijacking — Technique Sheet

## Overview

Broken link hijacking is the takeover of dead external links published on a target's own properties: when a website links out to a third-party resource (GitHub, Twitter/X, LinkedIn, Calendly, Confluence, HackerOne profiles, or entire domains) and that resource is 404/unclaimed/expired, an attacker registers the now-available target and inherits the trust of the original link. It pays because the target's content carries implied endorsement — a docs page, security page, or verified-identity block vouching for a link that now points at the attacker. It is cheap to validate (one HTTP request + one registration) and regularly rewarded even on programs that consider it "not actual exploitation."

## Distinct sub-patterns

### 1. Unclaimed GitHub username/repo referenced from vendor docs
- **Endpoint shape:** Docs/library pages linking to org or repo URLs, e.g. `GET https://kubernetes-csi.github.io/docs/drivers.html` → `github.com/DriveScale/k8s-plugins`; also `developer.twitter.com/en/docs/twitter-api/tools-and-libraries` → `github.com/HunterLarco`.
- **Payload:** None — the "payload" is registering the GitHub username (e.g. `HunterLarcol`) and creating the repository with the exact name referenced (e.g. `k8s-plugins`).
- **Root cause:** Docs reference a GitHub account or repository that was deleted, renamed, or never claimed. GitHub usernames are first-come; the target never re-validates outbound links.
- **Impact proven:** Visitors clicking the docs link land on attacker-controlled content — impersonation and malicious driver/plugin distribution (malware/ransomware delivery) from a trusted docs page.
- **Exemplars:** 1031321 (xAI), 1212853 (Kubernetes), 1466889 (Kubernetes — ChubaoFS production-drivers link 404 confirmed, attacker-matching repo now receives the redirect).

### 2. Disavowed/renamed social handle linked from corporate site
- **Endpoint shape:** Site header/footer/social links, e.g. `*.runpanther.io` Twitter link; `GET /about` team-member links → `x.com/<handle>` (2994013, 3035275).
- **Payload:** Not stated (registration of the old/disavowed handle).
- **Root cause:** The company changed handles or the account was deleted/disavowed, but the hardcoded link was never updated; the old handle becomes claimable by anyone.
- **Impact proven:** Reporter registered the disavowed handle and could masquerade as Panther Labs (program noted it was not actual exploitation but still rewarded it). At Hemi/Autodesk, broken `x.com` links were claimable for brand impersonation.
- **Exemplars:** 1117079 (Panther Labs), 2994013 (Hemi), 3035275 (Autodesk).

### 3. Unregistered LinkedIn profile on team/about page
- **Endpoint shape:** `GET /about` → team-member LinkedIn URL `linkedin.com/<in|company>/<slug>`.
- **Payload:** Not stated.
- **Root cause:** Employee's LinkedIn deleted/renamed; the about page retains the dead link and the slug is now unregistered.
- **Impact proven:** A malicious actor could claim the username and mislead users into following a fake "team member" (potential account hijack; not claimed by reporter).
- **Exemplar:** 2990368 (Hemi VDP).

### 4. Unclaimed Calendly link on documentation page
- **Endpoint shape:** Docs page (`https://docs.doppler.com/docs/removal-deprecated-packages-scripts`) → `https://calendly.com/doppler-ryan/onsite-install`.
- **Payload (verbatim):** `https://calendly.com/doppler-ryan/onsite-install` — PoC by registering the Calendly account `doppler-ryan`.
- **Root cause:** Calendly URLs are user-provisioned; when the employee's account lapses or the event link is deleted, the vanity URL is 404 and re-registerable. Docs content outlives the SaaS account.
- **Impact proven:** Reporter claimed the broken Calendly link and impersonated the employee in a booking flow — a malicious user could phish/trick anyone arriving via the docs.
- **Exemplar:** 2418210 (Doppler).

### 5. Unregistered SaaS/self-service subdomain page (Atlassian Confluence)
- **Endpoint shape:** `GET https://kubernetes.io/es/docs/concepts/workloads/controllers/daemonset/` → `sysdigdocs.atlassian.net` (Confluence page).
- **Payload:** Not stated (PoC content hosted on the registered page).
- **Root cause:** Docs cite a third-party Confluence whose workspace/account was never registered or lapsed; Atlassian allows claiming the site/space name.
- **Impact proven:** Reporter took over the unregistered Confluence space and hosted attacker content on a page linked from kubernetes.io docs.
- **Exemplar:** 1331361 (Kubernetes).

### 6. Dead HackerOne profile referenced from a security page
- **Endpoint shape:** Security/responsible-disclosure page → `GET https://hackerone.com/urbanclap` (returns 404).
- **Payload:** Not stated (impersonating H1 account registration).
- **Root cause:** Company rebranded (urbanclap → Urban Company) or profile URL changed; the old H1 handle is unclaimed. H1 handles are generic first-come usernames.
- **Impact proven:** Attacker can register the lookalike profile and deceive new researchers into submitting findings to the attacker's hands (reporter did not actually capture researcher data).
- **Exemplar:** 1239334 (Urban Company).

### 7. Expired outbound domain linked from blog content
- **Endpoint shape:** Blog posts on `about.gitlab.com/2011/11/22/whats-next/` with embedded external `href` to a since-expired domain.
- **Payload:** Not stated (registered the expired domain; masked final URL with bit.ly shortener).
- **Root cause:** Historical posts link to third-party domains nobody renews; WHOIS expiry makes the domain re-registerable. Old content is never link-audited.
- **Impact proven:** Full control of the linked destination for impersonation — with the link obfuscated via bit.ly to hide the malicious destination.
- **Exemplar:** 265696 (GitLab).

### 8. Expired social handle that a platform's "verified identity" block actively vouches for
- **Endpoint shape:** `GET /martindelille` and `GET /mdvhimself` (Liberapay profile pages, Linked Accounts section) → `https://x.com/martinodelilo`, `https://x.com/mdvhimself`.
- **Payload (verbatim):** `https://x.com/martinodelilo`; `https://x.com/mdvhimself`.
- **Root cause:** The linked Twitter/X handles expired and became registerable, while the donation page's "Recipient Identity" block still falsely presents the linked account as verified/controlled by the recipient. This is stronger than ordinary social-link rot: the platform itself asserts the association.
- **Impact proven:** Attacker claiming the handle can present it as an officially verified Liberapay team-member link — impersonation of team members in a payments context. Reporters hijacked the handles for PoC.
- **Exemplars:** 3721519, 3723002 (Liberapay).

## Bypass / chain notes

- **Claim-then-redirect chains:** 1212853 and 1466889 demonstrate the multi-step chain pattern: (1) find broken link to unclaimed GitHub repo on a docs page → (2) register the username and create the repo with the exact referenced name → (3) victims clicking the docs link are redirected to attacker content. Repo *name* must match, not just username.
- **URL obfuscation:** In 265696, the attacker shortened the hostile destination with bit.ly so users checking the visible link saw a neutral shortener — a presentation-layer evasion when destinations are audited.
- **Trust amplification via verification claims:** the Liberapay records (3721519/3723002) show chaining link-rot with a platform feature (Recipient Identity block) — the impact is not just "a dead link" but "a false verification statement."
- **Program-policy chain note:** Panther Labs (1117079) rewarded the claim even while stating it was not actual exploitation — establishing the claim itself as the reportable act.

## Gotchas / what NOT to do

- **Validate availability before claiming impact.** Every accepted report confirmed the target actually 404s / the handle is unregistered (e.g. 1239334: hackerone.com/urbanclap → 404; 1466889: ChubaoFS link → 404 confirmed). A link that "looks stale" but resolves to a live account is not a finding.
- **Registering ≠ exploiting.** Several reporters stopped at demonstrating claimability without harm; at least one program (Panther Labs) explicitly noted "not actual exploitation" yet rewarded. Do not use a claimed asset to capture real user data — 1239334 shows impact is credited as *capability* to deceive, not measured data capture.
- **Don't report orphan links.** All these records involve links published *by the program itself* (docs, about pages, security pages, blog). The report requires the program's page to be the trust source.
- **Repo-name precision matters** in the GitHub pattern: the claim must reproduce the exact referenced repository/username for the docs link to land on your content.
- **Don't skip the PoC-on-the-claimed-asset step.** Reports that hosted visible PoC content (1331361, 2418210) demonstrated control concretely; claims stated only hypothetically (2990368, 2994013) were weaker findings.
- **Handle-claim tactics:** registering the handle yourself (1031321, 1117079, 3721519, 3723002) is the demonstrated PoC method — where allowed by program rules; otherwise evidence claimability only.

## Real-world impact examples

- **Malware distribution from trusted docs:** Kubernetes CSI docs (1212853, 1466889) — attacker-claimed repos receive clicks from official driver-install documentation; users could be served malicious CSI drivers/ransomware.
- **Impersonation of the company itself:** Panther Labs' disavowed Twitter handle (1117079) and Autodesk's broken X link (3035275) allow full brand impersonation through the company's own social links.
- **Phishing via booking flow:** Doppler docs → Calendly `doppler-ryan` (2418210) — users attempting to schedule an official onsite install reach an attacker-controlled booking page.
- **Researcher-submission hijack:** Urban Company's dead `hackerone.com/urbanclap` security-page link (1239334) — fake intake profile could intercept vulnerability reports from new researchers.
- **False identity verification in payments:** Liberapay (3721519, 3723002) — claimed X handles rendered as verified "Recipient Identity" links on donation pages, enabling team-member impersonation around money movement.
- **Blog link takeover with URL masking:** GitLab (265696) — expired domain re-registered, embedded blog link controlled, destination hidden behind bit.ly.