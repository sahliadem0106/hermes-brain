---
name: hunter-l3-phishing
description: "Use when hunting Phishing on a target. Loads the L3 technique sheet: This class covers any bug that lets an attacker send content, redirect traffic, or present identity signals that appear to come from a trusted brand or platform, but which the attacker controls."
domain: cybersecurity
subdomain: web
tags:
- web
- phishing
- hunting
- l3
version: '1.0'
---

# Phishing — Technique Sheet

## Overview
This class covers any bug that lets an attacker send content, redirect traffic, or present identity signals that appear to come from a trusted brand or platform, but which the attacker controls. It pays when the target's trust in a legitimate-looking channel (branded email, official redirect domain, chat link formatting, browser UI, social handle) can be weaponized against its own users or researchers. Impact is proven by demonstrating a realistic deception vector — fake verification emails, spoofed display links, homograph domains — rather than exploiting server-side logic.

## Distinct sub-patterns

### 1. Branded email sending from platform features (share-by-email mutation)
- **Endpoint shape / parameter:** `POST /graphql` — mutation `shareReportViaEmail`; parameters: `message`, `emails`, `report_id`.
- **Payload that fired (verbatim):**
  ```
  {"query":"mutation Createvpncredentialsmutation($input0:ShareReportViaEmailInput!) {shareReportViaEmail(input:$input0){errors{edges{node{field,message,type}}},was_successful,clientMutationId}}","variables":{"input0":{"message":"If you would like to participate in the retest of this report , the payo
  ```
  (payload truncated in the record)
- **Root cause:** The `ShareReportViaEmail` mutation permits sending from a *sandbox* report — a report not yet disclosed/validated — and the resulting email carries no warning label distinguishing it. The message body is fully attacker-controlled, so the platform's own email infrastructure delivers plausible, legitimate-looking mail.
- **Impact proven:** Sent a realistic phishing email from a sandbox report claiming a $500 retest, which could trick a hacker into revealing their real email address (registering under attacker control).
- **Exemplar report IDs:** 1128701 (HackerOne).

### 2. Unclaimed social handles linked from official profiles
- **Endpoint shape / parameter:** N/A — the "endpoint" is the target company's HackerOne profile and its outbound social-media link; the attack surface is an unclaimed Twitter handle.
- **Payload:** None stated (action was registering the unclaimed username).
- **Root cause:** A social media account referenced from the company's official HackerOne profile was unregistered. Anyone can register an expired/unclaimed handle, and the profile link then points at the attacker's account — instant impersonation legitimacy.
- **Impact proven:** Hijacked the unclaimed Twitter username by registering a fake impersonating account capable of deceiving researchers (PoC only; username released after response).
- **Exemplar report IDs:** 1814824 (curl / Gener8).

### 3. Browser Shield/UI lacking IDN homograph protection
- **Endpoint shape / parameter:** N/A — browser UI surface (Brave Shield panel); the payload is a punycode URL.
- **Payload (verbatim):** `https://www.xn--80ak6aa92e.com`
- **Root cause:** Brave Shield lacked the IDN homograph protections present elsewhere, so a punycode domain renders as its Unicode lookalike. The address/Shield panel displayed `apple.com` for a domain that is not apple.com.
- **Impact proven:** Brave Shield panel displayed `apple.com` when visiting `www.xn--80ak6aa92e.com`, deceiving users into believing the site is legitimate.
- **Exemplar report IDs:** 1819329 (Brave Software).

### 4. Double-encoded path traversal on a trusted redirect/link domain
- **Endpoint shape / parameter:** `GET go.imgur.com/{path}` — parameter: `path` (arbitrary path appended to the brand's "go" tracking domain).
- **Payload (verbatim):**
  ```
  http://go.imgur.com/account-verification/%252e%252e%2f%252e%252e%2f%67%69%74%68%75%62%2e%63%6f%6d%2f%6b%69%79%65%6c%6c%2f%70%71
  ```
  Decoded once: `../..%2fgithub.com%2fkiyell%2fpq`-style traversal escaping the `account-verification` path and redirecting to an attacker-controlled external page.
- **Root cause:** Double-encoded dot-dot sequences (`%252e%252e%2f`) survive the first decode pass and then traverse out of the legitimate path on the trusted `go.imgur.com` domain, causing a redirect to an external attacker page while the visible URL stays on imgur's domain — spoofing imgur account-verification.
- **Impact proven:** Encoded double-dot URLs redirect `go.imgur.com` to phishing pages that harvest imgur account information.
- **Exemplar report IDs:** 384101 (Imgur).

### 5. Link label spoofing in chat message rendering
- **Endpoint shape / parameter:** `POST /api/chat.postMessage` — parameter: `text` (Slack message formatting syntax).
- **Payload (verbatim):** `<http://evil.com|http://example.com>`
- **Root cause:** Slack renders the label part (before the `|`) as visible display text while the actual href is the URL after the `|`. Visible link text can therefore differ arbitrarily from the real destination — no validation ties the two together.
- **Impact proven:** Created a message displaying `http://example.com` that actually links to `evil.com`, usable for phishing (leading victims to fake login pages).
- **Exemplar report IDs:** 481472 (Slack).

## Bypass / chain notes
- **Encoding layers to survive filters:** the Imgur traversal required *double* encoding (`%252e%252e%2f` instead of `%2e%2e%2f`) — a single-encoded `../` would have been normalized or blocked; the second decode happens inside the redirect handler after initial validation. Also note the fully hex-encoded target (`%67%69%74%68%75%62%2e%63%6f%6d...` = `github.com/...`) to avoid naive string-matching on the redirect destination. Chain shape: legitimate-brand domain → open-redirect via traversal → attacker phishing page.
- **Legit-channel delivery beats spoofed sender:** the HackerOne payload works not because of a fake sender but because the *real* platform sends the attacker's prose — no SPF/DMARC spoofing needed, and no warning banner marks sandbox content.
- **Trust inheritance without server access:** the Twitter-handle pattern and the Slack label-spoof pattern both inherit trust from context (official profile link; familiar chat rendering) rather than exploiting a server-side flaw — payloads are minimal, but context does the work.
- **No multi-step chains were recorded** in this record set; all five are single-step vectors.

## Gotchas / what NOT to do
- **Register-then-release for impersonation PoCs:** the Gener8 report explicitly registered the handle as proof and *released the username after the response* — don't squat a company's handle; demonstrate and give it back immediately.
- **Don't confuse branded-redirect traversal with generic open redirects:** the Imgur finding's value is that the redirect originates from a brand-trusted `go.` subdomain and masquerades as account-verification — a bare open redirect on an untrusted host is a much weaker report.
- **Sandbox reports are still delivery vehicles:** don't assume report state (sandbox/private) limits what the email feature does — check whether message content and recipient are validated; that gap was the bug.
- **Homograph findings must show UI-level deception:** the Brave report proved the Shield panel itself displayed `apple.com` — a punycode domain that merely looks similar in the address bar is weaker; demonstrate what trusted text the victim actually sees.
- **Check whether the display text and href can diverge:** in chat/link-rendering surfaces, the bug is the missing label↔URL consistency check — payload `label|destination` pairs with identical values are not a finding.
- Some records state no explicit payload (the Twitter-handle case); when demonstrating identity takeover, document the before/after state of the claimed resource instead.

## Real-world impact examples
- **HackerOne (1128701):** A realistic email sent through HackerOne's own infrastructure claimed a "$500 retest" of a report with no warning label — a researcher following it would hand their real email address to the attacker, enabling follow-on targeted phishing.
- **Imgur (384101):** A URL on `go.imgur.com` styled as `account-verification` ultimately landed on an attacker-controlled GitHub-hosted page, enabling harvesting of imgur account credentials — victims saw only the imgur domain in the address bar.
- **Slack (481472):** A message in a Slack channel displaying `http://example.com` but linking to `http://evil.com` — a one-request payload that turns any channel into a phishing delivery vector for fake login pages.
- **Brave (1819329):** Visiting `https://www.xn--80ak6aa92e.com` showed `apple.com` in the Brave Shield panel — complete brand-spoofing at the browser-trust layer.
- **Gener8 via curl program (1814824):** The company's official HackerOne profile linked to a Twitter handle anyone could register, allowing impersonation of the company toward the researcher community.