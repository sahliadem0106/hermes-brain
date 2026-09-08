---
name: hunter-l3-open-redirect
description: "Use when hunting Open Redirect on a target. Loads the L3 technique sheet: Open redirects abuse server-side redirect logic (Location headers, meta refresh, JS `window.location`, or OAuth/post-login `return_to` flows) to send victims to attacker-controlled destinations from a trusted domain."
domain: cybersecurity
subdomain: web
tags:
- web
- open-redirect
- hunting
- l3
version: '1.0'
---

# Open Redirect — Technique Sheet

## Overview
Open redirects abuse server-side redirect logic (Location headers, meta refresh, JS `window.location`, or OAuth/post-login `return_to` flows) to send victims to attacker-controlled destinations from a trusted domain. They pay on their own as low/medium findings, but the real money comes when they sit in authenticated flows (token leakage in `next`/`r`/`ReturnUrl` params), chain into account takeover (OAuth callbacks), or defeat link-filtering/interstitial mechanisms on high-traffic platforms. The 60 records below cluster into a small set of recurring root causes: unvalidated query params, double-slash / path-normalization bugs, allowlist bypasses via encoding and special characters, Host-header trust, and chained redirects through other same-domain redirectors.

## Distinct sub-patterns

### 1. Naked unvalidated query/POST parameter reflected into Location
- **Endpoint shape:** `GET /redirect?url=`, `GET /urbanup.php?hostname=`, `GET /ck.php?dest=`, `GET /login?nextPage=`, `POST /User/AuthenticateForms` (`ReturnUrl`), `POST /ama` (`failed`)
- **Payload:** verbatim examples — `https://events.hackerone.com/redirect?url=https://naglinagli.github.io` (id=1028345); `http://www.urbandictionary.com/urbanup.php?hostname=http://smsmafia.in` (id=12964); `ReturnUrl=https://evil.com` (id=1544236); `failed=http://xfs.bxss.me` (id=1257753); `http://evil.com` in `endpoint` (id=178278)
- **Root cause:** parameter is copied straight into the redirect target with no allowlist at all. Revive Adserver's `ck.php`/`lg.php` (`dest`/`oadest`/`ct0`) is open-by-design for impression/click tracking (id=1081406).
- **Impact:** plain off-domain redirect; id=1544234-style token leakage (Insightly: auth token in URL carried to evil.com post-login → account takeover).
- **Exemplars:** id=1028345 (HackerOne), id=1544236 (Insightly), id=12964 (Urban Dictionary)

### 2. Post-login / logout `return_to` / `return_url` / `redirect_to` params
- **Endpoint shape:** `GET /accounts?return_to=`, `GET /account/logout?return_url=`, `GET /wp-login.php?redirect_to=`, `GET /checkcookie?redir=`, `GET /zendesk_session?return_to=`
- **Payload:** `https://ecommerce.shopify.com/accounts?return_to=%40evil.com/` (id=155222 — note the `@` prefix); `https://wordpress.com/wp-login.php?redirect_to=https%3A%2F%2Fgoogle.com%2Fsearch?q=myFakeSite&reauth=1` (id=129091)
- **Root cause:** redirect-after-auth target validated only by prefix/hostname checks — or not at all; `@evil.com` passes because validation only checks for presence of a trusted string.
- **Impact:** credential-adjacent phishing (user enters login, lands on attacker page); id=155222 confirmed redirect to evil.com after credential entry.
- **Exemplars:** id=155222 (Shopify), id=129091 (Automattic), id=1050193 (Automattic `goto` on logoutRedir.php)

### 3. Double-slash / scheme-relative path injection (`//host`, `///host`, trailing-slash path parsing)
- **Endpoint shape:** `GET ///{host}/`, `GET /en//{url}/`, `GET /{path}` starting with `//`
- **Payload:** `https://apps.shopify.com//blackfan.ru/` → `HTTP 301 Location: //blackfan.ru` (id=160047); `https://www.uber.com/en//example.com/` (id=125791); `uber.com//216.58.217.206/calendar` (id=119236); `https://www.affirm.com///google.com/?www.affirm.com/?...` (id=1213580); `https://paragonie.com//google.com/` (id=113112); `//youtube.com/%2F..` on m.uber.com → `303 Location: //youtube.com/%2F../` (id=125000); `https://account.brave.com//example.com/%2F..` (id=1338437)
- **Root cause:** router treats the segment after `//` as a host, or the framework serializes a multi-slash path into a scheme-relative Location. `%2F..` adds a normalization step that pushes the `//host` past path-canonicalization.
- **Impact:** 301/303/302 to arbitrary host; looks like a fully legitimate domain in the address bar until the redirect lands.
- **Exemplars:** id=160047 (Shopify apps), id=125000 (Uber m.uber.com), id=1213580 (Affirm)

### 4. Leading-slash and encoded-slash allowlist bypasses (`////`, `%2F%2F`, `%2f`)
- **Endpoint shape:** `GET /auth/shopify?shop={shop}&return_to=`, `GET /apps/locksmith/...?path=`, profile URL hostnames
- **Payload:** `return_to=/////example.com` (id=175168); `path=%2F%2Fevil.com` (id=158434); `https://gratipay.com%2f@google.com` (id=128910)
- **Root cause:** filter blocks `http(s)://` and bare `//` but not four leading slashes or percent-encoded slashes; `%2f` in the authority is decoded by the browser after validation, splitting `gratipay.com/` off and leaving host `google.com`.
- **Impact:** redirect off-domain; id=158434 showed a 404 page then JS redirect to evil.com after 2 seconds in all browsers.
- **Exemplars:** id=175168 (Shopify), id=158434 (Shopify), id=128910 (Gratipay)

### 5. Substring / regex allowlist flaws (host contained anywhere, prefix matching, leading-dot regex)
- **Endpoint shape:** Dynamic Links `lnk.clario.co/?link={url}`, Rails Host-header sanitizer, `return_url` allowlists
- **Payload:** `https://lnk.clario.co/?link=https://evil.example.com/clario.co/` (id=1066410 — trailing `/clario.co/` path segment satisfies the regex); `Host: google.com#sub.tkte.ch` (id=1047447 — `#` defeats the leading-dot regex); `return_url=https://checkout.shopify.com/<victim_store_id>/../14467660` (id=165046)
- **Root cause:** validation does `"/clario.co/" in url` or a prefix match instead of parsing and comparing the exact registrable host. Fragment characters and `/../` traversal defeat naive matchers.
- **Impact:** id=1066410 created trusted-looking `lnk.clario.co` short links to arbitrary sites; id=165046 chained into the attacker's Shopify store whose 404 page injected HTML/JS into the victim's admin theme editor iframe.
- **Exemplars:** id=1066410 (Clario), id=1047447 (Ruby on Rails), id=165046 (Shopify)

### 6. Auth-token leakage via redirect parameter (redirect → account takeover)
- **Endpoint shape:** `GET /global/identity?r={url}` (Logitech/Streamlabs), `GET /login?callback_url=` (Periscope)
- **Payload:** `https://attacker.com%ff@www.periscope.tv` (id=108113); `r=https://dragynslair.live/` (id=1327742); `r=protocol://merch.streamlabs.com` (id=1178239)
- **Root cause:** the server appends `access_token` as a query parameter to the redirect destination. Periscope: hostname validation passes, then `%ff` is converted to `?` after validation, changing the parsed authority so the browser resolves attacker.com. Logitech: the whitelist contained expired/registrable domains (`dragynslair.live`), or accepted arbitrary protocols whose registered handler receives the tokenized URL.
- **Impact:** full account takeover — Periscope victim's account renamed "Pwn3d" after OAuth credential redirect; Streamlabs access_token captured with `/etc/hosts` + netcat and verified working against API endpoints.
- **Exemplars:** id=108113 (X/Periscope), id=1327742 (Logitech), id=1178239 (Logitech)

### 7. Chained redirects through same-domain redirectors and attacker-hosted content
- **Endpoint shape:** `GET /checkcookie?redir=` → files.slack.com SVG; `/zendesk_session?return_to=` → `support.hackerone.com/ping/redirect_to_account?state=...`; `checkout.shopify.com/{store_id}` as `return_url`
- **Payload:** `https://slack.com/checkcookie?redir=https://files.slack.com/files-pri/T0E7QLVLL-F0G41EG2W/redirect.svg?pub_secret=7a6caed489` (id=104087); `https://hackerone.com/zendesk_session?locale_id=1&return_to=https://support.hackerone.com/ping/redirect_to_account?state=compayn:/` (id=111968)
- **Root cause:** the validator allows any URL on the company's own domain, but the attacker controls a redirector *on* that domain (uploaded SVG with `onload=window.location`, custom Zendesk account, own store URL redirect).
- **Impact:** id=104087 landed victims on example.com via the Slack redirector; id=111968 bypassed the interstitial entirely and landed on evil.com with no warning; id=159522 used an attacker store's redirect from `checkout.shopify.com/{store_id}`.
- **Exemplars:** id=104087 (Slack), id=111968 (HackerOne), id=159522 (Shopify)

### 8. Interstitial / external-link-warning bypasses
- **Endpoint shape:** double-slash SAML URL, markdown links in exported PDFs, protocol-relative re-attack after a fix
- **Payload:** `https://hackerone.com/users//saml/sign_in?email=teste@snapchat.com&remember_me=true` (id=178345 — `//` bypasses the regex of the earlier fix); markdown `(https://example.com")` with appended quote + close-paren (id=1386277); `failed=//evil.com` bypassing a fix that blocked `http://evil.com` (id=1285081)
- **Root cause:** the fix patched one URL shape; the interstitial trigger is a regex/normalize check that other syntactically-valid forms skip. Reddit's `/ama` `failed` fix is a textbook regression target: block `http://`, get hit with `//`.
- **Impact:** victims reach external/SSO URLs with no warning page — the warning was the only control.
- **Exemplars:** id=178345 (HackerOne), id=1285081 (Reddit), id=1386277 (HackerOne PDF export)

### 9. Unicode / parser-differential bypasses (link deny-lists)
- **Endpoint shape:** `twitter.com/login?redirect_after_login={url}` chained to `analytics.twitter.com/daa/0/daa_optout_actions?...&rd={url}`
- **Payload (verbatim):** `https://twitter.com/login?redirect_after_login=https%3A%2F%2Fanalytics.twitter.com%2Fdaa%2F0%2Fdaa_optout_actions%3Faction_id%3D4%26rd%3Dhttps%253A%252F%252Fddosecrets%2525E3%252580%252582com%253F`
- **Root cause:** replace ASCII periods in the target domain with URL-encoded Ideographic Full Stop (`%E3%80%82`, U+3002) — the deny-list compares ASCII `.` but the browser normalizes U+3002 to a dot. Two chained trusted redirectors (login `redirect_after_login`, analytics `rd`) complete the trip. This regression was re-reported verbatim later (id=1421345).
- **Impact:** a tweet linking to the blocked domain ddosecrets.com redirects there with no interstitial — defeats the platform's link-blocking control.
- **Exemplars:** id=1032610, id=1421345 (X / xAI)

### 10. Host-header-based redirect generation
- **Endpoint shape:** `GET /` with attacker `Host:`, or `X-Forwarded-Host` in email-link flows
- **Payload:** `Host: google.com` → `301 Location: https://google.com/` (id=158019, Instacart); `Host: google.com#sub.tkte.ch` (id=1047447); `X-Forwarded-Host: bing.com` on the Omise email-verification resend (id=1444675)
- **Root cause:** server builds absolute redirect/self URLs from `Host`/`X-Forwarded-Host` instead of a configured canonical host.
- **Impact:** cache poisoning, password-reset/email-link poisoning (id=1444675 made the "request another email" link redirect to a malicious page); id=145306 (Veris) similarly let a registration-form `sub_link=example.com` build the verification email URL — verification-code theft and account hijack.
- **Exemplars:** id=158019 (Instacart), id=1444675 (Omise), id=145306 (Veris)

### 11. Authority-component tricks (`@`, credentials, fragment, arbitrary protocols)
- **Endpoint shape:** URLs where user data lands in the authority
- **Payload:** `https://█████_https@google.com` (id=1267176, JetBlue — user-controlled authority becomes the redirect target); `https://gratipay.com%2f@google.com` (id=128910); `https://attacker.com%ff@www.periscope.tv` (id=108113); `Host: google.com#sub.tkte.ch` fragment trick (id=1047447); `r=protocol://merch.streamlabs.com` (id=1178239)
- **Root cause:** validation parses one view of the URL; the browser parses another (userinfo `@`, non-ASCII → `?` conversion, fragment handling, protocol handlers).
- **Impact:** phishing via legitimate-looking URLs; account takeover when tokens ride the redirect (see sub-pattern 6).
- **Exemplars:** id=1267176 (JetBlue), id=108113 (X/Periscope)

### 12. Redirect-token validation gaps (presence-checked, not bound)
- **Endpoint shape:** `GET /redirect?u={url}&t={token}&g={context}`
- **Payload:** `https://www.zomato.com/redirect?u=http%3A%2F%2Ftest.com&t=38dc43d5f007f4c5d974f6c74f065158&g=user-profile-website` (id=143265)
- **Root cause:** token `t` is checked for existence only — not bound to the user or the `u` value — so any valid token authorizes any destination.
- **Impact:** any authenticated or unauthenticated user redirected to an arbitrary site.
- **Exemplars:** id=143265 (Eternal/Zomato)

### 13. Framework / library parser bugs (nil-host and empty-authority URLs)
- **Endpoint shape:** `URI.parse` (Ruby), Rails `redirect_to` protection
- **Payload:** `URI.parse("http:////malware.com/real/path")` — parses to nil host, but `to_s` resolves to `http://malware.com/real/path` in browsers (id=156615); Rails 7.0 `redirect_to` allowlist bypass via carefully crafted URL (id=1865991, CVE-2023-22797)
- **Root cause:** the parser's host-regex diverges from browser behavior: Ruby allowed empty hosts (four slashes → nil host that serializes back into a malicious URL); Rails' incomplete URL validation skipped host-allowlist checks.
- **Impact:** bypasses any host-validation built on the parser; CVE-2023-22797 fixed in 7.0.4.1.
- **Exemplars:** id=156615 (Ruby), id=1865991 (Internet Bug Bounty)

### 14. Tabnabbing (missing `rel=noopener`) — redirect-adjacent
- **Endpoint shape:** outbound links with `target=_blank` and no `rel=noopener/noreferrer`
- **Payload:** payload not stated (structural issue)
- **Root cause:** opened page can rewrite `window.opener`'s location.
- **Impact:** id=124620 (HackerOne escalation/CVE links) — reverse tabnabbing to a fake login page of the originating tab; id=158002 (Instacart list links) — opener tab URL changed to example.com, enabling phishing.
- **Exemplars:** id=124620 (HackerOne), id=158002 (Instacart)

### 15. Markdown / user-content link injection without warning pages
- **Endpoint shape:** profile statement markdown, WordPress failure-notice `_wp_http_referer`, unauthenticated file-viewer `file` param
- **Payload:** `[evil](http://attacker.com)` (id=151831); `?wpcspReceiveCSPviol=1&_wp_http_referer=example.com` (id=112955 — rendered as the trusted "Please try again" link); `https://demo.owncloud.org/index.php/apps/files_pdfviewer?file=https://evildomain.xx/EvilFile.xx` (id=131082 — Download button redirects unauthenticated users)
- **Root cause:** user-controlled strings rendered as link hrefs with no domain validation or leave-site interstitial.
- **Impact:** phishing links wearing trusted UI chrome.
- **Exemplars:** id=112955 (withinsecurity), id=131082 (ownCloud), id=151831 (Gratipay)

### 16. Path/hostname-suffix confusion (appended-domain redirects)
- **Endpoint shape:** `GET https://{ip-or-host}/.example.com`, `*.myshopify.com/account/login?checkout_url={tld-fragment}`
- **Payload:** `https://█.█.█.█/.example.com` → redirect to `https://www.8x8.com.example.com` (id=1637571); `checkout_url=.np` appended without a separating slash → `https://sehyoginfoshop.myshopify.com.np/` (id=103772)
- **Root cause:** user input concatenated into a hostname/redirect without enforcing a domain boundary — the attacker's suffix creates a new registrable domain.
- **Impact:** redirect to attacker-registered lookalike domain.
- **Exemplars:** id=1637571 (8x8), id=103772 (Shopify)

### 17. Browser-side linkshim defeat
- **Endpoint shape:** Facebook `l.php?u=` interstitial vs. Brave's client behavior
- **Payload:** `https://l.facebook.com/l.php?u=https://test.facebook-whitehat.com/` (id=1579374)
- **Root cause:** Brave requested the destination directly without confirming the redirect with `l.facebook.com`, skipping the server-side malicious-link check (CVE-2023-22798).
- **Impact:** Facebook's link filtering defeated for Brave users.
- **Exemplars:** id=1579374 (Brave)

### 18. Tooling-level meta-redirect following (niche)
- id=1541301 (PortSwigger): Burp Repeater/Intruder follows meta redirects regardless of content-type/content-disposition on follow-redirection click, disclosing the Referrer header (CVE-2022-35406) — low severity, multiple unlikely user-interaction steps.
- Exemplars: id=1541301

## Bypass / chain notes
- **After a fix is shipped, retest with a different URL syntax:** Reddit `failed=http://evil.com` → `failed=//evil.com` (id=1285081); HackerOne SAML `//` bypass (id=178345); Twitter's Ideographic-Full-Stop chain reproduced verbatim as a regression (id=1421345); Rockstar's previously-patched OAuth redirect regressed (id=1101771).
- **Encoding arsenal seen in records:** `%2F%2F` (id=158434), `/////` (id=175168), `%2f` in authority (id=128910), `%ff` → `?` post-validation (id=108113), `%2F..` path normalization (id=125000, id=1338437), U+3002 for `.` (id=1032610).
- **Chain ingredients that recur:** attacker-controlled redirectors *on* the target domain (uploaded SVG with `window.location` on files.slack.com; custom Zendesk account; own Shopify store URL redirect); expired domains still in a redirect whitelist (found via Wayback Machine — id=1327742); leaked API keys enabling the Dynamic Links shortener chain (id=1066410); arbitrary-protocol redirects handing tokenized URLs to registered handlers (id=1178239).
- **OAuth/identity chains:** open redirect in `callback_url`/`r`/`ReturnUrl` + server appending `access_token` to the redirect = account takeover, not just phishing (id=108113, id=1327742, id=1178239, id=1544236).

## Gotchas / what NOT to do
- Don't stop at "it redirects to google.com" without demonstrating attacker-controlled impact or token leakage — records with generic PoCs (e.g. id=1101771, id=1467046) were accepted, but the top-payout records all chained to takeover or filter-defeat.
- Don't test only `http://evil.com` — the records show filters commonly block scheme-prefixed URLs; try `//evil.com`, `/////evil.com`, `%2F%2Fevil.com`, `@`-authority, and fragment tricks before concluding the parameter is safe.
- Don't report sub-pattern 14 (tabnabbing) as compromise: id=124620 explicitly notes no real compromise — severity is limited to phishing against attacker-linked content.
- Don't assume a whitelist domain is safe — verify whether attacker-controlled content can live on it (user uploads, custom accounts, store redirects) and whether whitelist entries include expiring TLDs.
- Check `X-Forwarded-Host`/`Host` handling on email-generating endpoints (id=1444675, id=145306) — link poisoning there outclasses a browser redirect.
- Re-verify old disclosed reports against the target: several records are regressions of previously fixed bugs (id=1421345, id=1101771, id=1285081, id=178345).

## Real-world impact examples
- **Account takeover (Periscope):** `callback_url=https://attacker.com%ff@www.periscope.tv` — OAuth credential redirected to attacker.com; attacker logged into the victim's account and renamed it "Pwn3d" (id=108113).
- **Token exfiltration (Streamlabs/Logitech):** access_token appended to redirect to `dragynslair.live` (an expired whitelisted domain), captured with netcat, verified working against Streamlabs API — full account takeover (id=1327742).
- **Link-blocking defeat (Twitter):** chained login + analytics redirectors with U+3002 encoded dots got a tweet linking to the blocked domain ddosecrets.com to redirect with no interstitial (id=1032610).
- **Admin-frame HTML injection (Shopify):** `return_url=.../../14467660` prefix-match bypass forced the victim's theme editor iframe to the attacker's store, whose 404 page injected arbitrary HTML/JS (id=165046).
- **Verification-code theft (Veris):** `sub_link` poisoned the company's own verification email to point at the attacker site — account hijack (id=145306).
- **Cache poisoning vector (Instacart):** `Host: google.com` → `301 Location: https://google.com/` on the root path (id=158019).