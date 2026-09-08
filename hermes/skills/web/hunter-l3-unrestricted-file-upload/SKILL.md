---
name: hunter-l3-unrestricted-file-upload
description: "Use when hunting Unrestricted File Upload on a target. Loads the L3 technique sheet: Unrestricted file upload covers any feature that accepts a file (or a URL pointing to a file) and stores it without adequate server-side validation of extension, MIME type, content, or destination."
domain: cybersecurity
subdomain: web
tags:
- web
- unrestricted-file-upload
- hunting
- l3
version: '1.0'
---

# Unrestricted File Upload — Technique Sheet

## Overview
Unrestricted file upload covers any feature that accepts a file (or a URL pointing to a file) and stores it without adequate server-side validation of extension, MIME type, content, or destination. It pays because uploads are user-controlled content on the target's infrastructure: depending on how the server serves what it stores, the same root cause yields anything from free file hosting and stored XSS to information disclosure and full RCE. In these records, the confirmed outcomes ranged from CDN-hosted PHP/APK files and webshell-primed `.jpg` files to reading a server's internal IP and web.config from an uploaded `.shtml` file. Impact escalation almost always depends on where and how the uploaded file gets served — always verify that step.

## Distinct sub-patterns

### 1. Legacy / forgotten upload endpoint, no validation at all
- Endpoint shape: a legacy image upload API that is still live but no longer fronted by modern validation. Exemplar: Enjin (id=1081766) — "legacy image upload API endpoint", param: uploaded file. Also Linktree's `*.odesli.co` image upload (id=1644062).
- Payload: not stated in either record — dangerous file types were accepted as-is.
- Root cause: the legacy endpoint accepts files with dangerous types and stores them directly on the CDN with the file's original MIME type; no validation on image upload at all.
- Impact proven: Enjin — a file with a dangerous type uploaded directly to the CDN with its original MIME type (CWE-434 confirmed by the program). Linktree — PHP, APK, and zip files uploaded through the image upload feature and used for storage purposes.
- Exemplars: 1081766 (Enjin), 1644062 (Linktree).

### 2. Client-side-only validation → intercept and modify the request
- Endpoint shape: `POST /{redacted}` (DoD bug-report submission), param: `file`.
- Payload: not stated; the disallowed-extension and >5MB oversized file were used.
- Root cause: only a client-side check exists (extension allowlist + 5MB size cap). Server-side validation of extension or size is absent, so modifying the intercepted request bypasses it entirely.
- Chain (verbatim from record): attach file with an allowed extension → intercept the HTTP request on submit → change extension to a disallowed one and/or size >5MB → submit successfully.
- Impact proven: bug report submitted with a disallowed extension and an oversized file. Escalation logic: if a support agent opened such a file, malware would execute on the agent's system.
- Exemplar: 1850065 (U.S. Dept Of Defense).

### 3. Content-Type header swap (extension not tied to body type)
- Endpoint shape: `POST https://partner.tiktokshop.com/wsos_v2/oec_partner/upload`, param: the Content-Type header of the multipart part.
- Payload (verbatim, id=1890284):
```
--BOUNDARY
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: image/jpeg

<% out.println("pwned"); %>
--BOUNDARY--
```
- Root cause: the server derives acceptability from the Content-Type header only; changing it to `image/jpeg` allowed any file extension (a JSP shell named `shell.jsp`) through.
- Impact proven: per the program summary, any extension could be uploaded when content-type was changed.
- Exemplar: 1890284 (TikTok). Note the same header-swap mechanic appears in the Reddit record (#6 below) with an SVG payload.

### 4. Dangerous extension that gets served and executed server-side (.shtml/.html)
- Endpoint shape: `POST /recruitjob/hxpublic_v6/hxinterface6.aspx`, param: `filename` (Starbucks).
- Payload (verbatim): `<?php echo 1111;>`
- Root cause: upload accepts `.html`/`.shtml` files, which the server then serves — SSI-enabled extensions execute and disclose server information.
- Chain: modify filename suffix to `.shtml` → uploaded file served in browser reads server internals.
- Impact proven: uploaded `.shtml` file revealed the server's internal IP (10.92.29.50), the application physical path, and the site's web.config.
- Related: lemlist (id=722919) — `POST` Settings > Email Signature > Upload File, param `file`. An `.html` file uploaded with no specific payload ("dangerous extension uploaded"); the signature upload allowed any file type including `.html` and the files were served/executed, proving upload-restriction bypass and page defacement.
- Exemplars: 412481 (Starbucks), 722919 (lemlist).

### 5. URL-based "avatar/gravatar" parameter accepting arbitrary non-image URLs
- Endpoint shape: `POST /change_photo`, param: `url` (RATELIMITED).
- Payload (verbatim): `http://attacker.example.com/not-an-image.php`
- Root cause: the gravatar/no-photo option accepts an arbitrary `url` value without validating that it points to an image or checking file content, while the direct upload-photo option properly enforces image-only — an inconsistent-validation gap on a sibling feature.
- Chain: login to auth.ratelimited.me → intercept "change photo" with Burp → choose "gravatar" option → change the `url` parameter to a non-image file → file is accepted.
- Impact proven: non-image file (PHP) accepted via the gravatar `url` parameter. Code execution was NOT achieved — the report was honest about the limit.
- Exemplar: 463604.

### 6. Unauthenticated public-mode file manager on sensitive infrastructure
- Endpoint shape: `GET/POST /ui/core/index.html?mode=public` (FileCloud), on a `.mil` host.
- Payload: not stated; files used included images and `putty.exe`.
- Root cause: the FileCloud `?mode=public` endpoint allows read/write without authentication — no user needed at all.
- Chain: navigate to `/ui/core/index.html?mode=public` → create sub-directory → upload files hosted on the `.mil` domain.
- Impact proven: directories created and images plus an executable (`putty.exe`) hosted on a `.mil` site without authenticating.
- Exemplar: 683024 (U.S. Dept Of Defense).

### 7. Any-file-type accepted as an "image" (desktop executable as contact photo)
- Endpoint shape: contact image upload, param: `file` (Nextcloud).
- Payload (verbatim): `SimpleCrackMe.exe`
- Root cause: the contact image upload accepted any file type without restricting to image MIME types.
- Impact proven: executable uploaded as a contact image, enabling distribution of malware/viruses from the platform's storage.
- Exemplar: 808287.

### 8. Extension-only validation → PHP webshell saved as .jpg
- Endpoint shape: `POST /profile` (avatar upload) and `POST /template-order` (Stripo Inc), param: avatar file.
- Payload: PHP web shell (r57 shell) saved with a `.jpg` extension.
- Root cause: server validated uploads only by extension — PHP content disguised as a JPEG passed because the filename ends in `.jpg`. Accepted on BOTH endpoints (avatar and template-order), and confirmed with the response "User icon has been saved".
- Impact proven: PHP shell stored as `.jpg`, enabling webshell execution / potential RCE.
- Exemplar: 823588.

### 9. MIME-type swap to image/svg+xml (stored XSS via upload)
- Endpoint shape: Reddit image upload, param: Content-Type.
- Payload (verbatim): `<svg .../><script>alert(document.cookie);</script></svg>`
- Root cause: upload MIME type `image/png` could be swapped to `image/svg+xml` with an SVG body; the flow also required a prior normal PNG upload so the corrupted image could be posted.
- Chain: upload a normal PNG first → add another image and intercept → change Content-Type from `image/png` to `image/svg+xml` → replace body with SVG payload → publish.
- Impact proven: SVG uploaded and published, bypassing MIME validation (server returned 201 created), intended for stored XSS.
- Exemplar: 996041 (Reddit).

### 10. Internet-exposed upload tool with no restriction
- Endpoint shape: an internet-accessible Navy file upload tool (endpoint not stated).
- Payload: not stated.
- Root cause: accepted malicious files with no restriction or validation whatsoever.
- Impact proven: malicious files uploaded to a Navy server; analysts judged it could permit code execution on the server.
- Exemplar: 184596 (U.S. Dept Of Defense).

## Bypass / chain notes
- Client-side-only checks: the single most reliable bypass in the records — attach an allowed file, intercept with Burp, swap the extension/body/size, submit (1850065). Never trust the browser-enforced allowlist.
- Content-Type / MIME swap: two variants observed — swapping the multipart part's Content-Type to `image/jpeg` to smuggle a JSP (1890284), and swapping `image/png` → `image/svg+xml` with an SVG body (996041). Both require intercepting an otherwise-legitimate upload request.
- Extension-only validation: send dangerous content under a benign extension — r57 PHP shell as `.jpg` (823588). Validate that the server serves the file and executes it (content sniffing / misconfig) to claim impact.
- Served-and-executed extensions: simply changing the filename suffix to `.shtml` turned a benign upload into server-info disclosure (412481); `.html` uploads served/executed at lemlist (722919).
- Inconsistent sibling validation: when the direct upload path is locked down, check alternate paths — the gravatar `url` parameter accepted arbitrary URLs while the upload path enforced image-only (463604).
- Pre-step seeding: the Reddit chain needed a normal PNG uploaded first before the corrupted upload could be published — replicate the full legitimate flow before injecting (996041).
- Unauthenticated modes / forgotten features: `?mode=public` on FileCloud (683024) and legacy image endpoints (1081766, 1644062) skip validation entirely — enumerate old endpoints and public modes before attacking the main flow.
- Where stored, how served: escalation depends on the destination — direct CDN storage with original MIME (1081766), storage on a `.mil` domain (683024), or served pages that execute SSIs (412481). Map storage location and serving behavior before writing the report.

## Gotchas / what NOT to do
- Do not claim RCE without proving execution. The RATELIMITED record (463604) explicitly notes code execution was NOT achieved; report what you actually demonstrated. The Navy record (184596) framed execution as "could permit" — hypothetical impact, clearly labeled.
- Do not stop at "file uploaded": the real rating hinges on where it lands and whether it's served, executed, or downloadable by others. The Linktree finding's honest framing was "used the service for storage purposes" (1644062).
- Do not test only the obvious upload widget. Every bypass in these records went through an alternate path: legacy endpoint, gravatar URL param, public-mode file manager, email-signature uploader, contact photo, bug-report attachment.
- Do not forget the two-request flows: Reddit required a normal PNG first; intercepting the SECOND upload is what fired (996041).
- Do not assume extension checks imply content checks (or vice versa): Stripo checked extension only (823588); TikTok checked Content-Type only (1890284); Starbucks checked neither for `.shtml` (412481). Probe each dimension separately.
- Do not upload genuinely destructive payloads to .gov/.mil or production systems — the DoD records used proofs like `putty.exe`, a size violation, and a benign disallowed extension; that was sufficient.
- Payload honesty: several records have "payload not stated" (1081766, 1644062, 184596, 1850065, 683024). The dangerous file type itself was the payload; a contrived injection string is not required to prove the class.

## Real-world impact examples
- Internal network info disclosure: `.shtml` upload at Starbucks read internal IP `10.92.29.50`, the application physical path, and web.config off the server (id=412481).
- Webshell staged for RCE: r57 PHP shell stored as `.jpg` on Stripo, accepted on two endpoints, confirmed saved (id=823588).
- JSP shell staged on TikTok Partner: `shell.jsp` uploaded by swapping Content-Type to `image/jpeg` (id=1890284).
- Executable hosted on a .mil domain: `putty.exe` and images uploaded without authentication via FileCloud public mode (id=683024).
- Stored XSS stage: SVG with `alert(document.cookie)` published on Reddit, bypassing `image/png` validation with a 201 response (id=996041).
- Free file hosting / malware distribution: PHP/APK/zip on `*.odesli.co` (id=1644062); `SimpleCrackMe.exe` as a Nextcloud contact image (id=808287).
- CDN pollution with dangerous MIME: dangerous-type file stored on Enjin's CDN with its original MIME type, CWE-434 program-confirmed (id=1081766).
- Client-side-bypass to agent compromise: disallowed extension + >5MB file accepted by the DoD bug-report endpoint, where an opened attachment would execute malware on a support agent's machine (id=1850065).