---
name: hunter-l3-php-object-injection-xxe-ssrf
description: "Use when hunting PHP Object Injection / XXE / SSRF on a target. Loads the L3 technique sheet: This class chains PHP object injection into XXE and SSRF: user-controlled serialized data (here, uploaded files) is passed to `unserialize()`, and the reconstructed object's magic methods (`__toString"
domain: cybersecurity
subdomain: web
tags:
- web
- php-object-injection-xxe-ssrf
- hunting
- l3
version: '1.0'
---

# PHP Object Injection / XXE / SSRF — Technique Sheet

## Overview
This class chains PHP object injection into XXE and SSRF: user-controlled serialized data (here, uploaded files) is passed to `unserialize()`, and the reconstructed object's magic methods (`__toString()`, `__destruct()`, etc.) feed attacker-controlled strings into XML parsers that were created with dangerous libxml flags (`LIBXML_NOENT | LIBXML_DTDLOAD`). The result is non-blind XXE — full local file read and internal HTTP requests whose responses are echoed back in the server's output. It pays when the target imports/uploads XML or serialized blobs and the parser options aren't hardened.

## Distinct sub-patterns

### 1. File-upload parameter as the POI injection vector
- Endpoint shape: `POST /api/import_memes_2.0.php` with an uploaded file field `f`.
- Payload: the uploaded file itself is a serialized PHP object (a `ConfigFile` instance discovered by reading the source); `unserialize()` on its contents constructs the object.
- Root cause: unsafe `unserialize()` of user-uploaded data. No allowlist of classes; the `ConfigFile` class holds an XML string that gets parsed.
- Impact: entry point for everything below — arbitrary class instantiation with attacker-set properties.
- Exemplars: 415137, 415202.

### 2. Classic file-read XXE via SYSTEM file:// entity
- Endpoint shape: same upload endpoint; the file content is XML with a DOCTYPE declaring an external general entity.
- Payload (verbatim, 415137):
  `<?xml version="1.0"?><!DOCTYPE root[<!ENTITY foo SYSTEM "file:///etc/passwd">]><test><toptext>dddrrr &foo;</toptext></test>`
- Root cause: `ConfigFile::parse()` calls the XML parser with entity loading enabled (`LIBXML_NOENT | LIBXML_DTDLOAD`), so `&foo;` resolves server-side and the resolved value is rendered into the response (non-blind).
- Impact: local file read (`/etc/passwd`), used to read application source code.
- Exemplars: 415137, 415682.

### 3. PHP filter wrapper for encoding binary/large files
- Endpoint shape: same; entity SYSTEM URI is a `php://filter` wrapper.
- Payload (verbatim, 415682):
  `<?xml version='1.0' encoding='ISO-8859-1'?>\n<!DOCTYPE foo [\n<!ELEMENT foo ANY >\n<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=/etc/issue' >]>\n<memes><toptext>&xxe;</toptext><bottomtext>A</bottomtext><template>TeMPLaTe123</template><type>XML</type></memes>`
  (also seen as `php://filter/read=convert.base64-encode/resource=...` in 415202/415222)
- Root cause: same dangerous libxml flags; PHP stream wrappers are accepted as the entity's SYSTEM URI, so the filter chain base64-encodes content to survive XML charset handling.
- Impact: read files that would break inline (`/etc/issue`), and read remote content reliably (see sub-pattern 4).
- Exemplars: 415202, 415222, 415682.

### 4. Non-blind SSRF via SYSTEM http:// entity
- Endpoint shape: same; entity SYSTEM URI is an internal URL.
- Payload (verbatim, 415501):
  `<?xml version="UTF-8"?> <!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://localhost:1337/" >]><note><toptext>Tove</toptext><bottomtext>Jani</bottomtext><type>Reminder</type><template>&xxe;</template></note>`
  (415222 used `php://filter/read=convert.base64-encode/resource=http://127.0.0.1:1337` to base64 the response body)
- Root cause: the XXE parser fetches any SYSTEM URI, including internal HTTP endpoints — the entity becomes an SSRF primitive, and because the resolved value is rendered, the internal response comes back non-blind.
- Impact: fetched `http://localhost:1337` / `http://127.0.0.1:1337` and discovered an internal Maintenance API not exposed externally.
- Exemplars: 415202, 415222, 415501.

### 5. /proc-based service discovery through the SSRF primitive
- Endpoint shape: same XXE vector; SYSTEM URI targets `/proc/{PID}/cmdline` (implied by impact description of 415682).
- Payload: `php://filter/.../resource=/proc/{PID}/cmdline` style entity (exact verbatim not stated in records beyond the /etc/issue example).
- Root cause: with no port-scan capability, enumerate running processes via `/proc` to learn what's listening where.
- Impact: discovered the internal service on `localhost:1337` (Maintenance API) by reading process command lines.
- Exemplar: 415682.

## Bypass / chain notes
- Full chain observed in every record: LFR (read source) → discover `ConfigFile`/`import_memes` class → craft serialized `ConfigFile` object in the uploaded file → `unserialize()` instantiates it → `__toString()` triggers `parse()` → XXE fires → SSRF to internal service.
- Base64-encode entity output with `php://filter/...convert.base64-encode` when responses contain bytes invalid for the XML encoding (both for local files and for internal HTTP responses).
- `ISO-8859-1` and `UTF-8` encodings on the XML declaration both worked; single- and double-quoted SYSTEM URIs both worked — flexibility is fine as long as DOCTYPE/entity syntax is intact.
- The response rendering of the parsed XML is what makes this non-blind — the resolved entity is placed into a template field (`toptext`, `template`) that the app echoes.

## Gotchas / what NOT to do
- Don't stop at "XXE possible" — in this class the payload-to-proof path runs through the serialized object; a raw XML file with DOCTYPE won't fire if the file is first fed to `unserialize()`. Read the source (via the initial LFR) to get the class name and property structure exactly right.
- Don't attempt to read binary files directly through the entity — use the php://filter base64 wrapper.
- Don't assume internal services are unreachable because ports are filtered externally; SSRF to localhost + /proc enumeration found port 1337 in these records.
- Watch flag combinations: the bug exists specifically because of `LIBXML_NOENT | LIBXML_DTDLOAD` — DTD loading alone without entity substitution may yield a blind or no-fire result; both flags matter.

## Real-world impact examples
- Non-blind read of `/etc/passwd` and `/etc/issue` (415137, 415682).
- Source-code disclosure via file read, used to locate the import endpoint and `ConfigFile` class (415137, 415202 chains).
- Non-blind SSRF to `http://localhost:1337` / `127.0.0.1:1337`, revealing an internal Maintenance API with no external exposure (415202, 415222, 415501).
- Discovery of the internal service's identity/port via `/proc/{PID}/cmdline` read through XXE (415682).

All five records are from the same program (h1-5411-CTF, reporter ajaysenr) and the same endpoint/parameter — the variance across them is in payload form (raw file://, php://filter over file, php://filter over http, direct http://) and in how far the chain was pushed.