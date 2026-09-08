---
name: hunter-l3-csv-formula-injection
description: "Use when hunting CSV Formula Injection on a target. Loads the L3 technique sheet: CSV formula injection is a server-side-to-client-side attack: attacker-controlled input (stored or reflected via a query parameter) is exported by the application into a CSV/spreadsheet file without escaping dangerous leading characters."
domain: cybersecurity
subdomain: web
tags:
- web
- csv-formula-injection
- hunting
- l3
version: '1.0'
---

# CSV Formula Injection — Technique Sheet

## Overview

CSV formula injection is a server-side-to-client-side attack: attacker-controlled input (stored or reflected via a query parameter) is exported by the application into a CSV/spreadsheet file without escaping dangerous leading characters. When a privileged user (admin, support staff, translator) opens the export in Excel/LibreOffice/Google Sheets, cells beginning with `=`, `+`, `-`, or `@` are parsed as formulas — enabling command execution, data exfiltration via outbound formulas (e.g. DDE / `WEBSERVICE`), or reading local files. It pays when the exported data is opened by users who did NOT supply the input, and is especially valuable in admin-facing exports of user-generated content. The highest-value variant seen in the records is filter bypass against applications that *claim* to sanitize.

## Distinct sub-patterns

### Sub-pattern 1: Newline-prefix bypass of first-character filters

- **Endpoint shape / param:** `GET /export/csv` (Weblate), parameter: `translation` (i.e. translation content reflected into the CSV export).
- **Payload that fired (verbatim):** `%0A-3+3+cmd|' /C calc'!D2`
  - URL-decoded into the CSV cell, this is a newline followed by `-3+3+cmd|' /C calc'!D2` — a DDE-style formula that launches `cmd /C calc` (calculator as a benign command-execution proof).
- **Root cause:** The CSV injection filter only inspects the FIRST character of the cell value for `=`, `+`, `-`, `@`. A value whose first character is `%0A` (newline, `\n`) passes the check; the spreadsheet parser, however, strips/ignores the leading newline when evaluating the cell, so the `-` formula is still live. Additionally, the payload is not quoted in the output.
- **Impact proven:** Live formula in the exported spreadsheet that executes `cmd /C calc` when opened in Excel with content enabled — demonstrated bypass of the application's existing (imperfect) CSV injection defense.
- **Exemplar report:** id=223999 (Weblate, ajaysenr).

### Sub-pattern 2: Unsanitized stored field in an admin-facing CSV export (WordPress plugin)

- **Endpoint shape / param:** `GET /wp-admin/edit.php?post_type=talks` — the CSV export action of the admin post-list screen. Parameter: post `title`.
- **Payload that fired (verbatim):** `=1+1`
- **Root cause:** The export code wrote field values into the CSV with no sanitization; any cell beginning with `=`, `-`, or `+` is interpreted by Excel as a formula. The attacker sets the value simply by creating a post (talk) with the payload as its title.
- **Impact proven:** Excel evaluated the cell to `2` in the admin's export — proving formula evaluation. Escalates to command execution if the user enables content (DDE/`cmd|` payloads).
- **Exemplar report:** id=277525 (Ian Dunn, ajaysenr).

### Sub-pattern 3: Unsanitized answer field in export of user-submitted form data (Nextcloud Forms)

- **Endpoint shape / param:** `POST /apps/forms/{uuid}/answer` — submitting an answer to a Forms app form. Parameter: `answer`. The vulnerable surface is the app's CSV export of participants' answers.
- **Payload that fired (verbatim):** `=1+1`
- **Root cause:** The CSV export reflects answer cells without escaping leading `=`, `+`, `-`, `@`. Multi-user by design: the person opening the export (form owner/admin) is not the person who submitted the payload, which is the cross-user trust boundary that makes it exploitable.
- **Impact proven / stated:** Formula reflected in CSV enabling (1) exfiltration of other participants' answers, (2) reading local files, (3) code execution.
- **Exemplar report:** id=928280 (Nextcloud, ajaysenr).

## Bypass / chain notes

- The only bypass demonstrated in the records is the **newline prefix** (`%0A-...`): filters that scan only the first character can be defeated by prefixing the formula with a control character the spreadsheet still tolerates. Weblate had a filter; it was checked the first char only — that gap was the bug.
- Generic hardening that was ABSENT in all three targets: quoting/escaping cells, prefixing dangerous cells with `'`, tab/space-mangling, or replacing leading `=+-@` at any position after whitespace.
- No multi-step chains were recorded in these three findings (`chain: (none)` in all records); impact in every case was single-step: payload stored/submitted → CSV export opened → formula evaluated.

## Gotchas / what NOT to do

- Do not test only with `=1+1` and stop — a benign arithmetic result (`2`) proves evaluation, but the stronger finding is the DDE/command variant (`cmd|' /C calc'!D2`), which is what made the Weblate report a filter-bypass demonstration rather than a plain reflection.
- Do not assume a target is safe because it advertises CSV sanitization — verify the filter's exact logic (first-character-only checks are common and bypassable with `%0A`, `%09`, or similar prefixes; only the newline prefix is proven in these records).
- Use `cmd|' /C calc'` (calculator) as the command-execution proof, not destructive commands — calc is the accepted benign demonstration in these reports.
- Note the trust boundary in the report: the victim opening the export must be different from the payload submitter (admin opening user content). Same-user self-injection is usually a non-issue.
- The victim must click through Excel's "enable content" prompt for DDE execution; report formula-evaluation evidence (`=1+1` → `2`) as the guaranteed baseline impact.

## Real-world impact examples

- **Weblate (id=223999):** `%0A-3+3+cmd|' /C calc'!D2` in a translation value survived the CSV filter and executed `cmd /C calc` in Excel on export — a live command-execution primitive behind a filter that was supposed to stop it.
- **Ian Dunn WordPress site (id=277525):** A talk titled `=1+1` exported via `/wp-admin/edit.php?post_type=talks` evaluated to `2` in the site admin's spreadsheet, proving formula evaluation in an admin-facing export.
- **Nextcloud Forms (id=928280):** `=1+1` submitted as a form answer was reflected unescaped into the CSV export, with stated potential for exfiltrating other participants' answers, reading local files, or code execution.