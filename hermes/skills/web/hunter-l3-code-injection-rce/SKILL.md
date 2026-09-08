---
name: hunter-l3-code-injection-rce
description: "Use when hunting Code Injection (RCE) on a target. Loads the L3 technique sheet: Code injection is the class where attacker-controlled input is *evaluated as code* rather than treated as data — OGNL, PHP `eval()`, Ruby `render :inline`/`send()`, Node `vm.runInThisContext()`, shell"
domain: cybersecurity
subdomain: web
tags:
- web
- code-injection-rce
- hunting
- l3
version: '1.0'
---

# Code Injection (RCE) — Technique Sheet

## Overview

Code injection is the class where attacker-controlled input is *evaluated as code* rather than treated as data — OGNL, PHP `eval()`, Ruby `render :inline`/`send()`, Node `vm.runInThisContext()`, shell command strings, Elasticsearch Painless scripts, or a written webshell file that the server then compiles/executes. It pays heavily because impact is total: arbitrary command execution on the server (or the victim's client machine for client-side injection into generated code). In these records, severity ranges from P1 RCE on military infrastructure to CVSS 8.8 in open-source bounty programs, and client-side RCE with user interaction still gets paid.

## Distinct sub-patterns

### 1. Struts2 Jakarta multipart Content-Type OGNL injection (S2-045)

- Endpoint/param: `GET /pwsc/login.do`, attacker-controlled `Content-Type` header.
- Payload (verbatim, truncated in record):
  `%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageN...`
- Root cause: Struts2's Jakarta multipart parser throws an error that reflects the `Content-Type` header value into an OGNL expression evaluation. The payload resets the `SecurityMemberAccess` via `DEFAULT_MEMBER_ACCESS` (bypassing Struts's member-access restrictions) before running attacker code.
- Impact: The OGNL expression's evaluation result was printed into the HTTP response — proof shown by the response rendering `31337*31337` (i.e., `981485169`). Arbitrary code execution on the server.
- Exemplar: id=1070532 (MTN Group).

### 2. Arbitrary file write → ASPX webshell via report export parameters

- Endpoint/param: `POST /RServer/rdPage.aspx`, params `rdExportFilename` and `rdReportName` ( Izenda-style Report Manager).
- Payload (URL-encoded verbatim):
  `%3c%25%40%20%50%61%67%65%20%4c%61%6e%67%75%61%67%65%3d%22%43%23%22%25%3e...` — decodes to `<%@ Page Language="C#" %><%@ Import Namespace="System" %><% System.Diagnostics.Process process = ...`, i.e., a C# ASPX webshell.
- Root cause: The export feature lets the attacker control both the export *filename* (any path/extension → arbitrary file write anywhere on disk) and the export *content* (the "report" body is attacker-supplied). Writing a `.aspx` file into a web-served directory yields direct code execution on IIS.
- Chain as recorded:
  1. Change `rdReportFormat` and `rdExcelOutputFormat` to `NativeExcel`.
  2. Set `rdExportFilename` to `<name>.aspx` (arbitrary write).
  3. Inject the ASPX webshell via the report content.
  4. Execute commands through the shell, e.g. `?68c2c8b1fc47766eaf43027a8eaca121=whoami`.
- Impact: Command execution on a military (U.S. DoD) server — demonstrated with `whoami` through the shell.
- Exemplar: id=1072832 (U.S. Dept Of Defense).

### 3. User content reaching PHP `eval()` via theme block processing

- Endpoint/param: `GET /index.php?app=cms&module=pages&controller=builder&do=previewBlock`, param `block_content`.
- Payload (verbatim): `RCE%0ACONTENT;}}phpinfo();die;/*`
- Root cause: `previewBlock()` passes the user-supplied block content into `IPS\_Theme::runProcessFunction()`, which feeds template logic into `eval()`. The payload closes the surrounding PHP statement and braces (`;}}`) so the injected call lands at top-level scope, executes, then `die;` stops execution and `/*` comments out the remainder of the template to avoid parse errors.
- Impact: `phpinfo()` executed — arbitrary PHP code execution. Note the record's precondition: requires sidebar-management permissions (an authenticated/privileged-to-unprivileged-code-exec escalation).
- Exemplar: id=1092574 (Invision Power Services).

### 4. PHP injection via admin save path (sanitize-then-store failure)

- Endpoint/param: `Translate::save()` (admin area of ExpressionEngine); no discrete parameter recorded.
- Payload: not stated.
- Root cause: Improperly sanitized user input passed through `Translate::save()` allowed injection of arbitrary PHP code (input stored/compiled as PHP rather than escaped).
- Impact: The vendor program confirmed attackers could inject and execute arbitrary PHP; fixed.
- Exemplar: id=1093444 (ExpressionEngine).

### 5. Ruby on Rails `render` parameter coercion (CVE-2016-2098)

- Endpoint/param: `GET /render` — the route renders `params[:id]` directly.
- Payload (verbatim): `render params[:id]` — i.e., the app calls `render` with the user's parameter, so passing an inline-template value coerces Rails into `render :inline`.
- Root cause: `render` with unverified request parameters can be coerced into `render :inline` (or file/template variants), executing the parameter as Ruby code. Fixed in CVE-2016-2098.
- Impact: Arbitrary Ruby code execution via request parameters.
- Exemplar: id=113928 (Ruby on Rails program).

### 6. Rails ActiveStorage variant/preview → ImageMagick arg injection + Ruby `send()`/`eval` reach

- Endpoint/param: ActiveStorage variant/preview processing; params `params[:new_size]`, `params[:t]`, `params[:v]`.
- Payload (verbatim): `https://example.com/controller?t=eval&v=system("touch /tmp/hacked")`
- Root cause: User-supplied values to `variant()`/`preview()` are forwarded unvalidated into ImageMagick CLI arguments and into Ruby `send()` (method dispatch), with no whitelist of allowed operations/transformations. Two primitive results: (a) ImageMagick argument injection (`-set comment`, `-write /tmp/file.erb`, etc.) writes arbitrary files anywhere on the system — overwriting an ERB template yields RCE when rendered; (b) method-name injection reaches `eval`/`system` directly.
- Chain as recorded:
  1. Pass user input to `ActiveStorage.variant()/preview()`.
  2. Array-inject ImageMagick CLI arguments (e.g., `-set comment`, `-write /tmp/file.erb`) to write an arbitrary file.
  3. (Overwrite executable templates / reach `eval` via `send()`.)
- Impact: Code execution proven with `system('touch /tmp/hacked')` on a Rails deployment; arbitrary file write anywhere as a stepping stone.
- Exemplar: id=1154034 (Ruby on Rails program).

### 7. Client-side injection into generated code (escape failure in a browser extension)

- Endpoint/param: PortSwigger "Copy as Node Request" Burp extension — client-side; param: a cookie value that gets embedded in generated Node.js source.
- Payload (verbatim): `test='/require('child_process').exec('calc.exe')//`
- Root cause: The extension's `escapeQuotes` escaped double quotes but not single quotes, and the generated Node.js code wrapped the cookie in single quotes. A single quote in the cookie value closes the string; the remainder (`require('child_process').exec(...)`) becomes live JavaScript, and `//` comments out the trailing syntax.
- Impact: A victim copying and running the generated snippet executes attacker JavaScript locally — calc.exe popped. RCE with user interaction, still accepted/paid.
- Exemplar: id=1167530 (PortSwigger Web Security).

### 8. Hex-decoded header values executed via `vm.runInThisContext` (Node test harness)

- Endpoint/param: `getcookies` test harness (express-cookies Node.js module); attacker-supplied HTTP headers.
- Payload (verbatim, two headers):
  `X-Hacker: g0000h636465i`
  `X-Hacker: gfaffh636465i`
  (`h636465` is hex for `code` — the harness parses a `h<hex>i` marker, decodes the hex, and executes the decoded value.)
- Root cause: The harness decodes attacker-supplied hex embedded in HTTP headers into a buffer and passes it to `vm.runInThisContext`, executing arbitrary JavaScript server-side.
- Impact: Remote code execution on the target server; demonstrated with curl against express-cookies.
- Exemplar: id=346516 (Node.js third-party modules).

### 9. Elasticsearch sort parameter → arbitrary Painless script execution

- Endpoint/param: `POST /graphql`, query `Query.search`, argument `sort_query` (a string).
- Payload (verbatim):
  `[{"_script":{"type":"number","script":{"source":"doc[\"_seq_no\"].value","lang":"painless"},"order":"asc"}}]`
- Root cause: The GraphQL `sort_query` string argument is passed verbatim as the raw Elasticsearch sort parameter — no schema validation, no allowlist of sort fields. Elasticsearch `script` sort compiles and runs arbitrary Painless per document.
- Impact: Confirmed per-document Painless script execution on HackerOne's production Elasticsearch cluster from a *reporter-level* account. Proof technique: a script reading each document's `_seq_no` was used as a sort key; comparing result ordering against a constant key showed the script actually influenced ordering (zero overlap), proving code execution without destructive payloads.
- Exemplar: id=3694007 (HackerOne).

### 10. PHP injection into compiled delivery limitations (unexpected component param)

- Endpoint/param: Revive Adserver delivery-limitation save; param `component`.
- Payload: not stated.
- Root cause: Missing validation when saving delivery limitations lets a *low-privileged* user add an unexpected `component` parameter, injecting malicious PHP into the `compiledlimitations` field — code that is later executed during banner delivery (a store-then-execute pattern, like pattern 4).
- Impact: Injected PHP executed during banner delivery; classified Code Injection, CVSS 8.8.
- Exemplar: id=3744200 (Revive Adserver).

### 11. OS command injection via CLI tool arguments (two Node.js module variants)

- Endpoint/param: CLI/library arguments formatted directly into shell command strings.
  - meta-git: the `repository` argument, `metaGitUpdate.js`.
  - git-promise: the git command argument, `index.js`.
- Payloads (verbatim):
  - `meta-git clone 'sss||touch HACKED'`
  - `git("init;touch HACKED")`
- Root cause: Both modules interpolate user input directly into a shell command string and execute it without validation or sanitization. `||` and `;` shell metacharacters escape the intended command.
- Impact: Arbitrary command execution on the victim's machine, demonstrated by creating a `HACKED` file in the target directory.
- Exemplars: id=728040 (meta-git), id=728047 (git-promise) — both Node.js third-party modules.

## Bypass / chain notes

- **Privilege-gate bypass inside OGNL (S2-045):** the payload's conditional `(#_memberAccess?(#_memberAccess=#dm):(...ognlUtil.getExcludedPackageN...))` exists specifically to defeat Struts's `SecurityMemberAccess` sandbox — newer Struts builds block direct `_memberAccess` assignment, so the fallback path resets excluded packages via `OgnlUtil`. Mirror this two-branch structure when the target's Struts version is unknown.
- **Escape-to-scope chaining in `eval()` (Invision):** the payload is structured to survive surrounding code: `;}}` closes the enclosing statement and braces, `phpinfo();die;` executes and halts, `/*` neutralizes trailing template code. Any `eval()`/template-compile sink needs this kind of syntactic scaffolding.
- **Two-hop chains to RCE:** two records show file-write-then-execute rather than direct eval:
  - Arbitrary export write → `.aspx` webshell → command execution via a guessable query param (id=1072832).
  - ImageMagick argument injection (`-write /tmp/file.erb`) → overwrite a template that gets rendered → RCE, plus a parallel direct route via method-name injection into `send()` (id=1154034).
- **Store-then-execute:** two records involve writing PHP into a field that the application later compiles/executes (ExpressionEngine Translate::save; Revive `compiledlimitations`). The dangerous moment is the *save* or *compile* step, not the HTTP request itself.
- **Client-side chain:** extension escape failure → attacker string in clipboard code → victim executes locally (id=1167530). The injection lives in code the *victim* runs, not the server.
- **Escalating a low-privilege foothold:** the HackerOne Elasticsearch bug proved script execution from a reporter-level account; the Revive bug required only a low-privileged user. Code injection reachable from low-priv or untrusted roles is the strongest severity case.

## Gotchas / what NOT to do

- **Prove execution non-destructively.** id=3694007 proved Painless execution by comparing sort order against a constant key (script reads `_seq_no`); id=1070532 printed `31337*31337`. Arithmetic and read-only markers are accepted; destructive commands are not needed and not appreciated — especially on DoD/production targets.
- **Payload not stated ≠ payload unavailable** — two records (id=1093444, id=3744200) confirmed RCE with no verbatim payload recorded; the injection point and mechanism were still sufficient for triage. Document the sink even if you redact the payload.
- **Check auth/permission preconditions.** The Invision bug required sidebar-management permissions; Revive required a low-privilege account. A "RCE" that needs admin isn't automatically invalid, but the writeup must state the requirement.
- **Version matters for Struts:** S2-045 payloads need the OGNL sandbox-reset scaffolding; a bare OGNL expression against a patched build fails. The same applies to CVE-2016-2098 Rails — unpatched versions only.
- **Don't confuse command injection with code injection in your report** — the two CLI bugs are shell metacharacter injection (`||`, `;`), while the Elasticsearch one is script-language injection (Painless). Classify per the actual sink; it affects fix verification.
- **Client-side RCE still counts** (id=1167530) — don't dismiss extension/tooling bugs that generate code the user executes; note the user-interaction requirement explicitly.
- **Node third-party modules:** the vulnerable code is the *library*, not a web endpoint — several records here have no HTTP endpoint at all (id=728040, 728047, and partially 346516). Demonstrate with a minimal reproduction (`touch HACKED`) rather than against production.

## Real-world impact examples

- **U.S. DoD military server (id=1072832):** ASPX webshell written via report-export filename control; commands executed server-side (`?68c2c8b1fc47766eaf43027a8eaca121=whoami`).
- **MTN Group (id=1070532):** S2-045 OGNL injection through `Content-Type` on `/pwsc/login.do`; evaluation output reflected in the response.
- **HackerOne production Elasticsearch (id=3694007):** arbitrary Painless scripts compiled and executed per document from a reporter-level account, proven via sort-order differential.
- **Revive Adserver (id=3744200):** low-privileged user's injected PHP executed on every banner delivery — persistent code execution, CVSS 8.8.
- **Victim machines via npm-style tooling (id=728040, id=728047):** `meta-git clone 'sss||touch HACKED'` and `git("init;touch HACKED")` created attacker files on anyone running the CLI/library with attacker-controlled arguments.