---
name: hunter-l3-full-path-disclosure
description: "Use when hunting Full Path Disclosure on a target. Loads the L3 technique sheet: Full Path Disclosure (FPD) is an information-leakage bug class where a web application reveals the server's absolute filesystem path — the webroot, framework directory structure, or the exact source f"
domain: cybersecurity
subdomain: web
tags:
- web
- full-path-disclosure
- hunting
- l3
version: '1.0'
---

# Full Path Disclosure — Technique Sheet

## Overview

Full Path Disclosure (FPD) is an information-leakage bug class where a web application reveals the server's absolute filesystem path — the webroot, framework directory structure, or the exact source file and line number handling the request. On its own it is typically a low-severity finding, but it pays when (a) the program accepts information disclosure as a valid report class (Paragonie, Localize, Unikrn all paid), (b) it chains into other bugs (LFI/RFI, SQLi, source exposure), or (c) the disclosed path itself leaks sensitive structure — e.g. a publicly served PHP source file, or a hostname that reveals hosting infrastructure (`lvps178-77-99-228.dedicated.hosteurope.de`). The dominant, most repeatable trigger in the verified records is **PHP type-juggling warnings**: appending `[]` to a string-typed form parameter so that functions like `trim()` receive an array, causing PHP to emit a warning that includes the full path, file, and line number.

## Distinct sub-patterns

### 1. Array-suffix (`[]`) on form parameters → PHP `trim()` warning path dump

This is the workhorse pattern — 4 of the 7 records (all Localize). Any POST form field that the backend passes to a string function (`trim()`, `str_replace()`, etc.) can be forced to raise a warning by submitting it as an array.

**Endpoint shape:** any `POST /pages/...`, `POST /import/{num}`, `POST /projects/{num}/languages/{num}` form endpoint with a known parameter name.

**Payloads that actually fired (verbatim):**

- `create_project[name][]=My+Android&create_project[editRepositoryID][]=72` (full request: `CSRFToken=TOKEN VALUE&create_project[visibility]=1&create_project[name][]=My+Android&create_project[defaultLanguage]=1&create_project[editRepositoryID][]=72` — note `visibility` and `defaultLanguage` left scalar; only the target field got `[]`)
- `addGroup[name][]=new+group`
- `import[overwrite][]=0`
- `updatePhrases[edits][yy4][0][]`

**Root cause:** the parameter is declared/used as a string in PHP code; submitting `field[]=value` makes PHP pass an array into `trim()`, which raises `trim() expects parameter 1 to be string, array given in /path/to/file.php on line N` — with `display_errors` on, the path goes straight into the response.

**Impact proven:** absolute paths leaked with file and line number:
- `/var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/classes/UI.php on line 1495` (id=8088)
- `/var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/classes/Phrase.php on line 213` (id=8090)
- `/var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/index.php on line 410` (id=8091)
- `/srv/data/web/vhosts/www.localize.im/htdocs/index.php on line 192` (id=9745)

Note the bonus intel in the path itself: `lvps178-77-99-228.dedicated.hosteurope.de` exposes the server's hostname/IP structure on Host Europe's dedicated hosting.

**Exemplars:** 8088, 8090, 8091, 9745 (all [ajaysenr], Localize).

**How to apply:** enumerate every form parameter (including hidden ones like tokens and overwrite flags) and fuzz each with an appended `[]` while the rest of the request stays valid. Multi-dimensional suffixes work too: `param[subkey][index][]` as in `updatePhrases[edits][yy4][0][]`. Keep the CSRF token intact — the goal is a *valid* request that fails only at the string-function call.

### 2. Invalid file import via URL input → PHP notice reflecting path

**Endpoint shape:** `POST /index.php` with an import/file-handling parameter that accepts a URL or file reference.

**Param:** `importFileXML`

**Payload (verbatim):** `http://www.swarthmore.edu/libraries.xml` — a remote XML that fails validation on import.

**Root cause:** importing an invalid XML through the file/URL input triggered an unhandled PHP notice; the error message reflected the raw filesystem path without sanitization.

**Impact proven:** full application path disclosed — `/var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/index.php on line 421`.

**Exemplar:** 8013 (Localize).

**How to apply:** anywhere an app imports/parses user-supplied files or remote URLs, feed it malformed-but-fetchable content (invalid XML, truncated uploads) and watch the error output. The payload doesn't need to be hostile — just *invalid enough to trip a notice*.

### 3. Contact/error form reflecting server path in its response

**Endpoint shape:** `POST /contact` (paragonie.com). No named parameter — the normal form submission itself.

**Payload:** none stated — the standard contact form submission sufficed.

**Root cause:** the contact form exposes the server's absolute filesystem path in its response/error output (e.g. an error page generated on failed submission).

**Impact proven:** submitting the contact form revealed the full server path, leaking internal filesystem layout.

**Exemplar:** 145260 (Paragon Initiative Enterprises).

**How to apply:** on form endpoints with server-side validation, submit incomplete/malformed data and inspect every response — including error pages, headers, and JSON bodies — for path strings.

### 4. Directly served PHP source file → script path + source exposure

**Endpoint shape:** direct GET of a PHP file under a web-accessible framework bundle directory: `GET /app/bundles/CampaignBundle/EventListener/LeadSubscriber.php` on `crm.unikrn.com` (a Mautic-style bundle layout).

**Payload:** none — plain GET.

**Root cause:** the PHP source file was served publicly without an `.htaccess` block (or equivalent webserver rule) preventing direct access to application/bundle directories.

**Impact proven:** exposed the server-side script path and source at `https://crm.unikrn.com/app/bundles/CampaignBundle/EventListener/LeadSubscriber.php`. Depending on server config, raw PHP may be served as text, and even when executed, the request confirms the webroot + bundle layout.

**Exemplar:** 591002 (Unikrn).

**How to apply:** when you know the framework (Mautic's `app/bundles/...`, Laravel's `app/Http/...`, Symfony's `src/...`), request well-known source files directly. Also check `/app/`, `/vendor/`, `/config/` directory listings and whether `.htaccess` protection is missing on non-Apache stacks (nginx often lacks the Apache-only protections).

## Bypass / chain notes

- **One app, four paths in:** the Localize records show that FPD is rarely a single-endpoint bug — if `trim()`-array warnings fire on one form, systematically replay the trick across every form in the app (`create_project`, `addGroup`, `import`, `updatePhrases` all fell). Filing a single instance leaves easy duplicates for others; enumerating them all makes the report comprehensive.
- **Path → infrastructure intel:** the leaked path `lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/` exposes hosting provider, server identity/IP-embedding, and non-standard webroot naming — useful for recon on other targets in the same program.
- **Line numbers → code mapping:** `classes/UI.php on line 1495` and `classes/Phrase.php on line 213` give exact code locations, valuable when chained with a subsequent source-disclosure or injection bug (cf. id=591002 where the source itself was reachable).
- **CSRF-protected forms are still in scope:** all array-suffix payloads kept `CSRFToken=TOKEN VALUE` in the request — the technique requires valid session/token state, not bypassing it.

## Gotchas / what NOT to do

- **Severity is low alone.** FPD is accepted by some programs (all three programs here paid/reported it) and rejected by many. Check the program's policy on informational/information-disclosure findings before investing time. Don't dress it up as RCE — the records prove disclosure only.
- **Don't send a hostile payload when a trivial one works.** All confirmed triggers here were benign: an `[]` suffix, a zero value (`import[overwrite][]=0`), a public XML URL. Aggressive payloads risk tripping WAFs and getting your account flagged.
- **Don't change unrelated fields.** In id=8088 the reporter kept `visibility`, `defaultLanguage`, and the token scalar and only targeted `name`/`editRepositoryID` — a clean differential proves the root cause to the triager.
- **Check both display modes.** Some endpoints dump the path in the HTML response; others only in error pages from malformed imports (id=8013 vs id=8088). Capture full responses, not just status codes.
- **Raw PHP GET isn't always source disclosure.** On id=591002 the exposure was path+source; on a correctly configured PHP host the same GET executes silently. Verify whether the response contains code or merely confirms the path, and report what you actually observed.
- **Don't stop at one parameter.** Fuzz every field on a vulnerable form — the records show per-parameter findings (`name[]`, `editRepositoryID[]`, `addGroup[name][]`, `import[overwrite][]`, nested `updatePhrases[edits][yy4][0][]`).

## Real-world impact examples

- **Localize (4 reports, ids 8088/8090/8091/9745):** array-suffix on five different form parameters disclosed four distinct absolute paths across two servers, including exact file/line pairs (`classes/UI.php:1495`, `classes/Phrase.php:213`, `index.php:410`, `index.php:192`) and the Host Europe dedicated-server hostname — a complete map of the app's on-disk layout.
- **Localize (id=8013):** a single invalid XML import from `http://www.swarthmore.edu/libraries.xml` dumped the webroot path `…/httpdocs_localize/index.php on line 421` with zero custom tooling.
- **Unikrn (id=591002):** a public CRM exposed its framework bundle source at `https://crm.unikrn.com/app/bundles/CampaignBundle/EventListener/LeadSubscriber.php`, revealing server-side script paths and code.
- **Paragon Initiative Enterprises (id=145260):** the simplest variant — the company's own contact form returned the server's full filesystem path on submission, accepted as a valid FPD report by a security-expert-run program.

**Verification checklist before reporting:** (1) response body contains an absolute path with file and ideally line number; (2) reproduces reliably (records show deterministic warnings, not flaky races); (3) screenshot/copy the verbatim path; (4) state clearly that impact is information disclosure / filesystem layout leakage — no inflation.