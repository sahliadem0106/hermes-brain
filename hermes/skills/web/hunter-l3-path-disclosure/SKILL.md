---
name: hunter-l3-path-disclosure
description: "Use when hunting Path Disclosure on a target. Loads the L3 technique sheet: Path disclosure (full path disclosure, FPD) bugs leak the server-side absolute filesystem path of the webroot or a specific script — typically via unhandled PHP errors (type juggling, malformed input)"
domain: cybersecurity
subdomain: web
tags:
- web
- path-disclosure
- hunting
- l3
version: '1.0'
---

# Path Disclosure — Technique Sheet

## Overview

Path disclosure (full path disclosure, FPD) bugs leak the server-side absolute filesystem path of the webroot or a specific script — typically via unhandled PHP errors (type juggling, malformed input), reflected error messages, or direct access to scripts that expect to be included. On its own the impact is usually low-to-medium information disclosure, but it pays because the leaked path directly enables chaining: `load_file()` in SQL injection, LFI traversal base paths, and targeted file attacks. Four verified reports across Ian Dunn, Paragon Initiative Enterprises, Unikrn, and CS Money demonstrate four distinct trigger mechanisms.

## Distinct sub-patterns

### 1. Array-type juggling on a query-string parameter (PHP FPD classic)

- **Endpoint shape:** `GET /index.php` with an array-castable parameter — template: `GET /index.php?step[]=<junk>`
- **Payload that fired (verbatim):** `step[]=4'`
  - The essential trigger is `step[]` — passing an empty array. The trailing `'` is incidental; `step[]=` alone triggers the same class of error.
- **Root-cause pattern:** The application passes the `step` parameter into code that expects a scalar (e.g., a switch/comparison or string function). Passing an array instead produces a PHP warning/error ("Illegal offset type", "strpos() expects parameter 1 to be string, array given", etc.) whose message includes the absolute path of the file and line. Display_errors is enabled in production.
- **Impact proven:** Full path disclosure of the webroot/file location. Explicitly noted as chainable with `load_file()` SQLi — knowing the absolute path makes `SELECT load_file('/var/www/.../config.php')` practical.
- **Exemplar:** id=11729 (Ian Dunn)

### 2. Reflected special character into an error path (forgot-password / form reflection)

- **Endpoint shape:** `POST /forgot-password` with parameter `username` (applies generally to any form field that gets echoed back in an error or email-rendering context)
- **Payload that fired (verbatim):** `as"` — a short username string containing a double quote.
- **Root-cause pattern:** The double quote in the username breaks out of or malforms a string used in server-side processing (e.g., rendering into an error message, template, or log/email path handling), causing an error whose output includes the full server filesystem path. The attacker-controlled character is the error trigger; no authentication required.
- **Impact proven:** Full server path disclosed on the forgot-password page.
- **Exemplar:** id=228112 (Paragon Initiative Enterprises)

### 3. Direct access to plugin/module PHP scripts (include-guard scripts hit standalone)

- **Endpoint shape:** `GET https://crm.unikrn.com/plugins/*/*.php` — enumerate plugin directories and request each PHP script directly. Template: `GET /plugins/<plugin_name>/<script>.php` for every discoverable script under plugin paths.
- **Payload:** none needed — the request itself is the trigger.
- **Root-cause pattern:** Plugin scripts written to be included by a parent framework (with an access check or constant expectation) are directly reachable. When loaded standalone, a missing dependency, undefined constant, or failed check throws an error/warning whose output reveals internal paths. Defense-in-depth failure: no direct-access guard (`defined('ABSPATH') || exit` equivalent), and errors rendered to the client.
- **Impact proven:** Server information disclosure including the local folder location on the CRM host.
- **Exemplar:** id=503804 (Unikrn)

### 4. Crafted upload filename triggering a 500 error

- **Endpoint shape:** `POST` to a chat support file-upload endpoint; parameter is the uploaded `filename` (multipart filename field, not a normal body param).
- **Payload that fired (verbatim):** `/../../../../../.html`
- **Root-cause pattern:** The filename contains path-traversal metacharacters (`/`, `../`) and a dotfile segment. The server-side upload handler attempts filesystem operations with this filename (sanitize, move, or resolve), hits an unhandled exception, and the 500 error response leaks internal file paths. Note the payload is path-only — no extension trickery or oversized data needed; the traversal characters alone break the handler.
- **Impact proven:** The 500 response disclosed two internal file paths.
- **Exemplar:** id=979110 (CS Money)

## Bypass / chain notes

- **FPD → SQLi file read:** id=11729 explicitly frames the disclosure as a stepping stone: the absolute path makes `load_file()` usable in a chained SQL injection to read config/source files. Hunt for SQLi on the same host after any FPD.
- **FPD → traversal precision:** The CS Money payload shows the inverse direction — traversal input causing FPD. Either way, knowing the real base path (e.g., `/var/www/html/`) converts blind LFI/path-traversal attempts from guesswork into single-shot payloads.
- **Array-cast variant:** When `?param=value` gives nothing, try `?param[]=` (empty array) — the type mismatch is the trigger, not the value content (id=11729).
- **Error surfaces to check:** the HTTP response body of the erroring page (id=228112 — forgot-password page), direct script responses (id=503804), and 500 error responses on upload endpoints (id=979110). FPD often lives in pages hunters don't re-check after a malformed submit.

## Gotchas / what NOT to do

- **Don't discard FPD as "informational only" without checking chainability.** In id=11729 the path's value was precisely that it armed a `load_file()` chain — report the chain path, not just the leak.
- **Don't only fuzz GET parameters.** The reflection trigger here was a POSTed username (id=228112) and a multipart filename (id=979110) — cover every input surface including file metadata.
- **Don't assume a 500 is a dead end.** The CS Money 500 response body contained two internal paths; read the body before moving on.
- **Don't skip plugin/module directories** on CMS-style apps — scripts there are often written to be included, not requested directly (id=503804).
- **Payload must be preserved exactly where it matters:** in id=979110 the specific shape `/../../../../../.html` (leading slash + deep traversal + dotfile) was what tripped the handler — random junk filenames may not reproduce it.

## Real-world impact examples

- **Ian Dunn (id=11729):** `step[]=4'` on `/index.php` disclosed the full webroot path; report explicitly ties this to enabling `load_file()` in SQL injection for file reads.
- **Paragon Initiative Enterprises (id=228112):** submitting username `as"` to `/forgot-password` displayed the full server filesystem path on the response page — no auth, one request.
- **Unikrn (id=503804):** directly requesting `crm.unikrn.com/plugins/*/*.php` scripts leaked the local folder location on the production CRM host.
- **CS Money (id=979110):** a chat-support upload with filename `/../../../../../.html` returned a 500 whose response disclosed two internal file paths.