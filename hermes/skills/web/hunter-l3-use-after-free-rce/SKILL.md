---
name: hunter-l3-use-after-free-rce
description: "Use when hunting Use-After-Free (RCE) on a target. Loads the L3 technique sheet: Use-after-free bugs occur when a program frees memory (a PHP ZVAL, a C-level `FILE*` stream, or a heap object) while other code paths still hold and use pointers to it."
domain: cybersecurity
subdomain: web
tags:
- web
- use-after-free-rce
- hunting
- l3
version: '1.0'
---

# Use-After-Free (RCE) — Technique Sheet

## Overview
Use-after-free bugs occur when a program frees memory (a PHP ZVAL, a C-level `FILE*` stream, or a heap object) while other code paths still hold and use pointers to it. In bug bounty practice, this class appears almost exclusively in PHP engine internals (serialized data handling, `__wakeup()` property teardown) and in C-extension boundary conditions (libcurl callbacks freeing streams), and it pays extremely well — all exemplar records come from the Internet Bug Bounty (the program that pays for PHP core and related library issues). Every record here escalated to arbitrary code execution: this is not a "memory leak" or "warning" class; the impact ceiling is full RCE.

## Distinct sub-patterns

### Sub-pattern 1: `__wakeup()` frees a property, `unserialize()` still holds R:/r: references to it (CVE-2015-2787)
- **Endpoint shape / parameter:** No HTTP endpoint in the classic sense — the injection point is any application surface that passes attacker-controlled data into `unserialize()`. The parameter is the serialized string itself (e.g. a cookie, POST body, signed session blob, or any `unserialize($_GET[...])` sink). If you can find an app-level unserialize sink, engine-level UAF primitives in the core become reachable.
- **Payload that actually fired (verbatim):**
  ```
  unserialize('a:2:{i:0;O:9:"evilClass":1:{s:3:"var";a:1:{i:0;i:1;}}i:1;R:4;}')
  ```
  Structure decoded: an array of two elements; element 0 is an object of class `evilClass` with one property `var` (an array containing int 1); element 1 is an `R:4` reference — a back-reference to the ZVAL slot inside the object's property table. Defining `evilClass::__wakeup()` (the PoC class in the exploit) frees/releases that property during unserialization, at which point the `R:4` reference in element 1 points at freed memory the attacker now controls the contents of.
- **Root-cause pattern:** PHP's `unserialize()` processes `__wakeup()` on an object while still tracking `R:`/`r:` references into that object's property table. When `__wakeup()` (or property teardown) frees the ZVAL, the pending reference resolution uses the freed ZVAL. In the PoC, the attacker defines the `__wakeup()` handler, meaning the primitive is: "any way to get an object's `__wakeup()` to free a property while a back-reference to that property is still pending."
- **Impact that was proven:** Arbitrary PHP code execution — the PoC ran `system('sh')` and obtained a shell.
- **Exemplar report IDs:** 73235 (ajaysenr, Internet Bug Bounty).

### Sub-pattern 2: DateInterval property-type conversion frees the ZVAL during `__wakeup()` (same CVE class, no attacker-defined class needed)
- **Endpoint shape / parameter:** Same surface as Sub-pattern 1 — any `unserialize()` sink with attacker-controlled serialized data — but crucially this variant does NOT require a class with a malicious `__wakeup()` defined in the target's code. `DateInterval` is a built-in PHP class, so the primitive works on ANY unserialize sink.
- **Payload that actually fired (verbatim, truncated in record):**
  ```
  unserialize('a:3:{i:0;O:12:"DateInterval":1:{s:1:"y";a:2:{i:0;i:1;i:1;i:2;}}i:1;s:...;i:2;a:1:{i:0;R:5;}}')
  ```
  Structure: a three-element array; element 0 is a `DateInterval` object whose `y` (years) property is set to an ARRAY (not the expected integer); element 1 is a string (truncated as `s:...` in the record); element 2 is an array containing `R:5` — a back-reference into the `DateInterval`'s property ZVAL.
- **Root-cause pattern:** `DateInterval::__wakeup()` converts its `y`/`m`/`d`/... properties from the deserialized types into internal typed fields. When a property holds an array (unexpected type), the conversion path frees the array ZVAL — but `unserialize()`'s reference table (`R:5` pointing at the slot occupied by that array) still resolves against the freed ZVAL afterwards. The reference-resolution step reuses stale memory. This is the engine's type-coercion destructor racing the reference table: the freed memory is attacker-shaped because it was a deserialized PHP array (heap layout of an array of ints under attacker control).
- **Impact that was proven:** Arbitrary code execution — PoC ran `system('sh')` and got a shell.
- **Exemplar report IDs:** 73244 (ajaysenr, Internet Bug Bounty). Technique carries the same CVE (2015-2787) family as 73235.

### Sub-pattern 3: libcurl callback closes the stream after handler verification → freed `FILE*` reused by later callbacks (attacker-controlled vtable)
- **Endpoint shape / parameter:** Application code that uses PHP/libcurl options wiring a FILE stream into the handle and user callbacks:
  - `CURLOPT_FILE` (write target stream)
  - `CURLOPT_INFILE` (read source stream)
  - `CURLOPT_WRITEHEADER` (header write stream)
  combined with `CURLOPT_HEADERFUNCTION` / write callbacks that receive the stream as an argument. Trigger shape: the server response headers drive the callback, so the attacker controls *when* and *with what* the callback fires.
- **Payload that actually fired (described verbatim from record; not a serialized string):** the header callback (`hdr_callback`) closes `$f_file` (e.g. `fclose($f_file)` / freeing the underlying FILE structure) and then reallocates memory of the same FILE-structure size using `CURLOPT_COOKIE` (attacker-controlled string contents), so the freed FILE* memory is re-occupied with attacker-chosen bytes. Payload not stated as a single literal string; the record describes the mechanism.
- **Root-cause pattern:** Curl performs verification on the stream when options are set, but callbacks can close/free the stream later, during transfer processing. Subsequent callbacks (write/read/header) still receive and use the dangling `FILE*`. Because FILE structures in glibc contain function-pointer tables (vtable), an attacker who controls the reallocated bytes at that address controls the vtable → control-flow hijack. Two prerequisites chain together: (1) a callback the attacker can trigger with response content, and (2) an option whose value lets the attacker place bytes of the right size (COOKIE string).
- **Impact that was proven:** Arbitrary code execution on Linux via control of the freed FILE structure's vtable.
- **Exemplar report IDs:** 73246 (ajaysenr, Internet Bug Bounty).

## Bypass / chain notes
- No multi-step chains appear in the records (all three carry `chain: (none)`); each bug is a standalone RCE primitive. The "chain" in this class is *internal to the primitive*: e.g., in Sub-pattern 3, response-controlled callback → `fclose` → same-size reallocation via `CURLOPT_COOKIE` → vtable overwrite is itself a 3-step chain worth studying.
- Engine-level UAF (Sub-patterns 1–2) chains naturally with any app-level `unserialize()` sink. Hunt order: find the sink first (cookies, session handlers, signed blobs, `unserialize($_REQUEST[...])`), then apply the engine payload. The DateInterval variant (73244) is the more portable one because it needs no attacker-definable class on the target.
- Same-size reallocation is the general bypass for "freed but still used": in 73246 the attacker forces a heap chunk of exactly FILE-structure size to be allocated with attacker bytes immediately after the free, so the dangling pointer lands on controlled data. Apply the same idea to any UAF: identify the freed object's size, find an attacker-influenced allocation of that size, fill it.

## Gotchas / what NOT to do
- Do not report mere memory-corruption symptoms (crashes, segfaults, ASAN noise) without demonstrating controllability — this class only pays at the level of proven arbitrary code execution; all three exemplars ended in `system('sh')` / a shell or vtable control.
- Do not assume the class is HTTP-only: two of three records have "N/A" endpoints. The entry point may be a serialized-data parameter on an existing sink or C-extension misuse; the report still needs a concrete trigger path from attacker input to the vulnerable function.
- Payload truncation happens (see the `s:...` in record 73244) — when you reconstruct such payloads, verify reference indices (`R:5`) against your exact array structure; back-reference numbers are position-dependent and shift with any change to element order or count.
- The `__wakeup()` UAF of Sub-pattern 1 depends on the attacker's PoC class definition (the class in the report is `evilClass` with property `var`) — for engine CVE submission you demonstrate with a self-defined class, but for a *target application* you need a real path where an existing class's `__wakeup()`/destructor frees a property; a bare `unserialize()` of your class name on a target will just instantiate nothing useful unless the class exists there.
- This is PHP-core/libcurl CVE territory (Internet Bug Bounty), not a per-company program bug — route such findings to the correct upstream program rather than mass-reporting to every app using `unserialize()`.

## Real-world impact examples
- id=73235: `unserialize('a:2:{...R:4;}')` with an `__wakeup()` that frees the referenced property → arbitrary PHP code execution, demonstrated by running `system('sh')` and obtaining a shell.
- id=73244: `unserialize` of a `DateInterval` with an array in the `y` property plus a stale `R:5` back-reference → arbitrary code execution, again proven with `system('sh')`.
- id=73246: libcurl `hdr_callback` closes `$f_file`, then a `CURLOPT_COOKIE`-sized reallocation re-occupies the freed FILE structure → arbitrary code execution on Linux by controlling the freed FILE structure's vtable.