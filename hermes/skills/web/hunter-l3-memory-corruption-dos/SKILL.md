---
name: hunter-l3-memory-corruption-dos
description: "Use when hunting Memory Corruption (DoS) on a target. Loads the L3 technique sheet: This class covers crashes caused by memory-safety defects in C-level interpreter/library code — integer/length-check misses, invalid pointer dereferences, and heap corruption — reachable either direct"
domain: cybersecurity
subdomain: web
tags:
- web
- memory-corruption-dos
- hunting
- l3
version: '1.0'
---

# Memory Corruption (DoS) — Technique Sheet

## Overview
This class covers crashes caused by memory-safety defects in C-level interpreter/library code — integer/length-check misses, invalid pointer dereferences, and heap corruption — reachable either directly through language builtins (PHP's compress/convert/string functions) or through short snippet inputs to sandboxed scripting engines (mruby via Shopify Scripts). It pays when the target runs attacker-supplied input through the vulnerable code path server-side: a single request or script that triggers SIGSEGV/SIGABRT takes down the worker process, which qualifies as DoS in programs like the Internet Bug Bounty and Shopify Scripts. Most records here are single-function crashes with no chaining required — the entire value is in knowing which builtin surface and which malformed input shape reaches the faulty C code.

## Distinct sub-patterns

### Sub-pattern 1: PHP compression builtin crashes (gzcompress / bzcompress family)
- Endpoint shape: any PHP context where attacker input reaches compression builtins, e.g. `gzcompress($input)`, `bzcompress($input)` — typically via app code that compresses user data, or directly in PHP-sourcing targets (php.net bug bounty via Internet Bug Bounty).
- Payload: not stated in records (crash reproduced by invoking the functions; see PHP bugs 73357 and 73356).
- Root cause: memory-safety bug inside the compress functions themselves — `gzcompress` (bug #73357) and `bzcompress` (bug #73356) crash on crafted input.
- Impact: process crash (DoS) reproduced in the named functions; `gzcompress` crash also affected three other compress functions per bug 73357.
- Exemplars: 180109 (gzcompress + 3 other compress functions), 180111 (bzcompress).

### Sub-pattern 2: PHP string function crash — implode()
- Endpoint shape: `implode($glue, $array)` with attacker-controlled array contents/structure.
- Payload: not stated (PHP bug 73364).
- Root cause: memory defect in `implode()`'s C implementation (bug #73364) triggered by crafted arguments.
- Impact: process crash (DoS) reproduced in `implode()`.
- Exemplar: 180110.

### Sub-pattern 3: PHP iconv() missing string length check
- Endpoint shape: `iconv($in_charset, $out_charset, $str)` with attacker-controlled string or charset arguments — common in encoding-conversion code paths.
- Payload: not stated (PHP bug 73368).
- Root cause: explicit missing string length check in `iconv()` — an input length is not validated before use, allowing out-of-bounds access (bug #73368). This is the clearest length-check-miss pattern in the set.
- Impact: process crash (DoS) reproduced via `iconv()`.
- Exemplar: 180112.

### Sub-pattern 4: PHP ICU/intl crash — get_icu_value_internal
- Endpoint shape: intl extension functions that parse locale strings internally (e.g. `locale_*` functions dispatching into `get_icu_value_internal`).
- Payload: not stated (PHP bug 73378).
- Root cause: crash inside `get_icu_value_internal`, the shared internal locale-parsing helper (bug #73378).
- Impact: process crash (DoS) reproduced.
- Exemplar: 180113.

### Sub-pattern 5: PHP locale_get_keywords overlong keyword value
- Endpoint shape: `locale_get_keywords($locale)` (or `Locale::getKeywords()`) where the locale string is fully attacker-controlled, e.g. a locale of the form `language_KEYWORD=VALUE` with an oversized VALUE.
- Parameter: the keyword value inside the locale string.
- Payload: not stated; the triggering input shape is "the keyword value in the locale string is too long" (bug #73376).
- Root cause: `locale_get_keywords()` fails to bound the length of the keyword value it parses out of the locale string, causing a memory-safety fault (bug #73376; a second distinct crash in the same function is bug #73371).
- Impact: process crash (DoS) reproduced with an overlong locale keyword value.
- Exemplars: 180115 (overlong keyword value), 180116 (second, distinct crash in the same function).

### Sub-pattern 6: PHP zend_strtod invalid memory access
- Endpoint shape: any code path converting an attacker-supplied numeric string to a double — `zend_strtod()` underlies float casts, `floatval()`, numeric comparisons, and JSON/array coercion of decimal strings.
- Payload: not stated (PHP bug 73382).
- Root cause: invalid memory access inside `zend_strtod()` on a crafted numeric-string input (bug #73382).
- Impact: process crash / invalid memory access reproduced.
- Exemplar: 180588.

### Sub-pattern 7: PHP simplestring_addn crash
- Endpoint shape: XML/soap extension paths that buffer-append via `simplestring_addn()` (the simplestring helper used by the xmlrpc/soap C code).
- Payload: not stated (PHP bug 73349).
- Root cause: memory defect in `simplestring_addn`'s bounded-append logic (bug #73349).
- Impact: process crash (DoS) reproduced.
- Exemplar: 180589.

### Sub-pattern 8: mruby heap corruption via array-join / vformat garbage script
- Endpoint shape: mruby interpreter (mruby/mirb binaries or the Shopify Scripts sandbox) — attacker submits an arbitrary script.
- Payload (verbatim):
```
a=b=c=[]
a=[]..t=c
t %W=0 0 0 0 0 0 0
0 0 0 0 0 0 0 0 0
0 0
0 0 0 0 0 0
0 0
0 0 0 0 0
0
0
0
0 0 0 0 0
0 0 0 0 0 0 0 0 0 0 0
0
0 0=
```
- Root cause: the array join / vformat path drives glibc malloc into a corrupted heap state — abort with "corrupted double-linked list (not small)" raised inside `mrb_default_allocf`. The crash manifests in the allocator, not at a specific VM opcode.
- Impact: reproduced SIGABRT with `corrupted double-linked list (not small)` in mruby via `mrb_default_allocf`; crash/DoS of the sandboxed interpreter.
- Exemplar: 193773.

### Sub-pattern 9: mruby `super()` in instance_eval on a non-class receiver
- Endpoint shape: mruby script input.
- Payload (verbatim): `0.instance_eval{super()}`
- Root cause: calling `super()` at the top level via `instance_eval` makes `mrb_vm_exec` (vm.c:1296) dereference an invalid `target_class` pointer — the method environment has no valid class context for super lookup.
- Impact: SIGSEGV segmentation fault and core dump, crashing the sandboxed mruby interpreter.
- Exemplar: 196380. Note the payload is a single short line — the highest signal-to-effort crash in the set.

### Sub-pattern 10: mruby malformed multiple-assignment with inline method definition
- Endpoint shape: mruby script input.
- Payload (verbatim):
```
a,a,a,a=0,def e
end
a[]
```
- Root cause: a malformed multiple assignment (`a,a,a,a=`) whose RHS includes an inline `def e ... end` corrupts VM stack handling in `mrb_vm_exec` (vm.c:1272), which then dereferences an invalid `m->env->stack` pointer.
- Impact: SIGSEGV segmentation fault and core dump in the mruby sandbox and in the `mirb`/`mruby` binaries.
- Exemplar: 196386.

### Sub-pattern 11: mruby malformed loop over method symbols driving PC into invalid memory
- Endpoint shape: mruby script input.
- Payload (verbatim):
```
for i in methods Kernel.initialize.public_methods print
print %i[0 0 0 0]end
```
- Root cause: executing a malformed loop over method symbols combined with `print` statements drives the VM program counter into invalid memory, causing SIGSEGV in `mrb_vm_exec`.
- Impact: SIGSEGV segmentation fault, crashing the mruby interpreter.
- Exemplar: 196498.

## Bypass / chain notes
- No chains were used in any of the 13 records — all crashes fire from a single function call (PHP) or a single script snippet (mruby). Chain construction was not needed and no filter bypasses appear in the records.
- Two records hit the SAME function with distinct bugs: `locale_get_keywords` crashed via two separate defects (bugs 73376 and 73371). Lesson: once you find one memory bug in a parsing-heavy function, fuzz variations of the same input parameter (here: the locale keyword value) before moving on — a second crash in the same code path is likely.
- The gzcompress bug (73357) propagated to three other compress functions, so a single crash in one compression builtin should prompt testing the whole builtin family (`gzcompress`, `bzcompress`, and siblings).
- Reachability matters more than exploit complexity here: for PHP-sourcing targets the crash must be reachable from web input (encoding conversion via iconv, numeric parsing via zend_strtod, compression of user data, locale parsing); for sandbox targets (Shopify Scripts) any submitted script reaching the crash suffices — the sandbox itself crashing IS the impact.

## Gotchas / what NOT to do
- Do not report a segfault without a reproduction artifact. Every mruby record here included the exact crash signal (SIGSEGV vs SIGABRT), the faulting function, and where applicable the source line (`vm.c:1296`, `vm.c:1272`) and malloc diagnostic string (`corrupted double-linked list (not small)`). A report saying "it crashed somewhere" is not this class.
- Do not assume all crashes are equal impact: this set is DoS-only (process crash, core dump). None of the records demonstrate code execution — do not overstate impact beyond crash/DoS unless you prove more.
- Do not expect a payload for every PHP case: 9 of the 13 records do not state the concrete triggering input. If you replicate this class, capture and submit the actual crashing input — that gap is the biggest weakness in these records.
- For mruby, the crashing snippets are syntactically malformed on purpose (`a=[]..t=c`, `a,a,a,a=0,def e / end`, an unterminated-looking `for` loop). Don't "fix up" the syntax to look valid — the parser/VM mishandling of the malformed structure is often the trigger.
- Verify the crash occurs in the deployed/sandboxed context (the records confirm crashes in the Shopify Scripts sandbox AND in `mirb`/`mruby` binaries), not only in a locally built debug binary.
- Run crashes multiple times; ASAN or core-dump-backed confirmation (signal + faulting frame) is what makes an Internet Bug Bounty-class report credible.

## Real-world impact examples
- id=196380: one-line payload `0.instance_eval{super()}` produced SIGSEGV and a core dump, killing the sandboxed mruby interpreter — a full sandbox DoS from a single trivial script.
- id=193773: garbage-structured array-join script aborted the process with glibc's `corrupted double-linked list (not small)` inside `mrb_default_allocf` — heap corruption, not just a null deref.
- id=196386: the multiple-assignment-plus-def snippet crashed both the production sandbox and the standalone `mirb`/`mruby` binaries with SIGSEGV at `vm.c:1272` (invalid `m->env->stack` deref), with core dump.
- id=180115: an overlong keyword value inside an attacker-supplied locale string passed to `locale_get_keywords()` crashed the PHP process — showing that a purely string-parsing entry point (a locale, not a file or binary blob) is enough to reach memory corruption.
- id=180588: invalid memory access in `zend_strtod()` — the numeric-string parser used pervasively across PHP — meaning many ordinary code paths that cast user input to float were potential triggers.