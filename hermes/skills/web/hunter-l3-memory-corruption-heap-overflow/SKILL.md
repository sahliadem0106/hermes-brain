---
name: hunter-l3-memory-corruption-heap-overflow
description: "Use when hunting Memory Corruption (Heap Overflow) on a target. Loads the L3 technique sheet: This class covers heap-based buffer overflows, over-reads, and related memory-corruption bugs triggered via crafted inputs to a target application or one of its library dependencies."
domain: cybersecurity
subdomain: web
tags:
- web
- memory-corruption-heap-overflow
- hunting
- l3
version: '1.0'
---

# Memory Corruption (Heap Overflow) — Technique Sheet

## Overview
This class covers heap-based buffer overflows, over-reads, and related memory-corruption bugs triggered via crafted inputs to a target application or one of its library dependencies. In bug-bounty practice it pays almost exclusively through the "vulnerable open-source dependency" route (e.g., PHP core functions, nginx modules) submitted to umbrella programs like the Internet Bug Bounty, where a single library bug pays out across every host running the affected code. Proven impact ranges from information leak and DoS (SIGSEGV, memory exhaustion) to potential arbitrary code execution — DoS with a crash trace is typically the minimum bar to a valid report.

## Distinct sub-patterns

### 1. Signed integer overflow in user-controlled dimensional arithmetic (PHP `imagecrop()` / gdImageCrop)
- Endpoint shape / param: Not an HTTP endpoint — a PHP-language-level bug reachable via any app exposing GD image cropping to user input. The attacker controls `x`, `y`, `width`, `height` passed to `imagecrop()`. Direct template:
  ```php
  $img = imagecreatetruecolor(10, 10);
  $img = imagecrop($img, array("x" => 0x7fffff00, "y" => 0, "width" => 10, "height" => 10));
  ```
- Payload that actually fired (verbatim):
  ```php
  <?
  $img = imagecreatetruecolor(10, 10);
  $img = imagecrop($img, array("x" => 0x7fffff00, "y" => 0, "width" => 10, "height" => 10));
  ```
  The key value is `0x7fffff00` for the `x` dimension — chosen to overflow signed 32-bit arithmetic when the crop region is computed. Note the record also describes a secondary type-confusion: passing a string/array for the `'x'` dimension.
- Root-cause pattern: `imagecrop()`/`gdImageCrop()` performs unchecked signed arithmetic on user-supplied crop dimensions (`x/y/width/height`), so a near-INT_MAX `x` makes computed offsets wrap negative, producing an integer overflow that manifests as a heap buffer over-read and a heap overflow (oversized `memcpy`).
- Impact proven: All four POCs crashed PHP on 32-bit systems — segfault from invalid reads and heap overflow from oversized memcpy; the string/array type confusion on `'x'` also leaks pointers (information disclosure).
- Exemplar report: id=1356 (Internet Bug Bounty, [ajaysenr]).

### 2. Heap overflow in a deployed server module via crafted network request (nginx SPDY module)
- Endpoint shape / param: A live service URL — `https://grtp.co/` — running nginx 1.4.6 with `ngx_http_spdy_module` enabled. No specific HTTP parameter; the trigger is a specially crafted SPDY request to the server.
- Payload: not stated in the record (SPDY heap-overflow trigger request not recorded here).
- Root-cause pattern: Versioned-dependency identification — the server disclosed (or the reporter fingerprinted) nginx 1.4.6 with the SPDY module compiled in, which is vulnerable to a known heap-based buffer overflow triggered by a crafted request.
- Impact proven: Remote attacker can trigger a heap buffer overflow in a nginx worker process, potentially resulting in arbitrary code execution.
- Exemplar report: id=116352 (Gratipay, [ajaysenr]). This is the model for "find the vulnerable version in the wild and report it against the program running it."

### 3. Heap overflow in core string-encoding primitives (PHP `php_url_encode` / `php_raw_url_encode`)
- Endpoint shape / param: PHP internal functions `php_raw_url_encode` / `php_url_encode` — reachable wherever an application URL-encodes attacker-controlled data (an extremely wide attack surface, since these run on nearly every request involving `urlencode`/`rawurlencode`).
- Payload: not stated in the record (specific overflowing input string not recorded here).
- Root-cause pattern: Heap overflow in the encoding functions themselves (PHP bug 71750) — the encoder miscomputes output buffer sizing for certain inputs, overrunning the heap-allocated result buffer.
- Impact proven: Multiple heap overflows confirmed in `php_raw_url_encode`/`php_url_encode`; memory-corruption potential. No exploitation or data access demonstrated — i.e., confirmed crash/corruption without full RCE is still a valid, paid report.
- Exemplar report: id=124737 (Internet Bug Bounty, [ajaysenr]).

### 4. Invalid match offsets from regex engine metacharacter combinations (PHP PCRE wrappers)
- Endpoint shape / param: PHP PCRE functions `preg_match`, `preg_replace`, `preg_split` — the "parameter" is the regex pattern itself, supplied wherever an app lets user input shape a regex or the pattern's subject.
- Payload that actually fired (verbatim):
  ```
  /(?=xyz\K)/
  ```
  The combination is a zero-width look-ahead (`(?=xyz)`) chained with `\K` (reset match start). This is a small, precise pattern — the exploit does not need huge input.
- Root-cause pattern: `pcre_exec()` can return offsets where `start > end` for patterns like `(?=xyz\K)`. PHP's PCRE wrappers fail to validate these offsets before using them, so downstream logic consumes a bogus (negative-wrapping) length — producing heap overflows and memory exhaustion.
- Impact proven: Triggered a SIGSEGV in PHP 5.6.12 via `preg_match` — a runaway `memcpy` with length `18446744073709551613` (i.e., `(size_t)-3`, a classic negative-length-to-huge-unsigned wrap) — plus memory exhaustion via `preg_split`. Heap overflow / DoS, with possible (non-trivial) arbitrary code execution.
- Exemplar report: id=141839 (Internet Bug Bounty, [ajaysenr]).

## Bypass / chain notes
- No multi-step chains appear in the records — all four are single-trigger bugs. The "chain" in this class is instead the deployment chain: a bug in PHP core or an nginx module (ids 1356, 124737, 141839, 116352) is reported to the Internet Bug Bounty / the operator running it, and the same root cause pays across every affected deployment.
- Conversion tricks seen within single bugs: (a) negative or wrapped offsets becoming huge unsigned lengths — `start > end` from `pcre_exec` becoming `memcpy` length `18446744073709551613` (id=141839); (b) type confusion as an information-leak side channel — passing a string/array where an integer dimension is expected in `imagecrop()` (id=1356). These are the class's standard escalation levers from "crash" toward "leak" and "execute."
- 32-bit targets are the easiest crash surface: the `imagecrop` POCs specifically used `0x7fffff00` because 32-bit signed overflow makes the arithmetic wrap immediately. On 64-bit builds the same inputs may not crash — scope your POC to the vulnerable architecture.

## Gotchas / what NOT to do
- Don't inflate impact beyond what you demonstrated. Id=124737 was accepted with "no exploitation or data access demonstrated" — a confirmed heap overflow + crash is a valid report; claiming RCE you can't show is not.
- Don't confuse "possible arbitrary code execution" in your root-cause analysis with proven impact — the records carefully distinguish "potential RCE" (116352, 141839) from demonstrated crash/leak. State the demonstrated artifact (SIGSEGV trace, memcpy length, crash on all POCs) and label the rest as potential.
- Don't test live third-party services with heap-overflow payloads. Id=116352 works because the bug is in a known version (nginx 1.4.6 + SPDY) — identify version first, and coordinate with the program before sending anything that could corrupt a worker process.
- Don't forget version/OS scoping in your writeup: id=141839 specified PHP 5.6.12; id=1356 specified 32-bit systems. A POC that crashes your local build of the vulnerable version is the deliverable — not a vague "PHP has a bug."
- Don't assume a single POC is enough — id=1356 carried four POCs covering distinct manifestations (invalid reads, oversized memcpy, type-confusion leak). Multiple manifestations of one root cause strengthen the severity assessment.
- For regex-offset bugs, use minimal deterministic patterns (`/(?=xyz\K)/`) rather than complex pathological regexes — the crash here comes from the offset invariant violation, not resource exhaustion, and a minimal repro is far easier to triage.

## Real-world impact examples
- Segfault + heap overflow in PHP on 32-bit systems from a two-line `imagecrop()` POC; oversized `memcpy` from a single `x => 0x7fffff00` crop dimension, plus pointer leak via dimension type confusion (id=1356, Internet Bug Bounty).
- Heap buffer overflow in a production nginx worker at `https://grtp.co/` (nginx 1.4.6, SPDY module) with potential arbitrary code execution — a remote, network-triggerable memory-corruption primitive against a live payment-related service (id=116352, Gratipay).
- Confirmed multiple heap overflows in PHP's universal `php_url_encode`/`php_raw_url_encode` primitives (PHP bug 71750) — memory corruption reachable from ordinary attacker-controlled URL data across the PHP ecosystem (id=124737, Internet Bug Bounty).
- SIGSEGV in PHP 5.6.12 from the four-character-meaningful regex `/(?=xyz\K)/`: runaway `memcpy` of length 18446744073709551613 via `preg_match`, and memory exhaustion via `preg_split` — demonstrating both heap overflow and DoS from one root cause, with noted non-trivial RCE potential (id=141839, Internet Bug Bounty).