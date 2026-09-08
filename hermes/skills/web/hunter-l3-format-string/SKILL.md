---
name: hunter-l3-format-string
description: "Use when hunting Format String on a target. Loads the L3 technique sheet: Format string vulnerabilities occur when attacker-controlled data is passed as the *format* argument to a printf-family function (`sprintf`, `vsprintf`, `zend_vspprintf`, `curl_msnprintf`, etc.) instead of as an argument."
domain: cybersecurity
subdomain: web
tags:
- web
- format-string
- hunting
- l3
version: '1.0'
---

# Format String — Technique Sheet

## Overview

Format string vulnerabilities occur when attacker-controlled data is passed as the *format* argument to a printf-family function (`sprintf`, `vsprintf`, `zend_vspprintf`, `curl_msnprintf`, etc.) instead of as an argument. In bug bounty practice, these surface in two places: (1) interpreter/runtime internals (PHP, Perl, curl) where crafted input reaches a format call deep in the codebase — usually via obscure error paths — and (2) restricted/embedded CLIs where user commands are echoed through an insecure formatter. When proven, they yield write primitives (`%n`/`%hn`) leading to code execution, or at minimum reliable crashes. The class pays well in Internet Bug Bounty programs (PHP, Perl, curl) and in network-appliance programs (Ubiquiti) where the impact is auth-boundary escape.

## Distinct sub-patterns

### 1. Class name as format string in PHP error paths (zend_throw_or_error)

- **Endpoint shape:** Not a network endpoint — any PHP code path where an *undefined class name* is used in an instantiation/static call. The name flows into `zend_throw_or_error()` (Zend/zend_execute_API.c), which passes it as the format string to `zend_vspprintf`.
- **Payload (verbatim):**
  ```php
  <?php $name="%n%n%n"; $name::doSomething(); ?>
  ```
  Note that even plain `%n%n%n` in a class name string fires it — no exotic specifiers needed to prove the primitive.
- **Root cause:** A non-existent class name is passed as the format string to `zend_throw_or_error`/`zend_vspprintf`. The `%n` specifier writes the count of characters printed so far to the pointer taken from the (uncontrolled) argument — an arbitrary write-what-where if you can control arguments or the stack layout.
- **Impact proven:** A write-what-where primitive — controlled values in RAX/RDX at crash time, causing SIGSEGV. Assessed as exploitable for full code execution (PHP bug #70914). Resolved.
- **Exemplars:** id=106548, id=104009 (both ajaysenr, Internet Bug Bounty).

### 2. Format width overflow in Perl (sprintf with oversized widths)

- **Endpoint shape:** Perl interpreter's `sprintf` with attacker-controlled format string — the target is the parser/interpreter, so any Perl code path accepting user format strings counts. Also reachable via hostile format strings in code that interpolates user data into `sprintf`.
- **Payload (verbatim):**
  ```
  print sprintf("%2000.2000f this is a spacer %4000.4294967245a", 1, 0x0.00008234p+9);
  ```
- **Root cause:** Integer overflow in computing the required buffer size inside `Perl_sv_vcatpvfn_flags`. The huge precision on `%f` plus the overflowed width on `%a` (`4294967245` is just under 2^32 — chosen deliberately) makes the size computation wrap, producing a too-small allocation and subsequent buffer overflow. The `%a` specifier takes a hex float literal (`0x0.00008234p+9`) as its argument, giving fine-grained control of the value processed.
- **Impact proven:** Crashed the Perl interpreter (SIGSEGV) with a controlled `eax` register — a demonstrated path to code execution on hostile format strings.
- **Exemplar:** id=271330 (ajaysenr, Internet Bug Bounty).

### 3. Argumentless %hn in curl_msnprintf (self-referential crash)

- **Endpoint shape:** `curl_msnprintf()` in curl's `mprintf.c` — reached wherever a format string with more specifiers than supplied arguments is processed (e.g. attacker-influenced strings passed to curl's internal formatting, or buggy internal callers). Not an HTTP endpoint; this is a library-internal format-string handling bug triggered by a crafted format string alone.
- **Payload (verbatim):** `"%hnuked"`
- **Root cause:** `curl_msnprintf` mishandles the `%hn` specifier when no matching argument is supplied: it dereferences an invalid/misaligned pointer (`0x1`) and writes to it. Unlike classic format strings, the attacker does not need to control arguments — the missing-argument path itself produces the dangerous store.
- **Impact proven:** Crash reproduced under ASAN — misaligned store to address `0x1` causing SEGV in `formatf` at `mprintf.c:1047`. Denial of service via an attacker-controlled format string.
- **Exemplar:** id=2990139 (ajaysenr, curl).

### 4. Restricted-CLI escape via `%x%x%n` (Ubiquiti EdgeSwitch)

- **Endpoint shape:** Restricted (non-shell) admin CLI over SSH or TELNET on Ubiquiti EdgeSwitch — any command the restricted shell echoes or processes through an internal printf. The format string is typed directly as CLI input.
- **Payload (verbatim):** `%x%x%n`
- **Root cause:** User-controlled format string in the restricted CLI's command handling. Because the CLI runs privileged code that formats user input without a matching argument list, `%n` becomes a write primitive inside the privileged process.
- **Impact proven:** An admin user with specially crafted commands executed arbitrary shell instructions — bypassing the restricted SSH/TELNET CLI entirely (privilege/restriction escape on an embedded appliance).
- **Exemplar:** id=311884 (ajaysenr, Ubiquiti Inc.).

## Bypass / chain notes

- **No argument needed:** The curl case (id=2990139) shows that simply supplying a `%hn` specifier with *no* matching argument can trigger an invalid pointer dereference — you don't need a fully controlled write to get a crash. Try short, argument-mismatched specifiers first when probing a suspected sink.
- **Number-width trick for integer overflow:** In the Perl case, the width `4294967245` (just under 2^32) was chosen to overflow buffer-size arithmetic. When you suspect a size-computation overflow behind a formatter, try widths/precisions near the 32-bit boundary (`4294967245` verbatim worked) combined with a large precision (`%2000.2000f`, `%4000.`).
- **Hex-float precision control:** The Perl payload used a hex float literal (`0x0.00008234p+9`) as the `%a` argument — useful when you need exact control over a value flowing through the formatter rather than a plain decimal.
- **Error paths as sinks:** The PHP bug lived entirely in an error path (`zend_throw_or_error` when a class doesn't exist). Hunt for sinks that format *names/identifiers* — class names, hostnames, command strings — since developers rarely treat those as user data.
- **CLI escape chain:** In the EdgeSwitch case the format string alone was the chain: restricted CLI → privileged formatter → `%n` write → arbitrary shell command execution. No second bug required.
- **ASAN/SEGV evidence:** All interpreter bugs were demonstrated by crash under sanitizer or controlled-register SIGSEGV — that was accepted as proof of exploitability (write-what-where / controlled RAX/RDX/EAX), no full RCE PoC needed.

## Gotchas / what NOT to do

- Don't assume you need a full arbitrary-write PoC. In PHP (id=106548), demonstrating controlled registers at SIGSEGV plus the write-what-where reasoning was assessed as exploitable for full code execution. Report the primitive and the crash evidence.
- Don't forget that identifier fields are inputs. Class names (PHP), CLI command strings (EdgeSwitch), and internally-formatted strings (curl) all carried the format string — not obvious "user input" fields like query params.
- Don't stop at `%s`/`%x` reads when `%n`/`%hn` are reachable — the proven impacts here are all write-based (`%n` in PHP and EdgeSwitch, `%hn` in curl, width-overflow in Perl).
- Don't pad blindly: the Perl bug needed a *specific* combination (overflowing width + huge precision + hex-float arg), not just a long string.
- `%x%x%n` is enough to prove the EdgeSwitch-class bug — you don't need a long leak-then-write chain to establish the restricted-CLI bypass.
- Note program scope: three of five records are Internet Bug Bounty (PHP/Perl interpreter internals) — interpreter-level format string bugs are reportable and rewarded; target the runtime, not just web apps.

## Real-world impact examples

- **PHP (id=106548):** `%n%n%n` in an undefined class name → write-what-where with controlled RAX/RDX at SIGSEGV → assessed as full code execution (bug #70914, fixed).
- **Perl (id=271330):** `sprintf("%2000.2000f this is a spacer %4000.4294967245a", 1, 0x0.00008234p+9)` → integer-overflowed buffer size → SIGSEGV with controlled eax → path to code execution on hostile format strings.
- **curl (id=2990139):** `"%hnuked"` → misaligned store to `0x1` → SEGV in `formatf` (mprintf.c:1047) under ASAN → attacker-controlled format string DoS.
- **Ubiquiti EdgeSwitch (id=311884):** `%x%x%n` typed into the restricted SSH/TELNET CLI → arbitrary shell command execution as admin, full bypass of the restricted interface.