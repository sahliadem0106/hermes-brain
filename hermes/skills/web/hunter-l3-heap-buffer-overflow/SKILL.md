---
name: hunter-l3-heap-buffer-overflow
description: "Use when hunting Heap Buffer Overflow on a target. Loads the L3 technique sheet: Heap buffer overflow bugs arise when a routine writes past (or reads past) the end of a heap allocation — typically from a missing bounds check, an undersized allocation, or an integer-overflowed size computation."
domain: cybersecurity
subdomain: web
tags:
- web
- heap-buffer-overflow
- hunting
- l3
version: '1.0'
---

# Heap Buffer Overflow — Technique Sheet

## Overview
Heap buffer overflow bugs arise when a routine writes past (or reads past) the end of a heap allocation — typically from a missing bounds check, an undersized allocation, or an integer-overflowed size computation. In bug bounty practice these are almost exclusively found in C-extension/interpreter targets (PHP, Python, Ruby, Perl, mruby, LibSass, curl) where you control raw bytes fed to a parser, VM, or CLI option. They pay via Internet Bug Bounty / interpreter programs and are confirmed with AddressSanitizer (ASAN) reports showing out-of-bounds READ or WRITE on a malloc'd region.

## Distinct sub-patterns

### 1. Interpreter C-extension buffer overrun (fixed-size vs. variable-length mismatch)
- Endpoint shape: language builtin / extension function callable from a one-liner script.
  - PHP: `enchant_broker_request_dict` (PHP bug 68552)
  - Python: `hotshot` profiler's `pack_string` (bugs.python.org 24481)
- Payload: not stated — triggered by calling the function with ordinary argument shapes; the flaw is in the C implementation.
- Root cause: the C routine writes past a heap buffer while serializing/allocating its output; no length validation against destination size.
- Impact: Heap buffer overflow, resolved as CVE-2014-9705 (enchant case).
- Exemplars: id=104013 (PHP), id=104022 (Python).

### 2. Integer overflow → undersized allocation → controlled heap write
- Endpoint shape: a C routine that computes a buffer size from two (or more) attacker-influenced lengths, then `malloc`s and `memcpy`s into it.
  - PHP `ftp_genlist`: integer overflow in list-length computation (bug 69545) → heap overflow; CVE-2015-4643. id=104028.
  - Perl `pack() / S_pack_rec`: pack() with a large item count misallocates the buffer due to integer overflow; ASAN confirmed a heap-buffer-overflow WRITE in S_pack_rec with attacker-supplied pack data. id=354650.
  - curl `lib/vauth/cleartext.c Curl_auth_create_plain_message`: the `(zlen + clen)` check overflows so `plainlen` wraps, producing an undersized malloc and a controlled heap overflow. id=872089.
- Payload (curl cleartext, verbatim): a long `A` run as the authzid:
  `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
- Root cause: size arithmetic performed in a smaller integer type or without overflow guards, so the guard check itself is bypassed.
- Impact: PHP: CVE-2015-4643. Perl: attacker-controlled heap write. curl: potential local code execution via controlled heap overflow (no PoC executed in the report).

### 3. Missing NUL-termination → strlen() read past buffer
- Endpoint shape: Perl numeric parsing of a bit-op result: `perl -e 'v300&O|0'`.
- Payload (verbatim): `v300&O|0`
- Root cause: the UTF-8 string path of bit-and in `do_vop()` does not NUL-terminate the resulting string; the subsequent string→number conversion calls `strlen()` past the buffer end.
- Impact: Reproduced an ASAN heap-buffer-overflow READ of size 11 on Perl v5.25.x (crash/DoS).
- Exemplar: id=232150.

### 4. Undersized destination buffer in encoding/transform logic (write)
- Endpoint shape: Ruby core `String#tr` on non-ASCII-encoded strings.
- Payload (verbatim, one line):
  `"a".encode("utf-32").tr("b".encode("utf-32"),"c".encode("utf-32"))`
- Root cause: `tr_trans` allocates a destination buffer sized for the wrong encoding width, so `TERM_FILL` writes past the end of the buffer.
- Impact: ASAN reported a heap-buffer-overflow WRITE of size 4 in `TERM_FILL` — confirmed out-of-bounds heap write / memory corruption.
- Exemplar: id=144485 (Ruby).

### 5. Option/config value used without propagation → recv-into-undersized-buffer (write, network-facing)
- Endpoint shape: `curl --tftp-blksize N tftp://IP:PORT`
- Payload: `N < 293` (blksize smaller than the internal default); the host:port is attacker-chosen TFTP.
- Root cause: `state->blksize` retains the default size instead of the `--tftp-blksize` value, so `recvfrom()` reads into an undersized buffer at `lib/tftp.c:1114`.
- Impact: Heap buffer overflow leading to a crash; RCE possible only if the attacker also has a separate memory-leak primitive.
- Exemplar: id=550696 (curl).

### 6. Lexer/one-byte-lookahead read past end of file buffer (read)
- Endpoint shape: `sassc` CLI fed a `.scss` file.
- Payload (verbatim): the file contents are exactly `'\` (a quote followed by a backslash at EOF).
- Root cause: the libsass lexer matcher `Prelexer::exactly<'\\'>` (lexer.hpp:92) dereferences one byte past the end of the 3-byte input buffer when a backslash appears at end of file — it reads without checking the buffer boundary.
- Impact: ASan report (afl-clang-fast build): heap-buffer-overflow READ of size 1 at an address 0 bytes to the right of a 3-byte malloc'd region; crashes the process.
- Exemplar: id=221163 (LibSass).

### 7. VM dispatch-loop missing bounds check on realloc'd operand buffer (read)
- Endpoint shape: `./mirb < test000` (mruby CLI, fuzzed script on stdin).
- Payload: fuzzed mruby bytecode input (`payload not stated` beyond "fuzzed input").
- Root cause: mruby's VM interpreter `mrb_vm_exec` (vm.c:1556) reads 16 bytes past the end of a realloc'd operand buffer due to a missing bounds check in the VM dispatch loop.
- Impact: ASan report (afl-gcc + asan build): heap-buffer-overflow READ of size 16, 0 bytes to the right of a 16-byte `mrb_realloc` region; crashes the interpreter.
- Exemplar: id=221251 (shopify-scripts).

### 8. VM opcode handling without proper bounds/ownership checks (write)
- Endpoint shape: mruby VM processing crafted bytecode / script (shopify-scripts sandbox context).
- Payload: not stated.
- Root cause: the VM processed `OP_SEND` without proper bounds/ownership checks, allowing a heap buffer overflow.
- Impact: heap buffer overflow in mruby during `OP_SEND` processing; confirmed and fixed upstream in mruby#3475 (commit 8b089c09f7).
- Exemplar: id=206239 (shopify-scripts).

### 9. Config-file parser read past fixed stack→heap buffer (read)
- Endpoint shape: `curl -K <config>` (config file passed to curl's write-out handler).
- Payload: crafted config file, referenced as `LXdAAAou` (base64 of test0070.conf).
- Root cause: `ourWriteOut` reads past a 512-byte buffer when processing a crafted config file.
- Impact: ASAN heap-buffer-overflow READ of size 1, crashing the application.
- Exemplar: id=765664 (curl).

## Bypass / chain notes
- Integer-overflowed size checks are the recurring "guard bypass": in curl's cleartext auth the `(zlen + clen)` check existed but overflowed (id=872089); in PHP's `ftp_genlist` and Perl's `pack()` the overflow occurred during size computation itself (ids 104028, 354650). When auditing, treat any `a + b`/`count * size` guard as suspect.
- Encoding tricks as an entry point: forcing an unusual encoding (Ruby `utf-32` before `tr`) or a multibyte numeric literal (Perl `v300`) routes execution into code paths with different buffer-size assumptions (ids 144485, 232150).
- CLI option mismatch as the overflow vector: no malicious payload bytes are needed — the bug fires because an internal buffer keeps the default size while the protocol path uses a different one (curl `--tftp-blksize`, id=550696).
- Chaining to RCE: the only record claiming code execution is curl's cleartext auth overflow, and even there the report notes it's "potential local code execution" with no PoC executed; the curl TFTP bug explicitly required a separate memory leak to reach RCE. Do not overstate impact — most of these were confirmed as crashes/DoS with ASAN WRITE evidence as the escalation argument.
- No chains across separate bugs appear in the records; every finding was single-step.

## Gotchas / what NOT to do
- Do not guess payloads for records that state "payload not stated" (mruby OP_SEND, Perl pack, PHP/Python extensions) — those findings were found via fuzzing or code review; the repro is the harness/ASAN run, not a magic string.
- Reproduce under ASAN before reporting: every confirmed record here cites a specific ASAN verdict (READ/WRITE, size, bytes-to-the-right, allocation site). A plain segfault is far weaker evidence.
- Minimal reproducers win: `'\` in a 3-byte file, a one-line Ruby `tr` call, `perl -e 'v300&O|0'`, one curl command line. Don't pad the input hoping for a crash — the overflow is often exactly 1 byte.
- Note version/build context in the report (e.g., Perl v5.25.x, afl-clang-fast vs afl-gcc builds) — several records did, and it matters for triage.
- Distinguish READ from WRITE honestly: a 1-byte OOB read past a 3-byte buffer (LibSass) and a controlled WRITE via wrapped length (curl auth) are different severity classes; report what ASAN actually showed.
- Scope claims to the program: these landed in Internet Bug Bounty, Ruby, shopify-scripts, LibSass, and curl programs — not web-app VDPs. Heap overflow findings need the right target.

## Real-world impact examples
- CVE-2014-9705: heap buffer overflow in PHP `enchant_broker_request_dict` (id=104013).
- CVE-2015-4643: integer overflow → heap overflow in PHP `ftp_genlist` (id=104028).
- Perl: ASAN heap-buffer-overflow READ of size 11, reproducible with a one-liner on v5.25.x — crash/DoS in the interpreter (id=232150).
- Ruby: ASAN heap-buffer-overflow WRITE of size 4 in `TERM_FILL` via a single `String#tr` call on utf-32 strings (id=144485).
- curl TFTP: crash from `recvfrom()` into an undersized buffer; RCE contingent on an additional memory-leak bug (id=550696).
- curl cleartext auth: controlled heap overflow via wrapped `plainlen`; potential local code execution claimed, no PoC executed (id=872089).
- mruby/shopify-scripts: OOB read of 16 bytes in `mrb_vm_exec` and an `OP_SEND` heap overflow — both fixed upstream (mruby#3475, commit 8b089c09f7) (ids 206239, 221251).
- LibSass: 1-byte OOB read crashing `sassc` from a 3-byte input file (id=221163).