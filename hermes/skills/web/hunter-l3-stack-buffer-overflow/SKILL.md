---
name: hunter-l3-stack-buffer-overflow
description: "Use when hunting Stack Buffer Overflow on a target. Loads the L3 technique sheet: Stack buffer overflows occur when attacker-controlled input is copied into a fixed-size stack buffer without bounds checking — in CLI binaries, language runtimes, parsers, and RPC handlers."
domain: cybersecurity
subdomain: web
tags:
- web
- stack-buffer-overflow
- hunting
- l3
version: '1.0'
---

# Stack Buffer Overflow — Technique Sheet

## Overview
Stack buffer overflows occur when attacker-controlled input is copied into a fixed-size stack buffer without bounds checking — in CLI binaries, language runtimes, parsers, and RPC handlers. In bug bounty they pay almost exclusively through C/C++ code paths: parser entry points, protocol headers, and runtime APIs exposed to untrusted input. Proven outcomes in these records range from ASan stack-buffer-overflow reports (accepted even at PoC/crash level) to SEH-chain overwrite and full arbitrary code execution.

## Distinct sub-patterns

### 1. Negative length argument defeats size-limited input copy
- Endpoint shape: Any API that takes an explicit length `n` to "safely" bound a copy — e.g. `wgetnstr(win, buf, n)`.
- Payload (verbatim): `w.getstr(-1)` (also `w.instr(-1)` on the same codebase).
- Root cause: CPython's `PyCursesWindow_GetStr` passes `n` straight to `wgetnstr()` without checking it's non-negative. With `n < 0`, ncurses skips length checking entirely and writes unlimited input into a fixed 1024-byte stack buffer `rtn`.
- Impact proven: Feeding >1024 'A's produced `stack smashing detected` and `segmentation fault (core dumped)`. Reporter notes exploitability if combined with a stack canary leak.
- Exemplars: id=159690 (both getstr and instr, Internet Bug Bounty / Python).

### 2. Off-by-one / single-byte OOB write on line-buffer append
- Endpoint shape: Interactive shell / REPL reading a line of user input — e.g. mirb's `main()` filling `last_code_line` from stdin.
- Payload: not stated (crafted input via mirb stdin).
- Root cause: `main()` writes one byte past the end of the `last_code_line` stack buffer — OOB write of size 1, typically on a newline/terminator boundary when input exactly fills the buffer.
- Impact proven: AddressSanitizer: `stack-buffer-overflow WRITE of size 1 in mirb main() at mirb.c:466`.
- Exemplar: id=219870 (shopify-scripts).
- Note: single-byte OOB writes are accepted findings here; target loop/terminator logic (`<=` vs `<`, missing room for `\0`).

### 3. CLI option value copied into fixed stack buffer
- Endpoint shape: Command-line option taking a long free-form string.
- Payload (verbatim): 280 `A`s supplied as the `--tls-cipher` argument to OpenVPN.
- Root cause: The option value is copied into a fixed stack buffer with no length check.
- Impact proven: Stack buffer overflow triggered on OpenVPN via `--tls-cipher`.
- Exemplar: id=242579 (Internet Bug Bounty).
- Variant with stronger impact — same class, different surface: `$ENV{"A" x (0x1000)} = 0;` on win32 Perl. `CPerlHost::Add` copies the `$ENV` key into a fixed 1024-byte stack buffer without a length check → **arbitrary code execution** on Strawberry and ActiveState Perl (both built without stack canaries/ASLR). Exemplar: id=272497.

### 4. Protocol header line copied without destination-size check (server-side)
- Endpoint shape: HTTP request filter reading a header line. Concretely: `PROXY <long-string>` sent to Apache httpd (mod_remoteip PROXY protocol v1/v2 parsing).
- Payload (verbatim): `PROXY aaaa…` — a single header line of ~350 `a` characters (exact count not stated beyond the supplied literal).
- Root cause: `remoteip_input_filter` `memcpy`s attacker input into fixed-size `ctx->header` without checking destination size.
- Impact proven: SIGSEGV in the httpd worker thread; reporter notes stack overflow → memory corruption → potential RCE.
- Exemplar: id=674540 (Internet Bug Bounty).

### 5. UDP/protocol packet field length trusted over fixed buffer (network listener)
- Endpoint shape: A UDP listener on a custom protocol URL — here `rist://` handling RTCP packets in VLC's `rtcp_input()`.
- Payload (verbatim):
  ```
  buf = "\x80\xCA\x00\x00" + "\x00"*5 + "\x80" + "A"*232 + "B"*8 + "C"*8 + "D"*200
  ```
- Root cause: `rtcp_input()` `memcpy`s an attacker-controlled SDES name field of `name_length` bytes (up to 255, taken from the packet) into a fixed 128-byte `new_sender_name` buffer with no bounds check.
- Impact proven: SEH chain overwritten — control frames observed at `0x42424242` / `0x43434343` / `0x44444444` (the B/C/D blocks), app crashed with potential RCE / full system compromise.
- Exemplar: id=489102 (VLC, European Commission - DIGIT).
- Template takeaway: the payload is precision-structured — header bytes to reach the vulnerable copy, filler (`A`s) to reach the saved frame/SEH, then distinct byte-blocks (`B`/`C`/`D`) as address markers to confirm control.

### 6. RPC array handler missing the return/size reconciliation
- Endpoint shape: JSON-RPC method taking an array param — here Monero `RPC is_key_image_spent` with `key_images`.
- Payload: not stated (the size mismatch itself is the trigger).
- Root cause: In `on_is_key_image_spent`, a missing `return` statement lets execution continue so `b.data()` is used with a size that doesn't match the fixed `crypto::key_image` stack buffer.
- Impact proven: AddressSanitizer confirmed `stack-buffer-overflow READ of size 32` in the RPC handler; potential DoS.
- Exemplar: id=3240792 (Monero).

### 7. Logic-order bug in validation-vs-access → stack OOB READ
- Endpoint shape: Regex engine matching path — PHP mbstring (Oniguruma) `match_at()` during regex search.
- Payload: malformed regex (exact string not stated; the trigger is the validation/access ordering in `match_at()`).
- Root cause: A logical error orders validation *after* access, so the matcher reads out of bounds from a stack buffer.
- Impact proven: Stack out-of-bounds read during regex searching (CVE-2017-9224), potentially remotely exploitable.
- Exemplar: id=237915 (Internet Bug Bounty).

### 8. Runtime conversion writing .rodata table over stack buffer
- Endpoint shape: String-encoding conversion API — `mb_strtolower()` with UTF-32LE on invalid input strings.
- Payload: not stated (certain invalid UTF-32LE strings).
- Root cause: Invalid strings cause an overflown array from `.rodata` to overwrite a stack-allocated buffer.
- Impact proven: Straightforwardly crashes the PHP interpreter; memory corruption and potentially code execution (CVE-2020-7065).
- Exemplar: id=838127 (Internet Bug Bounty).

### 9. Path-handling internals missing bounds checks (library-internal entry points)
- Endpoint shape: Filesystem path handling inside language runtimes — PHP `php_stream_zip_opener` (via a `zip://` path/URL) and `virtual_file_ex()`.
- Payload: not stated in either record.
- Root cause: Both lack bounds checks when handling path data into stack storage, causing stack-based buffer overflows (php bug 72520 and 72513 respectively).
- Impact proven: Stack-based buffer overflow enabling memory corruption in both functions.
- Exemplars: id=152278 (zip stream wrapper), id=152280 (virtual_file_ex) — both Internet Bug Bounty.

## Bypass / chain notes
- **Canary-bypass precondition, not a bypass:** the Python curses finding (id=159690) is framed as exploitable only once combined with a stack canary leak — i.e., crash-level findings become RCE stories via a separate infoleak.
- **No-canary/no-ASLR targets convert crashes to RCE:** the win32 Perl build (id=272497) had no stack canaries or ASLR, which turned a plain 1024-byte overflow into arbitrary code execution. Build configuration is part of the attack surface.
- **SEH overwrite on Windows:** VLC (id=489102) used structured distinct byte-blocks to demonstrate control of the SEH chain — the marker technique (B/C/D) is how you prove control without a working exploit.
- **ASan-only findings are accepted:** mirb (WRITE of size 1), Monero RPC (READ of size 32) were both essentially sanitizer-confirmed OOB reports with no PoC exploit — half of these records are crash/ASan-level, not RCE.
- No records here show a multi-bug chain actually executed; all `chain` fields were empty. Chains appear as *potential* exploitation notes, not demonstrated steps.

## Gotchas / what NOT to do
- READ overflows still count: CVE-2017-9224 and the Monero RPC bug are OOB *reads* from stack buffers — don't assume only WRITEs qualify.
- Off-by-one (size-1 write) is a valid finding (mirb) — don't dismiss "only one byte" overflows.
- Negative-length parameters are easy to miss: the cursed APIs look length-limited ("getstr(n)") until you pass `-1`. Audit every `n` parameter for sign checks.
- Payloads in network-protocol findings need structure, not just length: VLC's PoC encodes exact header bytes (`\x80\xCA\x00\x00`, `\x80`) to reach the vulnerable memcpy, then block separators for control. A bare 255-'A' flood may reach the crash but not demonstrate control.
- Several records had no stated payload (php zip wrapper, virtual_file_ex, mb_strtolower, mirb, Monero RPC) — the trigger was a malformed input class or a code-level condition. Don't fabricate a payload for the report; describe the input class and the sanitizer output.
- Build/runtime context matters for severity: state whether the target ships canaries/ASLR (the Perl RCE hinged on it); a canary-protected build caps you at DoS/crash unless you can leak the canary.
- These were all reported to the right maintainer-level programs (Internet Bug Bounty, project-specific programs like shopify-scripts, Monero, VLC). Runtime and library internals were in scope there — don't assume they are on a typical web program.

## Real-world impact examples
- **Arbitrary code execution (win32 Perl, id=272497):** `$ENV{"A" x (0x1000)} = 0;` → `CPerlHost::Add` overflows a 1024-byte stack buffer; RCE achieved on Strawberry and ActiveState Perl because both lacked stack canaries and ASLR.
- **SEH chain overwrite (VLC rist://, id=489102):** malicious RTCP packet drove control frames to `0x42424242`/`0x43434343`/`0x44444444`; potential RCE / full system compromise.
- **Crash with RCE path (Python curses, id=159690):** `w.getstr(-1)` → `stack smashing detected` + segfault; canary leak needed to weaponize.
- **Server DoS (Apache mod_remoteip, id=674540):** crafted `PROXY` header → SIGSEGV in httpd worker thread.
- **Crash-level runtime bugs:** mirb OOB write (ASan, WRITE of size 1, id=219870); PHP mb_strtolower UTF-32LE interpreter crash (CVE-2020-7065, id=838127); PHP mbstring stack OOB read (CVE-2017-9224, id=237915); Monero RPC stack OOB read of 32 bytes (DoS, id=3240792); PHP zip wrapper / virtual_file_ex stack overflows (php bugs 72520/72513, ids 152278/152280); OpenVPN `--tls-cipher` overflow (id=242579).