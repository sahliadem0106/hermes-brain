---
name: hunter-l3-memory-corruption
description: "Use when hunting Memory Corruption on a target. Loads the L3 technique sheet: This class covers client-side and library-level memory-safety bugs: heap/stack overflows, out-of-bounds reads/writes, integer overflows that defeat size checks, type confusion, use-after-free/double-f"
domain: cybersecurity
subdomain: web
tags:
- web
- memory-corruption
- hunting
- l3
version: '1.0'
---

# Memory Corruption — Technique Sheet

## Overview

This class covers client-side and library-level memory-safety bugs: heap/stack overflows, out-of-bounds reads/writes, integer overflows that defeat size checks, type confusion, use-after-free/double-free, and unvalidated-parameter dereferences. In bug bounty practice it pays almost exclusively against parser and language-runtime surfaces — file format parsers (PHAR, TIFF, LZ4, SWF), deserialization entry points (WDDX), and sandboxed scripting engines (mruby, Flash AS3, PHP extensions) — where a single crafted input reaches native code. The dominant proven impact in these records is crash/DoS (SIGSEGV, ASAN heap-buffer-overflow), but many were rated as potential code execution and one (Flash double-free, CVE-2014-0502) was actively exploited in the wild. Detection tooling matters: ASAN, Valgrind, GDB, and crash-with-controlled-register evidence (e.g. EIP/EAX = 0x41414141 or 0xDEADBEEF) is what elevates a crash from "nice segfault" to a high/critical bounty.

## Distinct sub-patterns

### 1. Null-byte / malformed-name parser corruption
- Endpoint shape: file-format parser entry points; e.g. `phar_parse_tarfile` in PHP — the tar **entry filename** field.
- Payload: entry filename beginning with a null byte (`\x00...`) — payload not stated in full record form, the trigger is a leading-NUL name inside a crafted tar/phar.
- Root cause: `phar_parse_tarfile` mishandles entry filenames that start with a null byte, corrupting memory.
- Impact: memory corruption in PHP phar parsing; CVE-2015-4021 (PHP bug 69453).
- Exemplars: 104027.

### 2. Unvalidated index derived from attacker input (out-of-bounds read)
- Endpoint shape: `Perl glob() -> win32_stat -> VDir::MapPathA` on Windows — glob **pattern** argument.
- Payload (verbatim): `print glob "]:";`
- Root cause: `VDir::MapPathA` indexes `dirTableA` with an unvalidated drive-index computed from the attacker-controlled pattern, causing out-of-bounds reads and strcpy over-reads.
- Impact: access violation (crash) in `VDir::MapPathA` under a debugger, confirming OOB read; potential arbitrary code execution.
- Exemplars: 110352.
- Sibling pattern — palette index not validated against size: `imagecropauto()` (ext/gd) with `IMG_CROP_THRESHOLD`; the **color** param was used as index `col1=1337` into 256-entry R/G/B/A arrays → OOB read, arbitrary read/leak potential (GDB-confirmed). Exemplar: 178144.
- Sibling — signed capacity wrap: Tor's `smartlist_ensure_capacity` uses signed 32-bit capacity that wraps negative past `0x7FFFFFFF` elements; next `smartlist_add` writes `sl->list[-2147483648]` → OOB write/heap corruption (PoC used reduced element size to fit memory). Exemplar: 112386.

### 3. Missing bounds check before memcpy (stack overread)
- Endpoint shape: `name_parse` in libevent DNS — crafted DNS packet labels.
- Payload: crafted DNS packet via `libevent-poc.py`, exercised with `dns-example -servertest`.
- Root cause: no validation that `packet+j+label_len` stays within packet length before `memcpy`.
- Impact: ASAN "stack-buffer-overflow ... READ of size 1"; remote overread of up to 63 bytes of stack.
- Exemplars: 112632.
- Sibling: `X509_NAME_oneline()` — ASN1 strings >1024 bytes overread on EBCDIC systems; arbitrary stack data could land in the output buffer (CVE-2016-2176). Exemplar: 135946. Also `_TIFFPrintField` — C16/C32 ASCII tag values not guaranteed null-terminated → `strlen` reads outside buffer, ASAN SIGSEGV in tiffinfo (CVE-2016-9297). Exemplar: 182140. And libevent-style read-past-array: `TIFFNumberOfStrips()` recomputes strip count in TIFF_STRIPCHOP mode → ASAN heap-buffer-overflow READ of size 8 in `cpStrips` during tiffsplit (CVE-2016-9273). Exemplar: 181642.

### 4. Wrong object type passed to unvalidated API (Flash AS3 inner-class pattern)
This is the single densest sub-family in the records — a recurring Adobe PSDK bug shape:
- Endpoint shape: AS3 methods in `com.adobe.tvsdk.mediacore` that take an object parameter: `ContentFactory.retrieveAdPolicySelector(mt)`, `Metadata.setMetadata("test", mt)`, `OpportunityGenerator.update(1, tr)`, `ShimContentFactory.retrieveOpportunityGenerators()/retrieveResolvers()`, `ShimContentResolver.configure()`, `ShimOpportunityGenerator.configure()`, `ShimContentResolver.resolve()` with `resolverType=0` or `1` (skipping `canResolve()` validation), and `ShimAdPolicySelector.selectAdPolicySelector(ap)` built with `adPolicySelectorType=0`.
- Payload (verbatim example, CVE-2016-1099):
  ```
  package {
      import com.adobe.tvsdk.mediacore.metadata.Metadata;
      import flash.display.Sprite;
      public class poc extends Sprite {
          public function poc() {
              var mt:Metadata;
              new Metadata().setMetadata("test",mt);
          }
      }
  }
  ```
  i.e. call the API with an **uninitialized/null-typed object variable** instead of a real instance.
- Root cause: the method does not validate its parameter; an inner class instance is left absent and native code dereferences it → memory crash.
- Impact: memory corruption/crash, rated as leading to code execution. CVEs: 2016-1098, 1099, 1100, 4150–4155, 4188.
- Exemplars: 138516, 138517, 138518, 145265–145272, 151040.
- Related Flash pattern: calling a native `ASnative(101,10)` with a MovieClip object pointer → invalid EIP crash (CVE-2016-0981), exemplar 119652; and uninitialized-memory use during crafted SWF handling (Valgrind: use of uninitialised value, EXC_BAD_ACCESS; CVE-2016-0992), exemplar 122256.

### 5. Negative / hostile size parameter reaching memcpy or malloc
- Endpoint shape: PHP `mbstring` `mbfl_strcut` — size argument.
- Payload (verbatim): `-1`
- Root cause: negative size passed to `memcpy`.
- Impact: memory corruption in PHP 5.5/5.6/7. Exemplar: 127242.
- Sibling: `malloc` called with negative size in PHP (bug 73445). Exemplar: 181073.
- Sibling (size_t stored unchecked from error path): curl FTP GSSAPI/KRB5 — `krb5_decode` mishandles `gss_unwrap` GSS_S_BAD_SIG, doesn't clear the buffer and returns size -1, which `read_data` stores as unchecked size_t → forged FTP server responses make the client consume unallocated heap. Exemplar: 1590071.

### 6. Integer overflow defeating a length/size check
- Endpoint shapes and payloads:
  - OpenSSL `EVP_EncodeUpdate()` — very large input length overflows the length check → heap corruption (CVE-2016-2105). Exemplar: 135944.
  - OpenSSL `EVP_EncryptUpdate()` — large input **after a prior call with a partial block** overflows the length check → heap corruption (CVE-2016-2106). Exemplar: 135945.
  - PHP `number_format` thousand separator — payload (verbatim):
    ```php
    <?php
    ini_set('memory_limit', -1);
    $thousands_sep = str_repeat("A", 0x65000000);
    number_format(1234567890, 0, ".", $thousands_sep);
    ?>
    ```
    Integer overflow in `_php_math_number_format_ex` lets the oversized separator bypass the length check; SIGSEGV on 32-bit PHP, potential ACE. Exemplar: 180562.
  - PHP `number_format` huge decimals — payload (verbatim):
    ```php
    <?php
    ini_set('memory_limit', -1);
    number_format(1.337E+308, PHP_INT_MAX, "BBBBBBBBB", str_repeat("A", 0x0160b60c));
    ?>
    ```
    Missing size check with huge decimals → OOB write during '0' padding; SIGSEGV. Exemplar: 180572.
  - mruby `sprintf` hostile width — payload (verbatim): `sprintf("abcdefghijklmnopqrstuvwxyz % 2147483640s", s)` — integer overflow in the CHECK() macro handling the width; SIGSEGV/core dump. Exemplar: 204628.
  - LZ4 `LZ4_decompress_generic` — integer overflow on the compressed **literal run length** lets the attacker pick an arbitrary offset for a 4-byte write; OOB write at attacker-specified offset, DoS and out-of-window write practical (CVE-2014-4611). Exemplar: 17688.
  - mruby `Array#*` — `ARY_MAX_SIZE` compared MRB_INT_MAX (not divided by sizeof(mrb_value)) against a byte limit → oversized allocation, copy loop writes past the destination (`array_copy` in `mrb_ary_times`, EXC_BAD_ACCESS); after fix, same input cleanly raises "array size too big" (ArgumentError). Exemplar: 185899.
  - PHP `php_snmp_parse_oid()` — integer overflow in allocation → heap OOB write (PHP bug 72708). Exemplar: 178094.
  - PHP GD `gdImageAALine` — integer overflow computing clipped line limits → illegal read/write in `gdImageSetAAPixelColor`. Exemplar: 182420.
  - mruby `mrb_ary_set` — payload (verbatim): `ary = Array.new(0)` then `ary[0x7fffffff] = 1`; integer overflow computing n+1 for capacity expansion → `ary_fill_with_nil` OOB write; SIGSEGV. Exemplar: 192235.
  - mruby `mrb_ary_splice` — payload (verbatim): `ary = Array.new(1023)` then `ary[0x7ffffffffffffc00,0] = Array.new(1024)`; `size = head + argc` overflows, bypassing the capacity check → heap overflow, SIGSEGV in mruby AND mruby-engine. Exemplar: 192362.
  - PHP `php_basename` / `spl_filesystem_dir_open` / `spl_filesystem_info_set_filename` / `locale_compose` / WDDX-deserialize NULL deref — invalid memory access bugs (bugs.php.net 73295, 73316, 73296, 73372, 73331). Exemplars: 180590–180908.

### 7. Type confusion from missing type validation
- Endpoint shapes and payloads:
  - Python `itertools.chain.__setstate__` — payload (verbatim): `itertools.chain().__setstate__((None, 1))`; `chain_setstate()` sets source/active without checking they're iterators → type confusion at `PyIter_Next`; DEP access violation 0xc0000005, possibly exploitable. Exemplar: 175091.
  - mruby `NoMethodError.new` override — payload (verbatim):
    ```ruby
    NoMethodError.define_singleton_method(:new) do "waat" end
    Object.q
    ```
    Overriding `new` so it doesn't return an exception object → type confusion in `mrb_no_method_error`, segfault, possible ACE. Exemplar: 181871.
  - mruby `Symbol.new` — payload (verbatim): `a = Symbol.new` then `a.inspect`; symbol not backed by a valid symbol-table entry → `sym_inspect` dereferences invalid pointer, SIGSEGV. Exemplar: 185914.
  - mruby `mrb_any_to_s` boxing confusion — payload (verbatim): `NilClass.remove_method :to_s` then `nil.to_s`; with word boxing, boxed nil/symbol/fixnum values are treated as pointers → SIGSEGV at object.c:443; also reproducible with Symbol and Fixnum. Exemplar: 185794.
  - mruby `mrb_ary_concat` non-array operand — payload (verbatim):
    ```ruby
    case ""
    when 0
    end
    x *case
      when true
        * = 0
    end
    ```
    `mrb_ary_concat` dereferences operands without `mrb_array_p` check → EXC_BAD_ACCESS in `ary_modify`; crashes mruby 1.2.0 and the mruby-engine sandbox. Exemplar: 184712. Related parser-triggered variant (216615): `N *case\nwhen nil\n->()do end\ndef e()end\nend#` → ASAN SEGV in `ary_concat` in both mruby and mruby-engine.
  - mruby `mrb_obj_freeze` on crafted fixnum — payload (verbatim): `o=0x30303030.freeze`; invalid read on a user-controlled Struct RBasic pointer derived from a fixnum; SIGSEGV at 0x00000060606061 / 0x82828283 with RAX/RSI holding attacker-controlled values. Exemplar: 191994.

### 8. Use-after-free / double-free
- Endpoint shapes and payloads:
  - mruby OP_ARYCAT UAF — payload (verbatim):
    ```ruby
    class Klazz
      def $thing.name
        f@thing.f@thing.name *nil
      end
      f$thing.name
    end
    ```
    `mrb_ary_splat` at vm.c:2137 reads R(B) after the backing register region was realloc'd/freed → ASAN heap-use-after-free READ of size 8 on a 2048-byte region; crashes mruby-engine once limits raised (4MB→22MB memory, 100k→525k instructions). Exemplar: 184715.
  - PHP WDDX stack-pop UAF — payload (verbatim, inside a wddxPacket): `<binary><boolean/></binary>`; `<boolean/>` pops and frees a stack entry never pushed, then `php_wddx_pop_element` treats it as a string and base64-decodes a dangling pointer → SIGSEGV with **eax=0x41414141** during base64 decode; reporter assesses "read anything anywhere" / memory corruption. Exemplar: 188661.
  - Flash Player double-free (CVE-2014-0502) → memory corruption and code execution; actively exploited in watering-hole campaigns against nonprofits and human-rights orgs. Exemplar: 2170.
  - mruby Hash-default recursion — payload (verbatim): `d b = Hash.new {|s,k| s[k] }[1]`; recursive default block corrupts the VM stack → SIGABRT "realloc(): invalid next size"; DoS-grade. Exemplar: 198452.
  - mruby mutated-array-as-hash-key — payload: large multiline key array whose contents mutate between hash insertions, then `h.dup`; corrupts hash structure → "malloc(): memory corruption" and ASAN "free on address not malloc-ed". Exemplar: 216725.

### 9. Off-by-one write landing on attacker-controlled address
- Endpoint shape: `Phar::LoadPhar()` in PHP — crafted PHAR archive with mismatched alias.
- Payload (verbatim, excerpt): a PHP harness building `str_repeat("\xef\xbe\xad\xde", ...)` after loading `example_hostile.phar` with alias `alias.phar`.
- Root cause: `phar_parse_pharfile()` writes a `'\0'` one byte past the buffer (off-by-one) when the alias doesn't match, corrupting heap metadata.
- Impact: crash writing to **0xDEADBEEF** — demonstrated arbitrary-address write, potential RCE.
- Exemplar: 195586.

### 10. VM stack / argument-count corruption
- Endpoint shapes and payloads:
  - mruby excessive arguments — payload (verbatim): `d 0, 0, 0, 0, ...` (~100 zero args); heap-buffer-overflow WRITE of size 16 in `mrb_vm_exec value_move`, ASAN-confirmed. Exemplar: 204421.
  - mruby `%1094861636$` format specifier — payload (verbatim): `'%A%1094861636$'%2`; `mrb_vformat` doesn't bounds-check the number between `%` and `$` → heap-buffer-overflow (ASAN), SIGSEGV; value can overwrite mrb_value objects, high likelihood of code execution via heap grooming. Exemplar: 192318.
  - mruby VM-stack corruption from recursive Hash default (see UAF section, 198452).
  - TOCTTOU on string length — payload (verbatim, excerpt):
    ```ruby
    $s = "9" + ("\n" * (1024*1024-1))
    class Tmp
      def to_i
        $k.push("a"*1024)
        $s.chomp! ''
        $s.succ!
        95
      end
    end
    $s.setbyte(128, tmp)
    ```
    `String#setbyte` caches the length before loading args; a malicious `to_i` reallocates the string shorter, then `setbyte` writes OOB. Exemplar: 181893 (researcher planned reliable RCE against mruby-engine).

### 11. Parser-internal state corruption (assertion / backtrace crashes)
- Endpoint shapes and payloads:
  - Payload (verbatim): `i""do"".+end` — parse produces an irep with no line table → `mrb_debug_info_append_file` hits assertion `irep->lines`, SIGABRT in mruby/mirb/sandbox. Exemplar: 215967.
  - Malformed script (204047, `def foo(n)...` with `%foo(0)`) — segfault while printing the backtrace.
- Impact: sandbox DoS (the whole point of shopify-scripts was sandboxed execution).
- Exemplars: 215967, 204047.

### 12. File-format / game-data parsing corruption (non-web)
- Endpoint shapes: Nintendo Switch Mario Kart 8 Deluxe metadata parsing and ranking/replay file parsing.
- Root cause: improper metadata validation → **array index underflow** during parsing; malformed ranking/replay files → memory corruption.
- Impact: OOB access on Switch (High, CVSS 8.2) and memory corruption rated Critical, potential DoS or code execution.
- Exemplars: 1812732, 1813453.

## Bypass / chain notes

- Sandbox escape by raising limits: the mruby-engine heap-UAF (184715) only crashed the sandbox after resource limits were raised (4MB→22MB memory, 100k→525k instructions) — retest crashes under higher limits when the default sandbox masks them.
- ASLR/exploit chains seen: WDDX `<binary><boolean/></binary>` gave eax=0x41414141 (pointer control), PHAR off-by-one hit 0xDEADBEEF (arbitrary write demo), and `%1094861636$` could overwrite mrb_value objects — all explicitly assessed as RCE-capable with heap grooming.
- Multi-step TOCTTOU chain (181893): pass object with malicious `to_i` → `to_i` reallocates the target string shorter via `chomp!`/`succ!` → cached length in `setbyte` is stale → OOB write. The chain field is explicit: trigger the conversion inside the argument-loading window.
- Partial-block precondition: `EVP_EncryptUpdate` overflow only fires when large input follows an earlier call that left a partial block — the record's "chain" is call sequencing, not a web chain.
- Version-confirmation trick (185899): running the same PoC against the patched build and observing `ArgumentError: array size too big` instead of a crash is strong evidence the crash was the reported bug.

## Gotchas / what NOT to do

- Don't report a bare SIGSEGV without tooling evidence — the records that paid well carried ASAN output, Valgrind reports, GDB-confirmed OOB reads, or controlled-register crashes (EAX/EIP/RAX values). Attach sanitizer output.
- Don't assume PoC reproducibility transfers: 192235 (mruby `ary[0x7fffffff]=1`) crashed mruby but **could not be reproduced in mruby-engine** due to memory limits. Test in the actual target environment.
- Don't skip memory-limit setup in PHP: both `number_format` PoCs set `ini_set('memory_limit', -1)` first; without it the huge strings fail before reaching the vulnerable code.
- Don't forget 32-bit vs 64-bit: the `number_format` thousand-separator overflow (0x65000000) is SIGSEGV-on-32-bit only — integer overflow PoCs depend on pointer/int width.
- Don't understate memory requirements: the Tor smartlist integer-wrap PoC (112386) needed a reduced element size because allocating 0x7FFFFFFF real elements is impractical — note this in the report.
- Don't confuse DoS-only crashes with corruption: 198452 (`realloc(): invalid next size`) is explicitly noted "not exploitable beyond DoS" — scope your impact claim to what you demonstrated.
- Don't fabricate shellcode claims: several records (112057 zipimporter, 178094) were confirmed bugs with "no data access demonstrated" and still resolved; honest scoping is fine.
- Don't invent payloads when a structural trigger suffices — many of these fired on shape alone (uninitialized variable, oversized argument, malformed tag), with no exploit string.

## Real-world impact examples

- CVE-2014-0502 (Flash double-free, 2170): **actual code execution in victims' browsers**, actively exploited in watering-hole campaigns against nonprofit research institutions and human-rights activists — the clearest in-the-wild exploitation in this set.
- CVE-2016-0981 (Flash, 119652): crafted SWF calling `ASnative(101,10)` with a MovieClip pointer → invalid EIP, potential shellcode execution.
- PHP PHAR off-by-one (195586): crash writing to attacker-chosen address 0xDEADBEEF — arbitrary memory write, potential RCE.
- CVE-2016-2105/2106 (OpenSSL EVP_*, 135944/135945): heap corruption reachable from untrusted input lengths in a universally deployed library.
- CVE-2014-4611 (LZ4, 17688): out-of-bounds write at attacker-specified offset — practical DoS and out-of-window write, RCE untested.
- libevent DNS overread (112632): remote stack leak of up to 63 bytes via a crafted DNS packet, ASAN-confirmed.
- Nintendo MK8DX (1812732, 1813453): array-index underflow (CVSS 8.2, High) and replay-file corruption rated Critical with potential code execution on-device.
- shopify-scripts mruby sandbox (181871, 181893, 192318, 184715): segfaults/type confusion in the sandboxed engine, with one researcher explicitly planning a reliable RCE exploit against mruby-engine — sandbox DoS/escape is the core product-impact here.