---
name: hunter-l3-integer-overflow
description: "Use when hunting Integer Overflow on a target. Loads the L3 technique sheet: Integer overflow/underflow bugs occur when arithmetic on lengths, offsets, timestamps, or counts exceeds the width of the underlying integer type (int32, int64, unsigned), wrapping to negative or tiny"
domain: cybersecurity
subdomain: web
tags:
- web
- integer-overflow
- hunting
- l3
version: '1.0'
---

# Integer Overflow — Technique Sheet

## Overview
Integer overflow/underflow bugs occur when arithmetic on lengths, offsets, timestamps, or counts exceeds the width of the underlying integer type (int32, int64, unsigned), wrapping to negative or tiny values that defeat bounds checks or corrupt memory. In bug bounty this class pays almost exclusively at the *C-library / interpreter-core* layer: PHP, Python, Perl, mruby, OpenSSL, libcurl, zlib — typically via Internet Bug Bounty and low-level dependency programs. The winning move is finding arithmetic ordering mistakes (subtract-then-compare, add-then-check) and extreme boundary values (INT32_MAX, UINT64_MAX/near, INT64_MAX) fed into size, offset, and duration parameters.

## Distinct sub-patterns

### 1. Cipher/input-length overflow → negative output length (OpenSSL EVP)
- Endpoint shape: any caller doing `EVP_CipherUpdate(ctx, outbuf, &outlen, (unsigned char *)inbuf, len)` with an attacker-controlled `len`.
- Payload (verbatim): `res = EVP_CipherUpdate(ctx, outbuf, &outlen, (unsigned char *)inbuf, intmax);` — input length near INT_MAX (`intmax`).
- Root cause: `EVP_CipherUpdate` (EVP_aes_128_cbc) accumulated input length in an int; for large input sizes the output length computation overflowed and returned a *negative* outlen.
- Impact: negative length combined with pointer arithmetic accesses incorrect memory regions — typically segfault; memory-corruption primitive. Fixed OpenSSL 1.1.1j (CVE-2021-23840 / CVE-2020-36242).
- Exemplars: 1113025 (Internet Bug Bounty).

### 2. Length subtraction underflow bypassing a size cap (libcurl MQTT)
- Endpoint shape: `lib/mqtt.c mqtt_publish`, attacker controls `CURLOPT_POSTFIELDSIZE_LARGE` (i.e., a declared body size larger than the actual buffer).
- Payload: not stated — set CURLOPT_POSTFIELDSIZE_LARGE to a value that exceeds MAX_MQTT_MESSAGE_SIZE after underflow.
- Root cause: the MAX_MQTT_MESSAGE_SIZE check *subtracted* payload length before comparing; an oversized length underflowed (unsigned wrap) and passed the safety check. Two reports of the same flaw (incorrect arithmetic ordering).
- Impact: ASAN-confirmed heap-buffer-overflow read of size 314572800 in mqtt_publish; libcurl attempts a huge allocation / crashes. One report notes no direct remote exploitation; still accepted with ASAN proof.
- Exemplars: 3508500, 3508854 (curl).

### 3. Offset + size overflow bypassing a length check → heap overflow (PHP exif)
- Endpoint shape: PHP `exif_read_data()` / `exif_thumbnail_extract` on a crafted image; attacker controls EXIF `Thumbnail.offset` and `size` fields.
- Payload: not stated — craft an image whose EXIF thumbnail offset+size wraps a 32-bit int.
- Root cause: `ImageInfo->Thumbnail.offset + size` integer overflow on 32-bit systems wraps and bypasses the subsequent length check, leading to heap overflow in `estrndup`.
- Impact: ASAN-confirmed heap-buffer-overflow (READ of size 65535) in exif_thumbnail_extract (CVE-2018-14883); potential environment-info leak or segfault as part of a larger chain.
- Exemplars: 384477 (Internet Bug Bounty).

### 4. Signed type too small for a count → negative index out-of-bounds write (Perl eval)
- Endpoint shape: Perl interpreter `eval` on attacker-supplied source.
- Param: `source` (line count derived from it).
- Payload: not stated — source with a line/item count large enough to wrap I32.
- Root cause: `start`/`items` typed as I32; large line counts folded to *negative indexes*, causing out-of-bounds writes.
- Impact: crashes in Perl eval via OOB write.
- Exemplars: 272097 (Internet Bug Bounty).

### 5. Parser length-field overflow → heap OOB write with allocator-metadata corruption (libcurl + zlib gzip)
- Endpoint shape: libcurl with `Content-Encoding: gzip` responses; the client parses gzip headers manually.
- Param: none — attacker controls a server response's gzip header.
- Payload: not stated — an "endlessly large" gzip header (zlib < 1.2.0.4).
- Root cause: libcurl's manual gzip header parse lets a huge header overflow `z->avail_in`, shrinking the buffer and causing an out-of-bounds write before `free()`.
- Impact: PoC caused a *controlled* heap OOB write that overwrote allocator chunk metadata, triggering `free(): invalid pointer` crash — explicitly framed as a primitive toward RCE.
- Exemplars: 2956023 (curl).

### 6. Unbounded counter type in interpreter serialization (CPython unpickler)
- Endpoint shape: Python `_Unpickler_Read` when parsing malicious pickle data.
- Payload: not stated — attacker-supplied pickle.
- Root cause: integer overflow in `_Unpickler_Read` (read-length accounting) → out-of-bounds behavior.
- Impact: memory corruption when processing attacker-supplied pickle input.
- Exemplars: 103992 (Internet Bug Bounty).

### 7. Platform-width-dependent overflow in native deserialization/encoding (PHP core)
- Endpoint shape: PHP `unserialize()` on 32-bit platforms (bug 68044); PHP core `php_raw_url_encode` with certain input lengths (bug #71798).
- Payload: not stated for either.
- Root cause: integer overflow in the C implementation driven by input/length values exceeding platform int width. Note the 32-bit dependency in the unserialize case — width-specific bugs are valid findings on their own.
- Impact: CVE-2014-3669 (unserialize); confirmed fixed upstream (raw_url_encode).
- Exemplars: 104012, 126416 (Internet Bug Bounty).

### 8. Codegen counter overflow → crash in sandboxed-language compiler (mruby)
- Endpoint shape: mruby code generator — compile attacker-supplied Ruby source (shopify-scripts context, where sandboxed codegen bugs are in scope).
- Payload: not stated.
- Root cause: integer overflow in mruby's codegen counters results in a crash.
- Impact: crash; fixed upstream in mruby commit 6e0ba0085.
- Exemplars: 201903 (shopify-scripts).

### 9. Timestamp/ttl addition overflow → logic corruption / DoS (libcurl cookie Max-Age)
- Endpoint shape: HTTP response header `Set-Cookie` parsed by `lib/cookie.c`.
- Payload (verbatim): `Set-Cookie: session=abc123; Max-Age=9223372036854775807; Path=/`
- Root cause: the overflow check `CURL_OFF_T_MAX - now` and the addition `co->expires += now` are insufficient — near-INT64_MAX Max-Age still produces incorrect expiration values.
- Impact: attacker-controlled cookies persist beyond intended lifetime or expire immediately; cookie-jar pollution → denial of service. Note: a *logic/data-corruption* impact class, not memory corruption — still accepted.
- Exemplars: 3516186 (curl).

### 10. CLI option value × multiplier overflow → invalid parameter (curl --retry-delay / --retry-max-time)
- Endpoint shape: curl command line, `src/tool_operate.c` (`operator.c` in one report), `--retry-delay` and `--retry-max-time` options.
- Payloads (verbatim):
  - `curl --retry-delay 18446744073709552 -v 192.168.222.1:8080/test.html`
  - `curl --retry-max-time 18446744073709552 -v 127.0.0.1:8080/test.html`
- Root cause: `config->retry_delay*1000L` (resp. retry-max-time) overflows past 2^64 on 64-bit (and analogously 32-bit) when the option exceeds 18446744073709552 — the value wraps and the delay becomes invalid (e.g. computed as 384 instead of intended), breaking retry behavior.
- Impact: parameter becomes illegal/invalid; behavioral break rather than memory corruption. Both were accepted against curl — small local-only overflow bugs on popular tooling do get paid.
- Exemplars: 661847, 662412 (curl).

## Bypass / chain notes
- The recurring *bypass mechanism* in this class is arithmetic ordering: checks written as `if (len - x > MAX)` or `offset + size < MAX_LEN` can be defeated by under/overflow (records 3508500/3508854, 384477). When auditing, invert every subtraction-before-comparison and addition-inside-check you find.
- Wrap-to-negative is the second mechanism: signed counts (I32 in Perl, int in OpenSSL) flipping negative to pass `> 0` style guards (272097, 1113025).
- Boundary values that fired repeatedly: `9223372036854775807` (INT64_MAX, Max-Age), `18446744073709552` (just under 2^64/1000, so ×1000 wraps), `intmax` (INT_MAX input length), 32-bit thumbnail offset+size. Keep a boundary-value list: INT8/16/32/64 max, UINT max, UINT_MAX/1000 pre-multiplier, and value+1.
- Chaining is rare in these records (none recorded explicit chains), but reports themselves framed primitives: gzip-header OOB write overwriting allocator metadata "toward RCE" (2956023); exif heap overflow "as part of a larger chain" for info leak (384477). Frame your report in terms of the primitive it provides when direct exploitation isn't proven.

## Gotchas / what NOT to do
- Not every overflow is memory corruption — and that's fine. Max-Age overflow (3516186) and retry-delay wrap (661847) are pure logic/behavior bugs but were accepted. Don't dismiss "just a wrong value" bugs in widely deployed libraries.
- Do report ASAN evidence: heap-buffer-overflow with exact read size (65535, 314572800) appears in three accepted reports. Run PoCs under ASAN before submitting.
- Note platform width dependence honestly: several bugs are 32-bit-only (PHP unserialize, exif). Say so; it was still accepted (CVE-2014-3669, CVE-2018-14883).
- Distinguish severity claims from proof: 3508854 explicitly noted "no direct remote exploitation" — overclaiming RCE without evidence invites pushback.
- Sanity-check the multiplier: the curl boundary 18446744073709552 is UINT64_MAX/1000 — overflow happens in `value*1000L`, not in the option parse itself. Target the arithmetic site, not the parser.
- These records target core C libraries/interpreters via umbrella programs (Internet Bug Bounty, curl, shopify-scripts) — check whether your target program accepts upstream-dependency bugs before hunting this class in a web app; pure web-app integer overflow findings are absent from these records.

## Real-world impact examples
- CVE-2021-23840/CVE-2020-36242: OpenSSL EVP_CipherUpdate returned negative output length → wrong memory access/segfault (1113025).
- CVE-2018-14883: PHP exif_thumbnail_extract heap-buffer-overflow READ of size 65535 via thumbnail offset+size wrap (384477).
- CVE-2014-3669: PHP unserialize() integer overflow on 32-bit (104012).
- Controlled heap OOB write overwriting allocator chunk metadata → `free(): invalid pointer`, primitive toward RCE, in libcurl gzip handling (2956023).
- ASAN heap-buffer-overflow read of size 314572800 in curl mqtt_publish after size-check underflow (3508500).
- Perl eval OOB writes from I32 line-count folding → crashes (272097).
- Cookie-jar pollution/DoS via Set-Cookie Max-Age=9223372036854775807 producing wrong expirations in curl (3516186).