---
name: hunter-l3-null-pointer-dereference
description: "Use when hunting NULL Pointer Dereference on a target. Loads the L3 technique sheet: NULL pointer dereference bugs occur when code uses a pointer that a prior operation (an encoding lookup, an allocation, a parser state machine, a vector accessor) failed to produce, without checking it first."
domain: cybersecurity
subdomain: web
tags:
- web
- null-pointer-dereference
- hunting
- l3
version: '1.0'
---

# NULL Pointer Dereference — Technique Sheet

## Overview

NULL pointer dereference bugs occur when code uses a pointer that a prior operation (an encoding lookup, an allocation, a parser state machine, a vector accessor) failed to produce, without checking it first. In bug bounty practice this class almost always lands as an availability/DoS finding — a remote or authenticated crash (SIGSEGV) — rather than code execution, but it pays reliably in Internet Bug Bounty (PHP, libxml2, OpenSSH, curl) and cryptocurrency programs (Monero) where a single crafted input kills a daemon, a wallet, or a server worker. The winning pattern across these records is always the same: identify a code path where a "not found"/"empty"/"out of memory" result flows unchecked into a dereference, and deliver it with a minimal PoC.

## Distinct sub-patterns

### 1. Missing allocation-failure check in a size-controlled read path (OpenSSH SFTP)

- Endpoint shape: authenticated SFTP session; the client drives server-side read requests. The attacker controls read sizes up to 4GB.
- Payload: none needed as input bytes — the trigger is a malicious client requesting large SFTP reads (up to 4GB buffers) under low-memory conditions.
- Root cause: the sftp server read path allocates a buffer sized by an attacker-influenced request but never checks the allocation result; on allocation failure it dereferences NULL. The server crashes the authenticated user's sftp connection — and on thread-based servers the crash takes down legitimate users too.
- Impact: authenticated remote DoS; up to 4GB unchecked buffer allocations as an amplification vector. CVE issued.
- Exemplar: id=2070810 (Internet Bug Bounty).

### 2. Encoding-lookup NULL flows unchecked into a converter (PHP exif/mbstring)

- Endpoint shape: PHP function `exif_read_data()`, param `file` — any app that parses user-supplied images from EXIF data.
- Payload: payload not stated in record; it is a crafted JPEG whose EXIF user comment is JIS-encoded while `encode_jis` resolves to an empty string.
- Root cause: `encode_jis` is empty, so `zend_multibyte_fetch_encoding()` returns NULL; that NULL is passed unchecked into the mbstring converter, which dereferences it in `mbfl_convert_filter_get_vtbl`.
- Impact: crash of PHP (process segfault) when compiled with mbstring; reproduced on Linux, macOS and Windows — broad, cheap remote DoS against any app calling `exif_read_data()` on attacker images. Fixed in PHP (this and the related GD fix shipped across 5.5.37 / 5.6.23 / 7.0.8 era releases).
- Exemplar: id=152232 (Internet Bug Bounty).

### 3. Malformed structure parsing in recover/lenient mode (libxml2)

- Endpoint shape: XML parser processing untrusted XML, specifically in recover mode (`xmllint --recover` and equivalent lenient parser configurations).
- Payload (verbatim): `<!DOCTYPE[<!ELEMENT l((|s)>`
- Root cause: in recover mode, libxml2 continues parsing a malformed internal subset it should have aborted; the recovery path proceeds with parser state that was never initialized, producing a NULL dereference.
- Impact: segfault (SIGSEGV) in xmllint --recover on malformed XML — remote DoS wherever the application enables recovery mode on untrusted input.
- Exemplar: id=262665 (Internet Bug Bounty).
- Note: the lenient/recover mode is the key hunting insight — strict-mode parsing rejects this input early; the bug lives in the "keep going anyway" path.

### 4. Image-scaling NULL dereference in GD (PHP _gdScaleVert)

- Endpoint shape: PHP GD image scaling (`_gdScaleVert`, the vertical scaling routine used by `imagescale()`-type operations on user-supplied images).
- Payload: none stated.
- Root cause: NULL pointer dereference inside `_gdScaleVert` during image scaling (PHP bug #72407) — the scaled-output/state pointer is left NULL on certain inputs and used unchecked.
- Impact: NULL dereference crash during image scaling; fixed in PHP 5.5.37, 5.6.23 and 7.0.8; $500 bounty.
- Exemplar: id=146944 (Internet Bug Bounty).
- Hunting template: any image-processing endpoint accepting user uploads (avatars, thumbnails) is the attack surface; crash the scaler with degenerate dimensions/formats.

### 5. HTTP response parser NULL dereference (PHP)

- Endpoint shape: PHP's HTTP response parsing (the client-side parser that consumes HTTP responses — e.g. wrappers/streams consuming a remote server's response).
- Payload: none stated.
- Root cause: improper handling of a malformed HTTP response dereferences a NULL pointer in the HTTP header path — a header-lookup/parse result is used without a NULL check.
- Impact: PHP segment fault via inappropriate HTTP response parsing. Attack shape: point PHP at a server you control (or MITM a response) and return the malformed header set.
- Exemplar: id=305973 (Internet Bug Bounty).

### 6. Empty-container accessor after a guard that permits the empty case (Monero wallet RPC)

- Endpoint shape: `POST /gettransactions` — wallet RPC calling the daemon (reached via `check_tx_key` / `check_tx_proof`); attacker-influenced param `txs_hashes`. The realistic attack surface is a malicious/untrusted daemon replying to a wallet, or a crafted response injected into the wallet-RPC flow.
- Payload (verbatim, the *response* that fired):
  `{"status":"OK","untrusted":false,"credits":0,"top_hash":"","txs":[],"txs_as_hex":["<hex>"],"missed_tx":[]}`
- Root cause: `wallet2` has a guard that accepts `txs_as_hex`-only responses (an added compatibility path), but downstream code calls `std::vector::front()` on the `txs` vector — which is empty in exactly the responses that guard permits. `front()` on an empty vector is undefined behavior → SIGSEGV.
- Impact: a single crafted `/gettransactions` response kills `monero-wallet-rpc` with signal 11 during `check_tx_key` — a hard availability hit on payment verification. No RCE demonstrated; crash-only.
- Exemplar: id=3693636 (Monero).
- Hunting insight: this is a "new feature added without updating every consumer" bug — a response schema that gained an alternate valid shape (`txs_as_hex` without `txs`) while old code still assumed `txs` is non-empty.

### 7. URL-state field NULL from a "convenience" flag (libcurl URL API)

- Endpoint shape: libcurl URL API — `curl_url_set()` with `CURLU_DEFAULT_SCHEME`, then reading `CURLUPART_REDIRECT_URL` (via `redirect_url()`/`urlget_url()`).
- Payload (verbatim code trigger):
  `rc = curl_url_set(u, CURLUPART_URL, "/newpath", CURLU_DEFAULT_SCHEME);`
  against a CURLU handle that holds host/path but no scheme.
- Root cause: `urlget_url()` can generate a URL string using the DEFAULT_SCHEME convenience flag without ever storing `u->scheme` on the handle; `redirect_url()` then dereferences `u->scheme` via `strlen()` before any NULL check.
- Impact: PoC crashes the embedding process (SIGSEGV) on relative-URL + `CURLU_DEFAULT_SCHEME` input; claimed as crash/availability DoS, no code execution.
- Exemplar: id=3736234 (curl).
- Hunting insight: API-convenience flags ("default to X when absent") frequently create a derived state that was never materialized — read paths that consume the derived field without the null check.

## Bypass / chain notes

The records contain no multi-step chains (all `chain: (none)`), but three bypass-adjacent themes recur:

- Lenient-mode escape (libxml2): strict parsers reject malformed input; enabling recover mode moves execution onto the unrecovered-state path. If a target configures recovery/tolerant parsing, malformed-structure payloads like `<!DOCTYPE[<!ELEMENT l((|s)>` become viable.
- Guard-vs-consumer mismatch (Monero): the "bypass" is a legitimate feature path (`txs_as_hex`-only responses) that dodges the existing assumption `txs` is populated. Look for recently added alternate response shapes and grep for old accessors (`front()`, `[0]`, `.first`) on the original field.
- Default-filling flags (curl): `CURLU_DEFAULT_SCHEME` makes generation succeed where it would otherwise fail, masking that the scheme field was never set — the failure is deferred to a later read path.

Also note the low-memory variant (OpenSSH SFTP): no filter to bypass, but allocation failure is itself a trigger — large attacker-sized requests (4GB) plus memory pressure converts an unchecked allocation into a NULL deref. Report should note both the amplification (4GB per request) and the blast radius on thread-based servers (crash affects legitimate users).

## Gotchas / what NOT to do

- Do not frame these as memory-corruption/RCE wins unless proven. Every record here explicitly claims crash/availability only ("no RCE demonstrated", "crash/availability DoS, no code execution"). Overclaiming invites invalidation.
- Crash-only findings still need full repro conditions: PHP builds mattered (`exif_read_data` bug only reproduces with mbstring compiled in); libxml2 only in recover mode; OpenSSH only under low memory. State the required configuration.
- For parser bugs, confirm which side is attacker-controlled. The Monero and PHP HTTP-response bugs fire on a *response* — the attacker needs control of the responding server (malicious daemon, MITM, own HTTP server). A crash you trigger by talking to yourself is not a bug; a crash the victim's wallet/parser suffers against your crafted response is.
- For the Monero case, `std::vector::front()` on empty is UB but in practice segfaults — report the observed signal (SIGSEGV / signal 11) with the exact response JSON, not just the theoretical UB.
- Don't send the same payload expecting universal crashes: `_gdScaleVert` is version-bound (fixed in 5.5.37/5.6.23/7.0.8) — test against the program's actual versions before reporting.
- API-level bugs (curl) need a compilable PoC snippet, not a network request — include the exact `curl_url_set` call sequence as in the record.

## Real-world impact examples

- monero-wallet-rpc killed by one JSON response (id=3693636): `check_tx_key`/`check_tx_proof` — the payment-verification path — dies on signal 11 from a response with `"status":"OK","txs":[]` plus one `txs_as_hex` blob. Payment verification is a core availability property for a wallet; hard availability hit, no RCE shown.
- Authenticated 4GB SFTP read DoS (id=2070810): malicious client forces up to 4GB unchecked allocations; under low memory the server NULL-derefs, killing the sftp connection — and on thread-based servers, other users' sessions with it. CVE issued.
- PHP-wide image/EXIF DoS (ids 146944, 152232): crafted JPEG crashes PHP via GD scaling (`_gdScaleVert`, $500, fixed in 5.5.37/5.6.23/7.0.8) or via `exif_read_data()` when mbstring is compiled in — the latter reproduced on Linux, macOS and Windows, meaning any PHP app parsing attacker EXIF was one image away from a 500/crash.
- xmllint --recover SIGSEGV (id=262665) from the 27-byte input `<!DOCTYPE[<!ELEMENT l((|s)>` — remote DoS wherever lenient XML parsing of untrusted input is enabled.
- libcurl process crash (id=3736234): a two-step URL-API sequence crashes any embedding application, demonstrated with the exact `curl_url_set(u, CURLUPART_URL, "/newpath", CURLU_DEFAULT_SCHEME)` call against a scheme-less handle.
- PHP HTTP response parsing segfault (id=305973): a malformed response served to PHP's HTTP parser crashes the process via the header path.