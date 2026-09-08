---
name: hunter-l3-use-after-free
description: "Use when hunting Use After Free on a target. Loads the L3 technique sheet: Use-after-free (UAF) is a memory-corruption class where a pointer to freed heap memory is dereferenced afterward."
domain: cybersecurity
subdomain: web
tags:
- web
- use-after-free
- hunting
- l3
version: '1.0'
---

# Use After Free — Technique Sheet

## Overview

Use-after-free (UAF) is a memory-corruption class where a pointer to freed heap memory is dereferenced afterward. In bug bounty practice it appears almost exclusively in native code surfaces: C/C++ libraries (curl, PHP extensions, mruby, LibSass, mod_http2), script engines, browser/renderer C++ bindings, and deserialization entry points. It pays when you can reach the native parser/VM with attacker-controlled input through a supported program interface — a CLI flag, a crafted file, a network protocol message, or a scripting API. Proven impact ranges from ASAN-confirmed crash/DoS (always accepted in IBB-style programs for widely deployed libs) up to memory disclosure, ASLR bypass, and claimed/confirmed RCE.

## Distinct sub-patterns

### 1. Free-then-log / free-then-report (freed pointer passed to error path)
- Endpoint shape: any code path where an error formatter receives a buffer that was just freed. Exemplar: `lib/vssh/libssh2.c ssh_check_fingerprint` in curl.
- Payload: not required; the bug fires on a failed SSH sha256 fingerprint check.
- Root cause: `fingerprint_b64` is `free()`d, then immediately passed to `failf()` which dereferences it for logging. The error-handling path is an afterthought that reuses a dead pointer.
- Impact: crash or leak of whatever now occupies the freed buffer into the error log.
- Exemplars: 1913733 (curl).
- Related variant — "free of uninitialized pointer in early-return branch": `doh_decode_rdata_name` in curl frees an uninitialized pointer when remaining buffer length <= 0, because `Curl_dyn_init` is only called after the early-return branch (id=3037326). Grep for early `return` paths that free before initialization.

### 2. Stale cross-object pointer left un-NULLed (attach/detach asymmetry)
- Endpoint shape: library state-machine callbacks holding raw pointers into a peer object. Exemplar: curl's `Curl_detach_connnection`/`Curl_attach_connnection` not updating OpenSSL `ex_data` (`data_idx`/`connectdata_key`), leaving `ossl_new_session_cb` callable with stale `Curl_easy *`.
- Payload: none stated; reporter had no repro.
- Root cause: detach/attach pairs that update one side of a pointer graph but not cached copies of it (here, OpenSSL ex_data).
- Impact: theoretical UAF → potential RCE via crafted `lockfunc`; reported even without reproduction because the surface is attacker-reachable.
- Exemplars: 1180380 (curl).

### 3. Scripting-API object outliving its native backing (JS binding lifetime)
- Endpoint shape: browser-exposed API object with inner binding object. Exemplar: Brave's `window.ethereum` (`JSEthereumProvider::Install`).
- Payload (verbatim):
```js
function triggerGC() {
  for (let i = 0; i < 100; i++) { let a = new Array(1000000); }
}
let uafObj = ethereum._metamask;
delete ethereum;
triggerGC();
console.log(await uafObj.isUnlocked());
```
- Root cause: `IsUnlocked` callback bound via `base::Unretained(provider.get())` assuming `_metamask` cannot outlive `ethereum`. Grabbing the inner object reference, deleting the outer, and forcing GC frees the provider; the callback then dereferences freed memory.
- Impact: renderer crash (Chrome renderer process); RCE claimed but not demonstrated.
- Exemplars: 1977252 (Brave).
- Technique: hold a reference to the *inner* object, destroy the *outer* owner, force GC in a loop, then call a method. Forced-GC-by-allocation-loop is the reliable trigger idiom.

### 4. Explicit release/destroy on one of two live references (AS3 / refcounted object split)
- Endpoint shape: scripting API exposing `release()` while a second reference still exists. Exemplar: Adobe Flash PSDK (AS3 PSDK).
- Payload (verbatim):
```
var ps:PSDK = PSDK.pSDK; var ps_:PSDK = PSDK.pSDK; ps.release(); ps_.currentTime;
```
- Root cause: `release()` frees inner pSDK memory but AS3 references stay alive; virtual functions can still be invoked on the freed block — a highly controllable free condition.
- Impact: working exploit for shellcode execution claimed; CVE-2016-4248.
- Exemplars: 151043 (IBB).

### 5. Recursion / reentrancy during object construction frees the VM stack
- Endpoint shape: class definition + constructor recursion in an embedded VM. Exemplar: mruby (shopify-scripts).
- Payload (verbatim):
```ruby
class M
def M.new(r)
    super
    new(0)
    end
end
M.new(0)
```
- Root cause: recursive instance creation during class definition frees the VM stack while `mrb_vm_exec` still writes into it (ASAN WRITE on freed stack region).
- Impact: heap UAF → memory corruption / DoS.
- Exemplars: 216700 (shopify-scripts).
- Sibling pattern — exception-handling opcodes reusing freed stack: mruby `OP_RESCUE` reuses a freed stack region during exception handling. Verbatim payload (id=295276):
```
def e
	proc
ensure z rescue 
	yield 
end

e { 
	Class * def * x
	new { 
		Class * 0
	} 
	ensure 0[] = 00end rescue 
	0
} rescue
z
```
  Crashed both mruby and mirb, ASAN-verified.
- Technique: when fuzzing embedded language VMs, target unusual control-flow opcodes (rescue/ensure, redefined `new`, `super` mid-recursion) — lifetime bugs cluster where the VM manipulates the stack itself.

### 6. Iterator/reference invalidated by mutation during operation (list iteration after node free)
- Endpoint shape: shared-pointer or linked-list mutation mid-operation. Exemplars:
  - LibSass `sassc` stdin: payload verbatim `@P#{()if(0,0<0,0)}` — `if()` evaluation frees a shared pointer later dereferenced in `SharedPtr::incRefCount` (ASAN heap-use-after-free) (id=221289).
  - curl cookie replacement: `lib/cookie.c replace_existing()` accesses cookie data after freeing the replaced node during list iteration (id=3516202).
  - PHP `Future.remove_done_callback` (asyncio): callbacks removed from the done-callback list while it was being iterated → OOB access in `_asyncio_Future_remove_done_callback` (id=216151).
- Impact: ASAN crash in all three; curl cookie case assessed as potential arbitrary code execution.
- Technique: any code that mutates a container while iterating it or holding an element pointer across a call that can free.

### 7. Deserialization entry points (unserialize / phar / ArrayObject)
- Endpoint shape: `unserialize($data)`, `phar` file parsing, `ArrayObject` deserialization — the single densest cluster in the records (all PHP/IBB).
- Payloads: mostly "malicious serialized data"; one stated as "malicious serialized data with invalid array size". The mb_ereg/oniguruma one has a verbatim base64-ish crafted pattern `KCg/KAApMCspKysrKCgoMFxnPDA+KTApfCgpKSsrKysoKD8oMSkoMFxnPDA+KSkrKysrKyswKigpKSsrKysoKD8oMSkoMFxnPDE+KSspKysrKysrKysrKyooKSkrKysrKCg/KDEpKCgwKVxnPDA+KSspKysoKSkrMCsrKisrKygoKDBcZzwwPikpKigpKSsrKysoKD8oMSkoMFxnPDA+KSspKysrKysrKysrKyp8KSsrKysqKysrKCg/KDEpKCgwKVxnPDA+KSspKysrKysrKysrKCkpKysqfCkrKysrKCg/` fed as the `pattern` argument to `mb_ereg()` (id=692040).
- Root causes seen (each distinct):
  - ArrayObject deserialization UAF (bugs.php.net#73144) (id=180909).
  - Generic PHP7 `unserialize()` freed-memory access (bugs.php.net#74614) (id=245956).
  - Improper hash-API key deletion with invalid array size → heap UAF (CVE-2017-12932) (id=261335).
  - `zval_get_type` in Zend/zend_types.h touching a freed zval (CVE-2017-12934) (id=261338).
  - `mb_ereg()` oniguruma 6.9.0 UAF in `match_at()` (READ of size 8) (id=692040).
  - Malformed phar: freed memory used as a hash key inserted into the alias-filename hash table → memory info leak (CVE-2020-7068) (id=950299).
- Impact: memory corruption/crash; phar case = info leak; several flagged as potential RCE with untrusted input.
- Technique: fuzz `unserialize()` with objects/arrays whose sizes are inconsistent (invalid array size is the recurring trigger), and recycle serialized structures through hash-table insertion paths.

### 8. Native extension parsers fed crafted files
- Endpoint shape: one function call taking a file/blob. Concrete examples and payloads:
  - PHP `exif_read_data(file_get_contents("/full/path/to/test.jpg"))` with a crafted JPEG: `exif_read_from_file` frees the stream then dereferences it again — ASAN READ of size 8 in `_php_stream_free` (id=371135). Impact: DoS, corruption, info disclosure, potential RCE.
  - PHP `imagescale()` with crafted image line/window size: `_gdContributionsAlloc` frees uninitialized `.Weights` pointers when the `overflow2` check for `windows_size` fails — the loop's `u` decrement to -1 skips the guard (id=478367). Impact: local safe-mode bypass primitive; potentially remote.
  - PHP `xmlrpc_decode()` with malformed XMLRPC input → UAF and OOB access; potential code execution if parsing untrusted public API input (id=477896).
  - XML::LibXML `Node::replaceChild` — replaceChild frees then accesses the replaced node (CVE-2017-10672) (id=259390).
  - PuTTY `puttygen -L` with a crafted `.ppk`: `main()` reads a previously freed strbuf in cmdgen.c — ASAN READ of size 8 (id=481532).
  - Monero epee `array_entry_t` copy construction: no explicit copy constructor, so the implicit one copies an iterator into the source array; `delete ae; ae2->get_next_val();` is a UAF (id=511317). Payload verbatim: `auto ae2 = new epee::serialization::array_entry_t<uint64_t>(*ae); ... delete ae; ae2->get_next_val();`
- Technique: for C/C++ parsers, target double-lifetime around stream/free wrappers (`_php_stream_free` pattern) and implicit copy constructors holding iterators.

### 9. Network protocol state machines (IRC, HTTP/2, SMB)
- Endpoint shape: a sequence of protocol commands / connection reuse.
- Payloads verbatim:
  - Irssi (id=247028) — the exact IRC command sequence:
```
CAP LS
NICK root
USER root root /dev/stdin :root
MODE  +i
WHOIS root
WHO +00000000000000000000o00
```
    Heap-UAF in `nicklist_remove_hash` during channel destruction in irssi < 1.0.4.
  - curl SMB two-URL one-liner (ids 3591944, 3591956 — dupes of the same bug):
```
curl -u guest:guest "smb://127.0.0.1:5445/share1/file1" -o /dev/null "smb://127.0.0.1:5445/share2/file2" -o /dev/null
```
    Root cause: `smb_parse_url_path` sets `req->path` as a non-owning pointer into connection-owned `smbc->share`; on connection reuse the needle connection is freed (`smb_conn_dtor`) before `strlen(req->path)` in `smb_send_open`. ASAN read of size 1; guaranteed crash.
  - Apache mod_http2 — three distinct bugs, all network-triggered, no payloads stated:
    - Crafted HTTP/2 request accessing request data from a destroyed memory pool, poisoning `the_request` (id=527042).
    - `H2PushResource` very early pushes copying configured push link header values into the pushing request's pool without lifetime management → ASAN SEGV on ASCII string addresses, remote unauthenticated DoS (id=677557).
    - Race during connection shutdown: nghttp2 retains a stream reference after mod_http2 destroys it → read-after-free in httpd worker threads via fuzzed network input (id=680415).
- Technique: enumerate protocol command sequences (fuzzed network input), and force connection reuse (two URLs on one command line) against non-owning pointers into per-connection state.

### 10. Async write/error-path double free of callback objects
- Endpoint shape: TLS socket write + abrupt destroy. Exemplar: Node.js HTTPS server, `tls_wrap.cc StreamBase::WriteV`.
- Payload (verbatim): `socket.write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Keep-alive\r\n\r\n"); socket.destroy()` on `'data'`.
- Root cause: `TLSWrap::DoWrite` frees the WriteWrap via `EncOut`/`InvokeQueued` on a broken-pipe write error without returning an error, so `StreamBase::Write` returns the freed object for later use.
- Impact: ASAN-confirmed heap-UAF crash; RCE claimed.
- Exemplars: 988103 (Node.js).

### 11. Option/setopt string lifetime (freed string left dangling in state)
- Endpoint shape: `curl_easy_setopt`/`getinfo` string options. Exemplar: curl `CURLOPT_REFERER`.
- Payload (verbatim):
```c
curl_easy_setopt(curl, CURLOPT_REFERER, "http://example.com/secret-A");
curl_easy_perform(curl);
curl_easy_setopt(curl, CURLOPT_REFERER, "http://example.com/B");
curl_easy_getinfo(curl, CURLINFO_REFERER, &ref);
```
- Root cause: replacing/clearing CURLOPT_REFERER frees the old string but leaves `state.referer.ptr` dangling — setopt lacks the `bufref` mirror that CURLOPT_URL has. Three vectors: getinfo, NULL-set, and `curl_easy_duphandle()`.
- Impact: ASAN-confirmed heap-UAF on the referer string, read-only and in-process (bytes don't reach the wire).
- Exemplars: 3774279 (curl).

### 12. Connection-reuse / resolver-timeout races in multi-handle
- Endpoint shape: `curl_multi_perform` with DoH resolver timeout + `CURLOPT_PROXY`: freed DoH connection still referenced by the multi handle (id=3022041). Impact: UAF read; reporter notes it could bypass ASLR.
- Related: Set-Cookie `replace_existing` (covered in pattern 6) and the SMB reuse bug (pattern 9) — both are connection-reuse lifetime bugs.
- Technique: combine features (DoH + proxy + multi), since lifetime bugs live in interaction code.

## Bypass / chain notes

- ASAN is the primary detection instrument in nearly every record — several reporters note the bug is "reliably detectable only under AddressSanitizer" (id=3516202) or invisible without it. When testing native targets, build/obtain ASAN versions.
- Two-URL-one-command-line is a minimal connection-reuse trigger (SMB curl): reuse the connection so the first request's teardown frees state the second request still points into.
- Forced GC loop (allocate 100 × large arrays) is the standard way to make a JS-binding lifetime bug deterministic (Brave id=1977252).
- Race-condition variant: mod_http2's shutdown UAF needs concurrent activity while the connection tears down (fuzzed input in worker threads).
- ASLR bypass chaining: a UAF *read* of repurposed heap can leak addresses even when RCE isn't demonstrated (curl DoH id=3022041) — report reads as info disclosure when write primitives aren't proven.
- Hash-table insertion of freed memory (phar id=950299) chains the UAF into an info leak via the alias hash table.
- Chains across multiple findings were not present in any record (every record's chain field was empty) — impact claims beyond crash rely on the reporter's argument, not demonstrated chains.

## Gotchas / what NOT to do

- Don't report without a reproducer when one is obtainable: curl id=1180380 was a theoretical UAF with no repro — impact stayed speculative. id=3037326 and 3022041 similarly carried hedged impact ("possibly", "unsure it can gain RCE").
- Don't claim RCE without demonstrating it — several records explicitly note RCE was "claimed but not demonstrated" (Brave id=1977252, Node id=988103, PHP id=245956). Crash + ASAN trace is a solid report on its own for widely deployed libraries.
- Don't test only the happy path: nearly every bug fires on error/destruction/reuse paths — failed fingerprint checks, broken-pipe writes, connection teardown, invalid array sizes, early-return branches.
- Don't ignore uninitialized-pointer-free bugs ("UAF-adjacent"): `doh_decode_rdata_name` (id=3037326) and `_gdContributionsAlloc` (id=478367) are free-of-uninitialized-pointer, reported under the same class.
- Don't forget duplicate submissions: the SMB curl bug was filed twice (3591944/3591956) — check for existing reports of the same stack trace before filing.
- Read-only in-process UAFs (curl referer id=3774279) have bounded impact — set expectations honestly rather than claiming wire-relevant exploitation.

## Real-world impact examples

- CVE-2016-4248 (Flash PSDK AS3): working shellcode-execution exploit via controllable `release()` on a doubly-referenced object (id=151043).
- CVE-2017-12932 / CVE-2017-12934 (PHP unserialize): heap UAFs from malformed serialized data / invalid array size, impacting PHP integrity (ids 261335, 261338).
- CVE-2017-10672 (XML::LibXML replaceChild): confirmed UAF via node replacement (id=259390).
- CVE-2020-7068 (PHP phar): freed memory used as hash key → memory information leak (id=950299).
- curl SMB: ASAN-confirmed guaranteed crash from a two-URL command line — trivially reproducible DoS in a library shipped everywhere (ids 3591944/3591956).
- Node.js TLS: ASAN-reproduced heap-UAF crash in the HTTPS server write path with RCE claimed (id=988103).
- Apache mod_http2: remote unauthenticated DoS via crafted HTTP/2 requests and early pushes, with possible code execution if response headers are influenceable (ids 677557, 680415).
- PHP exif: ASAN READ of size 8 in `_php_stream_free` on a crafted JPEG — DoS, corruption, info disclosure, potential RCE (id=371135).