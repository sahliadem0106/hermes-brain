---
name: hunter-l3-double-free
description: "Use when hunting Double Free on a target. Loads the L3 technique sheet: Double free is a memory-corruption bug class where the same heap allocation is passed to a free routine twice, corrupting the allocator's freelist and opening a path to arbitrary code execution."
domain: cybersecurity
subdomain: web
tags:
- web
- double-free
- hunting
- l3
version: '1.0'
---

# Double Free — Technique Sheet

## Overview

Double free is a memory-corruption bug class where the same heap allocation is passed to a free routine twice, corrupting the allocator's freelist and opening a path to arbitrary code execution. In bug bounty practice, these almost always live in parsing/serialization code (XML/WDDX, YAML, regex compilers, protocol decoders) or in error/cleanup paths of C libraries (curl, PHP extensions, kernel network stacks). They pay at the very top of the market — Internet Bug Bounty (PHP, Ruby, curl core), curl's own program, and high-value targets like PlayStation — because a confirmed double free with allocator control is routinely escalated to RCE or kernel privilege escalation. The hunter's job is almost never to find the bug from the wire: it is to read the free paths of parsing code and construct malformed inputs that steer execution into an error branch that frees without nulling.

## Distinct sub-patterns

### 1. Deserializer frees a variable name twice on malformed element (WDDX/XML)

- Endpoint shape: any PHP application calling `wddx_deserialize()` on attacker-controlled XML (WDDX packets).
- Payload (verbatim):
```xml
<?xml version='1.0' ?>
<!DOCTYPE wddxPacket SYSTEM 'wddx_0100.dtd'>
<wddxPacket version='1.0'>
	<array>
		<var name="XXXXXXXX">
			<boolean value="none">AAAAAAA</boolean>
		</var>
		<var name="YYYYYYYY">
			<var name="ZZZZZZZZ">
				<var name="EZEZEZEZ">
				</var>
			</var>
		</var>
	</array>
</wddxPacket>
```
  The trigger is the `<boolean value="none">` element inside a named `<var>` — an invalid boolean value drives the parser into an error path.
- Root cause: `php_wddx_process_data` frees `ent->varname` twice when deserializing the malformed `<boolean value="none">` element, corrupting the heap freelist.
- Impact proven: SIGSEGV crash with the PoC; the double free lets the attacker make the allocator return an arbitrary GOT address (e.g. `memcpy@got`), potentially leading to remote code execution. Works on PHP 7.0.x.
- Exemplar: id=146255 (Internet Bug Bounty).

### 2. Serializer/unserializer error path double-frees the var_hash (YAML)

- Endpoint shape: `yaml_parse()` / `yaml_parse_file()` / `yaml_parse_url()` fed a crafted YAML document containing the `!php/object` tag.
- Payload (verbatim):
```
a:  !php/object O:0:1
b: !php/object
```
  The trigger is a `!php/object` tag whose payload is a malformed serialized object (`O:0:1`) plus a second, empty `!php/object`.
- Root cause: `php_var_unserialize()`'s error path frees `var_hash`, and the same `var_hash` is freed again before the function returns.
- Impact proven: crash inside `_efree` and an exploitable EIP-control demonstration (DEP access violation) showing arbitrary code execution.
- Exemplar: id=73256 (Internet Bug Bounty).

### 3. Regex compiler frees compiled pattern memory twice (Ruby)

- Endpoint shape: `Regexp.compile` / regexp literals compiled from attacker-influenced source. Any code path where user input becomes a regex source string (including via `Marshal.load`, which can carry compiled regex source).
- Payload (verbatim):
```
ruby -e '/(\x15\x17\xE2\xF5\xF5\xF5\xC2\x04\x08J,\x00\xD0\x00\x00(?(1)\xF5\xF5\xF5\xD7\xF5\xF5\xF5\x87\x04\xFA555\xBEJ,\x18FF\x15\xFF|\x03\x01\x00\x01\x00\x00\x8F\r|)44\x00\x8F\r|)+/m'
```
  Note the structure: a group with a conditional `(?(1)...)`, multiple alternations with high-byte/`0xF5`-filled bytes, and a `+` quantifier with `/m` — crafted bytes that corrupt the regex compiler's state machine.
- Root cause: a bug in Ruby Regexp compilation frees the same memory twice when compiling the crafted source string (CVE-2022-28738).
- Impact proven: double free on compilation; may lead to RCE when combined with `Marshal.load`.
- Exemplar: id=1549636 (Internet Bug Bounty).

### 4. Multibyte regex replace double free (PHP mbstring)

- Endpoint shape: PHP internal function `_php_mb_regex_ereg_replace_exec` — i.e. `mb_ereg_replace()`-family calls with attacker-controlled pattern/replacement.
- Payload: not stated in the record.
- Root cause: double free in `_php_mb_regex_ereg_replace_exec`.
- Impact proven: confirmed double free (PHP bug #72402) that can be turned into code execution; already fixed upstream.
- Exemplar: id=146200 (Internet Bug Bounty).

### 5. Locale parser double free (PHP intl)

- Endpoint shape: `Locale::parseLocale` (PHP intl extension) with attacker-influenced locale strings.
- Payload: not stated in the record.
- Root cause: `Locale::parseLocale` frees the same memory region twice.
- Impact proven: double-free memory corruption in PHP (reported upstream as bugs.php.net #67349).
- Exemplar: id=35102 (Internet Bug Bounty).

### 6. Free-without-nulling, then a second free on failure/teardown path (curl MQTT)

- Endpoint shape: `lib/mqtt.c`, `mqtt_doing()` — reachable by connecting to a server speaking MQTT (curl's MQTT client support).
- Payload: not stated (protocol-level trigger, no string payload).
- Root cause: `mqtt_doing()` frees `mq->sendleftovers` without nulling it after a partial send, so a subsequent failure path frees the same pointer again.
- Impact proven: demonstrated in a debugger — after a partial `mqtt_send` followed by a failed send, `mqtt_done()` frees the already-freed pointer and the CRT throws a double-free exception, yielding memory corruption potentially exploitable for code execution.
- Exemplar: id=3045390 (curl).

### 7. Free-after-list-removal plus error-path free (curl cookie engine)

- Endpoint shape: `lib/cookie.c`, `Curl_cookie_add()` — the cookie parser handling `Set-Cookie` headers from an HTTP server (i.e. a server-controlled replace_existing scenario).
- Payload (verbatim, the offending code shape):
```c
if (replace_n) {
    struct Cookie *repl = Curl_node_elem(replace_n);
    Curl_node_remove(replace_n);
    freecookie(repl);
}

fail:
    freecookie(co);
    return NULL;
```
- Root cause: Cookie objects are freed without ensuring they have not already been removed from the list (in the `replace_existing` path) and are then freed again on error paths.
- Impact proven: identified double-free conditions in cookie management leading to undefined behavior, segmentation faults, potential arbitrary code execution, and denial of service.
- Exemplar: id=3117697 (curl).

### 8. Failed-start free plus unconditional cleanup free (curl GSASL / SASL SCRAM)

- Endpoint shape: libcurl GSASL authentication over IMAP/SMTP, SASL mechanism `SCRAM-SHA-256` / `SCRAM-SHA-1`. The trigger is simply a server whose SCRAM exchange makes `gsasl_client_start()` fail.
- Payload (verbatim, the state that triggers it):
```c
return GSASL_UNKNOWN_MECHANISM;
```
  i.e. a server response that causes the GSASL client start to fail with an unknown-mechanism error.
- Root cause: `Curl_auth_gsasl_is_supported()` frees `gsasl->ctx` on failed `gsasl_client_start()` without nulling it, then `Curl_auth_gsasl_cleanup()` frees it again unconditionally at teardown.
- Impact proven: ASan run confirmed double-free on the actual libgsasl allocations — first free in `Curl_auth_gsasl_is_supported` (gsasl.c:49), second free in `Curl_auth_gsasl_cleanup` (gsasl.c:113) via `gsasl_conn_dtor`.
- Exemplar: id=3735193 (curl).

### 9. realloc-failure teardown double free (curl krb5 / security.c)

- Endpoint shape: `curl lib/security.c`, `read_data()` — the krb5/ftp Kerberos security layer; trigger is an allocation size that makes `Curl_saferealloc()` fail during teardown.
- Payload (verbatim, the reproducing condition):
```c
int len = 0x7fffffff; void *ptr2 = realloc(ptr, len);
```
  A huge length (`0x7fffffff`) forces `realloc` to fail, taking the error path.
- Root cause: CVE-2019-5481 — `read_data()` double-frees `buf->data` on teardown when `Curl_saferealloc()` fails.
- Impact proven: the `realloc()` failure with `len=0x7fffffff` was reproduced, which can lead to the double-free; the actual double-free was not reproduced in the report itself.
- Exemplar: id=686823 (curl).

### 10. Decoder double free leading to write-after-free (VLC libfaad)

- Endpoint shape: VLC `libfaad_plugin` during MKV (Matroska) audio decoding — trigger is a crafted Matroska `SimpleBlock` containing AAC data.
- Payload: not stated (crafted SimpleBlock binary data).
- Root cause: crafted Matroska SimpleBlock data triggers a double free in libfaad_plugin, leading to a write to freed memory.
- Impact proven: access-violation crash; possible to read or write memory data.
- Exemplar: id=503208 (VLC, European Commission - DIGIT).

### 11. Kernel mbuf double free via stale double pointer (FreeBSD/PS4 IPv6)

- Endpoint shape: kernel IPv6 input path on loopback — open a `SOCK_RAW` socket, send fragmented IPv6 packets to loopback; the bug sits in `IP6_EXTHDR_CHECK` usage inside `dest6_input()` / `frag6_input()`.
- Payload: not stated (raw packet crafting; fragmented IPv6 packets to loopback).
- Root cause: `IP6_EXTHDR_CHECK` can free the mbuf on loopback, but `dest6_input()`/`frag6_input()` don't update the double pointer, causing a double free / use-after-free.
- Impact proven: PoC escalated privileges to kernel on FreeBSD; chained with a WebKit exploit enables a fully remote attack on PS4 — stealing/manipulating user data and dumping/running pirated games.
- Chain (verbatim from record):
  1. Open SOCK_RAW socket from WebKit process on PS4
  2. Send fragmented IPv6 packets to loopback
  3. Trigger IP6_EXTHDR_CHECK double free in dest6_input/frag6_input
- Exemplar: id=943231 (PlayStation).

## Bypass / chain notes

- Marshal → RCE chain (Ruby): CVE-2022-28738's double free in `Regexp.compile` "may lead to RCE when combined with `Marshal.load`" — crafted serialized objects can carry regex source, so a deserialization sink becomes the double-free delivery mechanism. If you find a `Marshal.load` sink, graft this regex payload onto it.
- PS4 kernel chain: the IPv6 double free is local (raw socket + loopback) but becomes fully remote when chained behind a WebKit renderer exploit — open `SOCK_RAW` from the WebKit process, send fragmented IPv6 to loopback, trigger `dest6_input`/`frag6_input`. Lesson: "local-only" kernel double frees are remote-capable if any renderer/scripting context can open raw sockets.
- GOT-targeting via freelist corruption (PHP WDDX): the double free was used to make the allocator return an arbitrary GOT address (`memcpy@got`), turning a heap bug into a control-flow write. The exploit primitive is "allocate over a function pointer table," not just crash.
- realloc-failure precondition (curl krb5): the double free only fires when `Curl_saferealloc` fails — force it with absurd lengths (`len = 0x7fffffff`). Failure-path bugs often need a resource-exhaustion or boundary condition to reach the broken branch.
- Server-controlled triggers (curl cookie/GSASL/MQTT): a malicious server is enough — send a `Set-Cookie` replacement sequence, advertise then break SCRAM (`return GSASL_UNKNOWN_MECHANISM;`), or send a partial MQTT send followed by a failed one. No client-side user interaction beyond connecting to your server.

## Gotchas / what NOT to do

- Don't stop at the crash. Records that paid well showed more than SIGSEGV: EIP control (id=73256), debugger-verified double free with exploitation path (id=3045390), ASan stack traces naming both free sites (id=3735193), or an escalation chain (id=943231). Run ASan and include both free-site frames.
- Don't claim the final free without reproducing the precondition. In id=686823 the reporter reproduced the `realloc` failure that *can* lead to the double free but explicitly noted the actual double free was not reproduced — the report still landed (CVE-2019-5481) because the root cause was precise. Be honest about which stage you proved.
- Don't report "double free" when it's really use-after-free or vice versa without checking: id=943231's stale-double-pointer bug is both — the mbuf is freed and the pointer is stale. Name the exact pair of free sites (function + line) as the ASan-confirmed GSASL report did.
- Don't assume the bug needs a huge crafted file. Several triggers are tiny: a two-line YAML doc, one malformed `<boolean value="none">` element, a single server response. Minimize the PoC to the exact structural trigger.
- Don't fixate on user-facing endpoints. Most of these are library-internal paths (cookie engine, SASL cleanup, MQTT state machine, kernel input paths) reached via a malicious server or local raw sockets.

## Real-world impact examples

- PHP WDDX double free (id=146255): SIGSEGV PoC; attacker can force the allocator to return an arbitrary GOT address such as `memcpy@got`, enabling potential RCE on PHP 7.0.x.
- PHP yaml_parse (id=73256): crash in `_efree` plus a demonstrated DEP access violation with EIP control — arbitrary code execution.
- PHP mb_ereg_replace (id=146200): double free (bug #72402) turned into code execution.
- Ruby Regexp (id=1549636): double free on compilation (CVE-2022-28738), RCE path via `Marshal.load`.
- curl MQTT (id=3045390): debugger-confirmed CRT double-free exception from a partial-then-failed send — memory corruption potentially exploitable for RCE.
- curl cookies (id=3117697): double-free conditions yielding undefined behavior, segfaults, potential arbitrary code execution, DoS.
- curl GSASL (id=3735193): ASan-confirmed double free across `gsasl.c:49` and `gsasl.c:113` on real libgsasl allocations.
- VLC libfaad (id=503208): access violation with ability to read or write memory from a crafted MKV SimpleBlock.
- PS4/FreeBSD IPv6 (id=943231): kernel privilege escalation on FreeBSD; chained with WebKit for a fully remote PS4 attack — user data theft and game piracy capability.