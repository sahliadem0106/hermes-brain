---
name: hunter-l3-buffer-overflow
description: "Use when hunting Buffer Overflow on a target. Loads the L3 technique sheet: This class covers memory-corruption bugs found by auditing parsers, format-string consumers, and length-handling code — most commonly in C/C++ components exposed through higher-level platforms (PHP, P"
domain: cybersecurity
subdomain: web
tags:
- web
- buffer-overflow
- hunting
- l3
version: '1.0'
---

# Buffer Overflow — Technique Sheet

## Overview
This class covers memory-corruption bugs found by auditing parsers, format-string consumers, and length-handling code — most commonly in C/C++ components exposed through higher-level platforms (PHP, Python, Ruby, curl, tcpdump, game engines, embedded CGI). Almost every record here was found in programs that accept *untrusted structured input* (packets, file formats, HTTP messages, multipart forms, regexes, entity strings) and parse it with unchecked `strcpy`/`memcpy`/`sprintf`/`strcat` or broken integer math. These pay through Internet Bug Bounty (CVE-backed), vendor programs (curl, Node.js, Valve, Ubiquiti, FileZilla, Notepad++), and are typically proven with a crash (segfault, ASan report, stack-smashing abort) — with RCE argued or demonstrated where the overwrite is controllable.

## Distinct sub-patterns

### 1. Unchecked strcpy/strcat into a fixed-size buffer (classic stack overflow)
- **Shape:** Any parser that copies an attacker-controlled string field into a declared fixed buffer. Examples: `getpost()` copying the MIME boundary from `POST /login.cgi` into a 100-byte stack buffer; `ub_process_content()` memcpy'ing a content line into a fixed 512-byte `line` buffer; `yywarning_s` in mruby's `parse.y` calling `strcat` into a 256-byte buffer; Notepad++ using `lstrcat/lstrcpy` on a localization name attribute; GoldSrc `UTIL_StringToIntArray` using `strcpy` into a fixed buffer for `game_text` entity strings.
- **Payload (verbatim where available):**
  - Ubiquiti boundary: `Content-Type: multipart/form-data; boundary=----------------------------dddd…d` (long run of 'd' chars, >100 bytes)
  - Ubiquiti content line: `POST /login.cgi with a >512 byte multipart content line before CRLF`
  - mruby (id=535827): `300000000000000000000000000000000000000000000000E003000…0` (a huge numeric literal fed to the compiler; verbatim payload is a ~300+ char digit/exponent string)
  - FileZilla (id=798301): `buffer = "\x41" * 5000000; eip = "\x42" * 4` — 5M 'A's pasted into the Scale Factor settings field (non-float, excessive length).
- **Root cause:** Copy function has no bounds check; attacker controls the source length.
- **Impact:** Segfault proven in every case (lighttpd CGI dying with signal 11; exit code 11 with likely return-pointer overwrite; stack-smashing-detected abort). RCE judged achievable (Ubiquiti, mruby) or fully demonstrated (GoldSrc shellcode ran calculator; FileZilla EIP control via `\x42`*4).
- **Exemplars:** id=74004, id=74025 (Ubiquiti login.cgi); id=535827 (mruby); id=497255 (Notepad++); id=458929 (GoldSrc); id=798301 (FileZilla).

### 2. strncpy with the SOURCE size instead of the DESTINATION size
- **Shape:** `strncpy(dest[100], src, strlen(src))` — copies using the source's length. Seen in PHP `phar_tar_writeheaders_int()`: entry->link copied into a fixed 100-byte `linkname` tar field using the source size.
- **Payload:** payload not stated — supply a link target longer than 100 bytes in a phar tar entry.
- **Root cause:** Classic strncpy misuse: the size argument must bound the destination.
- **Impact:** Crash (DoS), with EOP/RCE considered possible.
- **Exemplar:** id=504761.

### 3. Width/precision specifiers honored by sprintf but ignored in size computation (format-driven overflow)
- **Shape:** Any C API that pre-computes a buffer size from a format string. Two records:
  - Python 2 `PyUnicode_FromFormat()/PyUnicode_FromFormatV()`: width/precision ignored when sizing buffers but honored by sprintf.
  - ctypes `PyCArg_repr` in `_ctypes/callproc.c`: `sprintf` used without checking output length when formatting a double with `%f`.
- **Payload:** `%999999999999s` (PyUnicode_FromFormat, verbatim); `c_double.from_param(1e300)` (ctypes, verbatim — extreme float produces a multi-KB `%f` rendering).
- **Root cause:** Size-estimation code and the actual formatter disagree on the worst-case output length.
- **Impact:** Stack-based AND heap-based buffer overflow in Python (code execution when format is attacker-controlled); ctypes: `*** buffer overflow detected ***: terminated / Aborted` — remote RCE possible in apps accepting untrusted floats.
- **Exemplars:** id=43443, id=1084342.

### 4. Integer overflow / signedness errors in length computation
- **Shape:** Length arithmetic done in a narrower or signed type before a size check or allocation:
  - libevent `evutil_parse_sockaddr_port`: `len = (int) (cp-(ip_as_string + 1));` (verbatim) — IPv6 bracket length cast to signed 32-bit goes negative when > INT_MAX, bypassing the buffer size check → out-of-bounds memcpy.
  - Ruby `CGI.escape_html`: `RSTRING_LEN(str) * HTML_ESCAPE_MAX_LEN` overflows a 4-byte long, allocating 1028 bytes while the copy loop writes up to ~4.3GB.
  - curl `Curl_dyn_addn`: `s->len + len > s->size` check overflows for huge inputs.
  - PHP `parse_ini_file`: `zend_ini_do_op()` writes `-2147483648` into `str_result[MAX_LENGTH_OF_LONG]` with no room for the sign → 1-byte stack overflow.
- **Payload:** libevent: a bracketed IPv6 literal whose inner length exceeds INT_MAX; Ruby: a string of 715828054 characters passed to `CGI.escapeHTML`; PHP INI (verbatim): `0=0&~2000000000`; curl: ~4GB input on 32-bit builds.
- **Impact:** libevent: segfault via negative-length memcpy (stack overflow). Ruby: heap overrun / crash. PHP 32-bit: stack-smashing abort (CVE-2017-11628). curl: memory corruption possible but practical risk low (~18 exabytes needed on 64-bit).
- **Exemplars:** id=112784, id=1455248, id=3037583, id=248601.

### 5. Array index without bounds check → adjacent structure overwrite
- **Shape:** Untrusted index/ID used to write into a fixed array that sits next to a function-pointer table. GoldSrc `MsgFunc_WeaponList/AddWeapon` in client.dll: weapon id `iId` (range -128..128) not bounds-checked before writing into `rgWeapons[]`, overwriting the `gEngfuncs` function table.
- **Payload:** crafted WeaponList network message plus a `weapon_pwn.txt` sprite list to place the overwrite contents; PoC popped calc.exe on the latest CS 1.6 client via a malicious server.
- **Root cause:** Index accepted from a network message without range validation.
- **Impact:** Client-side RCE via ROP chain (account compromise, malware injection).
- **Exemplar:** id=513154.

### 6. Parsing state machine walking past the end marker
- **Shape:** Incremental pointer-walk parsers where the loop pointer can advance past `end`. PHP PECL `http\Message::__construct()`: in `parse_hostinfo/parse_userinfo/parse_scheme`, `ptr` can be incremented past `end`, so parsing continues and overflows `state->buffer`.
- **Payload:** `$http_msg = new http\Message(file_get_contents("bug73185.bin"), false);` (verbatim — malformed HTTP message file).
- **Root cause:** Loop bounds checked against the wrong condition, allowing one-past-the-end (and beyond) traversal.
- **Impact:** Overwrote a `php_stream` struct including its `php_stream_ops` function pointer with attacker-controlled data; SIGSEGV in `_php_stream_free` with `rax=0x4142434445464748`; arbitrary code execution judged likely.
- **Exemplar:** id=174069.

### 7. Network packet / file-format parsers reading past the buffer (overreads)
- **Shape:** Binary protocol parsers missing caplen/bounds enforcement. tcpdump family is the exemplar set:
  - `ip6_print` (print-ip6.c): reads outside buffer on crafted IPv6 packet (CVE-2017-5204) — ASan: heap-buffer-overflow read of size 1.
  - `otv_print` (print-otv.c): overread on crafted packet (CVE-2017-5341).
  - `sig_print` (print-atm.c): receives correct caplen but doesn't use it (CVE-2017-5484).
  - `ether_print` (print-ether.c): `gre_print_0()` passes `length` instead of `caplen` (CVE-2017-5342).
  - `q933_print` (print-fr.c): overread on short packet (CVE-2017-5482 / CVE-2016-8575).
  - `bittok2str_internal` (util-print.c): local buffer length not validated against payload size.
  - tcpdump-style overreads also apply to PHP's `exif_process_IFD_in_TIFF` (uninitialized read on 32-bit builds, CVE-2019-9641 — data leak rather than overflow).
- **Payload:** payload not stated for most — supply crafted packets with truncated/garbled length fields; the bug classes are: wrong variable passed (length vs caplen), caplen ignored, short packets.
- **Impact:** Remote DoS proven (ASan-confirmed); RCE possible but unverified.
- **Exemplars:** id=202960, 202965, 202967, 202968, 202969, 800324; id=510336 (info leak variant).

### 8. Game-engine asset parsers (malicious files served by a hostile server)
- **Shape:** Client downloads/loads an attacker-crafted asset: `.BSP` map (CS:GO map download; GoldSrc entities), `.TGA` skybox (Half-Life GoldSrc). Parser mishandles crafted data → access violation.
- **Payload:** malformed .BSP / .TGA files; for the GoldSrc entity path, shellcode written into a `game_text` entity.
- **Root cause:** Unchecked data handling in asset loaders; in GoldSrc specifically, `strcpy` in `UTIL_StringToIntArray`.
- **Impact:** CS:GO: reliable Access Violation in csgo.exe, attacker-controlled server can trigger arbitrary code execution on the downloading client. GoldSrc skybox: crash with non-ASLR Steam DLLs making client RCE "trivial" → account theft. GoldSrc entities: full arbitrary code execution (calc PoC).
- **Exemplars:** id=351014, id=351016, id=458929.

### 9. Malicious server / backend response overflowing a client-side proxy
- **Shape:** A component that trusts a peer: Apache `mod_proxy_fcgi` pointed at a malicious FastCGI server, which sends a crafted response → heap buffer overflow.
- **Payload:** payload not stated.
- **Chain (verbatim):** point mod_proxy_fcgi at malicious FastCGI server → server sends crafted response → heap buffer overflow.
- **Impact:** Heap buffer overflow proven.
- **Exemplar:** id=36264.

### 10. Untrusted regex / crafted structured input overflowing the engine
- **Shape:** Perl regex engine: crafted regex causes heap buffer overflow (CVE-2020-10543). Chain (verbatim): feed crafted regex to Perl engine → heap overflow in regex processing → potential RCE.
- **Payload:** payload not stated.
- **Exemplar:** id=888986.

### 11. Platform-API sizing mismatches (pathconf vs PATH_MAX)
- **Shape:** Node.js `fs.realpath.native` (libuv): buffer sized with `pathconf` falling back to `_POSIX_PATH_MAX` (256), below the required `PATH_MAX` (1024).
- **Payload:** long symlink path (>256 bytes).
- **Impact:** Node process crash.
- **Exemplar:** id=965914.

### 12. Check-function misses the actual multiplication (division-remainder gaps)
- **Shape:** Python 2 `imageop.grey2rgb(x, y, len)`: `check_multiply_size()` doesn't account for division remainders, so the length check passes and the copy loop writes 4 bytes per iteration past the allocated buffer.
- **Payload:** payload not stated — use x/y/len values where the product check rounds away a remainder.
- **Impact:** Access violation and DEP violations indicating possible arbitrary code execution.
- **Exemplar:** id=73258.

### 13. Wire-protocol length field trusted without bounds check
- **Shape:** curl's test MQTT server `mqttd.c`: 2-byte password length field in a CONNECT packet not bounds-checked.
- **Payload (verbatim):** `\x10\x1a\x00\x04MQTT\x04\xc2\x00\x3c\x00\x04test\x00\x04user\xff\xff` — note the trailing `\xff\xff` password length.
- **Impact:** Single malformed CONNECT packet crashed the server (`malloc(): invalid size`, core dump); RCE not demonstrated.
- **Exemplar:** id=3101127.

## Bypass / chain notes
- **Malicious-infrastructure chain:** the recurring amplifier is attacker-controlled *server* context — hostile FastCGI backend → mod_proxy_fcgi heap overflow (id=36264); malicious game server sending crafted WeaponList messages (id=513154); attacker-hosted server serving a malicious .BSP to connecting clients (id=351014). If the target is a client that trusts servers, hunt the message handlers, not the UI.
- **Multi-step weaponization seen:** crafted message → overwrite adjacent function-pointer table (`gEngfuncs`) → ROP chain → client RCE (id=513154); parser overrun → overwrite `php_stream_ops` function pointer → controlled `rax` at crash = likely ACE (id=174069). A crash dump showing your bytes in a register (`0x4142434445464748`) is the strongest evidence for escalating DoS→RCE claims.
- **Non-ASLR environments:** GoldSrc crashes became "trivial" RCE because Steam DLLs were non-ASLR (id=351016). Check mitigation posture when judging impact.
- **Sanitizer-driven confirmation:** several reports lean on ASan output (id=104011, id=202960) — a clean ASan heap-buffer-overflow trace with a CVE attached was sufficient for the Internet Bug Bounty.
- **Numeric-literal triggers:** extreme values (1e300 float, `E003…` exponent literal, 2000000000 negation, 715828054-char string) reliably overflow size math — no shellcode needed to prove the bug.

## Gotchas / what NOT to do
- Don't claim RCE from a crash alone. Several records explicitly scoped impact to DoS when control wasn't demonstrated (curl MQTT — "RCE not demonstrated"; curl dyn — "practical risk is low"; bittok2str — "RCE possible but unverified"). Report the proven tier.
- Practical exploitability thresholds matter: curl's `Curl_dyn_addn` overflow needs ~4GB on 32-bit and ~18 exabytes on 64-bit — a technically real bug with near-zero practical risk. State the requirement.
- 32-bit vs 64-bit changes the bug: PHP INI sign-byte overflow (CVE-2017-11628) and exif uninitialized read (CVE-2019-9641) were 32-bit-specific. Verify the build you're testing.
- Crash location ≠ bug location: `gre_print_0()` passing `length` instead of `caplen` crashed in `ether_print`. Trace the caller when root-causing packet-parser crashes.
- For strncpy/size-argument bugs, the check exists but uses the wrong bound — don't assume "it uses strncpy, so it's safe."
- Length fields one layer down (MQTT password length at the end of the CONNECT body, weapon id in a HUD message, tar linkname) are commonly missed by fuzzers focused on header fields — but records show these were found by manual reading, not blind fuzzing.
- Game-engine findings require actually running the client against your malicious server/file; a debugger access violation trace plus shellcode PoC (calc) is what got these accepted.

## Real-world impact examples
- **Full RCE on game clients:** CS 1.6 WeaponList PoC popped calc.exe on the latest client via a malicious server (id=513154); GoldSrc `game_text` shellcode executed arbitrary assembly (id=458929); malformed skybox RCE "trivial" due to non-ASLR DLLs, enabling Steam account theft (id=351016); CS:GO map download → potential client ACE (id=351014).
- **Function-pointer control with attacker bytes in registers:** PHP http\Message parser overwrote `php_stream_ops` pointer; SIGSEGV with `rax=0x4142434445464748` (id=174069).
- **CVE-backed library bugs (Internet Bug Bounty):** PHP mkgmtime global-buffer-overflow → CVE-2014-3668 (id=104011); PHP INI 1-byte stack overflow → CVE-2017-11628 (id=248601); five tcpdump parser overreads → CVE-2017-5204/5341/5342/5482/5484 (id=202960–202969); Perl regex heap overflow → CVE-2020-10543 (id=888986); Python C-API format overflow (id=43443).
- **Embedded device pre-auth CGI:** Ubiquiti AirMax /login.cgi — two independent stack overflows (boundary strcpy, >512-byte content line) causing segfaults in the CGI process, RCE considered achievable (id=74004, id=74025).
- **Remote DoS with a single packet/message:** curl MQTT test server killed by one malformed CONNECT (`malloc(): invalid size`) (id=3101127); Node.js crash from a >256-byte symlink path (id=965914); Notepad++ crash on opening Shortcut Mapper with a malicious localization file (id=497255); FileZilla crash via 5M-char Scale Factor paste (id=798301).