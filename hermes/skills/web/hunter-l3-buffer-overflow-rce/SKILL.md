---
name: hunter-l3-buffer-overflow-rce
description: "Use when hunting Buffer Overflow (RCE) on a target. Loads the L3 technique sheet: Buffer-overflow RCE bugs in bug bounty are almost never found by fuzzing a live web target blind — every record here came from either (a) crafting malicious input into a *client-side or parsing* code "
domain: cybersecurity
subdomain: web
tags:
- web
- buffer-overflow-rce
- hunting
- l3
version: '1.0'
---

# Buffer Overflow (RCE) — Technique Sheet

## Overview

Buffer-overflow RCE bugs in bug bounty are almost never found by fuzzing a live web target blind — every record here came from either (a) crafting malicious input into a *client-side or parsing* code path (game server browser, file parser, HTTP header parser), or (b) deep reverse-engineering of native libraries. They pay extremely well (all five earned via Valve, Nintendo, or the Internet Bug Bounty) because a single overflow in a widely-distributed binary or interpreter yields remote code execution on end-user machines. The hunter's leverage point is identifying attacker-controlled data that reaches an unbounded stack copy inside a native component, then demonstrating EIP/return-address control.

## Distinct sub-patterns

### 1. Unicode conversion overflow in server-query responses (network-triggered, client-side RCE)

- Endpoint shape: UDP game-server query protocol. Attacker runs a game server; victim's client (Steam serverbrowser) issues an A2S_PLAYER query; attacker's *reply* is the attack vector. Attacker-controlled field: `player_name`.
- Payload (verbatim): `"A"*1100` placed in the player name field of the A2S_PLAYER reply.
- Root cause: Stack-based buffer overflow in the serverbrowser library when converting a large A2S_PLAYER player name to unicode. The buffer had **no canary protection**, so overwriting past the buffer reaches the saved return address directly.
- Exploitation mechanics: Unicode ROP chain calling `VirtualProtect` (unicode encoding constrains gadget bytes; VirtualProtect flips a page to RWX so shellcode can execute). Worked on Windows 8.1/10.
- Impact proven: Arbitrary code execution (demo: opened cmd.exe) on any Steam user who merely *viewed the malicious server's info* — zero interaction beyond browsing the server list. Reliability: ~0.2% (1/512) against ASLR; 100% when the module base address is known.
- Chain (as recorded): reply to A2S_PLAYER query with large unicode player name → serverbrowser unicode conversion overflows stack buffer (no canary) → unicode ROP chain.
- Exemplar: Valve report id=470520.

### 2. Malformed game-asset file parsing → EIP control (chained with client file-push)

- Endpoint shape: Not a network endpoint — the parser for `.nav` (navigation mesh) files consumed by `Left4Dead2.exe`. Attack surface is any file the client can be made to load.
- Payload: Not stated verbatim; the proof used a malformed `c1m1_hotel.nav` causing EIP to be set to `0x41414102` (note the `02` low byte — the recorded control value, indicating an encoding/length artifact during the overwrite).
- Root cause: Buffer overflow in the NAV file parsing routines, giving direct control of the EIP register.
- Impact proven: Controlled EIP to `0x41414102` and achieved code execution. Critically, chained with Source engine's ability to **push files to clients** — the server can deliver the malicious `.nav` to connecting clients, converting a local file-parse overflow into remote code execution on victims.
- Exemplar: Valve report id=542180.

### 3. Crafted length field in archive parsing (phar/tar/zip → interpreter RCE)

- Endpoint shape: Not a network endpoint — the PHP engine's archive parsing (`phar` stream wrapper handling tar/phar/zip archives). Attacker controls an archive file consumed by any PHP application calling phar functions.
- Param: the archive **length field** — a metadata/size value inside the archive structure itself.
- Payload: Not stated (the technique is crafting an inconsistent/malicious length value, not a long string).
- Root cause: `phar_set_inode` used the crafted length value when processing tar/phar/zip archives, producing a stack-based buffer overflow. Assigned CVE-2015-3329.
- Impact proven: Remote arbitrary code execution via a crafted length value in a tar, phar, or ZIP archive.
- Exemplar: Internet Bug Bounty report id=73237.

### 4. Oversized Host header in reverse-proxy mode (network-triggered, server-side)

- Endpoint shape: `GET / HTTP/1.1` sent to a **Squid reverse proxy**, with the overflow delivered entirely through the `Host` header. Requires the proxy to be running in accelerator/reverse-proxy mode (where Host is parsed into a fixed buffer), not plain forward proxying.
- Payload (verbatim, shape): `GET / HTTP/1.1\x0D\x0AHost: xxxx…` — an ASCII `x`-fill Host header running ~300+ bytes past the buffer (the record shows a single-line request with a massively elongated Host value; `\x0D\x0A` explicit CRLF after the request line).
- Root cause: Stack buffer overflow (**write**) in the Host-header parsing path of Squid's reverse-proxy mode.
- Impact proven: Remote code execution under certain circumstances; server crash (DoS) under most circumstances; and **leaking uninitialized data from the server** (info disclosure even when RCE fails). A three-tier impact from one bug.
- Exemplar: Internet Bug Bounty report id=778610.

### 5. Overflow in a proprietary native library of a console platform

- Endpoint shape: No endpoint — the ENL library embedded in Nintendo WiiU/Switch applications. This is reverse-engineering-driven: the researcher analyzed the shipped native library, details not disclosed.
- Param / payload: None stated.
- Root cause: Classic (stack) buffer overflow in the ENL library of WiiU/Switch applications.
- Impact proven: Remote code execution inside the ENL library on WiiU/Switch, per report title and severity.
- Exemplar: Nintendo report id=1541273.

## Bypass / chain notes

- **Unicode ROP to defeat DEP+encoding constraints** (id=470520): when the overflow path is unicode conversion, bytes are limited to the unicode range. The working bypass was building a ROP chain entirely from unicode-compatible gadgets that calls `VirtualProtect` to make memory RWX, then jumping to shellcode placed in the converted buffer.
- **ASLR reliability trade-off, quantified** (id=470520): ~0.2% (1/512) success with ASLR active (partial base-address override), 100% with a known module base. Reports this precisely — reviewers accept quantified exploitation odds.
- **File-parse overflow → network RCE via file push** (id=542180): a "local" parser bug becomes remote when the platform delivers attacker-controlled files to clients (Source engine file push). Always look for a delivery mechanism that makes the parse input remote-controlled.
- **One bug, three impacts** (id=778610): the same Host overflow was reported as RCE (some configs), crash (most configs), and uninitialized-memory disclosure. Enumerate the full impact surface rather than claiming only the strongest.
- **Length-field corruption instead of long strings** (id=73237): overflows don't always need long input — a crafted *length value* in structured data (archive metadata) made the parser copy into a fixed stack buffer. Craft metadata, not just payloads.

## Gotchas / what NOT to do

- Don't restrict hunting to HTTP endpoints: 3 of 5 records were non-HTTP (game file parser, PHP archive parser, native console library). Server-query protocols and file formats are first-class attack surface.
- Don't report EIP control alone as theoretical — the strongest records demonstrated actual execution (cmd.exe spawned; EIP set to `0x41414102` with code execution achieved). Show a concrete control artifact.
- Don't ignore exploit-reliability limits: id=470520 was accepted at ~0.2% reliability under ASLR. State the odds honestly instead of overselling; partial-overwrite techniques (base-address bracketing) are what make low-probability exploits acceptable.
- Don't assume modern mitigations kill the bug: no canary (id=470520) or no ASLR (fixed-base modules) are common in game engines and embedded/console libraries — verify which mitigations the specific binary actually has.
- Don't overlook client-side delivery: "any Steam user viewing the server info" (id=470520) is near-zero-interaction RCE. Victim-triggered parsing is the highest-impact framing.
- Where details are withheld (id=1541273), that's normal for console/IOT programs — a title + severity + demonstrated impact may suffice for the program even without public technical disclosure.

## Real-world impact examples

- **Steam serverbrowser (id=470520):** Attacker-hosted game server listed in Steam's browser; any user opening its info had `A2S_PLAYER`-reply with 1100 `'A'`s processed by serverbrowser's unicode conversion → no-canary stack overflow → unicode ROP calling `VirtualProtect` → cmd.exe opened on the victim's Windows 8.1/10 machine.
- **Left 4 Dead 2 (id=542180):** Malformed `c1m1_hotel.nav` set EIP to `0x41414102`; combined with Source's client file-push, enables remote code execution on players connecting to a malicious server.
- **PHP (id=73237, CVE-2015-3329):** Crafted length field in a tar/phar/zip archive → `phar_set_inode` stack overflow → remote arbitrary code execution in any PHP app processing the archive.
- **Squid reverse proxy (id=778610):** Single oversized-Host request caused RCE (certain configs), server crash (most configs), and uninitialized server-memory disclosure.
- **Nintendo WiiU/Switch (id=1541273):** Buffer overflow in the ENL library of shipped applications → RCE on console platform software.