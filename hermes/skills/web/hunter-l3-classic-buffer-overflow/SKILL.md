---
name: hunter-l3-classic-buffer-overflow
description: "Use when hunting Classic Buffer Overflow on a target. Loads the L3 technique sheet: Classic buffer overflows here are unbounded writes into fixed-size buffers — stack arrays, heap allocations, or static buffers — where attacker-controlled data (file-derived fields, user-supplied host"
domain: cybersecurity
subdomain: web
tags:
- web
- classic-buffer-overflow
- hunting
- l3
version: '1.0'
---

# Classic Buffer Overflow — Technique Sheet

## Overview
Classic buffer overflows here are unbounded writes into fixed-size buffers — stack arrays, heap allocations, or static buffers — where attacker-controlled data (file-derived fields, user-supplied hostnames, command-line arguments, network strings) flows into `memcpy`/`memmove`/string-escape routines without length validation. In practice these pay most where the vulnerable code parses untrusted input natively: media-file parsers (AVI), protocol encoders (DNS-over-HTTPS), privileged CLI tools (tcpdump), auth helpers (Squid SMB), and — notably — game-console multiplayer code. Proven impacts range from one-byte off-by-one writes confirmed under ASAN to full code execution and credential-hash disclosure; even "just a crash" in multiplayer services qualifies as meaningful DoS. Many of these land as CVEs via the Internet Bug Bounty, so the target surface is broad: anything that processes attacker bytes in C/C++.

## Distinct sub-patterns

### 1. Missing bounds check in a multiplayer string-escape function (game client/server)
- Endpoint shape: in-game multiplayer string handling — a string *escape/sanitization* function itself (no HTTP endpoint; the vuln is inside the sanitization layer of the multiplayer stack in Xenoblade Chronicles X: Definitive Edition).
- Payload that actually fired: payload not stated (the report does not give the triggering string).
- Root cause: the string escape function lacks proper bounds checking — the code that is *supposed to* neutralize dangerous input is itself the overflow site. Escaping can expand a string (e.g. adding escape characters) into a fixed buffer sized for the unescaped input.
- Impact proven: buffer overflow exploitable for multiplayer denial of service (crash of the multiplayer service/session).
- Exemplars: id=3048061 (Nintendo, [ajaysenr]).

### 2. Signed width field from a media file used directly in memmove/memcpy (AVI parser)
- Endpoint shape: media file parsing — `libavi_plugin` `ReadFrame()` in VLC; the dangerous parameter is `i_width_bytes`, read directly from the AVI container.
- Payload that actually fired: payload not stated (a crafted invalid AVI file; the width value is attacker-set inside the file header/chunk).
- Root cause: `ReadFrame` takes a *signed* `i_width_bytes` obtained directly from the file with no strict bounds checking before `memmove`/`memcpy`. Two classic flaws in one: (a) no sanity range check on a file-supplied integer, and (b) signedness — a negative or oversized width passes into a size argument and drives an out-of-bounds copy.
- Impact proven: opening the crafted AVI crashes VLC; assessed as possibly leading to remote code execution.
- Exemplars: id=484398 (VLC / European Commission - DIGIT, [ajaysenr]).

### 3. One-byte off-by-one when packing a hostname into a fixed 512-byte buffer (DoH encoder)
- Endpoint shape: `curl --doh-url https://irrelevant/ <hostname>` — the DNS-over-HTTPS encoder `doh_encode` receives the resolver hostname from the user.
- Payload that actually fired (verbatim):
  `x....xxxxxxxxxxxxxxxxxxxxx.x....x.xxxxxxxxxx.xxxxxxxxx.xxxxxxxxxxx.xxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxx...xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.x.x.......xxxxxxxxxxxxxxxxxxxxxx...xxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx...xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
  (used as the hostname argument to `curl --doh-url https://irrelevant/`)
- Root cause: `doh_encode` packs a hostname into a 512-byte buffer and can overflow by exactly one byte for certain long hostnames — a length-calculation edge case (DNS wire-format name encoding with label length bytes) where the terminator/length accounting overruns the buffer by a single byte on worst-case input.
- Impact proven: one-byte buffer write overflow, confirmed via ASAN / assertion failure with a crafted long hostname.
- Exemplars: id=694449 (curl, [ajaysenr]).

### 4. User-controlled name copied into a fixed array in an auth helper (local overflow → cred disclosure)
- Endpoint shape: `Smb_Connect()` / `Smb_Connect_Server()` in Squid's `smblib.c` (SMB auth helper path); parameter is the SMB domain controller name, which comes from user input.
- Payload that actually fired: no specific exploit payload in the report — domain controller names of excessive length passed to `Smb_Connect`.
- Root cause: domain controller names taken from user input were copied into an array with no bounds checking — a local buffer overflow in a helper process.
- Impact proven: code execution resulting in disclosure of credential hashes; patched as CVE-2019-18353.
- Exemplars: id=721333 (Internet Bug Bounty, [ajaysenr]).

### 5. Command-line argument parser with fixed stack buffer (privileged CLI tool)
- Endpoint shape: `tcpdump` CLI — the file-list argument parser `get_next_file()` in `tcpdump.c`; parameter is the command-line argument (the list of capture files).
- Payload that actually fired: no exploit payload in the report — an over-long command-line file list argument.
- Root cause: the command-line argument parser lacked bounds checking, writing past a stack buffer — direct stack smash.
- Impact proven: stack-smashing demonstrated under ASAN; where tcpdump runs with privileges (e.g. setuid/capabilities) or parses untrusted input, an attacker could inject code and take control of the process. Patched as CVE-2018-14879.
- Exemplars: id=724217 (Internet Bug Bounty, [ajaysenr]).

## Bypass / chain notes
- No multi-step chains appear in these records (every record lists chain: none) — the overflows fire directly from a single untrusted input reaching the unchecked copy.
- Indirect "bypass" patterns that recur instead: the data source itself evades scrutiny — a file header field (`i_width_bytes`) that the parser trusts, a hostname long enough to hit a boundary edge case rather than fail validation, or a CLI/helper argument assumed to be operator-controlled rather than attacker-controlled.
- Exploitability amplifiers seen: ASAN/assert used to *prove* the write where silent memory corruption would be hard to demonstrate (curl, tcpdump); signed integer used as a copy size (VLC) to reach the overflow with values a naive check might pass; privileged or credential-bearing context (tcpdump privileges, Squid helper with credential hashes) to convert a local overflow into disclosure/RCE.

## Gotchas / what NOT to do
- Don't assume "just a crash" is dismissible: the Nintendo case was accepted on multiplayer DoS alone; the curl case was accepted on a *single byte* of overflow. Precise root-cause framing (off-by-one, missing bounds check) is what makes low-yield primitives acceptable.
- Don't skip ASAN/assert reproduction: for curl and tcpdump, sanitizer output was the proof of impact. A heap/stack write that doesn't visibly crash may still be reportable with ASAN evidence.
- Don't treat local-only overflows as out of scope: tcpdump (command-line) and Squid smblib (helper input) were both local-trigger, yet both received CVEs — the privilege/credential context carried the impact.
- Don't overlook the escaping/sanitization layer itself: the Nintendo bug sits in the string *escape* function — code paths that transform strings (escape, encode, wire-format pack) are overflow sites, not just raw copy sites.
- Don't ignore signedness: `i_width_bytes` is signed; an unchecked signed value from file data flowing into `memmove`/`memcpy` sizing is a distinct flaw from a plain missing length cap.
- Payload availability is uneven: two of five records give no concrete payload. Where a payload is not stated, reproduce via the described input shape (crafted file, over-long argument/hostname) rather than assuming an exploit string exists.

## Real-world impact examples
- Nintendo (Xenoblade Chronicles X: DE), id=3048061: buffer overflow in the multiplayer string escape function, exploitable for denial of service of multiplayer.
- VLC, id=484398: crafted AVI file with unchecked signed `i_width_bytes` crashes VLC on open; possible remote code execution.
- curl, id=694449: one-byte heap write overflow in `doh_encode` triggered by a crafted ~512+ character hostname via `--doh-url`, confirmed under ASAN/assert.
- Squid (smblib.c), id=721333: unchecked SMB domain controller name → local overflow → code execution → credential hash disclosure; CVE-2019-18353.
- tcpdump, id=724217: stack buffer overflow in `get_next_file()` via command-line file-list argument, ASAN-confirmed stack smash; code execution possible in privileged contexts; CVE-2018-14879.