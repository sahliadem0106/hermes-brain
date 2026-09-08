---
name: hunter-l3-stack-overflow
description: "Use when hunting Stack Overflow on a target. Loads the L3 technique sheet: This class covers memory-corruption bugs where attacker-controlled data exceeds a fixed stack buffer (stack buffer overflow, `c0000409`-class crashes) or where unbounded recursion exhausts the call stack."
domain: cybersecurity
subdomain: web
tags:
- web
- stack-overflow
- hunting
- l3
version: '1.0'
---

# Stack Overflow — Technique Sheet

## Overview

This class covers memory-corruption bugs where attacker-controlled data exceeds a fixed stack buffer (stack buffer overflow, `c0000409`-class crashes) or where unbounded recursion exhausts the call stack. In bug bounty practice it shows up most often in (a) file/packet parsers accepting oversized fields (XML attributes, config files, protocol delta structures), (b) desktop-app "define your own language"/style configuration features, and (c) native library APIs with recursive algorithms (image fill). Payouts range from modest DoS bounties ($500 on PHP/GD via IBB) up to critical RCE when stack-allocated structs with function pointers/return addresses are reachable from remote input (Valve GoldSrc — RCE on the game client).

## Distinct sub-patterns

### 1. Oversized XML encoding attribute → stack buffer overflow in editor parser
- Endpoint shape: crafted local file, e.g. `attack.xml` opened in the target app. Param: the `encoding` attribute value of the XML declaration.
- Payload (verbatim):
  `<?xml version="1.0" encoding="AAAA...A">` — 200 'A's as the encoding string.
- Root cause: `_invisibleEditView.getText` writes the parsed encoding string into a fixed 128-byte `encodingStr` buffer with no bounds check when a big XML field is present.
- Impact: crash on simply opening the crafted `.xml` (stack buffer overflow, DoS).
- Exemplar: id=480883 (Notepad++).

### 2. Oversized field in the app's own config file → overflow on next launch
- Endpoint shape: the application's user-editable config file — Notepad++ `stylers.xml`, the `ext` field of a language entry. Param: `ext`.
- Payload (verbatim): 100 'A's: `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
- Root cause: `isInList` does not bound-check the fixed `word[64]` array when copying the long `ext` value.
- Impact: local attacker modifies `stylers.xml` with a long `ext` string; victim re-opens Notepad++ → stack buffer overflow and crash. Persistence-by-config is the notable twist: one file write, crash on every subsequent launch.
- Exemplar: id=480984 (Notepad++).

### 3. GUI "user-defined language" text field → stack overrun via clipboard paste
- Endpoint shape: Notepad++ "Define language" dialog → "Comment and Number" tab → Comment line style **Open/Close** fields. Param: the Open/Close comment-token strings.
- Payload (verbatim): `<20000 x 'A' — the literal 20KB comment-line string pasted into the Open/Close field>` (an 11KB variant also fired).
- Root cause: the dialog copies the pasted token into a fixed stack buffer without length validation.
- Impact: Windows structured-exception abort "Security check failure or stack buffer overrun" (`c0000409`) — Notepad++ DoS.
- Exemplar: id=481335 (Notepad++).

### 4. Attacker-controlled struct offsets/sizes in a network protocol parser → remote RCE
- Endpoint shape: network packets to the game client (GoldSrc engine, `hl.exe`, Counter-Strike 1.6): `svc_deltadescription` followed by `svc_event`. Param: `field_offset` / `field_size` of declared delta fields.
- Payload: not stated verbatim; the mechanism is a `svc_deltadescription` declaring fields with attacker-chosen `field_offset` (e.g. offset `0xac`, the return-address offset) consumed by `DELTA_ParseDelta`, then an `svc_event` packet parsed into a stack-allocated structure.
- Root cause: `DELTA_ParseDelta` fills structures based on attacker-controlled `field_offset` and `field_size` without verifying they stay within the allocated bounds — writes land past the stack-allocated `event_t`, including the saved return address.
- Impact: **Remote Code Execution** on the client — crafted packets popped `xcalc` on the victim.
- Exemplar: id=484745 (Valve).

### 5. Unbounded recursion in a native imaging API → stack exhaustion
- Endpoint shape: PHP GD library function `imagefilltoborder()` (no HTTP param; the "input" is image geometry/fill arguments driving recursive fill). Param: n/a.
- Payload: none stated.
- Root cause: excessive recursion in `imagefilltoborder` exhausts the stack (CVE-2015-8874; PHP bugs #66387/#72350).
- Impact: stack-overflow crash; fixed in PHP 5.5.37, 5.6.23, 7.0.8; $500 bounty via Internet Bug Bounty.
- Exemplar: id=146936.

## Bypass / chain notes

- Config-file persistence chain (id=480984): modify config → victim restarts app → crash reproduces without attacker presence. This converts a one-shot local bug into a persistent DoS and is the argument that elevates severity beyond "crashes on my machine."
- Two-packet chain (id=484745): step 1 — send `svc_deltadescription` declaring fields with attacker-chosen offset (`0xac` = return address slot); step 2 — send `svc_event` whose parse writes into the stack-allocated `event_t`, landing controlled data over the return address. The record is truncated after "stack-all..." but the proven outcome is client RCE (xcalc popped).
- No filter-bypass techniques appear in these records; the bugs are unchecked-copy primitives, so no WAF/encoding evasion is involved.

## Gotchas / what NOT to do

- Don't assume stack overflow = RCE. Four of five records are pure DoS crashes. RCE requires the overflow to reach a return address / function pointer AND controlled content — the Valve case only because the parser let you *choose the write offset*.
- Desktop-app file/format bugs need a delivery story: a crash on opening your own crafted file locally is weak; state the vector (victim opens file, or attacker seeds config) explicitly as the records do.
- Don't stop at the crash dialog: capture the exception code (`c0000409` in id=481335) — it distinguishes stack-cookie aborts from generic access violations and strengthens the report.
- Size matters, but 100–200 bytes of 'A' was enough where the buffer was 64–128 bytes; don't assume you need megabytes. Conversely, GUI fields accepted 11–20KB pastes.
- Library-level recursion bugs (GD) are usually handled through umbrella programs (Internet Bug Bounty) rather than the downstream app's program — report to the right layer.
- Payloads for the protocol RCE were not stated verbatim in the records — don't fabricate packet dumps; the offset mechanics (`0xac`) are the documented core.

## Real-world impact examples

- $500 bounty, PHP core (CVE-2015-8874): `imagefilltoborder()` recursion exhaustion, fixed across 5.5/5.6/7.0 branches (id=146936).
- Notepad++: three separate stack overflows — crafted XML encoding attribute crashes on open (id=480883); poisoned `stylers.xml` crashes on every restart (id=480984); 20KB paste into Define-language comment field aborts with `c0000409` (id=481335).
- Valve/Counter-Strike 1.6: remote stack overflow via `svc_deltadescription`/`svc_event` field offsets gave **RCE on the game client**, demonstrated by popping `xcalc` on a joining player (id=484745).