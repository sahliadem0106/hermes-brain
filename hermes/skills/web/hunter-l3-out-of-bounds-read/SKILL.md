---
name: hunter-l3-out-of-bounds-read
description: "Use when hunting Out-of-Bounds Read on a target. Loads the L3 technique sheet: Out-of-bounds reads occur when a parser or deserializer reads memory beyond the buffer it was given — typically triggered by malformed-but-accepted input (crafted pickles, serialized strings, archive formats)."
domain: cybersecurity
subdomain: web
tags:
- web
- out-of-bounds-read
- hunting
- l3
version: '1.0'
---

# Out-of-Bounds Read — Technique Sheet

## Overview
Out-of-bounds reads occur when a parser or deserializer reads memory beyond the buffer it was given — typically triggered by malformed-but-accepted input (crafted pickles, serialized strings, archive formats). In bug bounty terms this class is paid almost exclusively through interpreter/core-library bugs surfaced via the Internet Bug Bounty (CPython, PHP), where the attack surface is any network-reachable function that deserializes or parses attacker-controlled data. It pays when the read is reachable from remote input and can leak process memory or crash a service.

## Distinct sub-patterns

### 1. Python pickle `__setstate__` OOB read (CPython)
- Endpoint shape: any application flow that unpickles attacker-controlled data → `pickle.loads()` → CPython `__setstate__()` opcode handling (Python 3.3–3.5)
- Payload: not stated in record
- Root cause: the pickle `__setstate__()` function performs an out-of-bounds read on crafted input — a crafted pickle stream drives the C-level setstate handling past valid memory.
- Impact: out-of-bounds read inside CPython's pickle module when processing crafted data; reachable wherever applications deserialize untrusted pickles.
- Exemplar: id=103994 [ajaysenr], Internet Bug Bounty

### 2. PHP `phar_parse_zipfile()` OOB read (malformed zip-based phar)
- Endpoint shape: any code path that opens/inspects a phar archive built as a zip — `phar_parse_zipfile()` — fed a crafted zip-formatted phar file (upload → phar open/manifest parse)
- Payload: not stated in record; trigger is a crafted zip-format phar file (PHP bug #71498)
- Root cause: parsing a crafted zip-formatted phar triggers an out-of-bounds read inside `phar_parse_zipfile()` — the zip parsing loop reads beyond the buffer while handling malformed archive structures.
- Impact: out-of-bounds read in `phar_parse_zipfile()`; relevant to any PHP app exposing phar upload/processing.
- Exemplar: id=114172 [ajaysenr], Internet Bug Bounty

### 3. PHP `unserialize()` OOB read (crafted serialized string)
- Endpoint shape: any parameter that flows into PHP `unserialize()` — a crafted serialized string (e.g. `a:...{...}`-style payloads with malformed length/structure fields)
- Payload: not stated in record; trigger is crafted serialized input with an out-of-range structure
- Root cause: `unserialize()` performs an out-of-bounds memory read on crafted serialized input — the serializer trusts embedded length/offset fields in the serialized string and reads past the buffer.
- Impact: OOB read in `unserialize()` affecting all three supported PHP versions; fixed in 5.6.30, 7.0.15, 7.1.1 (CVE-2016-10161). Note this CVE is documented as an info leak type in PHP advisories.
- Exemplar: id=200909 [ajaysenr], Internet Bug Bounty

### 4. PHP `wddx_deserialize()` → `timelib_meridian()` heap OOB read (invalid datetime string)
- Endpoint shape: any parameter flowing into `wddx_deserialize()` (or anything that parses datetime strings through timelib) with a WDDX packet containing a `<datetime>` element
- Payload (verbatim):
  `<wddxPacket version='1.0'><data><datetime>2019-01-01 00:00:00 back of 2</datetime></data></wddxPacket>`
- Root cause: deserializing an invalid datetime value triggers a heap out-of-bounds read in `timelib_meridian()` — the "back of" / "front of" relative-time directives in the datetime string are parsed without bounds checks, reading past the heap buffer.
- Impact: heap OOB read reachable through network-exposed `wddx_deserialize()`, potentially leaking process memory back to the client (CVE-2017-16642). This is the most directly web-reachable pattern in the records: a single POSTable XML packet triggers it.
- Exemplar: id=283644 [ajaysenr], Internet Bug Bounty

## Bypass / chain notes
- No chains were present in the records (chain: none for all four). The records stand alone as single-hop deserialization/parser triggers.
- Practical reachability note (from the records' framing): the wddx case was specifically valued because the deserializer is network-exposed — the "bypass" here is really *delivery*: a WDDX packet is plain XML in a request body, so no special encoding is needed. For pickle/phar/unserialize cases, delivery depends on the app exposing those deserializers (upload endpoints, cookie/session blobs, API body fields).

## Gotchas / what NOT to do
- Do not assume any OOB read is in scope: all four records went through the Internet Bug Bounty (CPython/PHP core), not a normal web program. For standard bounty programs, the in-scope finding is the *application endpoint that exposes* the vulnerable deserializer, not the library bug itself.
- The payload surface is narrow and version-sensitive: pickle bug affects Python 3.3–3.5; unserialize bug fixed in 5.6.30/7.0.15/7.1.1; wddx/timelib fixed after CVE-2017-16642. Fingerprint the runtime version before reporting.
- For phar-based triggers, the crafted file must be a *zip-formatted phar* specifically — a random zip or tar phar will not hit `phar_parse_zipfile()`.
- The wddx payload requires the exact relative-directive tokens ("back of 2" / "front of") appended to a datetime string; a plain invalid date does not trigger `timelib_meridian()` parsing.
- Several records lack verbatim payloads (pickle, phar, unserialize) — don't guess; reproduce against a local build of the affected version first to construct a minimal trigger.

## Real-world impact examples
- Heap OOB read in `timelib_meridian()` via `wddx_deserialize()` with the `<datetime>2019-01-01 00:00:00 back of 2</datetime>` packet — potential process-memory leak back to the client over the network (CVE-2017-16642; id=283644).
- OOB memory read in PHP `unserialize()` on crafted serialized input, affecting all three supported PHP branches at disclosure; patched in 5.6.30, 7.0.15, 7.1.1 (CVE-2016-10161; id=200909).
- OOB read in CPython's pickle module via crafted pickle data hitting `__setstate__()` on Python 3.3–3.5 (id=103994).
- OOB read in PHP `phar_parse_zipfile()` when parsing a crafted zip-formatted phar (PHP bug #71498; id=114172).