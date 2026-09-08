---
name: hunter-l3-local-file-read-lfi
description: "Use when hunting Local File Read (LFI) on a target. Loads the L3 technique sheet: This class covers server-side arbitrary file read: an application parameter that is used as a filesystem path (typically a filename or partial path) without sanitization, letting the attacker substitu"
domain: cybersecurity
subdomain: web
tags:
- web
- local-file-read-lfi
- hunting
- l3
version: '1.0'
---

# Local File Read (LFI) — Technique Sheet

## Overview

This class covers server-side arbitrary file read: an application parameter that is used as a filesystem path (typically a filename or partial path) without sanitization, letting the attacker substitute an arbitrary absolute or traversal path and have the server read the file. In the records, the vector is a template/filename parameter in a file-generation endpoint where the file's contents are then rendered back to the attacker through the product's normal output flow (a generated artifact), turning a "pick a template" feature into a full read primitive. It pays whenever an output-rendering or file-handling parameter touches disk: the read primitive yields credentials, configuration, and — most valuably — application source code, which enables deeper chaining.

## Distinct sub-patterns

The records contain a single endpoint family, but three distinct exploitation sub-patterns differ in how the path is formed and how far the read reaches.

### Sub-pattern 1: Named-resource substitution (relative filename outside the template directory)

- **Endpoint shape / parameter:**
  `POST /api/generate.php`
  Body parameters: `template`, `type`, `top-text`, `bottom-text`.
- **Payload that actually fired (verbatim):**
  `template=template4.txt&type=text&top-text=test&bottom-text=test`
  Note: `template4.txt` is the *normal, valid* value shape — the discovery point is that `template` is accepted as a raw filename with no allowlist. The attacker sets `type=text` so the file's contents are emitted as text into the generated output.
- **Root-cause pattern:**
  `template` is used directly as a filename in the server's file-read call with no sanitization and no path restriction. The parameter is not validated against a fixed set of template names — whatever filename is supplied is opened on disk. `type=text` selects an output mode where the loaded file's contents are rendered into the generated artifact (a saved "meme"), so the file body is returned to the attacker via the saved output.
- **Impact proven:**
  Read of `/etc/passwd` and the complete PHP application source code.
- **Exemplar report IDs:** 415137 (h1-5411-CTF, ajaysenr).

### Sub-pattern 2: Relative traversal to an absolute system path (`../` prefix)

- **Endpoint shape / parameter:**
  `POST /api/generate.php`, same parameter set: `template`, `type`, `top-text`, `bottom-text`.
- **Payload that actually fired (verbatim):**
  `template=../../../../../../../etc/passwd&type=text&top-text=ad&bottom-text=asd`
- **Root-cause pattern:**
  When `template` is not a known template file, the server still concatenates/uses it as a path relative to a templates directory. Repeated `../` segments climb out of that base directory to the filesystem root, and because no normalization or base-path enforcement exists, the resulting path resolves to the absolute file `/etc/passwd`. Combined with `type=text`, the resolved file is read and its contents flow into the saved generated artifact.
- **Impact proven:**
  Read of `/etc/passwd` and the server-side PHP source code.
- **Exemplar report IDs:** 415501 (h1-5411-CTF, ajaysenr).

### Sub-pattern 3: Malformed-but-resolving traversal (typo'd path still proves the primitive)

- **Endpoint shape / parameter:**
  `POST /api/generate.php`, same parameter set.
- **Payload that actually fired (verbatim):**
  `template=../../../../../../..etc/passwd&type=text&top-text=.&bottom-text=.`
- **Root-cause pattern:**
  Same traversal root cause as sub-pattern 2, but note the payload is *not* a clean path — it has eight `../` segments followed directly by `etc/passwd` with no leading `/` (`..etc/passwd` rather than `../etc/passwd` after the last climb). The read still succeeded, which indicates the server's path resolution tolerated the malformed segment (path components collapse during `..` handling), or the traversal count landed the base path where resolution still reached the target. Practical takeaway: the read primitive is forgiving about exact traversal syntax — you do not need a perfectly formed path to confirm the bug.
- **Impact proven (the broadest read set in the records):**
  - `/etc/passwd`
  - `/etc/issue`
  - `/etc/resolv.conf`
  - `/etc/hosts`
  - `/var/log/apt/history.log`
  - The application source code
- **Exemplar report IDs:** 415682 (h1-5411-CTF, ajaysenr).

### How the output channel works (shared across all sub-patterns)

The exploit is not a direct in-response file dump. The chain observed in every record is:

1. Submit `POST /api/generate.php` with `template` set to the target path and `type=text`.
2. The server reads the file as if it were a template and builds a generated artifact (a "meme" — the endpoint is a meme generator, with `top-text`/`bottom-text` as caption fields).
3. The file contents are fetched via the *saved meme* — i.e., the attacker retrieves the saved generated output, which contains the file body because `type=text` renders the loaded file's content as text.

If a first response does not show contents, check the saved/generated artifact for the read result rather than assuming failure.

## Bypass / chain notes

Observed in the records:

- **Traversal depth tuning:** payloads used 7 (`../../../../../../../etc/passwd`) and 8 (`../../../../../../..etc/passwd`) `../` segments. Both landed; extra traversal segments past the root are harmless on Linux, so over-shooting depth is a reliable default.
- **Malformed path tolerance:** the typo'd `..etc/passwd` tail in 415682 still resolved. Do not assume a rejected/failed payload means a filter exists — retry with variations (extra `../`, missing separator, absolute path) before concluding.
- **Mode selection as the delivery mechanism:** `type=text` is the switch that makes file contents render as text into the output. Without the right `type`, the read may be invisible. When probing a similar feature, enumerate the `type`/format values and find the one that echoes the loaded file.
- **Source-code escalation chain:** all three records escalated from system files to the PHP application source code. Reading source is the high-value pivot: it exposes hardcoded credentials, further endpoints, and additional logic flaws. The records show `/etc/passwd` first (confirming the primitive), then application source (maximizing impact).
- **Broad system-context reads:** beyond `/etc/passwd`, the records demonstrate reading `/etc/issue`, `/etc/resolv.conf`, `/etc/hosts`, and `/var/log/apt/history.log` — OS-identification and host-context files that strengthen the report and can reveal internal network shape (resolv.conf) and software install history (apt logs).

## Gotchas / what NOT to do

- **Don't stop at `/etc/passwd`.** It proves the bug, but the records show the accepted-impact bar includes full application source code — pulling the PHP source is what made these reports complete. Always attempt a second-stage read of source/config.
- **Don't assume the contents come back in the immediate HTTP response.** In these records the file body is delivered via the saved generated artifact. Verify the full output flow before declaring the payload dead.
- **Don't require a textbook payload.** The records include a payload with a malformed traversal tail that still worked. Conversely, don't submit a sloppy path as your *primary* evidence — sub-pattern 2's clean traversal is the better demonstration; use variants only to establish root-cause breadth.
- **Don't ignore the non-exploit parameters' role.** `top-text`/`bottom-text` are needed to satisfy the endpoint's expected request shape (the records always include them, even trivially, e.g. `.` or `test`). A minimal request missing required fields may error before the file read happens.
- **Don't test this on a generator that renders templates as code without care** — in these records the read is passive (contents echoed), and that is what the records support. Anything beyond reading (e.g., attempting code execution through the template mechanism) is not demonstrated in the data and should not be claimed.
- **Scope check:** all records are from `h1-5411-CTF`. The endpoint `POST /api/generate.php` is a CTF-scope application. Confirm the target/program scope before replicating against production assets.

## Real-world impact examples

From the records:

- **Report 415137:** Using the valid-shape request but with `template` under attacker control, read `/etc/passwd` and the complete PHP application source code. Delivery: contents fetched via the saved meme after `type=text` submission.
- **Report 415501:** `template=../../../../../../../etc/passwd&type=text&top-text=ad&bottom-text=asd` → read of `/etc/passwd` plus the server-side PHP source code, demonstrating traversal out of the template directory.
- **Report 415682:** The widest enumeration in the set — `/etc/passwd`, `/etc/issue`, `/etc/resolv.conf`, `/etc/hosts`, `/var/log/apt/history.log`, and the application source code — from a single parameter with a (slightly malformed) 8-level traversal payload. This shows the same primitive supports systematic system-state enumeration: identity files, network configuration, and package-install history, then pivoting to source for credentials and further attack surface.

**Summary of the class as observed:** one root cause (unsanitized filename parameter used directly in a file read, contents echoed through the generated artifact), one delivery mechanism (`type=text` + saved output), and a graduated exploitation ladder — validate with the system file, enumerate host context, then exfiltrate application source for maximal proven impact.