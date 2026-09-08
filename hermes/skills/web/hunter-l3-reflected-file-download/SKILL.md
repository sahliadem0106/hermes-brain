---
name: hunter-l3-reflected-file-download
description: "Use when hunting Reflected File Download on a target. Loads the L3 technique sheet: Reflected File Download (RFD) is an attack where attacker-controlled input is reflected into the *body* of a response that is served as a downloadable file (via `Content-Disposition: attachment` or a "
domain: cybersecurity
subdomain: web
tags:
- web
- reflected-file-download
- hunting
- l3
version: '1.0'
---

# Reflected File Download — Technique Sheet

## Overview

Reflected File Download (RFD) is an attack where attacker-controlled input is reflected into the *body* of a response that is served as a downloadable file (via `Content-Disposition: attachment` or a `download` attribute), while the *filename* is also attacker-influenced to carry a dangerous extension (`.bat`, `.cmd`). The victim downloads a file that appears to come from the trusted site; when executed on Windows, the shell interprets the reflected content as batch commands. It pays on any endpoint that echoes a parameter into a JSON/JSONP response delivered as a file — especially session, config, export, or callback-style endpoints.

## Distinct sub-patterns

### 1. JSONP-style `callback` parameter → `.cmd` file (Ubiquiti)

- Endpoint shape:
  `GET /restapi/vc/authentication/sessions/{name}.cmd?restapi.response_format=json&callback={payload}`
  (exemplar: `/restapi/vc/authentication/sessions/Ubiquiti_update.cmd`)
- Parameter: `callback`
- Verbatim payload:
  `https://community.ubnt.com/restapi/vc/authentication/sessions/Ubiquiti_update.cmd?restapi.response_format=json&callback=\%22||calc||`
- Root cause: the `callback` parameter is reflected into a downloadable file's name/content without sanitization. The `\%22` (URL-encoded `\"`) lets the attacker break out of the JSONP quoting so the file body is valid batch syntax on both lines. Naming the session `Ubiquiti_update` plus the `.cmd` extension makes the downloaded file execute as a Windows command script.
- Impact proven: downloaded file `Ubiquiti_update.cmd` executed arbitrary commands (`calc.exe`) when opened — full victim machine compromise.
- Exemplar: id=107960 (Ubiquiti Inc., ajaysenr)

### 2. Reflected field in JSON served with `.bat` extension + `download` attribute (HackerOne)

- Endpoint shape:
  `GET /{team}/triggers/{id}.bat`
  where the trigger's `text` (Criteria field) value is reflected into the response body.
- Parameter: `text` (the trigger's Criteria field)
- Verbatim payload: `text" || calc ||`
- Root cause: the trigger Criteria `text` value is reflected unsanitized into a JSON response served with a `.bat` extension and a download attribute. The embedded `"` terminates the JSON string context so the rest of the line parses as batch commands. The trusted-origin filename (`...hackerone.com...bat`) induces the victim to run it.
- Impact proven: victim downloads a file presented as coming from HackerOne; executing it opens calculator (`calc`) — code execution under the site's trusted name.
- Exemplar: id=39658 (HackerOne, ajaysenr)

### 3. RFD on a re-download flow (Vimeo)

- Endpoint shape: video re-download endpoint on `www.vimeo.com` (re-download of a previously uploaded video).
- Parameter: the download request itself (specific parameter/payload not stated in the record).
- Root cause: a Reflected File Download was triggered during the re-download flow — the file-serving path reflects attacker-influenced content into a downloadable response.
- Impact proven: researcher was able to craft a Reflected File Download during re-download of a previously uploaded video.
- Payload: not stated.
- Exemplar: id=378941 (Vimeo, ajaysenr)

## Bypass / chain notes

- JSON quoting break-out: use `\%22` (URL-encoded `\"`) in the callback/reflected parameter so the response body is simultaneously valid JSON/JSONP *and* valid batch syntax — the standard RFD trick seen in id=107960 (`\%22||calc||`) and id=39658 (`text" || calc ||`).
- Filename control via path or upload naming: id=107960 embeds the desired filename (`Ubiquiti_update`) directly in the session-name path segment; id=39658 relies on the endpoint's hardcoded `.bat` suffix. Prefer a plausible name (`*_update.cmd`, `*.bat`) to increase the chance the victim executes it.
- Multi-step flow variant (id=378941): RFD does not always need a reflective query parameter on the file endpoint itself — attacker-influenced data stored earlier (e.g., an uploaded video) can be reflected into the file body when the victim re-downloads. Chain: attacker sets content → victim triggers re-download → malicious filename/content delivered.
- All three records were standalone (no chains recorded), but in each case the download alone led to command execution (`calc` as proof).

## Gotchas / what NOT to do

- The body must be syntactically valid in both the original format (JSON/JSONP) and batch — otherwise the response may be rejected or the file won't run. Use the `\"`-breakout (`\%22` encoded) trick rather than naive injection.
- Don't test only with a browser download — RFD impact is proven by *executing* the downloaded file (demonstrators used `calc`); a file that won't parse as batch is a non-finding.
- The extension matters: `.cmd`/`.bat` delivered with a download attribute/disposition is what makes this exploitable on Windows. A reflected payload without the executable extension is a different (weaker) class.
- Parameter and payload must be preserved exactly when reproducing — URL-encoding (`%22` vs `\%22`) changes whether the JSON/batch duality holds.
- Note: all three exemplar records are attributed to the same researcher (ajaysenr) — RFD findings on auth/session/export-style endpoints are the recurring shape; don't assume breadth beyond what's in these records.

## Real-world impact examples

- **Ubiquiti (id=107960)**: `Ubiquiti_update.cmd` downloaded from `community.ubnt.com` executed `calc.exe` on the victim's machine — arbitrary command execution, full compromise of the victim host.
- **HackerOne (id=39658)**: A `.bat` file that appears to come from HackerOne (trigger endpoint `/{team}/triggers/{id}.bat`), when downloaded and run by the victim, executes attacker commands (`calc` demonstrated).
- **Vimeo (id=378941)**: RFD crafted on the video re-download flow of a previously uploaded video — attacker-controlled file delivered from the trusted vimeo.com origin.