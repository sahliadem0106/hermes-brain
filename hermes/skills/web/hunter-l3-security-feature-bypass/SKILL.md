---
name: hunter-l3-security-feature-bypass
description: "Use when hunting Security Feature Bypass on a target. Loads the L3 technique sheet: Security Feature Bypass covers findings where a protection mechanism exists, is correctly implemented for its canonical input, but can be sidestepped by changing the *form* of the input rather than defeating the mechanism itself."
domain: cybersecurity
subdomain: web
tags:
- web
- security-feature-bypass
- hunting
- l3
version: '1.0'
---

# Security Feature Bypass — Technique Sheet

## Overview

Security Feature Bypass covers findings where a protection mechanism exists, is correctly implemented for its canonical input, but can be sidestepped by changing the *form* of the input rather than defeating the mechanism itself. The defense is not absent — it is applied non-exhaustively: URLs aren't normalized before matching a blocklist, file paths are monitored by one name only, or one UI setting silently disables another warning. These bugs pay well because they undermine an explicit security promise (blocked previews, tamper detection, malicious-download warnings) that the vendor markets as a feature, and the impact is demonstrable by direct comparison: bypass path triggers nothing, canonical path triggers the protection.

## Distinct sub-patterns

### 1. URL normalization gap in blocklist/allowlist matching (link preview bypass)

- Endpoint shape / parameter: any feature that takes a user-posted URL and matches it against a policy list — here, Slack's link preview generator (`slack.com` message unfurling), parameter = the posted URL in a message.
- Payload that actually fired (verbatim): `https://jub0bs.com/posts/2021-01-29-great-samesite-confusion/.` — a benign domain with a trailing `.` appended after the TLD (making the host `jub0bs.com.`), which resolves identically but string-matches differently. The record also cites non-normalized `../` path segments as an equivalent bypass vector.
- Root cause: Slack does not normalize posted URLs before matching them against the Blocked Previews list. The blocked-preview rules are exact/syntactic string comparisons against the raw posted URL, so a trailing dot on the hostname (a legal DNS form meaning "fully qualified root") or un-collapsed dot-segments in the path produce a string that fails the blocklist match while still resolving to (or behaving like) the blocked resource.
- Impact proven: Non-normalized URLs (trailing dot after host, or non-normalized `../` path segments) triggered link previews despite the workspace's blocked-preview rules. A workspace admin who blocked preview generation for a domain could have that block silently defeated in user clients.
- Exemplar: id=1102764 (Slack).

### 2. Path-identity gap in file-integrity monitoring (hardlink tampering bypass)

- Endpoint shape / parameter: local filesystem — the monitored target is a well-known security-relevant file, here `C:\Windows\System32\drivers\etc\hosts` as watched by GlassWire's system-file monitoring. The bypass operates through a second directory entry (hardlink) pointing at the same file.
- Payload: not stated as a verbatim string; the technique is a file operation sequence: create a hardlink to the hosts file (e.g. `mklink /H <link> C:\Windows\System32\drivers\etc\hosts` with admin rights), then append entries by writing through the link path.
- Root cause: GlassWire registered its change notification against the hosts file *path* (one directory entry / canonical name), not against the underlying file object. NTFS hardlinks mean multiple names can reference the same file data; a write through any non-monitored name still modifies the monitored file, but the watcher — keyed on the monitored path — never fires.
- Impact proven: Appending entries through the hardlink did not trigger GlassWire's 'system file changed' notification, while a direct edit of the same file did. Consequence: malware with admin rights can tamper with the hosts file (redirect domains, sinkhole AV update servers) undetected by the security product.
- Exemplar: id=141700 (GlassWire).

### 3. Cross-feature interaction suppressing a security warning (browser download flow)

- Endpoint shape / parameter: browser settings surface — Brave's Windows download flow; parameter is the combination of the 'Ask where to save each file before downloading' preference and the potentially-malicious-file-type warning logic. No network endpoint; the "input" is a configuration state.
- Payload: N/A (configuration-based, no payload).
- Root cause: Enabling 'Ask where to save each file before downloading' suppresses the potentially-malicious file type warning. The two features share a code path (both intercept the download-completion step), and the save-location prompt takes precedence — when it fires, the danger classification/warning is skipped entirely instead of being shown after the prompt.
- Impact proven: With 'Ask where to save each file before downloading' enabled, the potentially-malicious file type warning no longer appears for downloads, letting dangerous file types download silently — a user can be tricked into saving and running a flagged dangerous filetype with no warning at any point in the flow. The record notes the same behavior is present in Chrome, which matters for triage (it's a shared-Chromium interaction, and the vendor may still treat the user-facing consequence in their security surface as in-scope).
- Exemplar: id=1848062 (Brave Software).

## Bypass / chain notes

- No records chained the bypass into a second bug — all three stand alone. The single-step nature is the point: each bypass needs only one attacker-controlled transformation of an already-legitimate input.
- Transformation families observed across the records, usable as a checklist when hunting this class:
  1. Syntactic equivalence: trailing dot on hostname (`example.com.`), un-normalized `../` path segments — same resolution, different string.
  2. Identity equivalence: hardlink (same inode/file object, different path) — same file, different name.
  3. State equivalence: a benign setting that shares a code path with the security check — same user flow, warning suppressed.
- For the URL pattern, both the host and the path layers of normalization were missing; test each layer independently (trailing dot alone, `../` alone, then combined).

## Gotchas / what NOT to do

- Do not test the normalization bypass with a domain you don't control or one outside the blocklist — the payload must target a resource the policy actually blocks, or the diff (preview appears vs. suppressed) proves nothing.
- Don't report "the warning doesn't appear" without the control experiment: for the GlassWire class, the report explicitly established that a *direct* edit did trigger the notification while the hardlink edit did not. The comparison is the evidence.
- Don't assume Chromium-shared behavior is automatically out of scope. The Brave record (id=1848062) acknowledged the same behavior exists in Chrome but still demonstrated and reported the user-facing danger in Brave's download flow; scope decisions belong to the triager.
- Hardlink testing requires local admin (SeCreateSymbolicLink/hardlink creation on protected paths) — do this only on assets you're authorized to test, and restore the hosts file afterward.
- Don't conflate "feature behaves unexpectedly" with "security feature bypassed": each of these records showed a concrete security promise broken (blocklist circumvented, tamper detection silenced, malware warning suppressed), not merely a UX quirk.

## Real-world impact examples

- Slack (id=1102764): A workspace with blocked-preview rules in force could still unfurl previews for URLs on the blocklist when posted with a trailing dot or `../` segments — the admin's content policy silently not enforced in user clients.
- GlassWire (id=141700): An attacker with admin rights could append arbitrary entries to the system hosts file (e.g. redirecting update/AV domains) without GlassWire's 'system file changed' notification firing — a core tamper-detection feature defeated while the same edit through the normal path would alert.
- Brave (id=1848062): Dangerous file types (flagged as potentially malicious) downloaded with no warning whenever the save-location prompt setting was enabled — a default-plausible configuration under which the browser's malicious-download protection becomes a no-op, enabling user-trickery downloads of executable/dangerous content.