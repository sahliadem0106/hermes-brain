---
name: hunter-l3-arbitrary-file-deletion
description: "Use when hunting Arbitrary File Deletion on a target. Loads the L3 technique sheet: Arbitrary file deletion is the class of bugs where an attacker controls which file the server removes — via path traversal in a \"file reference\" parameter, via unvalidated identifiers that map to file"
domain: cybersecurity
subdomain: web
tags:
- web
- arbitrary-file-deletion
- hunting
- l3
version: '1.0'
---

# Arbitrary File Deletion — Technique Sheet

## Overview
Arbitrary file deletion is the class of bugs where an attacker controls which file the server removes — via path traversal in a "file reference" parameter, via unvalidated identifiers that map to filesystem paths, or via privileged services acting on attacker-influenced paths. While often dismissed as low-impact, these records show it pays: deletion of config files takes applications fully offline, deletion of shared storage destroys all user data, and deletion of protected OS files as SYSTEM can chain toward privilege escalation or EoL on Windows hosts. It is most reliable against appliance web interfaces (Cisco ASA/FTD webvpn), PHP apps passing paths to unlink(), multi-user platforms that derive data directories from user input, and Windows services that clean directories without verifying targets.

## Distinct sub-patterns

### 1. Cookie-based path traversal in appliance web services (Cisco ASA/FTD — CVE-2020-3187)
- Endpoint shape: `GET /+CSCOE+/session_password.html` with a poisoned cookie. The web services file system is rooted under `+CSCOU+/` / `+CSCOE+/`; traversal escapes it.
- Payload that actually fired (verbatim):
  - `token=../+CSCOE+/blank.html` (cookie: `Cookie: token=../+CSCOE+/blank.html`)
  - `curl -H "Cookie: token=../+CSCOU+/csco_logo.gif" https://█████/+CSCOE+/session_password.html`
  - Records 1026265 and 987090 both used the `token` cookie; record 1455266 confirmed vulnerable state via the webvpn cookie mechanism without performing a deletion.
- Root-cause pattern: the web services interface processes the `token` cookie (and webvpn cookie) with `../` sequences without validation, letting an unauthenticated attacker read or delete files within the appliance's web services file system. The session_password.html endpoint acts as the trigger; the cookie value is the file path.
- Impact proven: unauthenticated request deleted `/+CSCOE+/blank.html` — verified because a subsequent request for the file returned 404 "File not found" (1026265). DoS: deleting lua source files breaks the WebVPN interface until reboot. On patched versions session_password.html is removed, so a 200 response also serves as a vuln fingerprint.
- Exemplars: 1026265, 987090, 1455266 (all U.S. Dept Of Defense).

### 2. Path traversal in avatar/image-reference parameter reaching unlink() (PHP)
- Endpoint shape: `POST /members/{username}/profile/change-avatar/` with a parameter that tells the server the original avatar file location (BuddyPress-style `bp_avatar_set`).
- Payload that actually fired (verbatim, URL-decoded):
  `original_file=http://localhost/~sam/wordpress/wp-content/uploads/avatars/2/../../../../../wp-config.php`
- Root-cause pattern: `bp_avatar_set` accepted the attacker-controlled `original_file` parameter without validating it stays within the uploads directory; the path (which can be a URL the server resolves to a local path, or a direct path) is fed to `unlink()` after avatar upload succeeds, so `../` traversal re-points the delete target anywhere the webserver user can remove.
- Impact proven: deleted `wp-config.php` via unlink(), taking the entire WordPress blog offline — full site outage from a single authenticated (self-service profile) request.
- Exemplar: 183568 (WordPress program).
- Key detail: the parameter is URL-encoded in the POST body — traversal sequences must survive the server's URL decoding, so plain `../../` works when there is no second decoding/filter layer.

### 3. Data-directory derivation from username (user-as-path)
- Endpoint shape: Nextcloud user management — create user, then delete user. No HTTP parameter traversal involved; the username itself is the path component.
- Payload: username `.` (record states payload "." for the username).
- Root-cause pattern: Nextcloud derives each user's data folder from the username without validating `.`. Deleting a user deletes that user's data folder; a user named `.` maps to the parent `data` directory itself.
- Impact proven: creating a user named `.` and then deleting that user removed the whole `data` folder — all users' data on the instance destroyed.
- Exemplar: 220385 (Nextcloud).
- Chain (verbatim): ["Create new user with username '.'", "Delete that user", "Nextcloud removes the '.' folder, i.e. the whole data directory"]

### 4. Privileged Windows service deleting attacker-influenced paths via mount points
- Endpoint shape: local/low-priv interaction with `mms.exe` (Acronis Managed Machine Service); no web parameter. The primitive is a crafted NTFS mount point.
- Payload: none stated (no HTTP payload; the payload is the mount point object).
- Root-cause pattern: the Managed Machine Service deletes mount-point-linked directories as SYSTEM without verifying the target — it follows the reparse point and deletes whatever it links to.
- Impact proven: a low-privileged account caused deletion of files/folders as SYSTEM, including content under `C:\Windows\secret` (a protected location).
- Exemplar: 959815 (Acronis).
- Chain: ["Create a mount point linking C:\Acronis\PostRebootResult to a target folder", "Restart the Acronis Managed Machine Service", "Service deletes the linked target"] (chain text truncated in the record after "Service deletes the").

## Bypass / chain notes
- Webvpn-cookie traversal (pattern 1): traversal targets stay within the appliance's web services filesystem namespace by escaping one level with a single `../` then re-entering (`../+CSCOE+/blank.html`, `../+CSCOU+/csco_logo.gif`). One traversal step followed by an absolute-from-webroot path is what fired — not deep multi-hop `../../..` chains.
- Verify-deletion loop (pattern 1): re-request the deleted file and check for the appliance's 404 "File not found" response — this converts "probably deleted" into verified impact and is what made report 1026265 a confirmed deletion.
- Fingerprint-first (pattern 1): because patched builds remove `/+CSCOE+/session_password.html`, a 200 on that endpoint both identifies vulnerable hosts and justifies the finding (record 987090 used exactly this logic).
- URL-vs-path duality (pattern 2): the fired payload supplied `original_file` as a URL (`http://localhost/...`) whose path portion contained the traversal — the server resolved it to a local path before unlink(). Worth testing both direct filesystem paths and localhost URLs for parameters like this.
- Self-inflicted-destruction chain (pattern 3): when user input becomes a data path, the create-then-delete lifecycle of the resource is the delivery mechanism. Same template applies to any "delete user/folder/project" feature where the identifier names a directory.
- Windows reparse-point chain (pattern 4): low-priv attacker controls the link, SYSTEM service performs the delete on restart — a classic symlink/mount-point delegation chain; the service restart is the trigger, not a network request.

## Gotchas / what NOT to do
- Don't delete first, report later without a verification plan. Record 1455266 confirmed the vulnerable state and characterized impact without actually performing a destructive deletion — on production targets (especially .gov), demonstrating with a throwback-safe file (e.g. a webroot asset like blank.html or a logo gif) is the accepted approach.
- Don't assume "file deletion = low". Deletion of wp-config.php = full site outage; deletion of the data directory = total data loss of every user; deletion as SYSTEM on Windows = potential LPE chain. Frame impact in terms of what the deleted file breaks.
- Don't stop at read-only proof for traversal bugs that also support DELETE — the reports showing actual deletion (1026265) are strictly stronger than state-confirms only.
- DoS via deleting engine files (lua sources in pattern 1) is a real, accepted impact claim in these records — but it breaks the appliance until reboot; scope it and get authorization, and prefer a benign file for the demonstration.
- On the avatar pattern, the parameter is not the upload itself — the deletion fires as a side effect of the avatar-set flow, so you must complete the legitimate flow (upload an avatar) with the poisoned `original_file` value, not just POST the traversal parameter in isolation.

## Real-world impact examples
- Unauthenticated single request with `Cookie: token=../+CSCOE+/blank.html` deleted the Cisco ASA webvpn blank.html; follow-up request returned 404 "File not found" — deletion verified (1026265). Same class of request across three DoD targets (1026265, 1455266, 987090).
- One POST to `/members/{username}/profile/change-avatar/` with the traversal `original_file` deleted `wp-config.php`, taking the WordPress blog offline entirely (183568).
- User named `.` deleted on Nextcloud removed the entire `data` directory — all users' files on the instance gone (220385).
- Low-privileged Acronis user caused `mms.exe` (running as SYSTEM) to delete files including content under `C:\Windows\secret` via a crafted mount point and service restart (959815).