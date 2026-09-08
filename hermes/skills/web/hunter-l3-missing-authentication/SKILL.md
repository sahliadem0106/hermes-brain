---
name: hunter-l3-missing-authentication
description: "Use when hunting Missing Authentication on a target. Loads the L3 technique sheet: Missing Authentication covers endpoints that perform privileged or state-changing operations without verifying the caller's identity or authorization — no session, no token, no role check."
domain: cybersecurity
subdomain: web
tags:
- web
- missing-authentication
- hunting
- l3
version: '1.0'
---

# Missing Authentication — Technique Sheet

## Overview
Missing Authentication covers endpoints that perform privileged or state-changing operations without verifying the caller's identity or authorization — no session, no token, no role check. It spans server-side frameworks (Meteor methods, SAP Java services), local-only REST APIs on loopback ports, and admin configuration surfaces. It pays consistently because the bug is a simple check that was never written: if you can enumerate the method/route, you can often own the feature in one request, and the impact is frequently full administrative or global-config compromise rather than mere info disclosure.

## Distinct sub-patterns

### 1. Unauthenticated Meteor RPC method (server-side RPC without auth check)
- Endpoint shape: Meteor DDP method invocation over `Meteor.call('<method>', <args>...)`, against a Rocket.Chat/Livechat-style deployment. Here: `Meteor.call('livechat:saveOfficeHours', day, start, finish, open)` — parameters `day`, `start`, `finish`, `open`.
- Payload that actually fired (verbatim):
  `Meteor.call('livechat:saveOfficeHours','Monday','00:23','00:42',true);`
- Root cause: The Meteor method `livechat:saveOfficeHours` forwards input directly to the `LivechatBusinessHours` model without any authentication or authorization check. Any unauthenticated client can invoke the RPC.
- Impact proven: As an unauthenticated client, modified the GLOBAL Livechat Business Hours configuration (Monday, 00:23–00:42, open=true) — global service-config tampering, not just self-scoped data.
- Exemplars: 106315 (Coinbase).

### 2. Unauthenticated admin-user creation via exposed SAP NetWeaver RECON service
- Endpoint shape: `POST /` to an exposed SAP Java RECON service on a public host, e.g. `redapi.acronis.com` (SAP NetWeaver AS Java; CVE-2020-6286 / CVE-2020-6287).
- Payload: not stated in the record (RECON configuration payload; standard exploit flow is a POSTed LM configuration wizard payload that creates a new admin user).
- Root cause: The exposed SAP NetWeaver services perform no authentication check, allowing unauthenticated configuration actions — including user creation via the RECON vulnerability.
- Impact proven: Created an unauthenticated administrative user (`sapRpoc9049` : `Secure!PwD6751`) on the SAP Java system at redapi.acronis.com — full admin foothold from a single unauthenticated POST.
- Exemplars: 1103212 (Acronis).

### 3. Local privileged REST API with no auth (localhost port, unprivileged caller)
- Endpoint shape: `PUT /lists/processImages/white` and `PUT /lists/excludes` on the local `anti_ransomware_service` REST API listening on port 6109 (loopback). Parameter: `path` inside a JSON body.
- Payload that actually fired (verbatim):
  `data = {"additions": [{"path": "C:\\ProgramData\\ransomware_exe.exe"}], "removals": []}`
- Root cause: The `anti_ransomware_service` REST API performs no authentication, so any local unprivileged user can invoke its privileged functions. The service trusts "whoever can reach the port," but on a multi-user machine every local user reaches loopback.
- Impact proven: Whitelisted an arbitrary executable and excluded the entire system drive (`C:\*`) from monitoring — silently disabling the anti-ransomware protection entirely.
- Exemplars: 858608 (Acronis).

## Bypass / chain notes
- Local-port trust chain (858608): two chained PUTs, each trivially authorized by the missing-auth flaw:
  1. `PUT /lists/processImages/white` — add arbitrary exe (e.g. malware at `C:\ProgramData\ransomware_exe.exe`) to the process whitelist, so it is never flagged.
  2. `PUT /lists/excludes` — add `C:\*` to exclude the whole drive from scanning, so even non-whitelisted malicious activity is invisible.
  Together: complete silent disabling of the security product while leaving it appearing to run.
- The SAP case (1103212) is effectively a one-request chain by itself: unauthenticated config write → new admin account (`sapRpoc9049`) → persistent privileged access. No second bug needed.
- The Meteor case (106315) shows that "config" RPCs on user-facing chat products are often registered as methods with no `userId` check — worth testing other `livechat:*` / admin-ish methods the same way once one is found unauthenticated.

## Gotchas / what NOT to do
- Don't stop at "it returned 200": for config-changing endpoints, issue a harmless, reversible change and prove the state actually changed (here: business hours visibly set to Monday 00:23–00:42 open=true). Proof-of-state beats proof-of-access.
- On SAP/CVE-class findings, don't just show the service is reachable — demonstrate the privileged action (user creation) and report the account name and evidence, as 1103212 did.
- Don't assume a localhost-only API is out of scope or unexploitable: any unprivileged local user (or a separate low-priv process you control) can reach it. Scope-check the program, but the security-model break is real and was accepted (858608).
- Keep payloads harmless where possible — `C:\ProgramData\ransomware_exe.exe` was a non-existent/benign-named path used to prove whitelist control without deploying actual malware. Same for the drive-exclude: demonstrate the exclusion rule, don't actually attack the host while unprotected.
- Meteor: don't spray hundreds of method names blindly; enumerate the client bundle for method names, then test the privileged ones individually with minimal args.

## Real-world impact examples
- Global support-chat availability tampered on Coinbase's Livechat by a fully unauthenticated client (106315).
- Full administrative account (`sapRpoc9049` / `Secure!PwD6751`) created on Acronis's `redapi.acronis.com` SAP Java stack via unauthenticated RECON (1103212).
- Acronis anti-ransomware agent on a workstation completely neutralized — arbitrary exe whitelisted and `C:\*` excluded from monitoring — by any unprivileged local user via the unauthenticated port-6109 REST API (858608).