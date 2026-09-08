---
name: hunter-l3-hardcoded-credentials
description: "Use when hunting Hardcoded Credentials on a target. Loads the L3 technique sheet: Hardcoded credentials are secrets — passwords, API keys, app secrets, tokens — baked into client binaries, installers, config files, public source repositories, or system artifacts (e.g., the Windows registry) instead of a secrets manager."
domain: cybersecurity
subdomain: web
tags:
- web
- hardcoded-credentials
- hunting
- l3
version: '1.0'
---

# Hardcoded Credentials — Technique Sheet

## Overview
Hardcoded credentials are secrets — passwords, API keys, app secrets, tokens — baked into client binaries, installers, config files, public source repositories, or system artifacts (e.g., the Windows registry) instead of a secrets manager. This class pays because the credential is *real by construction*: no fuzzing or guessing required, only extraction and verification. It hits two surfaces — artifacts shipped by the company (APKs, MSIs, .config files, registries) and artifacts leaked by employees (public GitHub commits, repos). Impact ranges from low (empty FTP dir) to critical (AWS account takeover via SAML), and scope rules matter: "hardcoded in mobile app" is sometimes informational unless the key grants real access — check the program's policy on client-side secrets before reporting.

## Distinct sub-patterns

### 1. Credentials in public GitHub commit history
- **Endpoint shape / parameter:** Employee GitHub repos (including *deleted/rewritten* history); target = framework or tooling repos of the challenge creator / engineers. Then the credential is replayed against a live admin surface: `POST /phpmyadmin` (params `username`, `password`) or `cloud.acronis.com/login` (params `login`, `password`), or as an API key header: `req.Header.Add("x-api-key", "...")` against `console.jumpcloud.com/api/*`.
- **Payload that actually fired (verbatim):**
  - `forum:6HgeAZ0qC9T6CQIqJpD` (phpMyAdmin login)
  - JumpCloud `x-api-key` header (key value redacted in record)
- **Root-cause pattern:** Secrets committed to a public GitHub repo — crucially recoverable from commit *history* even after edits, and discoverable by pivoting off OSINT (a public tweet pointing to the creator's GitHub).
- **Impact proven:** Dumped user table in phpMyAdmin, cracked the md5 hash (`BahHumbug`), logged in as admin, read a private post containing the flag. At Starbucks, the leaked JumpCloud API key listed systems (multiple AWS instances), system users, and SSO applications — SAML config enabled full AWS account takeover and command execution on systems. At Acronis, leaked creds gave portal login and access to sensitive info.
- **Exemplars:** 1069141 (h1-ctf), 716292 (Starbucks), 1078373 (Acronis)

### 2. Secrets embedded in downloadable binaries / installers (MSI, .exe)
- **Endpoint shape / parameter:** Publicly downloadable files from the vendor's own site — e.g., the 8x8 `.msi` download; FTP-distributed client installers like `GET /pub/misc/FTP_{name}Sign.exe.config` (an `.exe.config` shipped on the FTP server itself).
- **Payload:** Not stated for the 8x8 MSI; for the .config case, the secret lives in the file's `userSettings` XML section (FTP username/password in plaintext).
- **Root-cause pattern:** Secrets (AWS access tokens, FTP credentials) baked into installer artifacts anyone can download, or into config files left readable on the same public server.
- **Impact proven:** Extracted hardcoded AWS credentials from the 8x8 MSI and demonstrated access to 8x8 AWS infrastructure (token since restricted). For the DoD FTP case: valid FTP credentials verified by connecting on port 21 — read access to any file on the FTP server.
- **Exemplars:** 1368690 (8x8), 235216 (U.S. Dept Of Defense)

### 3. Secrets in decompiled mobile app binaries (APK)
- **Endpoint shape / parameter:** Decompile the APK (e.g., `app.zenly.locator`, GlassWire's `GlassWire.exe` APK, Eternal's Android app) and grep strings/resources for keys, tokens, URLs with embedded creds, app secrets.
- **Payload that actually fired (verbatim):** GlassWire:
  ```
  App ID: 660471650708388
  App Secret: 71a2d003a5ecfab4f4ad86dfb70b74e0
  ```
  Zenly: "hardcoded API keys/tokens in APK". Eternal: credentials for a dev environment (payload not stated).
- **Root-cause pattern:** Client-side code cannot keep secrets — API keys, tokens, Facebook App ID/Secret, and dev-environment credentials shipped inside the binary are recoverable by anyone with the app.
- **Impact proven:** GlassWire: used the App Secret to obtain a valid Facebook app access token via `client_credentials`, usable to modify Facebook App settings. Zenly: extracted a batch of API keys/tokens usable to send malicious traffic on the app's behalf. Eternal: access to a dev environment (rotated after report). 8x8 (412772): a URL embedding credentials to a third-party bug-capture API — access restricted to pushing bug info.
- **Exemplars:** 1641475 (GlassWire), 753868 (Zenly), 246995 (Eternal), 412772 (8x8)

### 4. Credentials in exposed config files on public servers
- **Endpoint shape / parameter:** Anonymous-accessible files on public infrastructure — `GET /pub/misc/FTP_{name}Sign.exe.config` on an FTP server; the secret sits in the `userSettings` XML section.
- **Payload:** Not stated verbatim (username/password inside userSettings XML).
- **Root-cause pattern:** A config file meant for internal tooling is exposed alongside public content; it contains working credentials for the same server.
- **Impact proven:** Verified the extracted FTP credentials by connecting to port 21 — read access to any file on the FTP server.
- **Chain as reported:** anonymous FTP download → parse userSettings XML → connect with extracted creds.
- **Exemplar:** 235216 (U.S. Dept Of Defense)

### 5. Secrets written to system artifacts (Windows registry)
- **Endpoint shape / parameter:** After installing the vendor software, inspect the local Windows registry — Kaspersky stored FTP creds in plaintext there. Replay against `ftp://kavdumps.kaspersky.com`.
- **Payload that actually fired (verbatim):** `kavdumps / UxzAbKFLufVBSg8Y`
- **Root-cause pattern:** The installer persists credentials in plaintext in a system artifact rather than a protected store.
- **Impact proven:** Successful login to the FTP server — though the directory was empty, bounding the impact.
- **Exemplar:** 291200 (Kaspersky)

## Bypass / chain notes
- **Commit-history archaeology:** The phpMyAdmin finding (1069141) worked because the credential survived in commit *history* even after being removed from HEAD. Don't just search current repo content — walk `git log`, removed files, and framework repos discoverable via OSINT (the repo was found via a public tweet by the challenge creator).
- **Extraction → verification chain:** Every high-severity finding pairs extraction with *proof the credential works*: login to phpMyAdmin, connect to FTP port 21, obtain a Facebook app access token via `client_credentials`, list JumpCloud systems/users/SSO apps. Reports that stop at "I found a string" are weaker; demonstrate authentication.
- **Crack-then-authenticate chain:** 1069141: dump user table → crack md5 (`BahHumbug`) → admin login → read private post → flag. Credential leaks chain into credential-cracking findings.
- **API-key → infrastructure chain:** 716292: JumpCloud `x-api-key` → list systems (AWS instances) + SSO apps → SAML config enables AWS account takeover and command execution. A single leaked key became full cloud compromise.
- **OSINT seeding:** Discovering which repos to look at (via tweet → author → repos) was the unlock in 1069141; a blind GitHub search would likely have missed it.
- **Binary → token minting:** GlassWire's App ID + Secret weren't directly impactful alone; minting an app access token via `client_credentials` turned them into a working credential.

## Gotchas / what NOT to do
- **Not every hardcoded key is a finding.** 8x8's bug-capture API creds (412772) and Kaspersky's empty FTP dir (291200) had bounded impact. Severity tracks what the credential *accesses*, not the fact that it exists.
- **Check program policy on mobile-app secrets.** Some programs treat "hardcoded in APK" as informational by default; you must show meaningful access (GlassWire's token minting did this — a raw App Secret listing would not have).
- **Payload redaction is normal.** 1078373 and 716292 redacted the actual secret in disclosure; your report should too, but the *verifier* needs it — include working creds via the program's private channel, not in the public body.
- **Don't report without verifying.** All the well-received records authenticated before reporting (FTP connect, portal login, API list calls). An unverified key string invites a duplicate/informative downgrade.
- **Don't stop at HEAD of the repo** — the credential may only exist in history.
- **Note the empty directory:** Kaspersky's FTP login succeeded but the directory was empty — the finding stood but impact was limited. Report impact honestly.

## Real-world impact examples
- **AWS account takeover + command execution (Starbucks, 716292):** One JumpCloud API key from a public GitHub repo → listed systems including multiple AWS instances, system users, SSO applications → SAML config enabled AWS takeover and command execution on all managed systems.
- **Admin compromise via cracked hash (h1-ctf, 1069141):** GitHub commit history → phpMyAdmin login (`forum:6HgeAZ0qC9T6CQIqJpD`) → dump user table → crack md5 → admin login → private post read → `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`.
- **Cloud infrastructure access (8x8, 1368690):** AWS access token inside a public MSI download → demonstrated access to 8x8 AWS infrastructure.
- **Facebook app takeover vector (GlassWire, 1641475):** App ID + Secret in the binary → valid app access token via `client_credentials` → ability to modify Facebook App settings.
- **Arbitrary file read on FTP (DoD, 235216):** Exposed `.exe.config` in `userSettings` XML → valid FTP creds → read access to any file on `FTP_{name}Sign` server.
- **Send traffic as the app (Zenly, 753868):** Decompiled APK → batch of API keys/tokens usable to send malicious traffic on the app's behalf.
- **Dev environment access (Eternal, 246995):** Hardcoded dev-environment credentials in the Android app; environment access confirmed, creds rotated after report.