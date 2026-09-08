---
name: hunter-l3-sensitive-data-exposure
description: "Use when hunting Sensitive Data Exposure on a target. Loads the L3 technique sheet: This class covers secrets and sensitive data leaking through channels the application owner didn't intend to be public: credentials committed to source-control history, backup archives and plugin ZIPs"
domain: cybersecurity
subdomain: web
tags:
- web
- sensitive-data-exposure
- hunting
- l3
version: '1.0'
---

# Sensitive Data Exposure — Technique Sheet

## Overview
This class covers secrets and sensitive data leaking through channels the application owner didn't intend to be public: credentials committed to source-control history, backup archives and plugin ZIPs left in web roots, passwords echoed back in responses or written to logs, plaintext secrets in process memory, and partial redaction failures in documents. It pays whenever the exposed secret is *reusable* — a live DB credential, a `secret_key_base` that forges session cookies, a license key — or when it's real personal data (SSN digits, password hashes crackable offline). Many of these findings require no active exploitation at all: the download itself is the impact, and chaining turns them into full account compromise.

## Distinct sub-patterns

### 1. Database credentials leaked in git history → phpMyAdmin takeover
- Endpoint shape: `/forum/phpmyadmin` (any exposed phpMyAdmin or DB admin UI), plus `POST /forum/login` with params `username,password`.
- Payload (verbatim): `self::$write = new DbConnect( true,  'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );` and `self::$read = new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );` — i.e. DB user `forum`, password `6HgeAZ0qC9T6CQIqJpD`. Login payload form: `forum:6HgeAZ0qC9T6CQIqJpD`.
- Root cause: DB credentials committed to a public GitHub repo (`Grinch-Networks/forum`) in its commit history, and they remained valid on the live phpMyAdmin instance.
- Impact proven: logged into phpMyAdmin with the leaked creds, dumped the users table, retrieved MD5 password hashes, cracked the admin hash (`grinch:BahHumbug`), logged in as admin, and read a hidden post containing `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`.
- Exemplars: 1065731, 1065885 (also 1068880, 1068934 — same chain via `POST /forum/login`).

### 2. Full website backup archive in the web root
- Endpoint shape: `GET /mtn.zip` — a predictable backup filename at the site root (also try the pattern `/wp-content/uploads/{path}.zip`, see sub-pattern 4).
- Payload: none needed — direct unauthenticated download. Real hit: `https://mtn.co.rw/mtn.zip`.
- Root cause: the full website backup archive is publicly downloadable from the web root.
- Impact proven: downloaded the entire backup, leaking source code and database credentials usable to compromise the resource.
- Exemplar: 1516520 (MTN Group).

### 3. Secret keys committed to public repos (framework secrets)
- Endpoint shape: not an endpoint — a public GitHub repository (in this record, an "access-dashboard" repo).
- Payload: none stated.
- Root cause: the Rails `secret_key_base` was committed in plaintext to the public repo.
- Impact proven: exposed production `secret_key_base`, which allows forging signed cookies to impersonate any user in the application.
- Exemplar: 262620 (Gratipay).

### 4. Premium plugin/license archives exposed via WordPress media library + REST enumeration
- Endpoint shape: `GET /wp-json/wp/v2/media` (REST index of the media library) → `GET /wp-content/uploads/{path}.zip`.
- Payload: none; the discovery vector is the WP REST media endpoint listing the ZIPs. A verbatim confirmed download: `revslider-6.5.14-HcwXam9CAYQZ0Y5.zip` (HTTP 200, 7.6MB, no auth).
- Root cause: the WordPress media library stores 29 premium plugin ZIP archives in the publicly served uploads directory, indexed by the REST API and downloadable without authentication.
- Impact proven: extracted embedded license/purchase tokens and full plugin source; license keys for RevSlider/Wordfence/ACF Pro/Elementor are reusable, and the source can be analyzed for further exploits.
- Exemplar: 3839889 (Essity).

### 5. Plaintext password written to logs on failed auth
- Endpoint shape: WebDAV login path — the `validateUserPass` log line; parameter of interest: `password`.
- Payload: none (observation of the log content).
- Root cause: failed 2FA login attempts write the submitted password in plaintext to the log.
- Impact proven: confirmed the *correct* password of a failed WebDAV login attempt was stored plaintext in logs, potentially readable by multiple people with log access.
- Exemplar: 244092 (Nextcloud).

### 6. Plaintext password echoed back in later server responses
- Endpoint shape: `POST /signup` form; the leak surfaces in later responses (in this record: an invitation confirmation form). Parameter: `password`.
- Payload: "submitted password returned in clear text in later responses (invitation confirmation form)" — the reflection is the payload; no fixed string.
- Root cause: the signup/confirmation form reflects the submitted password back in plaintext in later server responses.
- Impact proven: confirmed the full password is submitted and returned in clear text in later responses, increasing the risk it can be captured via other vulnerabilities (session issues, broken access control, XSS).
- Exemplar: 90862 (Shopify).

### 7. Secrets persisting in process memory
- Endpoint shape: desktop/GUI client (in this record: NordVPN Windows client, GUI) — post-crash memory dump.
- Payload: none.
- Root cause: the GUI does not wipe the plaintext password from process memory after startup.
- Impact proven: plaintext user password found in a memory dump after GUI launch — exposable to malware or crash dumps.
- Exemplar: 761480 (Nord Security).

### 8. Partial redaction failure in public documents/media
- Endpoint shape: public presentation slides (document review of published material).
- Payload: none.
- Root cause: a public slide contained a screenshot of live data with only *partial* redaction.
- Impact proven: the last 4 digits of a soldier's SSN were exposed; combined with the full name, this can grant access to sensitive portals (PII exposure in a .gov/.mil program context).
- Exemplar: 665144 (U.S. Dept of Defense).

## Bypass / chain notes
- Git history is a first-class source: the strongest chain in the records is OSINT → public repo (`github.com/Grinch-Networks/forum`) → **commit history** (not just HEAD) leaks DB credentials → live phpMyAdmin login → dump users table → crack MD5 (`grinch:BahHumbug`) → admin login → read hidden content/flag. Check commit history even when the current source looks clean (1065731, 1068880).
- Leaked DB creds → offline hash cracking → application account takeover is the recurring escalation: the DB itself is step one, the application admin account is the payoff.
- Backup/ZIP exposure chains into code review: `mtn.zip` yielded source + DB credentials (1516520); the WP plugin ZIPs yielded license tokens *and* plugin source usable to hunt for further plugin vulnerabilities (3839889). Unauthenticated ZIP in a web-served path is a finding on its own; source access multiplies it.
- Framework secret (`secret_key_base`) → cookie forging → impersonate any user (262620) — no further endpoint access needed once the secret is confirmed live.
- Password-in-logs and password-reflection findings chain naturally with any secondary bug (XSS, broken access control, session handling) that lets an attacker read the log or the reflected response (244092, 90862).
- PII partial-redaction findings chain with OSINT: last-4 SSN + full name is enough to target identity-verification flows (665144).

## Gotchas / what NOT to do
- Don't stop at "repo is public" — the finding strength comes from proving the secret is still *valid* on the live system (phpMyAdmin login, cookie forgery). A dead credential is a much weaker report.
- Don't ignore commit history: in these records the credentials were recovered from history, not the tip of the repo.
- Don't only fuzz for `.zip` blindly — the WP media REST endpoint (`/wp-json/wp/v2/media`) is a legitimate index that enumerates exposed archives for you (3839889).
- Don't report a password visible in your own response as catastrophic on its own — in the Shopify record the proven impact was "full password reflected in later responses, increasing capture risk via other vulns" (90862). Frame the risk honestly; it may be accepted as lower severity.
- Don't overlook client-side/desktop targets in SDE programs — memory retention of passwords (76480's NordVPN record) is a valid finding without any web endpoint.
- Don't assume documents are fully redacted — check screenshots inside slides for partially masked identifiers (665144). Never exfiltrate or display more PII than needed to prove the exposure.
- When logging-based leaks are suspected, never spam failed logins against production to generate log entries at scale; a single controlled confirmation suffices (244092).

## Real-world impact examples
- Grinch Networks CTF (1065731/1068880): leaked DB cred `forum:6HgeAZ0qC9T6CQIqJpD` → phpMyAdmin → MD5 `grinch:BahHumbug` cracked → admin session → hidden post flag `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`. End-to-end: public git history to full admin compromise.
- MTN Group (1516520): `https://mtn.co.rw/mtn.zip` downloaded unauthenticated — full source code plus database credentials for the production site.
- Gratipay (262620): production Rails `secret_key_base` in a public repo — anyone could forge signed cookies and impersonate arbitrary users.
- Essity (3839889): 29 premium plugin ZIPs (e.g. `revslider-6.5.14-HcwXam9CAYQZ0Y5.zip`, 7.6MB, HTTP 200 unauthenticated) with embedded license/purchase tokens for RevSlider, Wordfence, ACF Pro, Elementor — reusable keys plus source for further exploit research.
- U.S. Dept of Defense (665144): soldier's SSN last-4 digits exposed in a public slide — identity data sufficient to target sensitive portals.
- Nord Security (761480): plaintext VPN password recoverable from a Windows client memory dump post-launch.
- Nextcloud (244092) / Shopify (90862): correct passwords surfaced in plaintext — in server logs (failed WebDAV 2FA attempts) and in later signup-confirmation responses respectively.