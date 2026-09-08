---
name: hunter-l3-exposed-credentials
description: "Use when hunting Exposed Credentials on a target. Loads the L3 technique sheet: This class covers secrets (database passwords, API tokens, infrastructure credentials) that leak through public code repositories or misconfigured web servers and remain valid on live production systems."
domain: cybersecurity
subdomain: web
tags:
- web
- exposed-credentials
- hunting
- l3
version: '1.0'
---

# Exposed Credentials — Technique Sheet

## Overview

This class covers secrets (database passwords, API tokens, infrastructure credentials) that leak through public code repositories or misconfigured web servers and remain valid on live production systems. It pays when the leaked credential is reused as-is on a real endpoint — a public GitHub commit is effectively a key dropped at the company's front door. Impact compounds when the exposed credential is a stepping stone (dump → crack → admin panel), rather than a dead secret.

## Distinct sub-patterns

### Sub-pattern 1: DB credentials committed to GitHub, reused on live phpMyAdmin

- Endpoint shape / parameter: `POST /forum/phpmyadmin` with parameters `username`, `password` (phpMyAdmin login form exposed on a reachable path).
- Payload that actually fired (verbatim): `forum','6HgeAZ0qC9T6CQIqJpD` — i.e. username `forum`, password `6HgeAZ0qC9T6CQIqJpD`, harvested from a public GitHub commit.
- Root-cause pattern: database credentials were committed to a public GitHub repository AND those same credentials were valid on a live, internet-reachable phpMyAdmin instance. Two failures stack: (1) secret in public VCS history, (2) exposed admin interface that accepts the leaked DB credentials.
- Impact proven: logged into phpMyAdmin, dumped the `users` table, cracked the `grinch` admin password hash to `BahHumbug`, logged into the forum admin panel, and read the flag `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}` (CTF flag standing in for full admin compromise / data access).
- Exemplar report IDs: 1066851, 1067037 (both h1-ctf, same finding chain reported twice with slightly different writeups).

### Sub-pattern 2: API token committed to GitHub, valid against the vendor's SaaS API

- Endpoint shape / parameter: `GET /rest/api/2/issue/{num}` (Jira/Atlassian REST API v2), authenticated via the `Authorization` header carrying the leaked token. Concrete probe: fetch a real issue number to prove authenticated read access, e.g. issue 67212.
- Payload: payload not stated (the secret itself is the credential; the demonstration was an authenticated GET against `/rest/api/2/issue/67212`).
- Root-cause pattern: a Jira API token was committed to a public GitHub repository. Unlike Sub-pattern 1, no exposed admin UI is needed — the vendor's official API endpoint is legitimate infrastructure, and the leaked token simply grants authenticated access to it.
- Impact proven: full access to the inDrive Atlassian panel — successfully fetched issue 67212 and could view projects, tasks, comments, accounts, and other sensitive data.
- Exemplar report ID: 1785145 (inDrive).

### Sub-pattern 3: Secrets-bearing config file publicly served by the web server itself

- Endpoint shape / parameter: `GET https://cz.acronis.com/docker-compose.yml` — a standard infrastructure file left in the webroot / publicly resolvable path, no parameters.
- Payload: payload not stated — the exposure is the file itself; it contained MySQL credentials (connection strings/host, user, password).
- Root-cause pattern: a `docker-compose.yml` containing MySQL credentials was deployed to (or copied into) a location served by the public web server. No VCS leak required — the secret is directly downloadable from the target's own domain. Any deployment artifact (`.env`, `docker-compose.yml`, `config.json`, backup dumps) in a web-served path is the same bug shape.
- Impact proven: MySQL credentials exposed publicly at the endpoint — anyone could retrieve working database connection details.
- Exemplar report ID: 963384 (Acronis).

## Bypass / chain notes

- Chain from Sub-pattern 1 (the highest-value chain in the records): Find leaked DB credentials in a public GitHub commit → Login to phpMyAdmin with `forum:6HgeAZ0qC9T6CQIqJpD` → Dump the users table → Crack the admin password hash (`grinch` → `BahHumbug`) → Log into the admin panel → read the flag / full account takeover. The critical insight: a leaked DB credential is rarely the end goal — it is an entry point into the application's own data, which contains the credentials for the next tier.
- GitHub leak → live reuse is the trigger for everything: a secret in a repo only pays if it is still valid somewhere. Test every leaked credential against the production surface that uses it (phpMyAdmin, the vendor API, the DB host itself).
- Sub-pattern 2 requires no chain — an authenticated API read of a real issue number (with visible projects/tasks/comments/accounts) is sufficient proof on its own. Enumerate the API (issue numbers, project listings) to demonstrate breadth of access.
- Sub-pattern 3 can chain forward the same way as Sub-pattern 1 if the exposed MySQL credentials are usable against a reachable DB host — the record shows only the exposure itself, but the credential-to-login step is the natural next move.

## Gotchas / what NOT to do

- Do not stop at "I found a secret in a repo" — a leaked credential with no demonstrated live validity is weak. The accepted reports here all showed the credential working on production (phpMyAdmin login, authenticated API read).
- Do not assume the exposed admin panel is the only target: with DB access, the users table is the real prize (password hashes → crack → app-level admin). Dumping and cracking was the multiplier in 1066851.
- Do not test leaked credentials against anything outside the program's scope — leaked secrets often point at third-party or internal systems; demonstrate impact only on in-scope endpoints.
- Do not brute-force or pivot beyond proof: fetching one real issue (67212) and describing available access was enough for 1785145; mass exfiltration is unnecessary and harmful.
- Do not report mere presence of a config file without sensitive contents — the Acronis finding (963384) paid because `docker-compose.yml` contained MySQL credentials, not because the file was 404-vs-200.
- Secrets rotate: re-verify the credential works before writing the report; a revoked token turns the finding into noise.

## Real-world impact examples

- 1066851 (h1-ctf): Public GitHub commit leaked DB creds `forum:6HgeAZ0qC9T6CQIqJpD` → phpMyAdmin login → dumped users table → cracked `grinch`/`BahHumbug` → admin panel → flag `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`. Full admin compromise from one leaked line of config.
- 1067037 (h1-ctf): same chain, same flag, reported with emphasis on the forum admin panel takeover.
- 1785145 (inDrive): Jira API token from a public GitHub repo → authenticated `GET /rest/api/2/issue/67212` → full access to the Atlassian panel including projects, tasks, comments, and account data.
- 963384 (Acronis): `https://cz.acronis.com/docker-compose.yml` publicly served with MySQL credentials inside — direct exposure of database connection secrets on the target's own domain.