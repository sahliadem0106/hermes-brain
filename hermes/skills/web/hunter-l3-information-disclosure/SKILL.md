---
name: hunter-l3-information-disclosure
description: "Use when hunting Information Disclosure on a target. Loads the L3 technique sheet: This class covers bugs where data that should be private becomes readable without authorization: hardcoded/committed secrets, exposed admin/debug consoles, directory listings, IDOR-style keyed URLs, v"
domain: cybersecurity
subdomain: web
tags:
- web
- information-disclosure
- hunting
- l3
version: '1.0'
---

# Information Disclosure — Technique Sheet

## Overview
This class covers bugs where data that should be private becomes readable without authorization: hardcoded/committed secrets, exposed admin/debug consoles, directory listings, IDOR-style keyed URLs, verbose errors, client-side API keys, and Referer leaks. It pays whenever impact can be proven — leaked credentials that log in, keys that generate billable API calls, PII files reachable unauthenticated. Almost every record here was triaged because the researcher went one step past "found a file" and demonstrated real use of the leaked data.

## Distinct sub-patterns

### 1. Credentials and secrets in public GitHub (repos, .env files, commit history)
- Endpoint shape: `https://github.com/{org}/{repo}/.env.testing`, or any file in a public repo; deleted secrets recoverable from commit history (`github.com/{org}/{repo}` — check earlier commits).
- Payload that fired: verbatim `.env.testing` contents: `LDAP_DOMAIN=███ / LDAP_BASE_DN=███ / LDAP_ADMIN_USER=███████ / LDAP_ADMIN_PASSWORD=██████` (id=1004412, Acronis). Also `new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' )` committed then removed in a later commit (id=1066203/1066504/1067443/1067835/1068434, h1-ctf Grinch-Networks/forum). Config scripts with hardcoded ESXi/SendGrid creds (id=365199, Uber).
- Root cause: secrets committed to public repos; "fix" commits delete the file but git history retains it.
- Impact proven: login to SendGrid as uber_infra_devtools → send email from any @uber.com (id=365199); leaked MySQL creds `forum:6HgeAZ0qC9T6CQIqJpD` → phpMyAdmin login → user table dump → admin login (h1-ctf chain).
- Exemplars: id=365199, id=1004412, id=1067443.

### 2. Exposed info/debug panels (phpinfo, Symfony profiler, Spring Boot actuator, AEM CRXDE, prow /config)
- Endpoint shapes:
  - `GET /{redacted}/phpinfo` (id=592885, Unikrn — via Cloudflare Access bypass)
  - `GET /{redacted}?panel=logger` and `?panel=config` (Symfony profiler panels, id=592885)
  - `GET /{redacted}/empty/search/results` (Symfony request log listing every request + client IPs, id=592885)
  - Spring Boot actuator `env`, `heapdump` on stripo.email (id=1019367) and `*.semrush.com` (id=1022048)
  - `GET /{redacted}/crx` — AEM CRXDE query, `param: query`, unauthenticated (id=1095830, DoD)
  - `GET /config` on prow.k8s.io (id=1018413)
  - `GET /info` (id=1049402, MTN Group)
- Root cause: management/debug consoles left bound to a public host without auth or WAF/Access protection.
- Impact proven: phpinfo/actuator → env vars; MTN `/info` → Laravel APP_KEY + DB creds + SMTP creds, researcher sent email as no-reply@mtn.bj; CRXDE → 200 JSON (Content-Length 1789) with admin/PII data; prow /config → GitHub team IDs, rerun auth configs, internal endpoints (127.0.0.1:1234).
- Exemplars: id=1049402, id=1095830, id=1019367.

### 3. Unauthenticated files / directory listings (PDFs, /doc/, vhost source, dev environments)
- Endpoint shapes: `GET /dereport.pdf` on a *.mil host (id=1007702); any `GET /█████.pdf` (id=1050196, 1057269); `GET /doc/` (id=105149, ownCloud); `GET /private/`, `/admin/`, `/includes/`, `/scripts/` etc. on api.acronis.com with listing enabled (id=1008364); public-internet-facing dev environments via security-group misconfig (id=100916, Imgur); stale diagnostic subdomain on *.hey.com surviving "remediation" (id=1026196, Basecamp).
- Root cause: files served with no access control; vhost config exposes source as static files with autoindex on; cloud security groups open to 0.0.0.0/0.
- Impact proven: ~750 individuals' phone numbers + private emails (id=1007702); ~1000 DoD contacts (id=1050196); 100–200 names/emails (id=1057269); thousands of Acronis source files incl. office.acronis.com with plaintext encryption keys (id=1008364); Imgur dev env keys/env vars incl. production info (id=100916).
- Exemplars: id=1008364, id=1007702.

### 4. Public support-request / user-generated content mirror (Google-indexed PII)
- Endpoint shape: `GET /{public support-request listing}` (id=1004964, DoD).
- Root cause: contact-form submissions mirrored to a public endpoint with no authorization; discoverable because it was indexed — the researcher found it by googling the submitter's name.
- Impact: all private support requests including customer PII publicly visible.
- Exemplar: id=1004964. Hunt tip from the data: search your own test-submission name in Google to detect this class.

### 5. Referer leak of password-protected links (no referrer-policy)
- Endpoint shape: Shopify store preview link (`your-store.myshopify.com` with token); `param: referrer`.
- Payload: N/A — leak occurs passively via the Referer header on any outbound link/embed to third-party (social media) sites.
- Root cause: store pages lack a referrer-policy meta/header; full URL (with preview token) appears in Referer to third parties.
- Impact: third-party site controllers could preview all store actions without the store password.
- Exemplar: id=1015283.

### 6. IDOR via predictable keyed resource URLs
- Endpoint shapes:
  - Nextcloud profile image URL keyed by `{email}` — change email in URL → another user's avatar (id=1022211).
  - `GET /swag-shop/api/user?uuid={uuid}` — returns personal data (address) for any uuid (id=1068880, h1-ctf).
- Root cause: resource authorization keyed only on a guessable/leakable identifier (email, uuid) with no ownership check.
- Impact: profile pictures; user records with physical address + CTF flag.
- Chain (id=1068880/1066851/1067037): fuzz `/swag-shop/api` → find `/sessions` (unauthenticated, returns active sessions) → decode sessions to get a valid uuid (`C7DCCE-0E0DAB-B20226-FC92EA-1B9043`) → `GET /swag-shop/api/user?uuid=...`.
- Exemplars: id=1022211, id=1068880.

### 7. Chat/API message endpoints creating lookup side-channels
- Endpoint shape: `POST /api/storefront/conversations/{num}/messages`, `param: skip_customer_creation`.
- Payload verbatim: `{"skip_customer_creation": false}`
- Root cause: setting the flag to false makes the chat create a customer record and echo the customer's full name from an email-based lookup.
- Impact: any customer's full name (first+last) from email alone.
- Exemplar: id=1018336 (Shopify).

### 8. Guest/unauthenticated object-level access via API frameworks (Salesforce Aura)
- Endpoint shape: `POST /acc/aura`, `param: message` with actions array; fired payload set `entityNameOrId: "Event"`, `pageSize: 100`.
- Payload verbatim (truncated in record): `{"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.com.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"Event",...`
- Root cause: Salesforce Event object has loose permissions for unauthenticated Guest users; Aura API queries not restricted by record-level security.
- Impact: unauthenticated retrieval of other users' meetings/sensitive records.
- Exemplar: id=1023572 (Acronis).

### 9. Verbose error / stack-trace disclosure
- Endpoint shapes:
  - `POST /sso/LoginRequest.do`, `param: username` with a ~100,000-character string → stack trace with `Internal Exception: java.sql.SQLException: ORA-01460: unimplemented or unreasonable conversion requested`, `Error Code: 1460`, plus internal DB call info (id=1020472, DoD).
  - `POST` richdocuments guest display name, `param: guest_displayname`, payload: an ~110-char name (`reallylongnameeee...`) overflowing the DB column → raw SQL exception returned verbatim.
- Impact (overflow case): full SQL INSERT statement + parameters disclosed — file id, owner uid, server host (https://demo2.nextcloud.com/), WOPI token, share id (id=1067834 → id=1067824, Nextcloud).
- Root cause: no input length validation; driver/framework exceptions surfaced to the client instead of a generic 500.
- Exemplars: id=1020472, id=1067824.

### 10. Path traversal on upload/state endpoints
- Endpoint shape: `POST /api/v4/projects/{num}/terraform/state/{path}?serial=1`, `param: path`.
- Payload verbatim (URL-encoded): `%2e%2e%2f%2e%2e%2fwikis%2fattachments`
- Root cause (GitLab): Workhorse rewrites the URL before Rails; the terraform State API reads request.body and appends it as a file, so traversal on the state upload path yields a valid Workhorse upload JWT (revealed verbatim in the mirror.gitlab-workhorse-upload field of the response).
- Impact: valid GitLab-Workhorse JWT obtained.
- Exemplar: id=1040786 (GitLab).

### 11. Client-side API keys without restrictions
- Endpoint shapes: `GET /js/main.044af6485f6b0cd90809.js` (Clario Firebase Dynamic Links key, id=1066410); Google Maps API key across `ass0-3.fetlife.com`, `app.fetlife.com`, `fetlife.com`, `ws.fetlife.com` (id=1065041).
- Root cause: key hardcoded in client bundles with no referrer/IP restriction; enables billable APIs.
- Impact: Clario key usable to create short links via firebasedynamiclinks.googleapis.com; FetLife key confirmed valid against Geocode API ($5/1000 requests) → quota abuse, cost, potential DoS. Prove validity by actually calling the API.
- Exemplars: id=1066410, id=1065041.

### 12. robots.txt / hidden-path disclosure
- Endpoint shape: `GET /robots.txt` → discloses `Disallow: /s3cr3t-ar3a` and in several records the flag itself directly in robots.txt; follow with `GET /s3cr3t-ar3a`.
- Payloads verbatim: `username=access&password=computer` (recorded as payload in id=1067037); flags `flag{48104912-28b0-494a-9995-a203d1e261e7}` (robots.txt), `flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}` (secret area).
- Root cause: secrets/hidden paths published in robots.txt; hidden pages readable in HTML/JS.
- Exemplars: id=1065731, id=1066504, id=1066851, id=1067037, id=1067835, id=1068434, id=1068880.

### 13. Secrets in client-side HTML/JS (DOM vs view-source)
- Endpoint shape: `GET /s3cr3t-ar3a` (and custom-modified locally-hosted `/assets/js/jquery.min.js`).
- Root cause variants in the records: (a) flag in a server-sent `data-info` attribute — present in the parsed DOM but hidden by view-source; (b) flag split across JS variables to be reassembled; (c) obfuscated JS setting `data-info` (decode it); (d) custom code in the local jQuery — found by diffing against stock jQuery; (e) HTML/JS comments in dev console pointing to a hidden `/apps` directory.
- Impact: flags recovered; the transferable lesson is that view-source misses the DOM — always inspect rendered DOM and diff self-hosted JS libs.
- Exemplars: id=1066203 (data-info via Inspect Element), id=1068434 (jQuery diff), id=1068880 (dev-console comment), id=1067037 (split JS variables).

### 14. Unauthenticated platform CVEs / framework endpoints
- Endpoint shapes: `GET /secure/QueryComponent!Default.jspa` (Jira CVE-2020-14179, versions <8.5.8 and 8.6.0–8.11.1 — custom field and SLA names, id=1067004); local on-disk `Local State` JSON storing the last Tor-session timestamp in cleartext (`13248493693576042`), CVE-2020-8276, Brave (id=1024668); exposed Kubernetes prow dev config (id=1018413).
- Impact: field/SLA names to unauthenticated users; proof of Tor usage to a local attacker.
- Exemplars: id=1067004, id=1024668.

### 15. Unauthenticated internal backends via edge bypass
- Endpoint shape: `GET /{redacted}/phpinfo` and Mautic backend paths behind Cloudflare Access (id=592885, Unikrn).
- Root cause: Cloudflare Access bypass exposes the internal Mautic backend; Symfony profiler/request logs reachable.
- Impact: phpinfo (server config + paths), full request log with client IPs, logger/config panels.
- Exemplar: id=592885.

### 16. Third-party/community channels leaking private reports
- Endpoint shape: public Slack — `https://www.impresscms.org/modules/news/article.php?article_id=1019` pointed to the public devel channel (id=1035976).
- Root cause: Slack invite open to anyone; private HackerOne reports discussed in the public channel.
- Impact: read disclosed/private H1 reports the team intended to keep private.
- Exemplar: id=1035976.

### 17. Status-code oracle for private resources
- Endpoint shape: `GET /{team_handle}/thanks.json` (HackerOne).
- Root cause: distinct status codes for sandboxed vs private vs non-existent handles (blank/500 vs 401 vs 404) allow enumerating private program existence.
- Impact: private-program existence confirmed by handle guessing.
- Exemplar: id=105887.

### 18. Leftover debug/backdoor endpoints (multi-parameter)
- Endpoint shape: `GET /██████████` with params `year, month, day, userId, profileId, dbName` (id=1048571, DoD).
- Root cause: debug/backdoor endpoints reachable without auth.
- Impact: scraped language proficiency, testing, and student info by date/user-id/profile-id.
- Chain verbatim (truncated in record): navigate to the debug endpoint and invoke the data request with year/month/day → extract user IDs from the JSON reply → feed a user ID into the next endpoint.
- Exemplar: id=1048571.

## Bypass / chain notes
- Git history defeats deletion: h1-ctf records show creds "removed" in a later commit still recoverable (ids 1067443, 1067835, 1068434). Always check commit history, not just HEAD.
- Leak-to-auth chains recur: leaked DB creds → exposed phpMyAdmin → dump hashes → crack MD5 (crackstation/hashcat) → login as admin (Grinch, `BahHumbug`). Exposed phpMyAdmin at `/forum/phpmyadmin` was the second half of the chain — an exposed panel plus a leaked secret is full compromise.
- Session-leak chain: unauthenticated `/swag-shop/api/sessions` → decode → uuid → `/swag-shop/api/user?uuid=` (ids 1066851, 1067037, 1068880).
- Cloudflare Access bypass → internal framework panels (phpinfo, Symfony profiler) in one step (id=592885).
- DOM inspection beats view-source: the `data-info` attribute was invisible to view-source but present in the rendered DOM (ids 1066203, 1066504, 1067835). Diff self-hosted JS libs (jquery) against stock versions to find injected code (id=1068434).
- URL-encode traversal: `%2e%2e%2f` form worked against the GitLab terraform state endpoint (id=1040786).
- Oversized input as an error oracle: ~100k-char username (id=1020472) and ~110-char guest name (id=1067824) both flipped servers into verbose exception mode.
- Google-dorking your own test submissions finds public mirrors of private data (id=1004964).
- Prove key validity: actually calling Geocode/Dynamic Links APIs with the extracted key turned "key found in JS" into accepted, program-confirmed findings (ids 1065041, 1066410).

## Gotchas / what NOT to do
- "API key found in a JS bundle" alone is usually not enough — the FetLife and Clario records were accepted because the key was verified against a live billable API. Always test and scope the cost impact.
- A diagnostic subdomain with "low-sensitivity internal info" (Basecamp id=1026196) was accepted in context of failed prior remediation — otherwise low-value info dumps are frequently triaged as informative. Demonstrate that something should not be public AND why it matters.
- robots.txt/hidden-page findings here are CTF records — do not file plain robots.txt contents on real programs as info disclosure without additional impact.
- Don't stop at the leak: the repeated accepted pattern is leak → use (login, send email, call API). id=1049402 (MTN) was strong because the researcher sent mail from the official no-reply address; id=365199 (Uber) because SendGrid login was demonstrated.
- Don't trust view-source for client-side secret hunting; render the DOM and inspect computed attributes (`data-info` case, id=1066203).
- When a session/uuid leak is present, decode the whole object — the valid uuid was embedded inside session data, not surfaced as a field (id=1066851).
- For path traversal on state-upload endpoints, the leak surfaces in the response's mirror/upload fields — read the full response body, not just the status (id=1040786).

## Real-world impact examples
- SendGrid account takeover from public GitHub creds → email as any @uber.com address (id=365199).
- Laravel APP_KEY + DB + SMTP creds from `/info` → email sent from no-reply@mtn.bj (id=1049402).
- Thousands of Acronis source files with plaintext encryption keys via directory listing on api.acronis.com (id=1008364).
- ~750–1000 individuals' personal phones/emails in unauthenticated PDFs on .mil (ids 1007702, 1050196).
- Full SQL INSERT with WOPI token and share id leaked via guest-name overflow (id=1067824).
- Valid GitLab-Workhorse JWT via `%2e%2e%2f` traversal on terraform state (id=1040786).
- Any customer's full name from an email via `{"skip_customer_creation": false}` (id=1018336, Shopify).
- Google Maps key confirmed live at $5/1000 Geocode calls across four fetlife.com hosts (id=1065041).
- Unauthenticated Salesforce Aura query on Event → other users' meeting records (id=1023572, Acronis).
- phpMyAdmin full compromise chain from one deleted git commit: dump users, crack MD5, admin login (ids 1067443, 1068434, h1-ctf).