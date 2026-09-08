---
name: hunter-l3-directory-listing
description: "Use when hunting Directory Listing on a target. Loads the L3 technique sheet: Directory Listing is a server misconfiguration class where a web server (Apache, Nginx, IIS, or an embedded Python/Java handler) is left with autoindex enabled on a directory that has no default index file."
domain: cybersecurity
subdomain: web
tags:
- web
- directory-listing
- hunting
- l3
version: '1.0'
---

# Directory Listing — Technique Sheet

## Overview
Directory Listing is a server misconfiguration class where a web server (Apache, Nginx, IIS, or an embedded Python/Java handler) is left with autoindex enabled on a directory that has no default index file. Instead of rendering a page, the server returns a browsable HTML index of every file and subdirectory, letting an attacker walk the entire webroot or application tree. It pays most on non-standard hosts — preview/staging servers, internal tooling instances (e.g. Spacewalk), speed-test/utility subdomains, and CMS upload directories — where engineers assume "nobody browses here" and sensitive or private files sit unindexed but fully reachable.

## Distinct sub-patterns

### 1. Directory listing on preview/internal application server instances
- Endpoint shape: `GET /<app-root>/` on a preview or secondary server hostname (e.g. `GET /cobbler/` and `GET /cblr/` — the Cobbler provisioning tool's web paths under a Spacewalk preview instance).
- Payload: none required — plain unauthenticated GET; the autoindex page is the "payload".
- Root cause: Directory listing was enabled on a Spacewalk preview server instance. Spacewalk (open-source systems management fork of Cobbler) exposes `/cobbler/` web paths; the underlying web server was serving autoindex instead of a handler/default index, so the open-source application's file tree was browsable.
- Impact: Directory listings exposed Spacewalk open-source files. Note: in the exemplar the program confirmed no sensitive information was disclosed — this sub-pattern is typically informational-to-low severity unless the exposed tree contains config, credentials, or internal data files.
- Exemplars: id=1771051 [ajaysenr] program=8x8.

### 2. Directory indexing on utility/service subdomains
- Endpoint shape: the subdomain root itself — `GET https://speedtest.8x8.com` (and the same pattern on `speedtest-uswest1.8x8.com`). These utility hosts (speed-test services, status pages, metrics endpoints) frequently run a bare web server pointing at a docroot with no index document.
- Payload: none stated — request the host root (and any paths discovered) and read the autoindex output.
- Root cause: Web server directory indexing is enabled on the subdomains, exposing the directory structure. Whoever deployed the speed-test service left autoindex on for the whole vhost, so every directory below the webroot is walkable.
- Impact: Full directory structure of the web directories on speedtest.8x8.com and speedtest-uswest1.8x8.com visible to anyone, revealing potentially sensitive information (deployment artifacts, test files, config remnants often live on such hosts).
- Exemplars: id=1825472 [ajaysenr] program=8x8.

### 3. Directory listing on CMS upload directories
- Endpoint shape: `GET /wp-content/uploads/` (WordPress media/uploads path; the same idea applies to any CMS upload path — `GET /wp-content/uploads/YYYY/MM/` once listing is confirmed at the root).
- Payload: none stated — direct GET on the uploads path.
- Root cause: The Mtn.ci upload directory has directory listing enabled. The WordPress uploads directory normally only guards itself via an empty index.php; if the web server's autoindex is active (or the index guard is missing), the entire upload history becomes browsable.
- Impact: Every file uploaded by the webmaster is accessible by navigating the upload directory, potentially including private/confidential data — uploads that are unlinked but never deleted remain reachable, including drafts, staging files, and documents that were "removed" from the site but not the server.
- Exemplars: id=762118 [ajaysenr] program=MTN Group.

## Bypass / chain notes
- None of the records involve a bypass or chain — all three fired on direct, unauthenticated GETs. The class needs no filter evasion; the obstacle is finding the directories, not getting past a control.
- Implicit enumeration technique consistent with all three records: identify non-standard hosts (preview/staging instances, utility subdomains, CMS roots), then probe well-known application paths (`/cobbler/`, `/cblr/`, `/wp-content/uploads/`) and the vhost root directly. Any response containing an HTML file index (or a generated listing) confirms the pattern; recurse into listed subdirectories — the impact usually lives one or two levels down from where listing first appears.

## Gotchas / what NOT to do
- Severity is proportional to what's actually exposed, not to the listing itself. In id=1771051 the listing exposed only Spacewalk open-source files, and the program confirmed no sensitive disclosure — expect a pushback on a bare "listing exists" report. Before submitting, walk the tree and document concrete sensitive files; if there are none, say so honestly and set severity expectations accordingly.
- Do not assume the listing is a vulnerability because the path is "internal-feeling". `/cobbler/` exposing open-source tool files is not sensitive by itself; the report's value hinges on what the traversal uncovers (config, backups, credentials, private uploads).
- Do not stop at the first level. "Full directory structure visible" (id=1825472) and "every file uploaded by the webmaster is accessible" (id=762118) are what earned these reports — enumerate recursively and show the depth of exposure in the report.
- Do not download, exfiltrate, or open files that clearly contain third-party personal data; demonstrating reachability (path + file listing, minimal proof) is sufficient.
- Check both the apex path and regionally-scoped variants of the same host: in id=1825472, the same flaw existed on both speedtest.8x8.com and speedtest-uswest1.8x8.com — reporting all affected vhosts in one report strengthens the case.

## Real-world impact examples
- 8x8 (id=1825472): web server directory indexing enabled on speedtest.8x8.com and speedtest-uswest1.8x8.com — the full directory structure of the web directories was visible to anyone, revealing potentially sensitive information.
- MTN Group (id=762118): mtn.ci's WordPress uploads directory (`/wp-content/uploads/`) had listing enabled — every file the webmaster ever uploaded was browsable, with the realistic possibility of private or confidential documents among them.
- 8x8 (id=1771051): directory listing on a Spacewalk preview server exposed `/cobbler/` and `/cblr/` file trees — accepted as a valid misconfiguration even though the program confirmed the exposed files were non-sensitive open-source content (illustrates the typical informational/low ceiling for this pattern without sensitive files).