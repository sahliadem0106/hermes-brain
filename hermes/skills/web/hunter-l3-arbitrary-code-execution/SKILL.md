---
name: hunter-l3-arbitrary-code-execution
description: "Use when hunting Arbitrary Code Execution on a target. Loads the L3 technique sheet: This class covers bugs that let an attacker execute attacker-controlled code or system commands — whether in a universal interpreter (PHP), a native application's DLL/plugin loading path, or a trusted extension ecosystem."
domain: cybersecurity
subdomain: web
tags:
- web
- arbitrary-code-execution
- hunting
- l3
version: '1.0'
---

# Arbitrary Code Execution — Technique Sheet

## Overview
This class covers bugs that let an attacker execute attacker-controlled code or system commands — whether in a universal interpreter (PHP), a native application's DLL/plugin loading path, or a trusted extension ecosystem. These findings pay well because impact is unambiguous: EIP control, a reverse shell, or code executing on a victim's machine. Note the recurring shape in these records: the target is often the *vendor's own product or platform* (PHP core via the Internet Bug Bounty, ownCloud desktop, Burp Suite extensions), not a traditional per-company web scope — so watch bug-bounty programs that accept vulnerabilities in widely deployed software.

## Distinct sub-patterns

### Sub-pattern 1: Memory corruption in interpreter/library string functions (PHP core)
- Endpoint shape / parameter: Not a web endpoint — a C-level PHP core function. Here: `str_ireplace()` (ext/standard), and `strtr()` (`php_str_to_str_ex()` in ext/standard/string.c). Report via the upstream interpreter's security process (Internet Bug Bounty covers PHP).
- Payload that fired (verbatim, id=113122):
```php
<?php
   $a = str_repeat('A', 65536);
   $b = str_repeat('ABCD', 32768);
   // Changing 'ABCD' into other value alters %eip to arbitrary value.
   $c = array('AA'=> $b);
   strtr($a , $c);
?>
```
  For id=104017, payload not stated — the finding was the memory corruption bug itself (PHP bug 70140).
- Root-cause pattern: For `str_ireplace` — a memory corruption bug inside the function (CVE-2015-6527). For `strtr()` — a missing size check before `zend_string_alloc()` in `php_str_to_str_ex()`, causing an integer overflow in the allocation size; the replacement result buffer is undersized and the copy overwrites beyond it.
- Impact proven: id=113122: controlled EIP = 0x44434241 (the ASCII of "ABCD") — full instruction-pointer control and a jump to arbitrary addresses on 32-bit PHP. id=104017: arbitrary code execution, resolved as CVE-2015-6527.
- Exemplars: id=104017, id=113122 (both ajaysenr, Internet Bug Bounty).
- How to hunt it: fuzz core string/memory functions with size-boundary inputs — large repeats (`str_repeat` to 64KB+) feeding replacement/translation functions, lengths chosen so the internal size math overflows a 32-bit int. Watch for the replaced content's bytes landing in EIP (the "ABCD"→0x44434241 trick is the classic confirmation: the pattern *is* the address).

### Sub-pattern 2: DLL hijacking via writable plugin directories (desktop application)
- Endpoint shape / parameter: Filesystem, not HTTP. Target path: `C:\usr\i686-w64-mingw32\sys-root\mingw\lib\qt5\plugins` — the QT plugin directory the ownCloud Windows desktop client loads from at startup. Parameter: the plugin DLL itself (QT platform plugins).
- Payload that fired (verbatim, id=155657):
```
msfvenom -a x86 --platform windows -p windows/messagebox TEXT="DLL Loaded" EXTIFUNC=process -f raw > shellcode
```
- Root-cause pattern: The client resolves QT plugins from a fixed path that any authenticated Windows user can populate (the app ships a mingw sys-root layout under `C:\usr\`). No integrity check on the plugin binaries → classic DLL/plant hijacking: build the expected folder structure, drop a malicious "platform" DLL, and the trusted application loads and executes it.
- Impact proven: Malicious QT plugin DLL executed automatically on launching the ownCloud desktop client; a "DLL Loaded" message box confirmed arbitrary code execution.
- Exemplar: id=155657 (ajaysenr, ownCloud).
- Chain (as recorded): create the expected plugin folder structure under `C:\usr\...\qt5\plugins` → plant a modified/malicious platform DLL → code executes automatically at client launch.

### Sub-pattern 3: Malicious extension/plugin in a trusted extension marketplace or loader
- Endpoint shape / parameter: The application's extension loader. Parameter: extension code (arbitrary code shipped inside a legitimate-format extension).
- Payload that fired (verbatim, id=3014158):
```python
subprocess.Popen(["calc.exe"], shell=True)
```
  (impact description also references an embedded PowerShell/Netcat reverse shell for persistence).
- Root-cause pattern: Burp Suite extensions run with the same privileges as the user and can call system APIs without restriction — the extension loading model grants native code execution by design, with no sandbox. The security issue is the social-engineering vector: a crafted extension distributed to a victim executes on install/load.
- Impact proven: crafted extension executed arbitrary system commands with the user's privileges; demonstrated a reverse shell and persistent access.
- Exemplar: id=3014158 (ajaysenr, PortSwigger Web Security).
- Chain (as recorded): convince victim to install a malicious extension → extension runs subprocess/system commands on load → attacker gains reverse shell and persistent access.

## Bypass / chain notes
- The EIP-control PoC doubles as its own bypass proof: because the replacement string bytes directly become the instruction pointer value, any 4-byte sequence in `strtr`'s replacement acts as an address — no ROP needed to demonstrate control (32-bit target).
- Both desktop patterns chain social engineering → automatic execution: the code runs at *launch* (QT plugin) or at *extension load*, so no exploit-on-demand is needed — the victim's normal use of the trusted application triggers it.
- The QT-plugin chain depends on multi-user Windows semantics: "any authenticated user can populate" the plugin directory is the privilege-model gap that makes a fixed-path loader exploitable. Verify writability by a low-privileged user before claiming impact.

## Gotchas / what NOT to do
- Don't report "extension can run code" without the delivery vector: the Burp finding was accepted because it demonstrated a realistic convince-the-victim chain ending in a reverse shell — an extension author running their own code is by design.
- Don't stop at a crash: id=113122 was valued because EIP was *controlled to an arbitrary value*, not because of a segfault. Show control (e.g., ASCII-address technique) rather than a generic DoS.
- Don't assume a DLL load path is exploitable just because it exists — the exploitability hinges on the directory being writable by an unprivileged authenticated user.
- These are interpreter/app-level bugs, not web-app bugs: payloads won't fit a standard HTTP request. Report through the correct program (Internet Bug Bounty for PHP core; the vendor's own program for their products) and cite the upstream issue ID (PHP bug 70140 → CVE-2015-6527).
- Keep PoC impact benign-but-conclusive: a message box ("DLL Loaded") or `calc.exe` proves execution without crossing into actual intrusion; the reverse shell was described as a demonstration of persistence, so match the program's rules of engagement.

## Real-world impact examples
- PHP `str_ireplace()` memory corruption → arbitrary code execution in PHP core; fixed as CVE-2015-6527 (id=104017).
- PHP `strtr()` missing size check → integer overflow before `zend_string_alloc()` → EIP set to attacker-chosen 0x44434241 on 32-bit PHP (id=113122).
- ownCloud Windows desktop client loaded an attacker-planted QT platform plugin from a user-writable path → arbitrary code executed on every client launch (id=155657).
- Malicious Burp Suite extension ran `subprocess.Popen(["calc.exe"], shell=True)` on load and was extended to a PowerShell/Netcat reverse shell with user-privilege persistent access (id=3014158).