---
name: hunter-l3-dos
description: "Use when hunting DoS on a target. Loads the L3 technique sheet: DoS findings span two families: (1) attacker-triggered server-side resource exhaustion — oversized/unvalidated inputs, expensive endpoint amplification, missing rate limits, and parser/handler bugs th"
domain: cybersecurity
subdomain: web
tags:
- web
- dos
- hunting
- l3
version: '1.0'
---

# DoS — Technique Sheet

## Overview
DoS findings span two families: (1) attacker-triggered server-side resource exhaustion — oversized/unvalidated inputs, expensive endpoint amplification, missing rate limits, and parser/handler bugs that hang or crash processes; and (2) stored/application-layer DoS where one crafted input (a message, comment, post, playbook, cookie) breaks rendering for every victim who touches it. It pays on standalone targets (libraries, daemons, self-hosted instances) where availability is in scope, and on shared platforms where a single payload poisons shared state. The strongest reports prove full availability loss: server crash, 502s, or victims locked out of an app.

## Distinct sub-patterns

### 1. Oversized input where no length limit exists
- **Shape:** Any string parameter stored or hashed server-side: password fields, account names, command strings, session names, playbook template attributes, log lines.
  - POST /register — param `password` (Reddit 1243009; Imgur 1411363)
  - POST /contacts/{num}/user/edit — param `name` (Basecamp 1018037)
  - POST /api/v4/commands/execute — param `command` = `/0000000000...` (66,000+ zero chars) (Mattermost 1243724)
  - POST /plugins/playbooks/api/v0/playbooks — `run_summary_template` = 50MB of characters (Mattermost 1685979)
- **Payload:** No length cap; multi-thousand-char / 50MB values. Reddit: `Crissrock3%40` repeated ~100x. Imgur: ~10KB of `A`s.
- **Root cause:** Client-side textbox limits only; server hashes/stores/logs the value in full.
- **Impact:** Server-side hashing burns CPU (Reddit/Imgur); a >64KB console log line froze Mattermost for all users until restart (1243724); 50MB template crashed the server on playbook run (1685979, full DoS proven with PoC video); Basecamp account 500s and mobile app crashed.
- **Exemplars:** 1243724, 1685979, 1411363.

### 2. Crash-the-parser: malformed input to an unguarded handler
- **Shape:** URLs/paths/format-specific fields fed to parsers without validation.
  - GET /i/flow/{path} — `path` = `https://twitter.com/i/flow/%00` (921286)
  - GET /{path} on fastify-static — `//^/..` passed to `new URL()` with no try/catch → 'Invalid URL' crash (1361804)
  - GET / (URL path) — newline `%0a` reflected + unbounded path repetition → redirect loop (Acronis 1382448)
- **Root cause:** Unhandled exceptions/nil dereferences on malformed input; server reflects path and 301s repeatedly, exhausting resources.
- **Impact:** Node server crash (Fastify); acronis.com down with 502 Bad Gateway for ~30-60 min within ~2 min of attack.
- **Exemplars:** 1382448, 1361804, 921286.

### 3. Memory/CPU bomb via single crafted request (allocations from attacker-controlled sizes)
- **Shape:** Content-Length or size-derived allocations; image processing.
  - mod_lua `r:parsebody()` — `Content-Length: 9223372036854775807` → `apr_pcalloc` attempts 0x8000000000000000 bytes → `abort()` (1596252)
  - PUT /api/v2/lists/{num} — crafted JPG in `list[remote_image_url]` → unbounded image processing → 502 (Instacart 159820)
  - Nextcloud preview generation of a broken image → ~5GB memory allocated per file (1261225)
- **Root cause:** Code allocates Content-Length+1 with no cap; image decoders allocate proportional to header claims regardless of file validity.
- **Impact:** Remote unauthenticated crash of httpd; 5GB memory per preview on Nextcloud — uploading many such files DoSes the server.
- **Exemplars:** 1596252, 1261225, 159820.

### 4. Expensive-endpoint amplification (single request → disproportionate server work)
- **Shape:** Endpoints with unbounded query parameters or per-request work proportional to input.
  - GET /core/statistics/v1/{account}/account — `interval=hour&period=<wide range>` → response grew ~2.5KB → ~372KB in one request, evading rate limits (Mapbox 136221)
  - GET /wp-admin/load-scripts.php?load=<huge script list> — CVE-2018-6389, ~3MB output per unauthenticated request (Sifchain 1186985)
  - GET /index.php/apps/files_sharing/shareinfo — returns the entire file tree per request, no rate limiting (Nextcloud 1173684, CVE-2021-32703)
  - GET /ocs/v2.php/.../sharees_recommended — 9 circles × 6 folders all shared → loop runs the full 1h max_execution_time (Nextcloud 1688199)
- **Payload:** verbatim for Mapbox: `?interval=day&period=1461766083142%2C1462370883143&metrics=countries%2Cbrowsers...` with `interval=hour` and an extended period.
- **Root cause:** No bound on requested range/payload size; work multiplies with input dimensions.
- **Impact:** Heavy DB/CPU load from a handful of requests; "site could be taken down with ~14,000 requests/day" (HackerOne JSON variant, below).
- **Exemplars:** 136221, 1186985, 1688199.

### 5. Missing rate limiting on heavy endpoints
- **Shape:** GET /reports/{num}.json with parallel curl — `for((x=0;x<10;x++)); do (curl https://hackerone.com/reports/NNNNNN.json & ); done` (125587); report view loading all ~450 comments at once → HTTP 524 Origin Time-Out (140720).
- **Root cause:** Unoptimized serialization + no throttling; Cloudflare cuts 30s sessions.
- **Impact:** 10 parallel requests paralyzed hackerone.com; ~800 activities made reports inaccessible.
- **Exemplars:** 125587, 140720.

### 6. Slow / connection-holding attacks
- **Shape:** Slowloris-style incomplete HTTP requests against nextcloud.com (163823).
- **Root cause:** No slow-client mitigation at the edge.
- **Impact:** Confirmed DoS; mitigated by the program.
- **Exemplar:** 163823.

### 7. Network egress amplification via server-side fetch
- **Shape:** POST a Talk message containing a link to a large file (`https://speed.hetzner.de/10GB.bin`); server fetches link previews with a hardcoded 10s timeout, downloading the body for the full 10s (Nextcloud 1806223).
- **Chain:** Post multiple messages linking a large high-availability file → server fetches each → saturates network/disk.
- **Impact:** Saturated a 2.5 Gbps server link for several seconds and temporarily filled disk.
- **Exemplar:** 1806223.

### 8. Stored / application-layer DoS (one payload poisons all viewers)
This is the highest-value family on shared platforms.
- **Shape/payloads:**
  - POST /api/v4/posts — `"deleted_at": 10` on a message → webapp crashes (blank screen) for every user viewing or switching into the channel (Mattermost 1253732, CVE-2021-37863)
  - Markdown comment `[This is SPARTAA](/%ff)` → any report rendering the comment fails to load (HackerOne 118663)
  - Slack post link payload: `https://xyz.com\"><img src=x name='constructor' /><img src=x name='adoptNode' /><img src=x name='append' />...` — DOM clobbering: img `name` attrs shadow document functions, breaking app JS; channel/DM view crashed, often the entire desktop app (1077136)
  - Bumble message `http://www.ab99` → smiley/link renderer corrupts recipient's messaging state; can't read or write messages (178742)
  - Oversized `ref`/`ssid` params copied into cookies (`1000+` comma chars) → HTTP 400 on livechat.shopify.com, www.shopify.com, app.shopify.com for 30 days (Shopify 105363 — cookie poisoning; `escape()` triples size)
- **Root cause:** Rendering paths assume valid data; no sanitization of stored fields before every subsequent view.
- **Exemplars:** 1253732, 105363, 1077136.

### 9. State-corruption DoS (break a workflow, not the server)
- **Shape:** Admin config / user state fields with missing validation.
  - Nextcloud workflow rules: unlimited stored data → load on later interactions (1018146, CVE-2020-8293)
  - Automattic email change without verification → set invite-email to a blocked address; admin can never invite any team member again (1041173)
  - Nextcloud user-admin state corruption → admins can't manage users (1147611, CVE-2021-32657)
  - Session name without size validation → server-side DDoS (1153138, CVE-2022-29243)
- **Impact:** Permanent functional lockout — arguably stronger than a transient crash.
- **Exemplars:** 1041173, 1147611.

### 10. Infinite loops / hangs (protocol and library handlers)
- **Shape:** Crafted protocol input that defeats a loop's exit condition.
  - curl `-T blabla-notexists -Z upload.example.com www.google.com ...` — parallel upload of a nonexistent file loops forever ("Can't open" repeatedly, zero traffic per tcpdump) (1019372)
  - curl CERTINFO with a mutual-issuer certificate chain loop → 100% CPU busy-loop (CVE-2022-27781) (1555441)
  - Node `dns.resolve4('ticbrasil.com.br', cb)` — 1300+ DNS responses hang the resolver, no timeout honored (CVE-2020-8277) (1032086... note: 1033107)
  - Node http2 server: `while true; do echo $request | openssl s_client -connect 127.0.0.1:50000 & done` — unknownProtocol + no error response leaks FDs/memory: 6MB→400MB in 30s, >7000 leaked FDs, server can't accept connections (1043360)
  - Python urllib against a server streaming `HTTP/1.1 100 OK` + endless `x:a` header lines — timeout=1 ignored, client hangs forever (CVE-2021-3737) (1188128)
  - Tor control port (bufferevents): `(chr(0x63)*2000) + chr(0x0A)` — >1024 bytes with LF after byte 1024 infinite-loops `connection_fetch_from_buf_line()`; tor needed `kill -9`; reachable pre-auth via `<img>` to localhost:9999 (113424)
- **Impact:** Process hang requiring kill; complete availability loss for anything embedding the library.
- **Exemplars:** 1043360, 1188128, 113424.

### 11. Crash via null dereference / logic bugs in sandboxed code (mruby family)
- **Shape:** Malformed or feature-misusing Ruby snippets evaluated in the sandbox:
  - `b = a () ? 1 : 0` — null pointer in codegen ternary (181677)
  - `BasicObject.remove_method(:method_missing)` then `1.__send__(:foo)` — null method pointer in OP_SUPER (181695)
  - `Range.remove_method(:initialize_copy)` then `(1..2).dup.to_s` — uninitialized Range dereference (181685)
  - `method(&a &&= 0)` — peephole opt elides MOVE, non-closure passed as block, null env pointer; crashed mruby, mruby_engine, AND parent MRI Ruby (181828)
  - `a=*"any splat operator", case ... redo |b|` — null RArray into `mrb_ary_push` → SIGSEGV (181232)
  - Exception subclass with `def to_s; end` then `raise A.new` → SIGABRT (180977)
- **Root cause:** Removed core methods / codegen edge cases break invariants → null derefs on the error path.
- **Impact:** Reliable process-level SIGSEGV/SIGABRT — sandbox escape of availability into the host process.
- **Exemplars:** 181828, 181232, 181677.

### 12. Integer overflow / unchecked index in unmarshalling
- Kubernetes gogo/protobuf `skip` loop missing negative `(iNdEx+skippy)` check → integer overflow → out-of-bounds index panic; attacker can crash nodes doing protobuf unmarshal (1073363, no PoC produced — asserted).
- Cloudflare goflow sflow decode lacked packet sanitization → malformed packets → large memory consumption (CVE-2022-2529) (1636320).

### 13. Nil-pointer crash on minimal/empty structured input
- **Shape:** RPC/object constructors with empty bodies.
  - Fabric gRPC `Evaluate` with `payload.ProposedTransaction = &peer.SignedProposal{}` → nil deref segfault kills the peer (1635854)
  - Kubernetes VolumeSnapshot with `persistentVolumeClaimName: blabla` (nonexistent) → snapshot-controller nil-pointer panic, crash-looping on the same object (1032086)
  - mod_lua websocket crafted PING → stack-recursion crash of httpd (CVE-2015-0228) (103991)
- **Impact:** Attacker can "bring down as many peers as desired"; snapshot functionality fully DoSed.
- **Exemplars:** 1635854, 1032086.

### 14. External dependency amplification (webhook/every-request cost)
- Kubernetes API server: concurrent ~1MB resources through an external ValidatingWebhook → API server crash + GKE control-plane repair triggered (1096907).
- HackerOne markdown via GraphQL fields: payload `[[[[[[[[[[[[[[[[][l]][l]][l]][l]][l]`][l]][l]][l]][l]][l]][l]][l]][l]][l]][l]][l]` + `[l]:ht0tp%3A%2F%2FdwqNo%0A+fg` → 502 from the frontend renderer (1138668).

### 15. Client-side / browser DoS
- WordPress.com oversized post ID `https://wordpress.com/post/2000000000000000000...` → unlimited requests to pixel.wp.com, 99% CPU (129091)
- Brave: `<script>window.location+='?\u202a\uFEFF\u202b';</script>` self-appending URL growth → renderer killed (181558); `open(""); setInterval('location.reload()',1);` → hang, unclosable tab (181686); popup recursion freeze (179248); repeated `window.print()` dialog loop (176364)
- Apache Killer overlapping Range headers against grtp.co (CVE-2011-3192, via nmap/Metasploit modules) (112687)
- curl cookie engine: control codes (<32) in a cookie get replayed to sibling sites → HTTP 400s (CVE-2022-35252) (1686935)
- Cloudflare WARP client: over-long "Excluded Host" IP-Range string crashes the desktop app (1781096)
- HackerOne error-page spam via unpatched error-handling flaw (17785)
- TikTok instance page: operator-triggered front-end DoS via uncontrolled resource consumption (1478930)
- Bime: many data sources break the page — can't load or delete any (141676)
- Rocket.Chat message with a specific character chain → hot loop, ~120% CPU, server stops responding (1461340, payload not stated)

### 16. Missing anti-automation on forms
- iandunn.name contact/backup forms with no CAPTCHA → flood-based DoS asserted, not demonstrated (176599). Note: weak form — no exploitation shown; treat as low-value.

## Bypass / chain notes
- **Rate-limit evasion by work-per-request scaling:** Mapbox — keep request count constant, multiply response size via `interval=hour` + long period (136221).
- **Two-step stored payloads:** Mattermost playbook — the oversized template doesn't hurt at creation; the DoS fires when the playbook *runs* (1685979). Same shape: Nextcloud workflow rules (store now, load later) (1018146).
- **Pre-auth escalation of local bugs:** Tor control-port hang reproduced without auth via `<img src>` request to localhost:9999 (113424).
- **Self-DoS via redirect reflection:** Acronis `%0a` + path repetition → 301 loop; curl `--max-redirs 100` amplified it (1382448).
- **Crash-loops:** Kubernetes snapshot-controller re-panics on the same persisted object every restart (1032086) — persistence multiplies impact.
- **Cookie persistence = long-tail DoS:** Shopify oversized cookies broke requests for 30 days without re-attacking (105363); curl control-code cookies poison sibling sites (1686935).
- **urllib chain:** attacker server replies `HTTP/1.1 100 OK` → streams header lines forever → client hangs despite timeout (1188128).

## Gotchas / what NOT to do
- **Don't report unbounded-input theory without effect.** 1243009 (Reddit password length) was marked duplicate; 176599 (no CAPTCHA, no demo) and 1073363 (no PoC) show assertions without demonstration are weak. Prove actual resource consumption or availability loss.
- **Don't stop at self-DoS unless scope allows it.** 1478930 (TikTok own-instance front-end DoS) and 176364-style browser PoCs land only where the program accepts them; escalate to cross-user impact (1253732 style) when possible.
- **Don't hammer production blindly.** Records that succeeded used bounded PoCs (10 parallel curls, ~450 comments, one crafted JPG) and quantified results (2.5KB→372KB; 6MB→400MB; ~5GB alloc). Measure before/after.
- **Payload not stated ≠ payload unknown — but note it.** 1461340 (Rocket.Chat), 1138668-adjacent records: several winning reports described the trigger class without a verbatim payload; keep the characterization precise.
- **Watch for duplicates on classic vectors:** unbounded password length reports were dupes across programs — check the program's history first.
- **Don't confuse client slowness with server DoS** — 129091 was accepted as client-side CPU pegging, but the report had to demonstrate the mechanism (unlimited pixel.wp.com requests), not just "my browser froze."

## Real-world impact examples
- **www.acronis.com down 30-60 minutes** (502 Bad Gateway) from ~2 minutes of `%0a` path-repetition requests (1382448).
- **Mattermost completely unresponsive for all users** from a single 66KB invalid slash-command until restart (1243724); full server crash from a 50MB playbook template (1685979).
- **Shopify site-wide HTTP 400s for 30 days** across three domains from one crafted URL setting oversized cookies (105363).
- **hackerone.com paralyzed by 10 parallel requests** to report JSON; takedown estimated at ~14,000 requests/day (125587).
- **Nextcloud ~5GB memory allocated** generating a preview of one broken image (1261225); **2.5 Gbps link saturated** and disk filled by Talk link-preview fetches (1806223).
- **Node http2 server: 6MB→>400MB RAM in 30s, >7000 leaked FDs** — unable to accept connections or open files (1043360).
- **Kubernetes API server crash + GKE control-plane repair** from concurrent 1MB webhook submissions (1096907).
- **Happy Tools admin permanently unable to invite anyone** after unverified email change (1041173) — permanent, not transient.