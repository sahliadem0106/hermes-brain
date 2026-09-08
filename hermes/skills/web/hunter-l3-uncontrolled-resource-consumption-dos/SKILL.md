---
name: hunter-l3-uncontrolled-resource-consumption-dos
description: "Use when hunting Uncontrolled Resource Consumption (DoS) on a target. Loads the L3 technique sheet: This class covers inputs that force a server to spend disproportionate resources — CPU, memory, worker threads, network fan-out — or that crash rendering/handling logic outright, degrading or killing availability."
domain: cybersecurity
subdomain: web
tags:
- web
- uncontrolled-resource-consumption-dos
- hunting
- l3
version: '1.0'
---

# Uncontrolled Resource Consumption (DoS) — Technique Sheet

## Overview
This class covers inputs that force a server to spend disproportionate resources — CPU, memory, worker threads, network fan-out — or that crash rendering/handling logic outright, degrading or killing availability. Unlike logic bugs, the payload is usually mundane (whitespace, markdown, repeated requests, a single malformed character); the severity comes from amplification ratio or the blast radius of a crash. It pays when you can demonstrate sustained degradation (OOM kills, worker exhaustion, multi-minute stalls, permanent 500s on core pages) rather than a one-off blip.

## Distinct sub-patterns

### 1. Markdown/renderer poison: invalid Unicode breaking the render path
- Endpoint shape: `POST /posts` (create content with markdown body); the blast radius hits the listing: `GET /users/{num}/posts`.
- Payload (verbatim): `[PoC](&#65534;(&#41;)`
- Root cause: the markdown renderer mishandles the HTML-encoded invalid Unicode char (U+FFFD substitute expressed as `&#65534;`), throwing an uncaught error during render. Because the user's post list renders all their posts server-side, one poisoned post 500s the entire listing — the damage is sticky, not per-request.
- Impact proven: confirmed 500 Internal Server Error — after posting the payload, the author's `/posts` page returned 500 for everyone, blocking all of the author's posts.
- Exemplars: 1176794 (FetLife).

### 2. Unbounded external image embeds → turning the target's users into a DDoS botnet
- Endpoint shape: `POST /~{username}/` statement (markdown body supporting images). General template: any profile/bio/comment field that renders `![](url)` markdown or raw `<img>` tags.
- Payload (verbatim shape): `![](http://blackdoorsec.net:80/1    "HTTP")` — repeated; the reporter placed 100 such images in one statement and verified them on their profile.
- Root cause: no limit on the number of external images allowed in a statement. Every visitor's browser then fires N outbound requests to attacker-controlled hosts on page load — the platform amplifies the attacker's traffic and each page view becomes a distributed request flood the target hosts.
- Impact proven: with 100 embedded images, a traffic counter on the reporter's host fired on page load, demonstrating users of the site can be turned into DDoS participants.
- Exemplars: 117739 (Gratipay).

### 3. Crypto-primitive amplification: crafted input to a precompile (modexp)
- Endpoint shape: not a web endpoint — the EVM `modexp` precompile in the RSK (rskj) node source; delivered via a crafted smart contract's bytecode. Payload is contract bytecode (hex, verbatim in record):
  `3332335b59313660d53d601c30303030333333333d601c30303030333333333333321b1b1b1b325b593136605858425a606052015952601d52609880808060006000600536f1603d3333321b1b1b1b32365b3159605858425a606052015952601d52609880808060006000600536f1603d313880813b60003960006000f50a30303030303030`
- Root cause: a bug in the modexp precompile let specially-shaped operands execute for minutes instead of milliseconds, consuming excessive CPU relative to the gas charged — a gas-metering/accounting flaw that breaks the cost model.
- Impact proven: the crafted contract took 8m23s of real execution time, causing long stalls that can stall the entire network.
- Exemplars: 2412583 (Rootstock Labs).

### 4. Worker-pool exhaustion via repeated state-changing requests
- Endpoint shape: `POST` payout preference update (an authenticated settings mutation — any frequent, non-rate-limited profile/preference update that does real work per request is the template).
- Payload: none stated — the technique is repetition, not a special payload.
- Root cause: continuously updating payout preferences exhausts the Unicorn worker pool; each update is expensive enough (or the pool small enough) that a loop of requests starves all workers, and no request — including other users' — gets served.
- Impact proven: exhausted the worker pool and took hackerone.com down (site shown in maintenance / DoS).
- Exemplars: 317543 (HackerOne).

### 5. Decompression bomb at the protocol layer (highly-compressed stanzas)
- Endpoint shape: XMPP stream — compressed XML stanzas per XEP-0138 (any protocol feature that transparently decompresses/decodes client input before applying limits is the template).
- Payload: 4GB of whitespace compressed to 4MB via zlib (the `xmppbomb` tool).
- Root cause: XMPP servers did not limit resources when decompressing highly-compressed application-layer stanzas — no cap on decompressed size, allocation, or expansion ratio before processing. A ~1000x compression ratio turns a small stream into gigabytes of allocation.
- Impact proven: Prosody allocated up to 7GB RSS and was OOM-killed; Openfire hit 100% CPU and wrote ~400MB to disk; Tigase pushed CPU to 100% for ~10 minutes; service availability degraded 100x–10000x.
- Exemplars: 5928 (Internet Bug Bounty).

### 6. Single-character rendering poison that also bricks remediation
- Endpoint shape: report comment field (any free-text field rendered on a heavily-cached/indexed page).
- Payload (verbatim): `_www.%40ebаy.com_`
- Root cause: a hex-encoded `%40` (in combination with the homoglyph `а` in the payload) broke report rendering — an uncaught error in the rendering path, same family as pattern 1 but from an encoding quirk rather than invalid Unicode. Critically, the report is where staff triage happens: breaking its render cascades into tooling built on top.
- Impact proven: entering the text caused the report to fail to load, and also broke the bulk edit interface, so the report could not be closed or removed — a self-locking DoS of the triage surface.
- Exemplars: 59369 (HackerOne).

## Bypass / chain notes
- No multi-step chains appear in the records; the power here is in the primitives themselves:
  - Compression is the dominant amplifier (5928): compress your payload so rate/size limits at the edge see 4MB while the server allocates 4GB. Look for any decode-then-process step (zlib, gzip, protobuf expansion, XML entity expansion analogues) that runs before size checks.
  - Persist your DoS (1176794, 59369): payloads stored in content that renders on shared pages convert a one-shot request into a standing outage for every visitor, and 59369 shows the poisoned object can disable the very interface (bulk edit) staff would use to remove it.
  - Fan-out through other users (117739): if the target refuses to count your requests as abuse, make their own users generate the traffic.
  - Metering mismatches (2412583): anything priced in gas/time units that can be made to cost more than it charges is the blockchain analogue of a worker-pool DoS.
  - Repetition against expensive-but-unlimited actions (317543): no exotic payload needed — find the authenticated mutation with the highest per-request cost and the weakest rate limit.

## Gotchas / what NOT to do
- Don't take the target down to prove you can: 4 (worker exhaustion) and 5 (xmppbomb) caused full outages — real programs expect you to minimize. Prefer sustained-but-recoverable evidence: single poisoned object, bounded request bursts, measured timings.
- Don't stop at "the request was slow." The accepted reports quantify: 8m23s execution, 7GB RSS, 100x–10000x availability degradation, 100 embedded images with a traffic counter. Build measurement into your PoC (timing, memory counters, request logs on your own host).
- Don't assume a 500 on your own view is enough — 1176794 worked because the 500 hit the user's public posts listing for everyone. Demonstrate the blast radius (who else can't see what).
- Don't overlook remediation-killers: a DoS the staff can't undo (59369 breaking bulk edit) is materially more severe — and is the thing to flag explicitly in the report.
- Payload hygiene: keep verbatim bytes. 59369 hinged on an exact `%40` and a lookalike Cyrillic `а`; 1176794 on the exact `&#65534;(&#41;)` encoding. Re-typing or "normalizing" these kills the bug.

## Real-world impact examples
- hackerone.com fully down via payout-preference update loop (worker pool exhausted; site in maintenance) — 317543.
- Prosody OOM-killed at 7GB RSS; Openfire 100% CPU + ~400MB disk; Tigase 100% CPU for ~10 min; availability degraded 100x–10000x from a 4MB stream — 5928.
- Entire posts listing of a user returning 500 to all visitors from a single 20-character markdown body — 1176794.
- Crafted RSK smart contract executing for 8m23s (vs. milliseconds) — network-stall class bug — 2412583.
- A HackerOne report rendered permanently unloadable and un-closable via bulk edit from one comment string — 59369.
- Verified external-traffic generation through the target's own user base (100 images, counter fires per page view) — 117739.