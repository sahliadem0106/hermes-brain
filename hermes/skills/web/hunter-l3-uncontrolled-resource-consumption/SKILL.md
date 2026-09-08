---
name: hunter-l3-uncontrolled-resource-consumption
description: "Use when hunting Uncontrolled Resource Consumption on a target. Loads the L3 technique sheet: Uncontrolled Resource Consumption covers bugs where an application, daemon, or protocol implementation fails to bound a resource — memory, CPU, sessions, email sends, message queue bytes — against att"
domain: cybersecurity
subdomain: web
tags:
- web
- uncontrolled-resource-consumption
- hunting
- l3
version: '1.0'
---

# Uncontrolled Resource Consumption — Technique Sheet

## Overview

Uncontrolled Resource Consumption covers bugs where an application, daemon, or protocol implementation fails to bound a resource — memory, CPU, sessions, email sends, message queue bytes — against attacker-controlled input or attacker-triggered events. Unlike classic injection bugs, the payload is usually volume, size, or repetition rather than special syntax, which means the skill lies in identifying *which counter, cap, or cleanup path is missing* and demonstrating measurable exhaustion. This class pays especially well in infrastructure/protocol targets (Node.js core, Tor, Rails) where a single CVE-grade finding is high-severity, and in SaaS targets where an unthrottled feature lets you burn a third-party service (SES, email infrastructure) on the victim's dime.

## Distinct sub-patterns

### 1. Protocol state machine keeps accepting data after teardown signal (HTTP/2 GOAWAY)

- **Endpoint shape:** Raw HTTP/2 connection handling — no HTTP endpoint. Trigger: send invalid protocol errors on an HTTP/2 session.
- **Payload:** None stated (protocol-level frame manipulation, not an HTTP request).
- **Root cause:** The Node.js HTTP/2 server continues accepting data even *after* it has sent a GOAWAY frame on invalid protocol errors. The session is supposed to be winding down, but session cleanup never runs, so the server keeps consuming resources for sessions that should be dead.
- **Impact:** Resource exhaustion / DoS on Node.js 22 and 24. Issued as CVE-2026-48937.
- **Exemplar:** id=3658225 (Node.js program)

### 2. Unbounded frame count on a client-facing protocol handler (HTTP/2 ORIGIN frames)

- **Endpoint shape:** Node.js HTTP/2 *client* receiving frames from a malicious server. Attacker role is reversed: you control the server side.
- **Payload:** None stated; the abuse is simply "server sends an unlimited number of ORIGIN frames."
- **Root cause:** The client does not bound the number of ORIGIN frames a server can send. Each frame allocates memory with no ceiling → unbounded memory growth until OOM.
- **Impact:** Out-of-Memory crash of the Node.js HTTP/2 client, affecting Node.js 22, 24, and 26. Issued as CVE-2026-48619.
- **Exemplar:** id=3676863 (Node.js program)

### 3. Allocation counter never decremented on abnormal-free path (Tor conflux OOO queue)

- **Endpoint shape:** Tor internals — `src/core/or/conflux_pool.c:conflux_free_`, parameter `ooo_q` (out-of-order queue). Requires being an exit relay on a conflux leg.
- **Payload (verbatim):** `CONFLUX_SWITCH` gap followed by `RELAY_DATA` cells.
- **Chain (as recorded):**
  1. Malicious Conflux-capable exit relay sends a CONFLUX_SWITCH gap then RELAY_DATA cells.
  2. Victim client queues out-of-order messages, incrementing the allocation counter (truncated in record at this step).
  3. Attacker exits are replaced by clean exits and real teardown runs — but the counter stays stuck.
- **Root cause:** `conflux_free_()` frees queued OOO messages *without subtracting their alloc cost from `total_ooo_q_bytes`*; the counter is only balanced on normal dequeue. Any teardown path that skips normal dequeue leaves a permanent phantom allocation.
- **Impact:** Conflux allocation counter remained non-zero — **1,441,452 bytes** — after legitimate teardown, persisting until the Tor process was restarted. No OOM was triggered in the recorded run (impact was the corrupted accounting state, demonstrated persistently).
- **Exemplar:** id=3701692 (Tor program)
- **Note:** This is a "slow leak via accounting bug" pattern — a small number of iterations is harmless, but each triggered cycle permanently consumes headroom.

### 4. Exposed amplification/brute-force surface due to broken WAF rule (XMLRPC)

- **Endpoint shape:** `POST /xmlrpc.php` on mariadb.org (WordPress XMLRPC endpoint).
- **Payload:** None stated — reachability itself is the bug.
- **Root cause:** XMLRPC was enabled and reachable because the web-server block rule had a *syntactic error* and silently did not apply. The bug class here is "unbounded third-party abuse via a publicly reachable amplification endpoint," and the root cause is config-as-code failure, not missing application logic.
- **Impact:** Proven via configuration evidence: xmlrpc.php accessible on mariadb.org, enabling DDoS amplification and brute-force attacks against/through the site.
- **Exemplar:** id=386160 (MariaDB program)
- **Hunting tip:** When a target advertises a blocked surface (blocklists, WAF rules), verify the block actually applies — a typo'd rule is an instant, config-provable finding.

### 5. Oversized string fields with no length validation (client-crashing DoS)

- **Endpoint shape:** `POST /i/moments/edit/{num}`, params `title`, `description`.
- **Payload (verbatim, structure):** `{"title":"","description":"","is_production_only":true,"has_owner_granted_location_permission":true}` — with `title`/`description` filled with up to **1,950,000 characters**.
- **Root cause:** Server lacked character-length validation on moment title/description, accepting arbitrarily large strings.
- **Impact:** Two-tier: (a) 1,950,000-char title/description produced a **500 error** server-side; (b) a 200,001-char moment caused the **Android app to hang or crash for anyone opening the shared link** — i.e., persistent stored DoS against other users, not just the attacker's own session.
- **Exemplar:** id=819088 (X / xAI program)
- **Key escalation:** the stored, victim-facing variant (200,001 chars crashing other users' apps) is far stronger than the self-inflicted 500. Demonstrate both, lead with the victim-facing one.

### 6. Unbounded side-effect generation through a free feature (bounced-email flood via SES)

- **Endpoint shape:** Sandbox program invitation flow on HackerOne (POST; endpoint not further specified).
- **Payload:** "Generating an unbounded number of bounced emails via unrestricted sandbox program invitations" — the abuse is the invitation flow itself, not a crafted string.
- **Root cause:** Unrestricted invitations in sandbox programs let an attacker generate an infinite number of bounced emails through Amazon SES. Each invitation → email → bounce consumes SES quota/reputation owned by the target.
- **Impact:** Generated enough bounced emails to put HackerOne's **SES service up for review** by Amazon, causing a DoS of HackerOne's email-sending service.
- **Exemplar:** id=823915 (HackerOne program)
- **Key insight:** you never exhaust the target's own CPU — you exhaust a *third-party dependency's trust* (bounce-rate thresholds). This converts a mundane invitation flow into a full email-service outage.

### 7. Global cache poisoned by nonexistent keys (framework-level memory leak)

- **Endpoint shape:** Any route containing `:controller` in a Rails (Action Pack) wildcard controller route; parameter `controller`.
- **Payload:** None stated — requests for *nonexistent* controller names are enough.
- **Root cause:** Routes containing `:controller` cause a global cached map of URL-controller-name → class to be populated even for nonexistent controllers. Every unique garbage controller string inserts a new permanent entry — attacker-controlled key cardinality with no cap.
- **Impact:** Objects leaked globally leading to unbounded memory growth / DoS. Issued as **CVE-2015-7581**.
- **Exemplar:** id=83962 (Ruby on Rails program)
- **Hunting tip:** For any parameter that becomes a cache/map key, send many *unique* values and watch memory (e.g. `/a`, `/b`, `/c`… through the wildcard). Linear memory growth with unique keys = leak.

### 8. Unthrottled replayable email-send on an unverified account

- **Endpoint shape:** `POST` send test/preview email endpoint (Courier); params: recipient email, message.
- **Payload:** Test email send request (verbatim body not stated) — notably **replayable**.
- **Chain:** (recorded as root-cause factors) (a) account registration required no email verification, so an attacker could register with a *victim's* email address; (b) the send-test-email endpoint had no request/rate limiting.
- **Impact:** Unlimited replay of the test-send request delivered emails to the victim's address — enabling **phishing from the target's legitimate sending domain** and resource-exhaustion DoS against the target.
- **Exemplar:** id=906226 (Courier program)
- **Key insight:** the missing email verification is what gives the attack *content injection into a trusted channel*; the missing rate limit is what makes it unbounded. Both gaps compound.

## Bypass / chain notes

- **Server-side 500 vs. victim-facing crash:** In the X moments case (id=819088), the oversized payload had two effects at different sizes. Chain them in one report: huge value proves missing validation; the moderate 200,001-char value proves *stored* cross-user DoS. The victim-facing impact is what justifies high severity.
- **Protocol-level role reversal:** The Node.js ORIGIN-frame bug (id=3676863) required attacking the *client* component from a malicious server position. When auditing protocol handlers, consider both directions — a missing bound on received frames is exploitable regardless of which peer sends them.
- **Missing-cleanup + missing-bound combos:** The Tor finding (id=3701692) chained a protocol trigger (CONFLUX_SWITCH gap + RELAY_DATA) with an accounting bug on the teardown path. Two independent flaws (queue accepts OOO data; free path doesn't decrement) combined into a persistent leak. When you find an unbounded queue, always check whether *every* free/dequeue path decrements the counter.
- **Auth gap + rate-limit gap:** The Courier bug (id=906226) needed both no-verification registration and an unthrottled endpoint. Individually each is low/medium; combined they yield phishing + DoS.
- **Config error as an enabler:** The MariaDB XMLRPC case (id=386160) is a chain of one: a syntactically broken WAF/block rule silently exposing an endpoint that enables amplification and brute force. Proof came from configuration inspection, not exploitation.
- **Abuse via third-party trust, not direct exhaustion:** The HackerOne SES case (id=823915) shows that "DoS" can be achieved by tripping a provider's abuse thresholds (bounce rate) rather than by CPU/memory exhaustion. Look for any feature that makes the target send email/requests on your behalf and can be made to fail en masse.

## Gotchas / what NOT to do

- **Don't claim OOM you didn't trigger.** The Tor report (id=3701692) explicitly states no OOM was triggered in the run — the accepted impact was the persistent corrupted allocation counter (1,441,452 bytes). Report what you measured.
- **Don't confuse "I can send a big string" with impact.** A 500 on your own request (id=819088, 1.95M chars) is weak; a crash for *other users* opening a stored link is strong. Build the victim-facing proof.
- **Don't stop at a missing rate limit without a compounding factor.** The strong records here pair the unthrottled endpoint with something else: no email verification (Courier), third-party bounce flood (HackerOne). A plain unthrottled endpoint with no attacker benefit is usually informational.
- **Don't assume framework CVEs are dead.** CVE-2015-7581 (Rails wildcard controller leak) is old, but the *pattern* — attacker-controlled keys populating an unbounded global cache — is what to hunt for in any stack; requests for nonexistent keys through wildcard routes are the probe.
- **Don't overlook your own resource use while testing.** The records that "worked" here involved volume (bounces, frames, cells). Keep your testing bounded and state your test volume in the report so the triager can reproduce safely.
- **Don't rely on blocked surfaces being blocked.** Verify the rule (id=386160) — a syntactic error in a WAF rule is silent until you test it.

## Real-world impact examples (from records)

- **CVE-2026-48937 (Node.js, id=3658225):** Server continues accepting data after GOAWAY on invalid protocol errors → resource exhaustion/DoS on Node.js 22 and 24.
- **CVE-2026-48619 (Node.js, id=3676863):** Unbounded ORIGIN frames from a malicious server → unbounded memory growth / Out-of-Memory on the Node.js HTTP/2 client (Node 22, 24, 26).
- **Tor (id=3701692):** Conflux allocation counter stuck at **1,441,452 bytes** after real teardown, persisting until Tor restart.
- **MariaDB (id=386160):** xmlrpc.php reachable on mariadb.org due to a syntactically broken block rule → DDoS amplification and brute-force surface (proven via config).
- **X / xAI (id=819088):** 1,950,000-char moment title/description → server 500; 200,001-char moment → Android app hangs/crashes for anyone opening the shared link (stored cross-user DoS).
- **HackerOne (id=823915):** Bounce-email flood via sandbox invitations put HackerOne's **Amazon SES account up for review**, DoSing the company's email-sending service.
- **Ruby on Rails (id=83962):** Wildcard `:controller` routes leak objects into a global cache for nonexistent controllers → unbounded memory growth / DoS (CVE-2015-7581).
- **Courier (id=906226):** Unverified registration + unthrottled replayable test-email endpoint → unlimited phishing emails from the target's trusted sender, plus resource-exhaustion DoS.