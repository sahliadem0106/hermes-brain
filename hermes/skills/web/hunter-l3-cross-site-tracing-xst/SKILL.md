---
name: hunter-l3-cross-site-tracing-xst
description: "Use when hunting Cross-Site Tracing (XST) on a target. Loads the L3 technique sheet: Cross-Site Tracing exploits servers that still have the HTTP TRACE method enabled."
domain: cybersecurity
subdomain: web
tags:
- web
- cross-site-tracing-xst
- hunting
- l3
version: '1.0'
---

# Cross-Site Tracing (XST) — Technique Sheet

## Overview

Cross-Site Tracing exploits servers that still have the HTTP TRACE method enabled. TRACE is a loopback diagnostic: the server reflects the entire request — method, path, and every header — back to the client verbatim. That echo defeats the HttpOnly cookie protection, because an HttpOnly cookie (or an Authorization header) that JavaScript can never read via `document.cookie` still rides in request headers, and TRACE bounces those headers straight back into readable response body territory. In bug bounty practice, XST pays as a server-misconfiguration finding only when you demonstrate the echo of sensitive material; a bare "TRACE is enabled" report gets rejected or marked out of scope. The full weaponization path is chaining the echo with XSS to hijack HttpOnly sessions.

## Distinct sub-patterns

The records contain three distinct sub-patterns, which effectively form a test sequence: method discovery → canary echo proof → sensitive-header echo proof.

---

### Sub-pattern 1 — Canary header echo probe (prove TRACE reflects attacker-controlled headers)

**Endpoint shape / parameter:**
`TRACE /` against the host root. No query parameters, no path-specific behavior — this is a method-level server misconfiguration, so the root path is the correct and sufficient target. Test directly against the live hostname (exemplar was `plugins.trac.wordpress.org`).

**Payload that actually fired (verbatim, record 222692, WordPress):**

```
TRACE / HTTP/1.1
X-Header: geeknik/pentest
```

Note the structure: an innocuous path (`/`), a standard HTTP/1.1 request line, and a single attacker-injected header carrying a recognizable canary string. The canary (`geeknik/pentest`) serves two purposes — it's unambiguous to spot in the response, and it attributes the probe.

**Root-cause pattern:**
The server accepts the TRACE method and, per the TRACE specification, echoes the full request back. Crucially, it does not filter or strip injected headers — the attacker-supplied `X-Header` comes back in the response body. This proves the general property that matters: *any* header the client sends is reflected. That generalization is what upgrades the finding from "diagnostic method enabled" to "header content disclosure primitive."

**Impact that was proven:**
The server responded to TRACE and echoed the injected `X-Header` back, confirming XST potential for stealing cookies and credentials on `plugins.trac.wordpress.org`. The reporter's root-cause statement explicitly names the target classes: HttpOnly cookies and Authorization headers.

**Exemplar report IDs:** id=222692 [ajaysenr, WordPress].

---

### Sub-pattern 2 — Cookie echo proof (directly demonstrate HttpOnly cookie exposure)

This is the strongest pattern in the records and the one that maps most directly to real harm. Instead of a generic canary header, you send a `Cookie` header — a placeholder or canary value — and prove that the *sensitive header class itself* is reflected.

**Endpoint shape / parameter:**
`TRACE /` at the host root, sent with a `Cookie` header. Again parameterless; the Cookie header is the payload vehicle.

**Payload that actually fired (verbatim, record 83373, ownCloud):**

```
TRACE / HTTP/1.0
Host: owncloud.com
Cookie: 74b33b43fa
```

Note two details: the request uses **HTTP/1.0** (not 1.1 — see Bypass notes), and the Cookie value is a short canary-style token (`74b33b43fa`) rather than a full live session credential. The probe is minimal and self-contained.

**Root-cause pattern:**
TRACE echoes the full request, including the Cookie header, back to the client. This is precisely the scenario XST exists to exploit: HttpOnly exists to stop JavaScript from reading cookies, but it does nothing to stop a header echo, because the cookie travels in the request the server deliberately mirrors. A cookie that is invisible to `document.cookie` is fully visible in a TRACE response.

**Impact that was proven:**
The TRACE response echoed the request including the httpOnly cookie. The reporter's stated consequence: combined with XSS, this becomes a **critical** attack vector — session hijack of an HttpOnly-protected session on ownCloud's domain.

**Exemplar report IDs:** id=83373 [ajaysenr, ownCloud].

Why this beats Sub-pattern 1: an arbitrary `X-Header` echo proves TRACE works; a `Cookie` echo proves the exact exploitation scenario. If you can only submit one proof, send the cookie version.

---

### Sub-pattern 3 — Method enumeration via OPTIONS/TRACE (recon stage; insufficient on its own)

**Endpoint shape / parameter:**
`OPTIONS` and `TRACE` requests against the host (exemplar: `checks.identity.com`). `OPTIONS` typically returns an `Allow:` header enumerating enabled methods, letting you discover TRACE support; a direct `TRACE` request then confirms it.

**Payload that actually fired:**
Payload not stated in the record. The record documents only that OPTIONS and TRACE checks were performed against `checks.identity.com`.

**Root-cause pattern:**
The server has both OPTIONS and TRACE HTTP methods enabled. This confirms the same server-level misconfiguration as the other sub-patterns, but at the discovery stage only — no echo of injected content was demonstrated.

**Impact that was proven:**
OPTIONS and TRACE methods were confirmed enabled (potential XST). **No data access was demonstrated**, and the program marked the finding out of scope. No bounty resulted.

**Exemplar report IDs:** id=283502 [ajaysenr, Inflection].

Treat this sub-pattern as step one of the hunt, never as the deliverable. It is included here because knowing what a *non-paying* version of this finding looks like is as valuable as knowing the paying version — it is the exact failure mode to avoid.

---

## Bypass / chain notes

**HTTP version choice.** Record 83373 used `TRACE / HTTP/1.0` while record 222692 used `TRACE / HTTP/1.1`. The HTTP/1.0 variant is a barebones request with no mandatory Host-header-dependent framing and no assumptions about HTTP/1.1 method handling. Both worked against their targets, so if one version is filtered or mishandled by a proxy in front of the target, the records show the other version is a legitimate fallback — both have verified successes.

**Filter bypasses.** No record in this set demonstrates a TRACE filter being bypassed — there is no instance of a blocked TRACE that was then defeated. Do not invent WAF-bypass tricks here; if TRACE is blocked at the edge, the records offer no verified technique past that. Report what you actually observe.

**Discovery companion.** Record 283502 shows `OPTIONS` used alongside `TRACE` for method enumeration. Practically: fire `OPTIONS /` first, read the `Allow` header to see whether TRACE is advertised, then confirm with a direct TRACE. This is also a lower-noise discovery path since OPTIONS is a more common, less alarming probe.

**Chains.** Every record has `chain: (none)` — no full exploit chain was executed in any of the three findings. However, the escalation path is stated explicitly in the records themselves and should anchor any impact narrative you write:

- Record 83373 (ownCloud): the echoed httpOnly cookie "combined with XSS becomes a critical attack vector."
- Record 222692 (WordPress): TRACE/XST potential "for stealing cookies/credentials," with Authorization headers named as a target header class alongside HttpOnly cookies.

The chain shape implied by these statements: (1) find an XSS or header-injection primitive on the same origin, (2) use it to make the victim's client issue a TRACE request, (3) the victim's browser automatically attaches its HttpOnly session cookie to the request, (4) the server echoes the full request including that cookie, (5) the XSS reads the echo and exfiltrates the session. The Authorization-header callout in record 222692 extends the same logic to API clients on the same host — bearer tokens in `Authorization` headers are equally exposed to the echo.

**Severity calibration from the records.** Cookie-echo proof (Sub-pattern 2) was rated critical-when-chained. Canary-header echo (Sub-pattern 1) was accepted as a valid XST confirmation. Enablement-only (Sub-pattern 3) was rejected/out of scope. Write your report severity to match the strongest proof you actually demonstrated.

## Gotchas / what NOT to do

- **Do not report "TRACE is enabled" alone.** This is the single clearest lesson in the dataset: record 283502 confirmed TRACE and OPTIONS enabled and was still marked out of scope because no data access was demonstrated. The two findings that paid (222692, 83373) both demonstrated the echo — of an injected header, or of a cookie. Enablement is a claim; echo is evidence.
- **Prove the sensitive header class, not just any header.** An `X-Header` echo is a valid confirmation, but the `Cookie` echo in record 83373 is materially stronger because it demonstrates the exact exploitation scenario. If the canary header comes back, immediately re-probe with a `Cookie:` header before writing the report.
- **Don't assume a browser-side exploit was shown.** None of the records demonstrates a working end-to-end browser attack — all three proofs are direct server-side echo demonstrations, and the impact language in the accepted reports is "potential" and "combined with XSS." Frame your report the same way: proven echo, stated chain potential. Do not overstate a hijack you didn't perform.
- **Check scope before testing.** Record 283502's finding on `checks.identity.com` was out of scope for the Inflection program despite being technically accurate. Method-enabled findings are exactly the kind of thing programs de-scope; read the policy first.
- **The root path is sufficient.** All three records test `TRACE /` at the host root. This is a method-level misconfiguration, not a route-level one — there is nothing to gain from fuzzing deep paths with TRACE, and the records show no path-specific behavior.
- **Use canary values, not live credentials, in proofs.** Record 222692 used a marker string (`geeknik/pentest`); record 83373 used a short token (`74b33b43fa`) rather than a full live session. Your proof does not need your real session cookie in the request — and putting real credentials in report evidence is an avoidable risk.
- **Don't skip the OPTIONS pre-check.** It costs one request and tells you whether TRACE is even advertised before you send a TRACE that some logging/WAF layers will flag.

## Real-world impact examples

1. **WordPress — plugins.trac.wordpress.org (id=222692):** A `TRACE / HTTP/1.1` request with an injected `X-Header: geeknik/pentest` was accepted and echoed back verbatim by the server. This confirmed XST potential for stealing cookies and credentials — HttpOnly cookies and Authorization headers — on a WordPress infrastructure host. Root cause: TRACE enabled, full header reflection.

2. **ownCloud (id=83373):** A minimal `TRACE / HTTP/1.0` request carrying `Cookie: 74b33b43fa` came back with the request — including the cookie — echoed in full. Because the echoed cookie was httpOnly-protected, the finding established that an XSS on the same origin could read the TRACE response and hijack the session, rated a critical attack vector when combined.

3. **Inflection — checks.identity.com (id=283502, counter-example):** OPTIONS and TRACE were confirmed enabled, but no echo of injected or sensitive content was demonstrated. The program marked the finding out of scope and no bounty was paid — the canonical example of why method-enablement alone is not a finding.