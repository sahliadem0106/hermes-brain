---
name: hunter-l3-session-hijacking
description: "Use when hunting Session Hijacking on a target. Loads the L3 technique sheet: Session hijacking is the reuse of a victim's established session — via a stolen cookie, an exposed session ID, or server-side session storage — to gain authenticated access without credentials."
domain: cybersecurity
subdomain: web
tags:
- web
- session-hijacking
- hunting
- l3
version: '1.0'
---

# Session Hijacking — Technique Sheet

## Overview
Session hijacking is the reuse of a victim's established session — via a stolen cookie, an exposed session ID, or server-side session storage — to gain authenticated access without credentials. It pays when combined with any disclosure primitive (XSS, SSRF/file read, cross-origin leaks) or when the target's session validation is weak enough that cookies alone are sufficient authentication. The four records here span four very different surfaces: browser cookie replay, an auth-flow design flaw, a C library leaking cookies on redirects, and VPN appliance session storage — showing that this class applies well beyond "steal a cookie with XSS."

## Distinct sub-patterns

### 1. Direct cookie replay in a fresh browser
- **Endpoint shape / parameter:** No specific endpoint — the entire authenticated application accepts the `Set-Cookie` session token (plus matching `Referer` / `X-XHR-Referer` request headers) as sole authentication. Program: HackerOne (id=19640).
- **Payload that actually fired:** payload not stated — the technique is transporting the captured session cookie into a different, not-logged-in browser and replaying it verbatim against the authenticated app.
- **Root cause:** The application's session validation was transport/context-agnostic: a captured cookie paired with the expected `Referer`/`X-XHR-Referer` values was accepted from any client while the victim's session remained active. No binding to device, IP, or one-time token freshness beyond simple validity.
- **Impact proven:** Full access to the victim's logged-in account state without credentials, demonstrated from a browser where the attacker was never logged in, while the victim's session was live.
- **Exemplar:** id=19640 (HackerOne).

### 2. Auth-flow design flaw exposing the session ID → XSS chain
- **Endpoint shape / parameter:** `www.identity.com` authentication flow (Inflection program, id=241194). The flaw sits in how the flow handles the session identifier during login/redirect steps rather than in a single query parameter.
- **Payload that actually fired:** payload not stated. The recorded chain is:
  1. Exploit the auth-flow flaw to expose/access the session ID.
  2. Chain with an XSS to take over the victim's session.
- **Root cause:** The authentication flow left the session ID reachable (readable/exfiltratable) at a point where a separate injection surface (XSS) could retrieve it. Two independent weaknesses — an over-exposed session ID and script execution — combine into one takeover.
- **Impact proven:** Full session takeover, confirmed in the program's own summary.
- **Exemplar:** id=241194 (Inflection).

### 3. Cookie leakage on cross-origin redirects (library-level, `CURLOPT_COOKIE`)
- **Endpoint shape / parameter:** Any client using curl with `CURLOPT_FOLLOWLOCATION` and a cookie set via the `CURLOPT_COOKIE` option; specifically the cookie-attachment code path `http_cookies()` in curl. Parameter at fault: `CURLOPT_COOKIE` (vs. the `CURLOPT_HTTPHEADER` `Cookie:` path). Program: curl (id=3766065).
- **Payload that actually fired (verbatim):**
  ```
  curl -sS -v -L -b "session=SECRET-TOKEN-12345" http://127.0.0.1:8080/
  ```
  with the local server responding with a redirect to a cross-origin host.
- **Root cause:** `http_cookies()` appends the `CURLOPT_COOKIE` value to outgoing `Cookie:` headers without invoking `Curl_auth_allowed_to_host()` — the host-scope check that the `CURLOPT_HTTPHEADER` `Cookie:` path does invoke. So when `-L` follows a redirect to a different origin, the session cookie travels to the redirect target.
- **Impact proven:** Confirmed leak — the session cookie was transmitted to the cross-origin redirect target, which logged it verbatim. A control run using `-H "Cookie: ..."` instead of `-b` sent no Cookie header to the target, isolating the leak to the `CURLOPT_COOKIE` path.
- **Exemplar:** id=3766065 (curl).

### 4. Server-side session storage reuse (VPN appliance, `randomVal` / `data.mdb`)
- **Endpoint shape / parameter:** Pulse Secure SSL VPN session mechanism — cached user sessions stored in `randomVal` / `data.mdb`. No web parameter; the "parameter" is the appliance's session cache.
- **Payload that actually fired (verbatim):** `a;id;echo pwned` — used to obtain the file-read primitive that reaches the session store.
- **Root cause:** Cached user sessions persisted in `randomVal`/`data.mdb` remain replayable even when Roaming Session is not enabled. Session material at rest is therefore a reusable credential, not just ephemeral state.
- **Impact proven:** Reused stored user sessions to log into the SSL VPN **without 2FA** — the session itself bypassed the second factor entirely.
- **Recorded chain:**
  1. Read `randomVal`/`data.mdb` via file read (armed with the shell payload above).
  2. Replay the stolen session to authenticate.
- **Exemplar:** id=591295 (X / xAI program, Pulse Secure).

## Bypass / chain notes
- **XSS → session ID → takeover (id=241194):** the auth flow's exposure of the session ID is the multiplier. A low-severity "session ID accessible" issue becomes critical when any XSS on the same surface can read it. Hunt auth flows for places the session identifier appears (URLs, response bodies, redirect parameters) where script execution can reach it.
- **File read → session store → 2FA bypass (id=591295):** a two-step chain where the first step is arbitrary file read (enabled by the command-injection payload `a;id;echo pwned`) and the second is replaying extracted session values. Key insight: session stores that survive without the expected feature toggle (Roaming Session disabled) mean session values act as standing credentials that skip MFA.
- **Referer/X-XHR-Referer matching as a replay requirement (id=19640):** the replayed request needed the matching header values — i.e., the app used header consistency as a weak CSRF/origin check, not as a hijack defense. Capture not just the cookie but the full header set when testing replay.
- **Cookie-option vs. header-option divergence (id=3766065):** differential testing between `-b`/`CURLOPT_COOKIE` and `-H "Cookie:"` was what isolated the root cause — the header path correctly consulted `Curl_auth_allowed_to_host()`, the cookie option did not. This diff-testing pattern generalizes: when a leak occurs on redirect, compare every code path that can set the sensitive header.

## Gotchas / what NOT to do
- Do not assume a stolen cookie alone proves takeover — in id=19640 the replay also required matching `Referer`/`X-XHR-Referer` values. Document the full minimal replay condition or the report understates the exploit requirements.
- Do not conflate the two curl code paths: `CURLOPT_HTTPHEADER` with a `Cookie:` entry was the *control* (no leak), `CURLOPT_COOKIE` was the vulnerable path. Reporting the wrong option invalidates the finding.
- Do not treat session-in-storage as ephemeral. On appliances, absence of a feature (Roaming Session) does not mean sessions were purged — the id=591295 finding hinged on exactly that assumption being wrong on the vendor's side.
- Do not report "session ID accessible via auth flow" in isolation as full takeover; the impact in id=241194 is credible *because* it was chained with XSS and confirmed by the program. State the chain.
- Payloads are not always stated — in id=19640 and id=241194 no verbatim payload exists in the records; reconstructing one is part of the hunter's work, and the sheet's value there is the structural pattern (header-matched replay; auth-flow exposure + XSS chain), not a copy-pable string.

## Real-world impact examples
- **id=19640 (HackerOne):** An attacker with a captured session cookie accessed the victim's logged-in account from a completely unauthenticated browser, bypassing login entirely — full account-state access while the victim's session was active.
- **id=241194 (Inflection, identity.com):** Auth-flow flaw exposing the session ID, chained with XSS, yielded confirmed full session takeover of identity.com accounts.
- **id=3766065 (curl):** A user's session cookie set via `CURLOPT_COOKIE` was transmitted verbatim to a cross-origin redirect target and logged there — credential theft via any malicious/sibling redirect, affecting every curl consumer of `-b` + `-L`.
- **id=591295 (X / xAI, Pulse Secure):** Sessions extracted from `randomVal`/`data.mdb` were replayed to log into the SSL VPN with no 2FA challenge — authenticated VPN access, the highest-value position in a corporate network, from a file-read primitive.