---
name: hunter-l3-credential-leak-information-disclosure
description: "Use when hunting Credential Leak / Information Disclosure (curl client-side credential leakage) on a target. Loads the L3 technique sheet: This class covers bugs in curl/libcurl where credentials configured for one host (via `.netrc`, or Digest auth state held on an easy handle) are sent to a *different* host than intended — typically ac"
domain: cybersecurity
subdomain: web
tags:
- web
- credential-leak-information-disclosure-curl-client-side-credential-leakage
- hunting
- l3
version: '1.0'
---

# Credential Leak / Information Disclosure (curl client-side credential leakage) — Technique Sheet

## Overview
This class covers bugs in curl/libcurl where credentials configured for one host (via `.netrc`, or Digest auth state held on an easy handle) are sent to a *different* host than intended — typically across HTTP redirects or across `curl_easy_perform()` reuse. The bugs are client-side: the attacker operates a host the client is redirected to (or a second origin the handle is reused against) and passively receives or replays credentials. These pay well against curl itself (bounty target `program=curl`) because every release ships to millions of clients; the hunter's job is a precise reproduction showing the credential crossing an origin boundary.

## Distinct sub-patterns

### Sub-pattern 1: `.netrc` credential leak on redirect to an entry-less host (CVE-2024-11053 family)
- **Endpoint shape / trigger:** Any curl HTTP transfer with `--netrc` / a populated `~/.netrc`, where the origin server responds with a 3xx redirect to a second host. Template: `curl --netrc https://a.tld/` → redirect → `https://b.tld/...`.
- **Payload that fired:** None at the HTTP layer — the payload is the `.netrc` itself plus the redirect. Verbatim reproduction `.netrc` from the records:
  ```
  machine a.com
    login alice
    password alicespassword
  default
  ```
- **Root-cause pattern:** When curl uses a `.netrc` entry matching the redirect target and that entry *omits credentials* (or matches via `default`), curl reuses/leaks the redirecting host's credentials to the next host. The credential-selection logic fails to bind the credentials to the origin that authenticated for them.
- **Impact proven:** A transfer from `a.tld` redirected to `b.tld` with a `.netrc` entry for `b.tld` exposed the password as it passed through the network. Affected curl 6.5–8.11.0 — an extremely wide vulnerable range.
- **Exemplars:** id=2912277 (initial, no verbatim payload stated), id=2917232 (reproduction with verbatim `.netrc` above).

### Sub-pattern 2: Incomplete fix — `.netrc` leak via `default`/omitted-credential entry (CVE-2025-0167)
- **Endpoint shape / trigger:** Same shape as Sub-pattern 1, but tested *against the patched build*. Trigger: `.netrc` contains `machine a.com` with credentials **and** a bare `default` entry; `a.com` redirects to `b.com`.
- **Payload that fired:** Verbatim `.netrc` (above): `machine a.com\n  login alice\n  password alicespassword` followed by `default`. Post-redirect, curl sent `alice`/`alicespassword` to `b.com`.
- **Root-cause pattern:** The CVE-2024-11053 fix was incomplete: when netrc is used and the redirect target matches a default/omitted-credential entry, credentials are still reused/leaked to the target. Key hunting lesson — retest the *same* pattern with subtly different `.netrc` shapes (matching entry, default entry, credential-less entry) after a fix ships.
- **Impact proven:** Reproduced the leak directly: after redirect, the credentials `alice`/`alicespassword` were reused for `b.com`. Awarded as CVE-2025-0167.
- **Exemplars:** id=2917232 (report explicitly framed as testing the CVE-2024-11053 fix).

### Sub-pattern 3: Digest auth state replayed across origins on easy-handle reuse (CVE on `curl_easy_perform()` reuse)
- **Endpoint shape / trigger:** Library-usage pattern, not a single URL: one `curl_easy` handle, two sequential `curl_easy_perform()` calls against different origins. First origin issues a Digest challenge (`WWW-Authenticate: Digest ...`); handle is then re-targeted at a second origin (attacker-controlled) for the same URI path. Endpoint template: perform #1 → `https://legit-api.example.com/hook` (Digest 401 → auth), then perform #2 → `https://attacker.tld/hook`.
- **Payload that fired (verbatim Authorization header sent to the attacker server):**
  ```
  auth=Digest username="alice", realm="legit-api@example.com", nonce="LEGIT-NONCE-7c3f0e1d", uri="/hook", cnonce="6sNdpZj9k+2dGcxj", nc=00000002, qop=auth, response="9c85cd807d6e52bfdc8f2a2c09420fea", opaque="LEGIT-OPAQUE", algorithm=MD5
  ```
- **Root-cause pattern:** `Curl_pretransfer` drops `initial_origin` when the handle is re-pointed, but fails to clear `data->state.digest` between `curl_easy_perform()` calls — so the first origin's Digest challenge state (nonce, realm, opaque, nc counter) survives and curl computes a fresh Digest response *for the wrong host*. Origin binding is lost at exactly one state field.
- **Impact proven:** The attacker server received a fully-formed Digest `Authorization` header computed for the legitimate server — nonce, cnonce, nc, response — reproduced for two users (`alice` and `bob`). Two concrete impacts: (1) same-URI replay within the nonce lifetime against the legitimate server, and (2) offline password cracking via the exposed `HA1=` material (the response hash leaks a verifiable function of the password).
- **Exemplars:** id=3793260.

## Bypass / chain notes
- The dominant "bypass" here is **fix-incompleteness**: CVE-2024-11053's fix left the `default`/omitted-credential `.netrc` path open, yielding CVE-2025-0167 (id=2917232). When a credential-leak fix lands, enumerate the decision matrix — entry for target host, entry for source host, `default` entry, entry present but credential-less — and retest each branch.
- Sub-pattern 3 required no filter bypass at all: the origin check existed (in `Curl_pretransfer`) but only covered `initial_origin`, not `data->state.digest`. Audit which state fields a fix actually clears, not just which flag it flips.
- No multi-step chains (redirect chains, SSRF pivots) were present in the records; every confirmed impact was a single redirect or a single handle reuse.

## Gotchas / what NOT to do
- Do not stop at the first `.netrc` shape. The confirmed second CVE came specifically from the `default` entry variant — a bare `default` line after a machine entry behaves differently from a per-host credential entry.
- For handle-reuse bugs, the reproduction must show the *full* second Authorization header (nonce/cnonce/nc/response) landing on your listener — a claim that "state leaked" without the verbatim header was not the accepted form; id=3793260's strength is the complete captured header.
- These are client-side bugs: your impact statement must assume an attacker who controls a redirect target or a second origin, not a network MITM. The one network-exposure claim in the records (password "passed through the network" in id=2912277) was tied to the transfer itself, not an eavesdropper scenario.
- Don't retest only on the latest release: Sub-pattern 1 affected curl 6.5–8.11.0, so version scoping is part of the report.

## Real-world impact examples
- id=2912277: `.netrc` + redirect on curl 6.5–8.11.0 leaked the source host's password to the redirect target host `b.tld`.
- id=2917232: post-fix reproduction — with the verbatim `.netrc` above, `alice`/`alicespassword` were sent to `b.com` after redirect from `a.com`; assigned CVE-2025-0167.
- id=3793260: attacker-controlled second origin captured a complete MD5 Digest `Authorization` header (realm `legit-api@example.com`, nonce `LEGIT-NONCE-7c3f0e1d`, response `9c85cd807d6e52bfdc8f2a2c09420fea`) computed for the legitimate API — enabling same-URI replay within the nonce lifetime and offline cracking of the HA1 secret, confirmed for both `alice` and `bob`.