---
name: hunter-l3-reflected-html-injection
description: "Use when hunting Reflected HTML Injection on a target. Loads the L3 technique sheet: Reflected HTML injection is the failure to output-encode attacker-controlled input when it is copied from a request (URL path, query parameter) into the response body or DOM."
domain: cybersecurity
subdomain: web
tags:
- web
- reflected-html-injection
- hunting
- l3
version: '1.0'
---

# Reflected HTML Injection — Technique Sheet

## Overview

Reflected HTML injection is the failure to output-encode attacker-controlled input when it is copied from a request (URL path, query parameter) into the response body or DOM. Unlike classic XSS it requires no filter evasion beyond tag injection — the payoff is arbitrary HTML rendered on a trusted-origin page: content spoofing, defacement, and (highest value) phishing UI on authentication pages. It pays best when the reflected surface is a search page on a government/military host, a federated SSO login page (ADFS), or any parameter consumed by client-side JS via `innerHTML`.

## Distinct sub-patterns

### 1. Double-URL-encoded tag injection into a search-path template (WordPress)

- **Endpoint shape:** `GET /search/{term}` — the search term lives in the URL *path*, not a query param. WordPress permalink-style search on the target host.
- **Payload (verbatim):**
  ```
  https://www.██████.mil/search/%2522%253E%253C/form%253E%253Ch1%253EHTML%2520INJECTION%2520IS%2520POSSIBLE%2520!!!%253C/h1%253E%253C/body%253E%253C/form%253E%253C!--
  ```
  Decoded once: `%22%3E%3C/form%3E%3Ch1%3EHTML%20INJECTION%20IS%20POSSIBLE%20!!!%3C/h1%3E%3C/body%3E%3C/form%3E%3C!--`
- **Root cause:** The WordPress search page echoes the attacker-supplied term without output encoding. Note the payload shape: it *breaks out of an enclosing attribute/tag context* (`">` prefix), closes the surrounding `<form>` and `<body>`, injects an `<h1>`, then opens an HTML comment `<!--` to swallow the trailing page markup so nothing looks broken. Double encoding (`%2522` = `%22` after one decode pass) is used so the payload survives an intermediate decode layer before reaching the page.
- **Impact proven:** Injected `<h1>` plus closing `</form>`/`</body>` tags rendered on a .mil search page — arbitrary HTML injection / content spoofing and defacement on a government host.
- **Exemplar:** id=2554003 (U.S. Dept Of Defense, ajaysenr).

### 2. Direct HTML anchor injection via FAQ-search query parameter

- **Endpoint shape:** `GET /contact` (FAQ search), parameter `q` — search box on a consumer brand's FAQ widget.
- **Payload (verbatim):**
  ```html
  <a href="https://evil.com">click</a>
  ```
- **Root cause:** The FAQ search parameter is reflected into the page ("no results for X" style output) without sanitization. No encoding context break needed — the parameter lands in raw HTML context.
- **Impact proven:** Attacker-controlled anchor pointing at `https://evil.com` rendered in the response, demonstrating arbitrary HTML injection with clickable link-farming / phishing potential in other users' browsers.
- **Exemplar:** id=2578985 (Mars, ajaysenr).

### 3. Script-tag probe via adjacent search parameter on the same surface

- **Endpoint shape:** `GET /contact` (FAQ search), parameter `search` — same FAQ surface as sub-pattern 2 but a *different parameter name* (`search` vs `q`). Probe both.
- **Payload (verbatim):**
  ```html
  <script>alert(1)</script>
  ```
- **Root cause:** Same reflection flaw — the contact/FAQ search value is echoed unsanitized. The plain `<script>` payload confirms the reflection accepts arbitrary tags including script (execution is the escalation step, not the reflection itself).
- **Impact proven:** Confirmed reflected HTML injection; payload reflected unsanitized, enabling arbitrary HTML and potentially script execution in other users' browsers.
- **Exemplar:** id=2587101 (Mars, ajaysenr).

### 4. innerHTML-based DOM injection of auth-page messaging parameters (ADFS)

- **Endpoint shape:** `GET /adfs/ls` — the ADFS federated sign-in endpoint; parameters `infotext` and `signintext`, consumed by a JS theme script (the ADFS "customization" layer) that does:
  `element.innerHTML = getQueryStringValue('infotext')` (equivalent pattern).
- **Payload (verbatim, URL-decoded):**
  ```html
  <h2 id=phish93470>Security notice</h2><p>Continue to verify.</p><a id=link93470 href=https://example.com/>Continue</a>
  ```
  Sent as:
  `infotext=%3Ch2%20id%3Dphish93470%3ESecurity%20notice%3C%2Fh2%3E%3Cp%3EContinue%20to%20verify.%3C%2Fp%3E%3Ca%20id%3Dlink93470%20href%3Dhttps%3A%2F%2Fexample.com%2F%3EContinue%3C%2Fa%3E`
- **Root cause:** A client-side theme script reads `infotext`/`signintext` straight from `location.search` and inserts them into the DOM via `innerHTML` with no sanitization. This is a *sink* problem (DOM injection), not a server-encoding problem — server-side output encoding of the reflected string does not save it, because the JS decodes and re-parses the value.
- **Impact proven:** A fake "Security notice" header plus a "Continue" link pointing to an attacker-controlled domain rendered on the live ADFS login page. This is UI redress on the credential-entry surface — the highest-impact variant in this class: a fully believable pre-login phishing interstitial on the organization's real SSO domain.
- **Exemplar:** id=3781785 (Essity, ajaysenr).

## Bypass / chain notes

- **Encoding layering:** id=2554003 used double URL-encoding (`%2522` → `%22` → `"`), implying the application decodes the search term once before rendering. If a single-encoded payload reflects literally or gets blocked, try double encoding; also try single encoding if the server blocks the double-decoded form.
- **Context escape + page closure:** The working payload did not just append markup — it opened with `">` (escaping a preceding attribute), closed `</form>` and `</body>`, then appended `<!--` to comment out the rest of the legitimate page. This makes the injected content the *only* thing the user sees — closer to full defacement than a stray tag.
- **Parameter-name permutation:** The same Mars FAQ surface was reported twice (id=2578985 with `q`, id=2587101 with `search`). When one search param is sanitized or filtered, test the sibling parameter that feeds the same feature.
- **Server vs DOM sinks:** Two distinct reflection mechanisms appear in the records: server-side template reflection (WordPress, FAQ search) and client-side `innerHTML` sink (ADFS). For framework customization parameters (`infotext`, `signintext` on ADFS; theme/customization params generally), the injection survives even correct server-side encoding — check how the JS handles the value.
- **No cross-parameter or multi-step chains were present in the records** — all four findings fired from a single GET request with the payload in one parameter or the URL path.

## Gotchas / what NOT to do

- **HTML injection ≠ XSS by itself.** The DoD and Mars findings were accepted as HTML injection / content spoofing. Do not oversell; demonstrate the reflected HTML (rendered `<h1>` or anchor) and let impact follow. The Mars records claim "arbitrary HTML/script execution" as *potential*, with only the reflection proven.
- **Map every parameter of a search feature.** `q` and `search` both existed on the same FAQ endpoint. Testing only the obvious one misses reflections.
- **Don't ignore client-side sinks.** On ADFS and similar SSO pages, the vulnerable code is a theme script using `innerHTML` — reading the page's JS is what turned a boring "infotext" parameter into a phishing-proof impact (id=3781785).
- **Craft payloads that survive rendering.** A bare `<h1>` after page content may look unconvincing in a report. The accepted DoD payload broke out of context, closed the form/body, and commented out trailing markup — a visually complete injected page.
- **Keep the link target clearly attacker-controlled but harmless.** `https://evil.com` / `https://example.com/` were used; don't point injection payloads at third parties that didn't consent.
- **GET-only reflection is still reportable** on government and SSO surfaces even without a delivery vector, but note "payload not stated" gaps honestly — the Mars script-tag record (id=2587101) proves reflection, not execution.

## Real-world impact examples

- **U.S. Dept Of Defense (id=2554003):** Arbitrary HTML — an injected "HTML INJECTION IS POSSIBLE !!!" heading with surrounding form/body markup — rendered on `www.██████.mil`'s WordPress search page via a double-encoded URL-path payload.
- **Mars (id=2578985):** An attacker-controlled `<a href="https://evil.com">click</a>` reflected through the orbitgum.com FAQ search parameter, injectable into browsers of other users.
- **Mars (id=2587101):** `<script>alert(1)</script>` reflected unsanitized through the `search` parameter of the same FAQ surface — confirming the reflection accepts script tags, not just benign markup.
- **Essity (id=3781785):** A fake "Security notice / Continue to verify" interstitial with an attacker-domain link rendered on the live ADFS federated login page via the `infotext` parameter — a credential-phishing-grade UI redress on the organization's own SSO domain.