---
name: hunter-l3-universal-xss
description: "Use when hunting Universal XSS on a target. Loads the L3 technique sheet: Universal XSS is XSS that executes not merely on one vulnerable origin, but in the context of *any* site the user visits — typically via a browser extension, security product UI injected into every pa"
domain: cybersecurity
subdomain: web
tags:
- web
- universal-xss
- hunting
- l3
version: '1.0'
---

# Universal XSS — Technique Sheet

## Overview
Universal XSS is XSS that executes not merely on one vulnerable origin, but in the context of *any* site the user visits — typically via a browser extension, security product UI injected into every page, or a WebView in a mobile app that is bound to a privileged cookie domain. It pays heavily because the security boundary broken is the browser's own origin model: a single bug yields script execution on google.com, your broker, and your bank alike. In these records it appears in two families: desktop browser extension/security-frame injection (postMessage + `javascript:` URL), and Android exported-activity → `loadDataWithBaseURL()` WebView injection.

## Distinct sub-patterns

### Sub-pattern 1: Browser extension script execution across origins
- Endpoint shape: Proctorio browser extension (no HTTP endpoint; extension surface).
- Parameter: none — the extension itself accepted script execution across origins.
- Payload: not stated in the record.
- Root cause: the extension's architecture allowed script execution across origins — i.e., extension-injected content or messaging did not constrain execution to the extension's own origin, so any page context could reach extension privileges.
- Impact: universal cross-site scripting within the Proctorio extension; confirmed and patched.
- Exemplars: HackerOne 1326264 (Proctorio).

### Sub-pattern 2: Exported Activity → WebView `loadDataWithBaseURL()` HTML injection
- Endpoint shape (Android component, not HTTP): `com.exness.investments: SMFeedbackActivity` (exported). Variant seen on SurveyMonkey's `com.surveymonkey...SMFeedbackActivity` — the same third-party feedback component shipped in multiple apps.
- Parameter: Intent extras `smSPageHTML` and `smSPageURL` (or `smSPageHTML,smSPageURL`).
- Payload (verbatim, EXNESS 1455987):
  `smSPageHTML="<h1>Exploited</h1><script>document.write(document.cookie)</script>"` with `smSPageURL="https://my.exness.asia/r/"`
- Payload (verbatim shape, EXNESS 532836): `<html><h1>Universal XSS</h1><script>var form = document.createElement("form");... form.submit();</script></html>` — attacker HTML builds and submits a form from inside the WebView.
- Root cause: an exported activity passes attacker-controlled Intent extras straight into `WebView.loadDataWithBaseURL(smSPageHTML, smSPageURL)` with JavaScript enabled and no validation. Because the base URL is the app's cookie-bearing domain (e.g. `https://my.exness.asia/r/`), the injected script runs in that origin.
- Impact (1455987): attacker HTML in the WebView exposed cookies for `my.exness.asia` and other sites the app loads → account takeover.
- Impact (532836): arbitrary JS in the internal WebView exfiltrated cookies including payment-system and mql5 cookies.
- Exemplars: HackerOne 1455987, 532836 (both EXNESS).

### Sub-pattern 3: Same-component cross-app hunt
- Endpoint shape: the identical `SMFeedbackActivity` exported component appears in *different* vendors' apps (SurveyMonkey SDK embedded in Exness; reported again in the SurveyMonkey context). One writeup of the pattern in one app is a direct template for finding the same vulnerable SDK in every app that embeds it.
- Payload: same extras as above.
- Root cause: vulnerability lives in the embedded SDK, not the app vendor — so every app shipping the SDK inherits the bug.
- Impact: same cookie exfiltration per app.
- Exemplars: 1455987 and 532836 demonstrate the same component reported across program contexts.

### Sub-pattern 4: postMessage origin-validation failure in a first-party injected frame → `javascript:` URL
- Endpoint shape: `GET /{inject_id}/ua/url_advisor_balloon.html` — a frame the Kaspersky extension injects as first-party content on *every* domain the user visits (parameter `{inject_id}` is the per-page injected frame identifier).
- Parameter: data arriving via `window.postMessage()` into the balloon frame (no parameter in the URL itself).
- Payload (verbatim): `javascript:alert(1)`
- Root cause: the frame does not validate `event.origin` on incoming postMessage; the message data is assigned as a link target, so a malicious page can set the link to a `javascript:` URL. The user is then clickjacked into clicking the attacker-controlled link, executing the payload in the *host page's* origin.
- Impact: arbitrary JS executed in the context of `www.google.com` (and any domain) in Microsoft Edge, via user click on the tricked link.
- Exemplars: HackerOne 463915 (Kaspersky).

## Bypass / chain notes
- Intent-launch chain (mobile): malicious app → `startActivity` on exported `SMFeedbackActivity` with crafted extras → WebView loads attacker HTML with `smSPageURL` set to the cookie domain → `document.cookie` read or a form auto-submitted → cookies exfiltrated. Both EXNESS reports follow this chain. 532836 additionally notes reading the cookie file via a symlink parsed as HTML as part of the exfiltration path.
- Clickjacking chain (desktop): first-party frame present on all domains → postMessage with no origin check → link target set to `javascript:` payload → user must be tricked into clicking the balloon link. Note the two preconditions that make this "universal": the frame is injected on every page, and the JS executes in the page's origin rather than the extension's.
- WebView base-URL control is the crux on mobile: the exploit only reaches "universal" value because `smSPageURL` lets the attacker pick the origin whose cookies the WebView exposes. Locking the base URL to a benign local page would downgrade the bug to mere HTML injection.
- Cookie-file symlink read (532836 chain): exfiltration did not stop at in-page `document.cookie` — the record shows a symlink-to-cookie-file step read as HTML, i.e. cookie material retrieved beyond the WebView JS API surface.

## Gotchas / what NOT to do
- Android WebView XSS is only report-grade if you can show the cookies you actually obtain (here: `my.exness.asia` session, payment-system, mql5). An `alert(document.cookie)` demo with benign cookies is weaker — enumerate the sensitive cookie set.
- The `javascript:`-URL frame bug required a user click (clickjacking). Do not overstate it as fully silent; the report's impact claim rests on the clickjack step, and it was Edge-specific (test per-browser — extension behavior differs across Chromium/Firefox/WebKit).
- For exported activities, first verify the component is actually `exported=true` in the manifest and reachable by a third-party app with no permissions — that reachability is the whole bug.
- `loadDataWithBaseURL` with a neutral base URL (e.g. `about:blank` or a local file) is usually a non-issue; the severity comes from an attacker-controlled or cookie-domain base URL. Confirm which one the code uses before reporting.
- Extension-based universal XSS (Proctorio) had no public payload in the record — don't guess the mechanism when writing your own PoC; derive it from the extension's messaging/content-script code.
- For postMessage handlers, check `event.source` as well as `event.origin`; these records show origin validation is the commonly missed control, but sloppy source checks broaden the attack equally.

## Real-world impact examples
- Account takeover at EXNESS: cookies for `my.exness.asia` exposed from the app's own WebView via two lines of attacker HTML (`<script>document.write(document.cookie)</script>`) launched from a hostile app (1455987).
- Payment credential exposure at EXNESS/SurveyMonkey: injected form-submitting HTML exfiltrated cookies including payment-system and mql5 cookies (532836).
- Script execution on www.google.com: Kaspersky URL Advisor balloon, exploited with the four-character payload `javascript:alert(1)` plus a clickjack, running in any domain the user visits in Edge (463915).
- Extension-wide XSS at Proctorio: universal XSS inside a proctoring extension that runs on every exam page — confirmed and patched (1326264).