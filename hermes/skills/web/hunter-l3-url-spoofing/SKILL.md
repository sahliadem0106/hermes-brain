---
name: hunter-l3-url-spoofing
description: "Use when hunting URL Spoofing on a target. Loads the L3 technique sheet: URL spoofing is the class of bugs where a UI element (address bar, redirect/interstitial page, popup, shield panel) displays an origin or domain that does not match the actual destination or content the user is interacting with."
domain: cybersecurity
subdomain: web
tags:
- web
- url-spoofing
- hunting
- l3
version: '1.0'
---

# URL Spoofing — Technique Sheet

## Overview
URL spoofing is the class of bugs where a UI element (address bar, redirect/interstitial page, popup, shield panel) displays an origin or domain that does not match the actual destination or content the user is interacting with. It pays when you can show a trusted domain (google.com, hackerone.com, brave.com) while the user is actually on attacker-controlled content, or when a privileged/trusted origin's settings are inherited by an attacker-controlled domain. Browser programs (Brave) and any site with link-redirection interstitials or rich-text link rendering are the primary targets.

## Distinct sub-patterns

### 1. Domain-highlight confusion via userinfo (`@`) on redirect/link-warning pages
- **Endpoint shape / param:** A markdown renderer or external-link redirect page that parses the destination URL and highlights the "real domain". Param: the markdown link URL / website field. Template: `[visible text](https://user@evil.com)` — the parser highlights the component after `@`.
- **Payload that actually fired (verbatim):**
  ```
  [*<http://myfuneral.ru/>*_<www.hackerone@yandex.ru>_](https://hackerone.com/pisarenko)
  ```
- **Root cause:** The domain-highlighting logic only highlighted domain-like components after `@`, so `www.hackerone@yandex.ru` rendered with the fake "hackerone" part emphasized while the real destination (yandex.ru / the redirect target) was misrepresented.
- **Impact proven:** HackerOne's own redirect page highlighted a fake domain (`www.hackerone.com@yandex.ru` style), misleading users about where a link leads. Fixed.
- **Exemplar:** HackerOne report id=113070.

### 2. Missing subdomain elision in browser UI (Shields popup / URL display surfaces)
- **Endpoint shape / param:** Browser chrome UI — Brave Android Shields popup. Param: n/a; the "endpoint" is the URL shown when toggling Shields. Template: `https://<very-long-subdomain-chain>.trusted-brand.com` where the long front part pushes the real registrable domain out of view or display logic.
- **Payload:** not stated (record gives no concrete hostname; the trigger is any sufficiently long subdomain string in the Shields popup).
- **Root cause:** Brave Android Shields UI does not elide long subdomains from the front of the URL, leaving the registrable domain invisible/truncated and enabling URL confusion.
- **Impact proven:** URL confusion/spoofing when toggling Shields; assigned **CVE-2024-37406**.
- **Exemplar:** Brave Software report id=2501378.

### 3. Renderer/parser URL-parsing differential → shield/whitelist inheritance
- **Endpoint shape / param:** Any URL containing an encoded backtick or non-standard character in the host, parsed differently by two URL parsers. Template: `http://trusted.com%60x.attacker-domain.org/` (`%60` = backtick).
- **Payload that actually fired (verbatim):** `http://brave.com%60x.code-fu.org/`
- **Root cause:** Inconsistent URL parsing between the renderer (WHATWG URL) and Node's `url.parse`. The two components disagree on what the hostname is, so the attacker-controlled host (`code-fu.org`) inherits the hostname-shield/whitelist settings of `brave.com`.
- **Impact proven:** Demonstrated on video that the shield setting for `brave.com` also applied to `code-fu.org` — a malicious domain inheriting whitelisted privileges (e.g. Flash) granted to a trusted domain.
- **Exemplar:** Brave Software report id=255991.

### 4. `document.write` over a legitimately opened window (address bar stays on real URL)
- **Endpoint shape / param:** JS on an attacker page: `window.open('https://trusted-domain/any-path')` then `setTimeout(...)` calling `x.document.write(...)`. Param: none; the target URL is the display victim.
- **Payload that actually fired (verbatim):**
  ```js
  window.onclick = function () {
      x = window.open('https://www.google.com/csi');
      setTimeout(function () {
          x.document.write(`I am not a www.google.com;<button onclick="alert('I can run JS on this page!')">click me</button>`)
      }, 100);
  }
  ```
- **Root cause:** After `window.open` to a URL, `document.write` replaces the real content while the address bar continues displaying the opened URL — the shown origin is `about:blank` content wearing a trusted URL.
- **Impact proven:** Address bar displayed `https://www.google.com/csi` while the actual page was `about:blank` with attacker-injected content; `alert()` executed while the address bar kept showing www.google.com.
- **Exemplar:** Brave Software report id=369086.

### 5. Address bar not cleared after navigation to an invalid protocol-handler URL
- **Endpoint shape / param:** JS `window.open` to a scheme that fails navigation but leaves the address bar populated. Template: `window.open('http.://google.com')` — note the malformed scheme `http.`.
- **Payload that actually fired (verbatim):**
  ```html
  <body>
      <script>
          window.onclick = () => {
              x = window.open('http.://google.com')
              setTimeout(() => {
                  x.document.write(`Hello Google.com! <button onclick="alert('I can run JS on this page!')">Click me!</button>`)
              }, 1000)
          }
      </sc
  ```
  (record truncated; full script continues symmetrically to id=369086's shape)
- **Root cause:** Brave does not clear the address bar after navigation to a protocol-handler URL, so a parent window can write arbitrary content into a window that *appears* to be on the target domain.
- **Impact proven:** URL spoofing demonstrated — attacker window opened `'http.://google.com'`, injected JS presenting a fake Google page with the spoofed address-bar URL; screencast supplied.
- **Exemplar:** Brave Software report id=373721.

## Bypass / chain notes
- No multi-step chains were recorded in these records — all five are standalone spoofing bugs. But two force-multipliers appear:
  - **Parsing differentials (sub-pattern 3):** hunt any encoded character in the host (`%60` backtick shown; the class generalizes to characters one parser treats as host-delimiter and the other as literal) that makes two components disagree. The win is not just display confusion but *privilege/setting inheritance* from a whitelisted domain.
  - **Timing via `setTimeout`:** both window-write payloads used a 100–1000 ms delay after `window.open`, letting navigation state settle before `document.write` overwrote the window while the address bar was already committed to the trusted URL.
- The `@` userinfo trick (sub-pattern 1) also generalizes to any UI that picks a "display domain" by string heuristics rather than proper URL parsing — test userinfo, port, and encoded-at (`%40`) variants against domain-highlighting and interstitial pages.

## Gotchas / what NOT to do
- **Payload not stated ≠ payload not needed:** for UI-elision bugs (sub-pattern 2), you must supply a concrete long-subdomain hostname and screenshots showing the truncated/overflowing display. The Brave Android report succeeded with a demonstrable UI state plus CVE assignment.
- **Provide video/screencast:** three of the five accepted reports (255991, 373721, and the id=369086 impact narrative) relied on recorded demonstrations. Static description of address-bar spoofing is weak evidence.
- **Test the right surface:** these are browser-chrome and redirect-page bugs, not server-side issues — payloads live in URLs, `window.open` targets, and markdown link fields, not HTTP request bodies.
- **Do not assume origin confusion = XSS:** in records 369086/373721, the injected `alert()` ran on attacker content over a spoofed address bar — the reported impact was URL spoofing, not script execution on google.com. Report the impact that is actually proven.
- **Invalid-scheme timing matters:** `http.://google.com` must be openable enough for the window object to exist but fail enough to leave the stale address bar; the 1-second delay in the payload was load-bearing.

## Real-world impact examples
- **Fake-domain highlighting on HackerOne's own redirect page (id=113070):** a crafted markdown link made the platform's link-warning page emphasize `www.hackerone.com@yandex.ru`-style fake domains — fixed by the program.
- **CVE-2024-37406 (id=2501378):** Brave Android Shields popup failed to elide long subdomains, enabling URL confusion when users toggled Shields — CVE-level impact from a pure UI display bug.
- **Privilege inheritance (id=255991):** `http://brave.com%60x.code-fu.org/` caused a fully attacker-controlled domain to inherit brave.com's shield whitelist (Flash allowed), demonstrated on video.
- **Trusted origin over attacker content (id=369086):** address bar showed `https://www.google.com/csi` while `alert('I can run JS on this page!')` executed on attacker-written `about:blank` content.
- **Fake Google page (id=373721):** `window.open('http.://google.com')` + `document.write` rendered a convincing fake Google page under a google.com address bar, with screencast evidence.