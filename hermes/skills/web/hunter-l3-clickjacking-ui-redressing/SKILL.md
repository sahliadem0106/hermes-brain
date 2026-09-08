---
name: hunter-l3-clickjacking-ui-redressing
description: "Use when hunting Clickjacking (UI Redressing) on a target. Loads the L3 technique sheet: Clickjacking is the embedding of a target site's pages inside an attacker-controlled iframe/frameset, overlaying attacker UI so the victim's clicks and keystrokes are directed at the target page."
domain: cybersecurity
subdomain: web
tags:
- web
- clickjacking-ui-redressing
- hunting
- l3
version: '1.0'
---

# Clickjacking (UI Redressing) — Technique Sheet

## Overview
Clickjacking is the embedding of a target site's pages inside an attacker-controlled iframe/frameset, overlaying attacker UI so the victim's clicks and keystrokes are directed at the target page. It pays when a *state-changing or sensitive* page is frameable — settings pages, user-management panels, and especially SSO/login pages. The bug is almost always trivially reproducible (no X-Frame-Options / no CSP frame-ancestors), so your report lives or dies on demonstrating credible proven impact, not on finding the missing header.

## Distinct sub-patterns

### 1. Frameable authenticated settings / user-management page
- **Endpoint shape:** `GET https://app.<target>.com/teams/{team_id}/settings/user/{user_id}/users` — any authenticated app subdomain page that renders sensitive controls.
- **Payload (verbatim, from lemlist):**
  ```html
  <iframe src="https://app.lemlist.com/teams/tea_sgYr5dZr478x4FQ9K/settings/user/usr_Z3GZ4DDHLLyLyZHj5/users" height="550px" width="700px"></iframe>
  ```
- **Root cause:** `app.lemlist.com` sets neither `X-Frame-Options` nor `Content-Security-Policy: frame-ancestors`, so any origin can embed it.
- **Impact proven:** target pages render inside attacker iframes, enabling clickjacking and keystroke hijacking of user input on the settings/user-management UI.
- **Exemplar:** 1574017 (lemlist).

### 2. Same-origin framing via HTML-editor filter bypass (frameset/frame instead of iframe)
- **Endpoint shape:** the target's own HTML editor (Khan Academy) where a user can author raw HTML that the site later renders. This is framing *of same-origin pages* from inside the site itself.
- **Payload:** payload not stated in record 285609 — the technique is injecting `<frameset>`/`<frame>` tags instead of the commonly blocked `<iframe>`/`<object>`/`<embed>` tags.
- **Root cause:** the editor's sanitizer blacklists `iframe`/`object`/`embed` but misses `frameset`/`frame`. Because the injected page is served from the same origin, it satisfies the site's `X-Frame-Options: SAMEORIGIN` check — the browser allows the frame since the framing document is also from the target's origin.
- **Impact proven:** the user settings page loaded inside a frameset/frame construct despite `X-Frame-Options: SAMEORIGIN`, enabling clickjacking against that page.
- **Exemplar:** 285609 (Khan Academy).

### 3. Frameable public marketing/product pages
- **Endpoint shape:** `GET /` on `www.semrush.com` — i.e., any broad set of public pages on the main domain.
- **Payload:** payload not stated in record 289246 — standard attacker page with `<iframe src="https://www.semrush.com/...">` and an overlay.
- **Root cause:** pages do not set `X-Frame-Options: DENY/SAMEORIGIN` (and no frame-ancestors CSP), so they are frameable from any origin.
- **Impact proven:** multiple pages could be framed in an attacker page, enabling clickjacking/UI redressing across the site.
- **Exemplar:** 289246 (Semrush).

### 4. Frameable SSO / login page (highest-sensitivity variant)
- **Endpoint shape:** `https://geo.semrush.com/` — the Single Sign-On login page.
- **Payload:** payload not stated in record 318295 — attacker page embedding the SSO login page in an iframe.
- **Root cause:** the SSO login page lacks anti-framing protection, so it can be embedded in an attacker-controlled iframe.
- **Impact proven:** the SSO login page rendered inside an attacker iframe, enabling credential-exposure / account-control clickjacking (e.g., luring a logged-in victim into actions on the login/SSO flow, or harvesting interaction with credential fields).
- **Exemplar:** 318295 (Semrush).

## Bypass / chain notes
- **`X-Frame-Options: SAMEORIGIN` is not a panacea when the attacker gets same-origin context.** The Khan Academy case (285609) shows the key bypass: if you can inject HTML that renders on the target's own origin, a `frame` tag inside it legally satisfies SAMEORIGIN and can frame other same-origin pages (like user settings). When a sanitizer blocks the obvious tags, check the full HTML tag inventory — `frameset`/`frame` are the classic survivors.
- **Prove impact through the sensitive page, not the header.** All four records gained acceptance by anchoring on a sensitive target: a user-management/settings page (1574017), user settings (285609), site-wide pages (289246), and the SSO login flow (318295). Framing a generic landing page with no demonstrated click-path is the weakest variant of this class (289246-style) — prefer 1574017/318295-style targets.
- No multi-step chains were recorded in this dataset; every finding was a standalone framing issue.

## Gotchas / what NOT to do
- Don't report "no X-Frame-Options" on pages with no sensitive action — the lowest-value record in this set (289246) is exactly that, and many programs will close it as informational. Always name the concrete page and the click you would hijack.
- Don't stop at the `iframe` tag being blocked. Khan Academy's editor blocked `iframe`/`object`/`embed` and the finding was still valid via `frameset`/`frame` — incomplete tag filtering is itself the root cause worth reporting.
- Don't forget BOTH headers matter: the lemlist root cause is the absence of *either* `X-Frame-Options` *or* `CSP frame-ancestors`. If one is present, test whether the other is missing/misconfigured on the specific page you care about.
- Don't leave the payload unstated in your own reports. Three of these four records lack verbatim payloads; in your submission include the actual attacker-page HTML with realistic dimensions and overlay technique (the lemlist report's explicit `height`/`width` iframe is the exemplar).
- Don't test only the main domain. The Semrush SSO finding (318295) is on a separate subdomain (`geo.semrush.com`) — login/SSO hosts frequently escape the site-wide header policy applied on `www`.

## Real-world impact examples
- **lemlist (1574017):** `app.lemlist.com` team/user settings page embeddable in an attacker iframe — enables clickjacking and keystroke hijacking of user input on the account's user-management UI.
- **Khan Academy (285609):** despite `X-Frame-Options: SAMEORIGIN`, the user settings page was loaded inside a frameset/frame injected through the HTML editor's incomplete tag filter — same-origin clickjacking of a sensitive page.
- **Semrush (289246):** multiple `www.semrush.com` pages frameable from attacker pages — broad UI-redressing surface across the domain.
- **Semrush (318295):** the `geo.semrush.com` SSO login page rendered inside an attacker iframe — clickjacking with credential-exposure and account-control implications.