---
name: hunter-l3-clickjacking
description: "Use when hunting Clickjacking on a target. Loads the L3 technique sheet: Clickjacking (UI redressing) exploits the absence of frame-protection headers (X-Frame-Options, CSP frame-ancestors) to embed a target page in an attacker-controlled iframe — transparent, hidden, or o"
domain: cybersecurity
subdomain: web
tags:
- web
- clickjacking
- hunting
- l3
version: '1.0'
---

# Clickjacking — Technique Sheet

## Overview

Clickjacking (UI redressing) exploits the absence of frame-protection headers (X-Frame-Options, CSP frame-ancestors) to embed a target page in an attacker-controlled iframe — transparent, hidden, or overlaid — so a logged-in victim's clicks and keystrokes perform actions on the target site without their knowledge. It pays when the frameable page exposes a **state-changing authenticated action** (delete, deactivate, purchase, settings change) or a **credential-entry form** (login, SSO). The bare header gap alone is frequently duped/informative in mature programs (Yelp resolved one as informative; WordPress hardened without bounty), so impact demonstration is the difference between bounty and closure.

## Distinct sub-patterns

### 1. Framed authenticated settings/deletion page → forced account modification

- **Endpoint shape:** `GET /user/{username}/settings`, `GET /profile`, `GET /dashboard/account`, `GET /affiliate-network/campaign-settings/`
- **Payload that fired:** `<iframe height="3000" width="1300" scrolling="no" src="https://hackers.upchieve.org/profile"></iframe>` (UPchieve, id=1301113); also `<iframe src="https://gener8ads.com/dashboard/account" sandbox="allow-top-navigation allow-same-origin allow-scripts" width="500" height="500"></iframe>` (Gener8, id=783191)
- **Root cause:** No X-Frame-Options / frame-ancestors on authenticated pages; the victim's session cookie rides along in the iframe.
- **Impact proven:** Force privacy-setting changes in two clicks (Imgur, id=103178); deactivate the account (UPchieve); change email address (Gener8); modify account details (Automattic refer.wordpress.com, id=765355); unauthorized profile changes (UPchieve, id=1198907).
- **Exemplars:** 103178 (Imgur), 1301113 (UPchieve), 783191 (Gener8), 765355 (Automattic)

### 2. Framed one-click destructive action (delete X)

- **Endpoint shape:** `GET /user_photos/{num}/remove`, developer-app deletion page, `GET /clips` on a clip-sharing domain
- **Payload that fired:** `<iframe src="https://www.yelp.com/user_photos/bvPb9EsYxQoT_XCF363HJQ/remove" scrolling="no" style="width:1349px;height:765px;position:absolute;left:5px;top:-107px;border:0;" frameborder="0" id="childFrame"></iframe>` (Yelp, id=201842 — note the negative `top` offset used to align the delete button under the decoy)
- **Root cause:** The confirmation/delete page is frameable; the delete button is positioned under an attacker-chosen decoy button.
- **Impact proven:** Victim removes their own profile photo (Yelp); victim deletes their own clips (crossclip.com, id=1294767: `<iframe src="https://crossclip.com/clips" frameborder="0 px" height="1200px" width="1920px"></iframe>`); victim deletes a TikTok Developer App (id=1416612, confirmed by program).
- **Exemplars:** 201848 (Yelp), 1294767 (Logitech/Crossclip), 1416612 (TikTok)

### 3. Framed commerce/checkout page → monetary loss

- **Endpoint shape:** `GET /checkout/deal/{id}` with params `biz_id, fsid, return_url`; `GET /reservations`
- **Payload:** payload not stated (Yelp id=391385); payload not stated (Yelp reservations id=355859)
- **Root cause:** Frameable checkout/reservation flow with a saved payment method or pre-filled contact details.
- **Impact proven:** Victim unknowingly purchases a **$450 deal** with their saved credit card (Yelp id=391385); victim makes an unintentional restaurant reservation, forwarding email/mobile to the business with potential cancellation fees and blocked genuine bookings (Yelp id=355859).
- **Exemplars:** 391385, 355859 (both Yelp — Yelp paid for concrete-loss clickjacking even while duping bare-framing ones)

### 4. Framed login / SSO / credential page → phishing & keystroke capture

- **Endpoint shape:** `GET /login` on app domains, `GET /` on SSO hosts, `GET /login.php` on portals
- **Payload that fired:** `<iframe id="frame" width="100%" height="100%" src="https://app.mavenlink.com/login"></iframe>` (Mavenlink, id=14494); `<iframe src="https://sso.semrush.com/"></iframe>` (id=299009); `<iframe src="https://join.nordvpn.com" width="500" height="500"></iframe>` (id=765955)
- **Root cause:** Auth pages framed like any other page; victims can be layered into typing credentials into a frame they believe is a different site, or tricked into login/forgot-password flows.
- **Impact proven:** Credential-stealing UI redress on Mavenlink login; SSO login page embeddable for credential reveal (Semrush — program-accepted as generic, "not concretely proven"); portal.nextcloud.com/login.php framed for credential/phishing trickery (id=347782). Multiple Sifchain reports (1176104, 1185949, 1188639, 1195209) established whole-site framing for "type credentials into an invisible frame" — note the same researcher filed per-property, and four separate reports were accepted across docs/root/cryptoeconomics hosts.
- **Exemplars:** 14494 (Mavenlink), 347782 (Nextcloud portal), 299009 (Semrush)

### 5. Framed OAuth authorize button → forced consent

- **Endpoint shape:** OAuth authorization page on the identity provider domain
- **Payload:** payload not stated
- **Root cause:** OAuth endpoints lacked the same security headers as the rest of the site — a classic gap because header sets are often applied to the app but not the OAuth routes.
- **Impact proven:** The "authorize" button on Coinbase's OAuth page was clickjackable — an attacker can trick users into authorizing an OAuth app without consent (id=65825).
- **Exemplar:** 65825 (Coinbase)

### 6. Framed social/community actions (follow, flag, bookmark, compliment)

- **Endpoint shape:** `GET /flag_content`, `GET /following_user/add`, `GET /thanx`, bookmark action
- **Payload:** payload not stated; demonstrated via hidden iframes + PoC video
- **Root cause:** Important action endpoints served without X-Frame-Options/frame protection; each click of a decoy page performs one hidden action.
- **Impact proven:** Victim tricked into report-a-profile, follow-a-user, and send-a-compliment (Yelp id=305128); victim bookmarked N restaurants in a repeatable loop (Yelp id=228295); forced follows on Periscope (id=198622).
- **Exemplars:** 305128, 228295 (Yelp), 198622 (X/Periscope)

### 7. Framed card/embed/widget endpoint that exfiltrates data on click

- **Endpoint shape:** `GET /i/cards/tfw/v1/{num}` (Twitter card URLs with query params like `cardname=promotion&autoplay_disabled=true&earned=true&lang=en&card_height=357`)
- **Payload that fired:** `<html>\n<iframe src=https://twitter.com/i/cards/tfw/v1/759046372544741376?cardname=promotion&autoplay_disabled=true&earned=true&lang=en&card_height=357>\n</html>` (id=154963)
- **Root cause:** The card page is frameable and, unlike a static marketing page, **performs a data-bearing action on click** — in this case submitting victim email and username to the attacker's domain.
- **Impact proven:** Victim's email and username sent to the attacker's domain from inside the framed card — actual data exfiltration, not just a state change.
- **Exemplar:** 154963 (X/Twitter)

### 8. Framed download / file-delivery page

- **Endpoint shape:** `GET /` on download hosts (download.nextcloud.com)
- **Payload that fired:** `<iframe src = "https://www.download.nextcloud.com" height = "700px" width = "700px"> </ iframe>` (id=662155)
- **Root cause:** Frameable download page; clicks meant for the decoy page trigger downloads or route users to attacker-chosen applications/domains.
- **Impact proven:** User tricked into downloading files unintentionally (id=658011); click hijacking routing users to another application/domain (id=662155).
- **Exemplars:** 658011, 662155 (Nextcloud)

### 9. Framed admin panel

- **Endpoint shape:** `GET /admin/users`
- **Payload:** payload not stated
- **Root cause:** Server did not return X-Frame-Options on the admin section — admin pages are commonly missed when headers are applied per-app rather than globally.
- **Impact proven:** The Rocket.Chat admin info/users page loaded inside an attacker iframe while the victim was logged in as admin (id=728004).
- **Exemplar:** 728004 (Rocket.Chat)

### 10. Whole-site framing (marketing/docs/low-auth pages) — bulk, lower-value

- **Endpoint shape:** site roots and docs: `/`, `/docs`, `/en/latest/`, `/share/embed`
- **Payload that fired (typical):** `<html>\n<head>\n<body>\n<p>Website is vulnerable to clickjacking!</p>\n<iframe src="https://demo.nextcloud.com" width="500" height="500"></iframe>\n</body>\n</html>` (id=222762); semi-transparent variant used by the same reporter: `iframe { width: 800px; height: 500px; position: absolute; top: 0; left: 0; filter: alpha(opacity=50); opacity: 0.5; }` + `<iframe src="https://fanfootage.com/">` (id=15574)
- **Root cause:** No frame-protection header anywhere; often on S3-hosted static sites (Legal Robot id=149572: "AWS S3-hosted site served pages without security headers").
- **Impact proven:** Acceptable when paired with a plausible redress — tricking users into submitting Name/Email/Company into the framed form (Legal Robot id=163753), adding arbitrary tasks (GlassWire id=27594, Localize id=7862). But many were downgraded: Yelp main domain "resolved as informative" (id=197115), Factlink "no concrete victim action demonstrated" (id=17664), jobs.wordpress.net "hardening fix without bounty" (id=223024), WebSummit header-missing-only (id=202797).
- **Exemplars:** 163753 (Legal Robot — the paid one, because it had a form), 197115 (Yelp — the informative one, because it didn't)

### 11. Deprecated header values that silently fail → framing in modern browsers

- **Endpoint shape:** any site that "has" X-Frame-Options but uses `ALLOW-FROM`
- **Payload that fired:** `<iframe name="cksl7" src="https://exchangemarketplace.com" style="border: 0pt none ; left: -6px; top: -3px; position: absolute; width: 1366px; height: 576px;" scrolling="no"></iframe>` (Shopify, id=658217); `<iframe src="https://vulnerable.site" frameborder="0"></iframe>` against canary-web.pscp.tv (id=591432)
- **Root cause:** `X-Frame-Options: ALLOW-FROM https://twitter.com/` is unsupported in Chrome (and several other browsers), so the header is a no-op there and the page frames freely. The site looks protected in a curl check from a whitelisted-UA perspective but isn't.
- **Impact proven:** Attacker framed exchangemarketplace.com and hijacked clicks on sensitive actions (Inbox, Logout, "Sell your business") for logged-in users (id=658217); attacker tricked a Periscope user into deactivating their account unknowingly (id=591432); forced follows on periscope.tv (id=198622).
- **Exemplars:** 658217 (Shopify), 591432, 198622 (X/Periscope)

### 12. Frameable page chained into multi-step account compromise

- **Endpoint shape:** DM-delivered link with URL truncation — `https://accounts.youtube.com/accounts/SetSID?...&continue=https%3A%2F%2Fwww.google.com%2Faccounts%2FLogout...`
- **Payload:** the URL itself (above, verbatim)
- **Root cause:** Very long DM links are truncated to 38 characters in display, so a malicious link appeared to be an authenticated YouTube video; the link drove users through a logout-then-login flow that captured Google credentials and authorized a malicious third-party Twitter app — a clickjacking-style redirect/redress sequence rather than a plain iframe.
- **Impact proven:** Thousands of Google account credentials harvested; malicious third-party Twitter apps installed on thousands of accounts, which virally re-sent the malicious DM to victims' reciprocal followers (RiskIQ confirmed ~1000 breached accounts).
- **Exemplar:** 643274 (X/Twitter) — the highest-impact record in this set; shows clickjacking-class bugs can become mass-compromise campaigns when chained with URL truncation and OAuth app authorization.

## Bypass / chain notes

- **ALLOW-FROM bypass (most reliable in this set):** when the site uses `X-Frame-Options: ALLOW-FROM <origin>`, test in Chrome/Firefox — the directive is unimplemented there and framing just works (records 658217, 591432, 198622).
- **Negative-offset overlay alignment:** the working Yelp PoC used `style="...position:absolute;left:5px;top:-107px;..."` to shift the framed page so the real delete button sat precisely under the decoy — position alignment is the actual exploit, not just embedding (id=201848).
- **Sandboxed iframe for top-level navigation:** Gener8's PoC used `<iframe ... sandbox="allow-top-navigation allow-same-origin allow-scripts">` to keep the framed page controllable (id=783191).
- **Opacity overlay standard:** the recurring PoC template is a full-viewport absolutely-positioned iframe with `opacity: 0.5; filter: alpha(opacity=50)` (records 15574, 163753) — enough transparency to aim clicks, enough visibility to debug.
- **Chains seen:** frame → decoy click → state change (WakaTime: "Host a page that iframes https://wakatime.com/share/embed → Overlay a fake click button over the transparent frame → Victim clicks and performs unintended action", ids 244697/244967); frame → overlay → "User actions performed on target site" → account takeover/credential phishing (Top Echelon id=2964441); truncated DM link → Google logout/login capture → malicious OAuth app install → viral DM re-send (id=643274); Twitter card framing → PII exfil to attacker domain (id=154963); clickjacking combined with CSRF risk (LeaseWeb id=119828).
- **IE-only frameability:** Zomato pages framed via `<frameset><frame src="https://www.zomato.com/users/fan-feng-52680914"/>` targeting IE, hitting authenticated pages (settings, invite, bookmarks, managewallets) for data change / account deletion (id=337219). Niche browser coverage still paid.

## Gotchas / what NOT to do

- **Bare framing on a marketing/docs/root page is routinely duped or informative.** In this set: Yelp main domain (informative, 197115), Factlink (no concrete action, 17664), jobs.wordpress.net (unbountied hardening, 223024), WebSummit (202797), Khan Academy shop (header-check only, 6370), Inflection goodhire.com/api (confirmed header missing, nothing more, 298028), staging.seatme.us (49888). Find the *action*, not just the header.
- **One URL per report was accepted repeatedly** (Sifchain: 4 separate reports for docs/root/cryptoeconomics; Nextcloud: 12+ URLs reported) — but batch per-property coverage varies by program; check the program's aggregation rules before mass-filing.
- **Don't rely on the header being absent to prove exploitability in your writeup** — state the victim action and demonstrate it (WakaTime and Yelp PoC-video records show the accepted format).
- **Same reporter (ajaysenr) produced essentially all 60 records** — these are one researcher's systematic sweep; dedupe against program history before assuming any specific target is still unfixed.
- **"Login page frameable = credentials stolen" without demonstration drew explicit hedging** (Semrush 299009: "not concretely proven") — always demonstrate or clearly bound your claim.
- Sandbox attributes, offsets, and scroll behavior matter: `scrolling="no"` and fixed pixel sizes (1366x576, 1349x765, 1920x1200) appear in the working PoCs to eliminate scrollbar artifacts that give away the overlay.

## Real-world impact examples

- **Mass credential harvesting:** Truncated DM link led to ~1000 confirmed breached accounts, thousands of harvested Google credentials, and viral self-propagation via malicious installed Twitter apps (X/Twitter, id=643274).
- **Direct financial loss:** $450 deal purchased with the victim's saved credit card via framed Yelp checkout (id=391385); unintentional reservations with cancellation-fee exposure (id=355859).
- **Account destruction/loss of access:** forced deactivation of Periscope accounts (id=591432), TikTok Developer App deletion (id=1416612), account email change via framed dashboard (Gener8, id=783191).
- **PII exfiltration:** victim email + username delivered to attacker's domain from a framed Twitter card (id=154963).
- **Silent privilege-surface exposure:** Rocket.Chat admin/users page framed while victim was admin (id=728004); forced OAuth app authorization on Coinbase (id=65825).