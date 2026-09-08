---
name: hunter-l3-authentication-bypass
description: "Use when hunting Authentication Bypass on a target. Loads the L3 technique sheet: This class covers any mechanism that gets an attacker past a login/authorization gate without valid credentials, or lets them impersonate another principal."
domain: cybersecurity
subdomain: web
tags:
- web
- authentication-bypass
- hunting
- l3
version: '1.0'
---

# Authentication Bypass — Technique Sheet

## Overview

This class covers any mechanism that gets an attacker past a login/authorization gate without valid credentials, or lets them impersonate another principal. In the record set it spans: client-trusted auth state (cookies, localStorage, response status fields), unsigned or skipped cryptographic verification (JWT, SAML, cookies), parameter-injection attacks (HPP, Mongo operators, mass-assignment), broken session/token reuse, exploitable secondary endpoints (alternate login URLs, session-issuing scripts), and flows that skip verification steps (email, phone, OTP, 2FA rate limiting). It pays at every severity tier — from P1 account takeover (Uber, Rocket.Chat, Automattic) to info disclosure — and is heavily represented in DoD, Uber, and h1-CTF programs. The unifying root causes are: **auth decided on the client, signatures not verified, and validation performed on input that differs from what is later used**.

## Distinct sub-patterns

### 1. Unsigned base64 JSON cookie tampering (admin flag flip)
- Endpoint/param: `POST /secure-login` / `GET /secure-login`, param `cookie` (h1-CTF/Shopify/Reddit synthetic challenges).
- Payload (verbatim): `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=` → decode → `{"cookie":"1b5e...","admin":false}` → set `"admin":true` → re-encode. Also seen as `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true}`.
- Root cause: auth state stored client-side in base64-encoded JSON with no signature/HMAC, and the server trusts it for admin decisions.
- Impact: downloaded admin-only password-protected zip, cracked it (password `hahahaha`), got flag{2e6f9bf8-...}.
- Exemplars: 1067443, 1069039, 1069189, 1065885.

**How to apply:** on any app, decode every base64-looking cookie. If it parses to JSON/structured data with role/admin/uid fields and there is no HMAC suffix, flip the privilege field and replay.

### 2. Client-trusted response status / response manipulation
- Endpoint/params: `POST /api/Account/Login` (UPS VDP 1490470 — login response `status` field); Sony admin login (1508660, param name redacted); Harbor sign-in → `GET /api/v2.0/users/current` (1690548, 401→200); OTP verification endpoint (130460, intercept server response and change value to "valid"); Uber partner iOS app `POST /login` with `{"allowNotActivated":true}` plus proxying `isActivated:false` → `true` (126260); DoD registration flow skipping event code / email verification via altered response (2061982).
- Payloads: verbatim — `{"UserName":"██████","Password":"██████████"}` then flip status false→true; `HTTP/1.1 401 Unauthorized` → `HTTP/1.1 200 OK`; `"allowNotActivated":true`.
- Root cause: the client (web SPA or mobile app) decides "authenticated / verified / activated" from a server response value that is only advisory, and no server-side revalidation gates subsequent API calls — or the gate exists only in UI rendering.
- Impact: full admin UI access, changed admin password, deleted 1066 reports and viewed company data (UPS VDP); Harbor authenticated API access; bypassed OTP; non-activated driver used all partner features (Uber).
- Exemplars: 1490470, 1690548, 1508661, 130460, 126260, 2061982.

**How to apply:** in a thick client (mobile especially), proxy match/replace failure responses to success and watch which app features unlock. Always pair with the follow-up: if backend APIs still reject you, it's not a finding; if the client then presents data or performs privileged actions server-side, it is.

### 3. Client-side localStorage / UI gating
- Endpoint/param: `GET /████████/███/?#/` — set localStorage key `███████` to `true`, reload (1877989).
- Root cause: SPA reads a localStorage flag to decide whether to call authenticated APIs; the flag, not a session token, is the "auth."
- Impact: authenticated access exposing sensitive user data (phone number, email address).
- Exemplar: 1877989.

### 4. Unsigned JWT accepted (signature not verified)
- Endpoint: `POST /wp-json/newspack-extended-access/v1/google/register` (Automattic, 2536758).
- Payload (verbatim): `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXpwIjoiMTIzNDUtYWJjZGVmLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUub3JnIn0.Nq7Nc2AyWe17gPmIHVRCc4z9qKP-HBZwfWhyQ_dg9X0` — header `alg:HS256` with claims `azp` (Google App ID) and `email`.
- Root cause: endpoint accepts JWTs without verifying the signature, trusting user-supplied claims.
- Impact: authenticated a browser as the target user — arbitrary account registration, account hijack, access to private account details (billing address).
- Exemplar: 2536758. Related: TikTok ads intelbot service "JWT was not properly verified" (1328546).

**How to apply:** forge JWTs with the target's email/app-id claims; try `alg:none`, garbage signatures, and re-signed tokens with any secret. Chain: obtain the public Google App ID (often in client JS) to construct matching claims.

### 5. SAML signature-verification bypasses
Three variants in the records:
- **Missing `<ds:Signature/>` skip:** `POST /wp-content/plugins/onelogin-saml-sso/onelogin_saml.php?acs` with `RelayState=/wp-login.php` and forged unsigned `SAMLResponse` XML (Uber newsroom, 136169). Plugin skips verification when no Signature element is present → logged in as administrator on newsroom.uber.com and created a subscriber on eng.uber.com. Sibling finding: uchat.uberinternal.com same class, $8,500 bounty (223014).
- **Cert-toggling via unauthenticated RPC:** `Meteor.call("addSamlService", "Default_cert")` (Rocket.Chat, 1049375). Unauthenticated Meteor method sets `SAML_Custom_Default_cert` to false, disabling cert validation → login as arbitrary admin user with faked SAML response.
- **Generic improper SAML verification:** bypassed OneLogin auth on internal chat (223014).
- Exemplars: 136169, 1049375, 223014.

**How to apply:** always test SAML ACS endpoints with a self-signed/unsigned response first; strip the Signature element entirely. Look for admin/config RPCs (Meteor methods, internal APIs) that can disable crypto settings.

### 6. Default/known password + unrestricted API (XMLRPC)
- Endpoint: `POST /xmlrpc.php` (Uber, 138869).
- Payload (verbatim): methodCall `wp.getOptions` with params `zzz`, `cbarry@uber.com`, `@@@nopass@@@`.
- Root cause: OneLogin WordPress plugin provisions SSO users with default password `@@@nopass@@@` but leaves XMLRPC enabled, which honors the internal user DB.
- Impact: authenticated as existing Uber WordPress users, created pages/posts on love.uber.com and newsroom.uber.com, uploaded files.
- Exemplar: 138869. Related weak-credential chain in CTF: brute-force `access:computer` (1065731, 1069039).

### 7. NoSQL operator injection in login
- Endpoint: `POST /api/v1/login` (Rocket.Chat, 1447619).
- Payload (verbatim): `{"loginToken": { "$exists": false }}`.
- Root cause: `loginToken` passed unsanitized into a MongoDB `findOne` query.
- Impact: unauthenticated response returned `userId: rocket.cat` and valid authToken (`MnTHVIRTZfRBQiFQYzWZ1xbBlL4BUwK2-3UBWTftXpB`), authenticating as the privileged `rocket.cat` account via `/api/v1/me`.
- Exemplar: 1447619.

**How to apply:** send object values (`{"param":{"$gt":""}}`, `{"$exists":false}`, `{"$ne":null}`) into every auth endpoint parameter; look for tokens/userIds in the response and immediately validate them.

### 8. Session/OTP verification against the wrong user (2FA bypass)
- Endpoint: `POST /users/sign_in` (GitLab, 1288546/128085), params `user[otp_attempt]`, `user[login]`.
- Payload (verbatim): `user[login]` = `john` (victim's username).
- Root cause: `find_user` gives `params[:login]` precedence over `session[:otp_user_id]` during OTP verification, so the OTP is checked against a different user than the logged-in session.
- Impact: signed in as any 2FA-enabled user using attacker's own password + victim's (captured/knowable) OTP code, without the victim's password — full account takeover.
- Exemplar: 128085.

### 9. HTTP Parameter Pollution in OAuth flows
- Endpoint: `GET /login` (Twitter Digits web auth, 114169), params `consumer_key`, `host`.
- Payload (verbatim): `host=https%3A%2F%2Fwww.periscope.tv&host=https%3A%2F%2Fattacker.com`.
- Root cause: host validation compares the first `host` parameter while the last one receives the OAuth credential transfer.
- Impact: OAuth credential data sent to attacker-controlled host; PoC logged into the victim's Periscope account and renamed it "Pwn3d".
- Exemplar: 114169.

### 10. Scientific-notation integer overflow to corrupt auth records
- Endpoint: `POST /signup-manager/` / `/signup-manager/index.php` (h1-CTF/Shopify/DoD), params `age`, `firstname`, `lastname`.
- Payloads (verbatim): `action=signup&username=random&password=random&age=2E3&firstname=random&lastname=randomlastnameY`; `age=1e5&firstname=YYYYYYYYYYYYYYY&lastname=YYYYYYYYYYYYYYY`; `age=1e6&lastname=YYYYYYYYYYYYYYY`.
- Root cause: `age` validated with `strlen()` but stored with `intval()`; `"1e5"` passes the length check, expands to 1000, overflows the fixed-width padded record (113 chars, admin flag = 113th char), shifting attacker bytes over the trailing admin flag `N`→`Y` in `users.txt`.
- Impact: self-registered admin accounts; flag{99309f0f-1752-44a5-a03e4150757d} etc.
- Exemplars: 1067443, 1069189, 1069392.

**How to apply:** wherever fixed-width records are built from validated-but-not-normalized input, test `1e6`, `2E3`, `0x10`, negative numbers — anything `is_numeric` accepts that `intval` expands.

### 11. Pre-signed URL / magic-link signature bypass
- Endpoint: `GET /remote.php/dav/files/{username}/{filename}` (ownCloud, 2337427) with params `OC-Date, OC-Expires, OC-Signature, OC-Credential, OC-Verb`.
- Payload (verbatim): `https://localhost:9200/remote.php/dav/files/admin/secret.txt?OC-Credential=admin&OC-Verb=GET&OC-Expires=60&OC-Date=2024-01-27T00:00:00.000Z&OC-Signature=notchecked` — i.e., set `OC-Date` in the past and `OC-Expires` tiny.
- Root cause: expiry check returns a null (no) error for expired values, so the signature/key verification step is never reached.
- Impact: read private files (`admin/secret.txt`) with only a known username and filename, no authentication.
- Exemplar: 2337427. Related: Eternal verify-email link never expires and auto-authenticates via base64 `fbcid` param (user id + 4-digit code + email, no password) — 124151; Veris non-expiring, predictable onboarding token — 123902.

**How to apply:** for any presigned/magic URL, test (a) expired timestamps — does failure short-circuit signature checking? (b) token entropy/expiry, (c) what PII sits in the token itself.

### 12. Alternate/secondary endpoints bypassing the primary auth layer
- Shapes seen: `GET /login` on `crm.unikrn.com` — alternate login URL bypasses Cloudflare Access on the Mautic server, exposing internal endpoints (592885); `POST /session` on expired subdomain `help-basecamphq.37signals.com` — same login flow as `launchpad.37signals.com` but without anti-automation checks, cookie flagging, or real `authenticity_token` enforcement (empty token accepted) (1024880); `GET /████████/GxSessionIfc.php` issues a valid session to unauthenticated users, unlocking the gated `/dncp/home.php` (2414707); DoD admin form — a forged POST with a hidden parameter set to `1` satisfies "admin auth" with no credential check (1146600); GoCD stale thread-local security context: repeat unauthenticated requests to `/go/remoting/*` until a thread with a leftover X509 security context authenticates you — read/upload all artifacts (241244); Kubernetes nginx-ingress external auth: `GET /public-service/..%2Fprotected-service/protected` with manipulated `X-Original-Url` / `X-Auth-Request-Redirect` headers hits the protected service without `X-Api-Key` (1357948).
- Exemplars: 592885, 1024880, 2414707, 1146600, 241244, 1357948.

### 13. Connection-reuse credential confusion (libcurl / shared clients)
- Patterns: OAUTH2 bearer not checked on pooled IMAP reuse — valid bearer authenticates a second transfer with `--oauth2-bearer anything` (CVE-2022-22576, 1552110); TLS/SSH options omitted from reuse checks — authenticated SSH sessions reused across different keys (CVE-2022-27782, 1565624, 1898475 — `get_protocol_family()` never matches so the key check is skipped); FTP `--ftp-account` mismatch — `curl -v --ftp-account alice "ftp://.../file1" -: --ftp-account bob "ftp://.../file2"` fetches file2 as alice (1892780); GSS delegation `always` connection reused for a `none` request (1895135).
- Exemplars: 1552110, 1565624, 1892780, 1895135, 1898475.

**How to apply:** for client libraries/SDKs with connection pools, diff every auth-relevant option between two requests to the same host and check reuse honors it.

### 14. Verification-flow bypasses (email / phone / 2FA rate limiting)
- Reddit ads: `PATCH /api/v2.0/accounts/{id}` accepts an extra `email` field (`{"data":{"brand_safety_tier_preference":"EXPANDED","email":"█████"}}`) that marks the email verified without the verification step → set arbitrary email, accept ads-team invites sent to it, assume invitee's role — invite-based account takeover (1551176).
- TikTok seller signup: manipulate the URL after initial login steps to skip phone-number verification (2286745); TikTok 2SV: rapid repeated incorrect attempts in quick succession beat the timeout check (1747978).
- Yoti iOS PIN: lockout uses the device's local clock — change device date/time past the 5-minute lockout for unlimited attempts (1257586); Nextcloud iOS app lock: no throttling on the 4-digit PIN at all (2245437).
- Automattic Jetpack SSO: invite an unconfirmed WordPress.com account holding the victim's email; accepting the invite verifies it, and Jetpack "match by email" SSO then logs you into the victim's WP admin with no user interaction (2037902).
- Phabricator registration: 128-char email `aaaa...@facebook.com` gets `@facebook.com` truncated by MySQL VARCHAR(128), bypassing `auth.email-domains` (2224); or inject a Unicode char > U+FFFF (`attacker@gmail.com𝌆@allowed-domain.com`) so MySQL truncates at it — validation sees the whitelisted suffix, storage keeps the attacker address (2233).
- Exemplars: 1551176, 2286745, 1747978, 1257586, 2245437, 2037902, 2224, 2233.

### 15. Weak/id-borne tokens & misconfigured gateways (misc)
- AWS IAM authenticator webhook: token with duplicate query params in case variants (`Action`/`action`) bypasses the whitelist while AWS processes the attacker-chosen value; also omit/replay the signed cluster-id header and choose AccessKeyID → webhook returns `authenticated:true` with attacker-controlled username and groups (1580493).
- Flask-AppBuilder AUTH_OID: `POST /login/` with `openid=https://openstackid.org` — allowed-IDP list not enforced (CVE-2024-25128) → forge auth to any Airflow account (2401359).
- Uber shared session cookie `_csid` on `domain=.uber.com`: steal via subdomain takeover (saostatic.uber.com), relay with CSRFTOKEN/state, land logged-in as victim on riders.uber.com/trips (219205).
- Nextcloud Global Site Selector auth-as-any-user (CVE-2024-22212, 2248689); ownCloud SMB backend with Samba `map to guest = bad user` — log in as any existing user with any password (148151); GoCD 241244 above; DoD `signin=admin` GET param authenticates as any user without credentials, and can force-logout a victim via a link; clientid/clientsecret leaked in page source (2334420); unauthenticated browse-as-authenticated-user (187705); exposed Tomcat /admin and /manager (1364022); TVA admin-only ASPX endpoints (`/Evaluation/EditNotes.aspx?ProjectId={num}`, `AddressLookup.aspx`) with no auth, enumerable from forgot-password responses (2043552); GitHub Enterprise SSH-CA auth without proving ownership lets another user's secret gists be modified (1901040); Apache mod_proxy incorrect-encoding URL forwarding to backends (CVE-2024-38473, 2585384).

## Bypass / chain notes

- **Response-tampering needs backend confirmation:** the strongest findings (UPS VDP, Harbor, Sony) paired the flipped client response with real server-side privileged actions (password change, report deletion). Report the actions, not just the flip.
- **Chain templates observed:** brute-force/enum → cookie flag flip → admin resource access (CTF records); subdomain takeover → shared cookie theft → session relay (Uber 219205); invite-accept → email verification → SSO email-match login (Automattic 2037902); expired subdomain login → missing anti-automation → unchecked authenticity_token (Basecamp 1024880); unauthenticated config RPC → disable cert validation → forged SAML (Rocket.Chat 1049375); default plugin password → unrestricted xmlrpc.php (Uber 138869).
- **Filter-bypass primitives in the data:** duplicate params with case variation (Action/action, 1580493); HPP first-vs-last param (114169); path traversal encoding `..%2F` through a public prefix with spoofed X-Original-Url (1357948); Unicode/length truncation against DB storage (2224, 2233); scientific-notation numeric expansion (1069392); stale thread-local security context via request repetition (241244).

## Gotchas / what NOT to do

- Don't stop at "the UI let me in." If flipping a response only changes client rendering and backend APIs still 403, it's not a bypass. Conversely, verify stolen tokens actually authenticate (`/api/v1/me` style checks, as in 1447619).
- Don't report client-side rate limiting (device clock, local PIN lockout) as server 2FA bypass without testing the server path — the records show these are still accepted as valid findings (Yoti, Nextcloud iOS) but are lower severity.
- Don't assume base64 = encrypted. But also don't tamper with production cookies that are actually signed — a garbled signature just gets you blocked; confirm encoding first.
- Don't brute-force without prior access signals — TikTok 2SV (1747978) explicitly required prior email/password or phone code; impact framing matters.
- Don't overlook boring endpoints: Tomcat /manager, exposed ASPX admin pages, GxSessionIfc.php session issuers, and `signin=` GET params all paid out.
- Don't invent the SAML response — check whether the plugin/library skips verification when `<ds:Signature/>` is absent first; the records show that exact precondition.

## Real-world impact examples

- Full admin takeover of newsroom.uber.com and user creation on eng.uber.com via unsigned SAML (136169); internal chat access on uchat.uberinternal.com ($8,500, 223014).
- Arbitrary-user 2FA bypass on GitLab — login as victim with only their OTP code (128085).
- Privileged `rocket.cat` token issued to unauthenticated attacker via Mongo operator injection (1447619).
- Admin takeover on UPS VDP: password changed, 1066 reports deleted, company data viewed (1490470).
- Periscope account impersonation ("Pwn3d") via Digits HPP (114169).
- Private file reads on ownCloud with zero authentication (2337427); Airflow full account hijack via OpenID IDP forgery (2401359); Nextcloud GSS login-as-any-user CVE-2024-22212 (2248689).
- WordPress.com Jetpack SSO silent admin login with no victim interaction (2037902).