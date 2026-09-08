---
name: hunter-l3-brute-force
description: "Use when hunting Brute Force on a target. Loads the L3 technique sheet: Brute force findings are about the *absence or bypassability* of throttling on any endpoint that validates a secret: login passwords, PINs, 2FA/OTP codes, reset tokens, share-link passwords, invite/pr"
domain: cybersecurity
subdomain: web
tags:
- web
- brute-force
- hunting
- l3
version: '1.0'
---

# Brute Force — Technique Sheet

## Overview

Brute force findings are about the *absence or bypassability* of throttling on any endpoint that validates a secret: login passwords, PINs, 2FA/OTP codes, reset tokens, share-link passwords, invite/promo codes, API tokens, and "current password" confirmation fields. They pay when a guessable secret gates something valuable (account takeover, private data, free credit) and the target either never implemented rate limiting, implemented it inconsistently across parallel endpoints, or implemented it in a way you can dodge (IP rotation, header spoofing, multicall batching, clock manipulation). The core proof is always the same: demonstrate differential responses (status code or body length) between wrong and right secrets, plus a volume of unthrottled attempts.

## Distinct sub-patterns

### 1. Plain login password brute force (no lockout / no captcha / no rate limit)

- **Endpoint shape:** `POST /login`, `POST /sessions`, `POST /accounts/login/`, `POST /users/sign_in`, `POST /auth/post_login`, `POST /web-client/api/user/login`, `POST /wordpress/wp-login.php`
- **Payload that fired:** `email=07CA51kX%40www.irccloud.com&org_invite=&password=SrEeHaRiDasSsS` (IRCCloud, id=7226); wordlist-driven loop `python hackeronebrute.py <user> 10k_most_common.txt venet0 50` (id=127844); X login body `{"username":"TARGET@exmple.com","password":"HACKEDP@SS"}` (id=819930)
- **Root cause:** No account lockout, no CAPTCHA, no per-IP or per-account throttle.
- **Impact proven:** 26th attempt correct password logged in (id=145727); 10,001 guesses cracked `Geniaal2!!` and full login on hackerone.com (id=127844); 100+ consecutive attempts with session-cookie delta confirming success (id=3174778); full ATO (id=410451, id=6697).
- **Exemplars:** id=145727 (Nextcloud), id=127844 (HackerOne), id=3174778 (Mars), id=7226 (IRCCloud)

### 2. WordPress xmlrpc.php — system.multicall amplification

- **Endpoint shape:** `POST /xmlrpc.php`
- **Payload that fired:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value>asha8fd635db6e9</value></param>
<param><value>password</value></param>
</params>
</methodCall>
```
and the multicall wrapper (id=125624): `<methodName>system.multicall</methodName>` wrapping an array of `wp.getUsersBlogs` structs, each carrying a username/password pair.
- **Root cause:** `wp.getUsersBlogs` acts as a credential oracle; `system.multicall` batches hundreds of credential checks into one HTTP request, sidestepping per-request rate limits.
- **Impact proven:** per-call 403 faults returned with HTTP 200 confirming batched credential checking (id=1147225/1147433 Shopify; id=125624 Uber across newsroom/eng/brand.uber.com).
- **Chain seen:** enumerate usernames via `/wp-json/wp/v2/users` → multicall credential attempts.
- **Exemplars:** id=1147433 (Shopify), id=125624 (Uber)

### 3. IP-rotation bypass of per-IP rate limits

- **Endpoint shape:** any login with per-IP throttling (`POST /sessions`, `POST /web-client/api/user/login`, `POST /users/sign_in`)
- **Payload/technique that fired:** assign 500+ IPv6 addresses from a VPS /64 to the interface and rotate source addresses, staying under the per-IP 4-second threshold (id=127844); X: hit the ~120-request IP ban, then rotate through a proxy pool and continue at "virtually unlimited speed" (id=819930); Omise dashboard: rotate IP per attempt to defeat the account attempt limit (id=1466967).
- **Root cause:** throttling keyed only on source IP; IPv6 subnets and proxy pools give unlimited fresh identities.
- **Impact proven:** cracked password + full login (id=127844); full ATO (id=819930); program-confirmed brute force (id=1466967).
- **Exemplars:** id=127844 (HackerOne), id=819930 (X/xAI)

### 4. Weak short codes with no attempt cap (OTP / PIN / login codes)

- **Endpoint shape:** `POST /verify_login_code` (`utf8=%E2%9C%93&phone=(888)+999-5555&login_code=3425&commit=Submit`, id=158157); mobile app PIN screens; Bumble `POST bma.ClientSecurityCheck`
- **Payload:** none beyond the code parameter; 5-digit code space = 100K.
- **Root cause:** no attempt limit on a tiny keyspace (5-digit codes, 4–5 digit PINs).
- **Impact proven:** Instacart code broken at guess 43K → full shopper account takeover from phone number alone (id=158157); Bumble success at attempt 56 (`success:true`) (id=174668); MyEtherWallet: lockout timer driven by device local time — changing the clock resets the 5-minute lock and permits unlimited PIN guesses (id=1242212).
- **Exemplars:** id=158157 (Instacart), id=174668 (Bumble), id=1242212 (MyEtherWallet)

### 5. Password-reset / token verification endpoints left unthrottled

- **Endpoint shape:** `POST /password` with `reset_password_token` (id=271533); Nextcloud `LostController.php` reset-token endpoint (id=1987062); forgot-password PIN verification (id=1059758); GraphQL `resetPassword` (id=1165225)
- **Payload:** payload not stated in records.
- **Root cause:** reset-token verification missed when throttling was rolled out to the rest of the flow; or token entropy too low; or (id=1165225) login *and* reset both unthrottled with a weak 5-char password policy.
- **Impact proven:** reset PIN brute-forced → new password set → full ATO given victim's email (id=1059758); `resetPassword {status:true}` vs `{status:false}` doubles as username enumeration and returned a JWT on success → ATO (id=1165225); reset tokens brute-forced → ATO (id=271533).
- **Exemplars:** id=1059758 (DoD), id=1165225 (Reddit/Dubsmash), id=1987062 (Nextcloud)

### 6. 2FA / TOTP guess-rate gap

- **Endpoint shape:** `POST /users/sign_in` 2FA step (GitLab, id=149598)
- **Payload:** none stated.
- **Root cause:** ~20 guesses per 60-second token window with only short-lived rate limiting; locked accounts still validate passwords, so the 2FA step stays reachable.
- **Impact proven:** ~9.5% chance of success within 3.5 days; neither victim nor admin notified.
- **Exemplar:** id=149598 (GitLab)

### 7. "Current password" confirmation endpoints (post-auth brute force)

- **Endpoint shape:** `POST /account/close` (XVIDEOS); `POST /settings/security` (backup codes / delete account / profile update, Nextcloud); `POST /settings` current-password field (nextcloud.com); `POST /secure_session` (Moneybird); old-password check on `POST https://old.reddit.com/prefs/update`
- **Payload:** none stated; detection via response differentiation.
- **Root cause:** sensitive-action password re-confirmation often gets weaker throttling than login — or none at all. Moneybird (id=269318): the secure-session password rate limit was explicitly *lower* than regular login's.
- **Impact proven:** 8,000+ old-password guesses on Reddit, correct one revealed in response → ATO with stolen cookies (id=1165285); Nextcloud password recovered in cleartext via unlimited confirmation attempts (200 vs 403) (id=1842114); XVIDEOS: account deletion possible from a moment of device access (id=1392287).
- **Exemplars:** id=1165285 (Reddit), id=1842114 (Nextcloud), id=269318 (Moneybird)

### 8. Password-protected share links and WebDAV/Basic auth

- **Endpoint shapes:** `GET /s/{shareId}` share password; `GET /index.php/s/{uuid}` (303 on success, id=1894653); `PROPFIND /public.php/webdav` with Basic auth (id=1192159); `GET /remote.php/dav/calendars/{email}/app-generated--deck--board-{num}/` (id=1879549); `POST /share/{uuid}/password` (id=2039447)
- **Payload that fired:** `https://efss.qloud.my/remote.php/dav/calendars/ha.ckitbharat3@gmail.com/app-generated--deck--board-5269/` — calendar link leaks username; capture the Basic auth header, base64-decode to locate the password position, run Intruder against it.
- **Root cause:** Nextcloud's bruteforce protection is wired into some endpoints but not others: public.php/webdav never records to `oc_bruteforce_attempts`; federatedfilesharing mount protection only triggers for password-protected/file-drop shares, not public tokens; share-password POST endpoints unprotected. The success signal is a different response code/length (303 vs other; body length 414 vs 297 after 1000 guesses, id=2039447).
- **Impact proven:** share password bypass (id=1894653); full account takeover via calendar DAV Basic auth — CVE-2023-32319 (id=1879549); sensitive survey data (results, answers, devices, locations, participants) exposed (id=2039447).
- **Exemplars:** id=1879549, id=1894653, id=1192159 (all Nextcloud)

### 9. Code/token enumeration for monetary value (invite, promo, coupon codes)

- **Endpoint shapes:** `GET /join/?invite_code={code}` / `GET /drive/?invite_code={code}` (Uber); `GET /api/discounts/{coupon}` (Infogram); promo apply on riders.uber.com payment page; `POST cn-sjc1.uber.com/rt/users/apply-clients-promotions` (validates only `x-uber-token` + promo code)
- **Payloads that fired:** `547kkgvcv` ($500 credit), `6w3wt2b8z` ($300), `xez7rgs2u` ($100) — 9-char lowercase alphanumeric; response-length oracle on promo apply (1951=valid, 1931=invalid, 1921=expired, id=125505).
- **Root cause:** no rate limit/captcha on code validation; codes are human-customizable or short, shrinking the keyspace; Uber prefixes custom codes with "uber" further shrinking it; 1,680 invite codes were also Google-indexed (id=144877).
- **Impact proven:** free rides / $100–$500 credits harvested; inviter's name and profile photo leaked in responses; >1M parallel attempts enumerated valid x-uber-tokens in minutes with no account → session compromise (id=293359).
- **Exemplars:** id=144616, id=144877 (Uber), id=288846 (Infogram), id=293359 (Uber)

### 10. Endpoint-inconsistent throttling (parallel auth paths)

- **Endpoint shapes:** mobile `POST https://www.instacart.com/oauth/token` vs web login (id=160109); app endpoints generally vs web.
- **Payload:** none stated; 401 vs 200 oracle; ~50 attempts with no restriction.
- **Root cause:** the mobile/API auth path lacks the lockout/rate limiting the web path has — and accounts locked on web remain loginable via the unprotected path.
- **Impact proven:** password brute-forced through /oauth/token → account access including contact info and order history.
- **Chain seen:** observe /oauth/token has no lockout → repeat via proxy → brute until 200.
- **Exemplars:** id=160109 (Instacart)

### 11. Throttle logic bugs (counter only counts failures / header trust)

- **Endpoint shapes:** `POST /graphql` `customerAccessTokenCreate` (Shopify, id=708013); `POST /login` with `X-Forwarded-For: <valid-format IP>` (Nextcloud throttler, id=2230915)
- **Payload that fired:** `X-Forwarded-For: <valid-format IP>` — a syntactically valid spoofed IP defeats `getRemoteAddress()` when trusted_proxies is misconfigured, eliminating the throttler sleep delay.
- **Root cause:** Shopify's throttle increments/checks its counter only on *invalid* passwords, so submitting the real password after hitting "Login attempt limit exceeded" still succeeds. Nextcloud's throttler trusts attacker-controlled XFF (CVE-2023-49792).
- **Impact proven:** brute force despite visible rate-limit errors → customer account access incl. contact info and order history (id=708013); unlimited credential brute force (id=2230915).
- **Exemplars:** id=708013 (Shopify), id=2230915 (Nextcloud)

### 12. Directionality gaps: per-user-only and per-IP-only throttling

- **Endpoint shapes:** `POST login` on www.twitter.com with one fixed password across many accounts (id=854424); login throttled per-IP only (id=127844).
- **Root cause:** limiting failed attempts per single account but not per-password-across-accounts (credential stuffing), or per-IP but not per-account — either axis alone is bypassable.
- **Impact proven:** password brute-forcing/stuffing across accounts without effective rate control (id=854424).
- **Exemplar:** id=854424 (X/xAI)

### 13. Misc unthrottled secret checks

- **Stats/API tokens:** `GET /statsapi/?token=...` — correct token returns 200; another user's stats viewable (id=412526, Chaturbate).
- **Private room passwords:** `POST /roomlogin/user/` — 1k+ guesses unblocked; private broadcast room access ($500 bounty) (id=385381, Chaturbate).
- **Private video passwords:** `POST /clip/password` (Vimeo, id=124564) — program confirmed and added a limit.
- **Self-unlock codes:** Steam self account unlock → unrestricted account access (id=410221, Valve).
- **Card numbers:** Starbucks card history PIN endpoint; inconsistent rate-limit application → card number brute force / fraud potential (id=194318).
- **CA admin:** exposed `0.0.0.0:7054` fabric-ca server, no wrong-password limit + default maxenrollments → admin account brute-forced, high-privilege network access (id=411364).
- **Non-auth endpoints wired for auth:** OIDC `user_oidc` login/code/logout controllers missing brute-force protection (CVE-2023-32074, id=1954711); Nextcloud settings password field (id=199714).

## Bypass / chain notes

- **IP rotation:** IPv6 /64 subnet binding (500+ addrs on one interface) beats per-IP windows; proxy pools beat IP bans (HackerOne, X, Omise). Watch for the ban threshold (~120 requests on X) to calibrate.
- **Request batching:** xmlrpc.php `system.multicall` packs hundreds of `wp.getUsersBlogs` checks into one request — defeats per-request rate limiting entirely.
- **Header spoofing:** `X-Forwarded-For` with a valid-format IP resets the throttler's view of your source address when trusted_proxies is misconfigured.
- **Clock manipulation:** device-local-time-based lockouts (mobile PIN screens) reset on timezone/clock change.
- **Wrong-oracle bypass:** if the counter only increments on failures, the correct credential still works after the limit trips.
- **Parallel endpoints:** web-locked accounts stay attackable via mobile/app/API paths that never inherited the throttle.
- **Username pre-staging:** enumerate valid usernames first (`/wp-json/wp/v2/users`; `resetPassword` status:true/false differential) so attempts aren't wasted.
- **Chains to ATO:** stolen cookies + old-password brute (Reddit); private link with username in URL → Basic auth crack (Nextcloud); email knowledge + reset-PIN brute (DoD); Google-indexed invite codes as seed lists (Uber).

## Gotchas / what NOT to do

- Never actually access victim data beyond the minimum to prove the oracle — Nextcloud records (id=1192144, id=1192159) were accepted as "no actual data accessed" and still valid.
- Low-volume proof is often enough: 20–26 wrong attempts followed by the correct one (id=145727, id=6883), or ~50 attempts (id=160109), or 1k (id=385381). Match volume to the keyspace; don't run millions against a login form.
- Don't assume one unthrottled endpoint generalizes — several programs had protection on the main login but not on change-password, delete-account, or reset-token endpoints. Test each secret-checking endpoint separately.
- Response-length oracles (1951/1931/1921 bytes; 414 vs 297; 303 vs other) must be documented explicitly — differential responses are usually the actual evidence, not the successful login.
- Client-side tools with no server lockout (curl, id=3030158) are weak findings on their own; the value is in server-side validation endpoints.
- Verify your guesses actually register: some endpoints silently swallow attempts; confirm with the documented oracle before claiming impact.

## Real-world impact examples

- Full account takeover via 5-digit login code brute-forced at guess 43,000 of 100K — any shopper account given a phone number (Instacart, id=158157).
- 10,001st guess cracked `Geniaal2!!` on hackerone.com after rotating 500+ IPv6 addresses (id=127844).
- 8,000+ old-password guesses on old.reddit.com unthrottled; correct password disclosed in the response → ATO chain with stolen cookies (id=1165285).
- Nextcloud calendar WebDAV Basic auth cracked → full account takeover (CVE-2023-32319, id=1879549); XFF spoofing defeat (CVE-2023-49792, id=2230915); user_oidc controllers (CVE-2023-32074, id=1954711).
- >1M parallel promo-token enumeration in minutes with no account required → session compromise (Uber, id=293359).
- $100–$500 ride credits harvested from brute-forced invite codes, plus inviter PII leakage (Uber, id=144616/144877).
- JWT returned by unthrottled GraphQL `resetPassword` with a 5-char password policy → ATO (Reddit/Dubsmash, id=1165225).
- ~9.5% success probability against GitLab 2FA within 3.5 days, silently (id=149598).
- Fabric-ca admin brute-forced via exposed 0.0.0.0:7054 → high-privilege access on a permissioned network (id=411364).
- Private broadcast room password cracked after 1k+ unblocked guesses ($500 bounty, Chaturbate, id=385381).