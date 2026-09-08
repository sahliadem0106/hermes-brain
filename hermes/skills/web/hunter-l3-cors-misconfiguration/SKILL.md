---
name: hunter-l3-cors-misconfiguration
description: "Use when hunting CORS Misconfiguration on a target. Loads the L3 technique sheet: CORS misconfiguration is the class of bugs where a server's `Access-Control-Allow-Origin` (ACAO) policy is so permissive that an attacker-controlled origin can read the responses of credentialed, auth"
domain: cybersecurity
subdomain: web
tags:
- web
- cors-misconfiguration
- hunting
- l3
version: '1.0'
---

# CORS Misconfiguration — Technique Sheet

## Overview
CORS misconfiguration is the class of bugs where a server's `Access-Control-Allow-Origin` (ACAO) policy is so permissive that an attacker-controlled origin can read the responses of credentialed, authenticated requests made by a victim's browser. It pays when the misconfigured endpoint sits behind a session (cookies with `SameSite=None`/no SameSite) and returns sensitive data or state-changing capability. The dominant root cause across all records is **Origin reflection combined with `Access-Control-Allow-Credentials: true`** — the server echoes whatever Origin the client sends instead of validating against an allowlist. Impact is proven whenever the hunter demonstrates a cross-origin read of an authenticated response, not merely the presence of the headers.

## Distinct sub-patterns

### 1. Full arbitrary-Origin reflection + credentials (the dominant pattern — ~15 of 25 records)
- **Endpoint shape:** Any authenticated endpoint; observed on `GET /wp-json`, `GET /wp-json/wp/v2/users/`, `POST /accounts/login/`, `GET /organic-traffic-insights/api/rest/1.2/users/{num}/projects` (Semrush), `GET /content-paywall/api/accesslevel` (Semrush), `GET /~nordvpn/api/widget/v1/faqs`, `GET /version/` (Semrush), `PUT /v2/account` (Acronis), `GET /abudhabi` (Zomato), plus bare domain roots.
- **Payload that fired (verbatim where stated):**
  - `Origin: https://evil.com` (Nord VPN, DoD #1771149)
  - `Origin: evil.com` (DoD #1530581, on `https://www.{host}/wp-json`)
  - `Origin: https://bing.com` (Sifchain #1194280)
  - `Origin: http://attacker.com` (DoD #995144)
  - Response then contains `Access-Control-Allow-Origin: <reflected origin>` + `Access-Control-Allow-Credentials: true`.
  - Working XHR PoC (Semrush #235200): `var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://www.semrush.com/organic-traffic-insights/api/rest/1.2/users/███/projects?_=1496248656402',true); req.withCredentials = true; req.send('{}'); function reqListener() { alert(this.responseText); };`
  - WordPress variant (DoD #1092125): `var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://████████/wp-json/wp/v2/users/',true); req.withCredentials = true; req.send();`
- **Root cause:** Server has no origin allowlist; it copies the request's `Origin` header into ACAO and unconditionally sets `Access-Control-Allow-Credentials: true`.
- **Impact proven:** Cross-origin read of logged-in user data — WordPress user IDs/names/usernames (#1092125), Semrush project/user info and subscription fields `product_group, used_trial, is_custom, upgraded` (#769058, #235200), victim personal info on DoD targets (#995144, #1530581), Nord VPN authenticated FAQ response read (#796557), Zomato personal info read + privileged actions performed (#426165).
- **Exemplars:** #1530581 (DoD), #235200 (Semrush), #796557 (Nord Security).

### 2. Prefix / suffix (string-match) origin validation bypass
- **Endpoint shape:** Domain-wide on `sifchain.finance` (GET /).
- **Payload that fired:** `Origin: https://sifchain.finance.evil.com` — accepted because the server does a naive substring/contains check for the trusted domain.
- **Root cause:** Origin validation implemented as string containment (`origin.contains("sifchain.finance")`) rather than exact allowlist match; attacker registers `sifchain.finance.evil.com`.
- **Impact proven:** Reflection of the attacker origin with `Access-Control-Allow-Credentials: true`, enabling credentialed cross-origin reads.
- **Exemplar:** #1192147 (Sifchain).

### 3. Wildcard subdomain trust + subdomain takeover chain
- **Endpoint shape:** `PUT /v2/account` on `account.acronis.com`; admin panel on `admin.myndr.net` (login-admin, login-admin-new-password, cp/postcode endpoints).
- **Payload that fired:** `Origin: https://register.acronis.com` (Acronis); `Origin: https://evil.myndr.net` (Myndr). Both return ACAO = the origin plus `Access-Control-Allow-Credentials: true`.
- **Root cause:** Server trusts ALL `*.acronis.com` / `*.myndr.net` subdomains with credentials. Trust is only as strong as the weakest subdomain — a dangling DNS record or attacker-usable subdomain converts "internal trust" into full attacker control.
- **Impact proven:**
  - Acronis: any attacker-controlled `*.acronis.com` subdomain can make credentialed requests to the account API.
  - Myndr: any `*.myndr.net` origin can read authenticated admin responses **including CSRF nonces and session data**, chained into CSRF password change → **full admin account takeover**.
- **Exemplars:** #1018621 (Acronis), #3930957 (Myndr).

### 4. `Access-Control-Allow-Origin: *` on authenticated/sensitive endpoints
- **Endpoint shape:** `GET /sockjs/info` (app.legalrobot.com), `GET /version/` (Semrush).
- **Payload:** none stated; observed in response headers.
- **Root cause:** Server returns ACAO `*`. Note: browsers won't attach credentials to `*` requests, but any origin can still two-way interact in the user's security context where cookies flow anyway, and wildcard leaks data with no origin check at all.
- **Impact proven:** Legal Robot — any domain retrieves content within the logged-in user's security context; Semrush — version/infra info (`product_info` version/hash) retrievable cross-domain.
- **Exemplars:** #163491 (Legal Robot), #310579 (Semrush).

### 5. Missing `Vary: Origin` with reflection (cache poisoning amplifier)
- **Endpoint shape:** `POST /blog/ws/` (Semrush), `GET /ws/info` on `chatws25.stream.highwebmedia.com` (Chaturbate).
- **Payload that fired:** `hhgdhgjgbxg.com` as the Origin value (Semrush); reflected origin `https://vazeeukllvua.com` (Chaturbate).
- **Root cause:** Server reflects arbitrary Origin with credentials **and omits `Vary: Origin`**, so intermediate caches may store a response generated for an attacker origin and serve it to other users — CORS misconfig escalating into response cache poisoning.
- **Impact proven:** Any origin trusted with credentials → cross-origin data theft plus cache poisoning.
- **Exemplars:** #288912 (Semrush), #417453 (Chaturbate).

### 6. WebSocket/SockJS info endpoints with permissive CORS
- **Endpoint shape:** `GET /sockjs/info`, `GET /ws/info`.
- **Payload:** none stated.
- **Root cause:** Handshake/info endpoints frequently ship permissive CORS defaults (SockJS libraries), overlooked in origin policy reviews.
- **Impact proven:** Any origin can retrieve content in the logged-in user's security context (Legal Robot); reflected arbitrary origin + credentials (Chaturbate).
- **Exemplars:** #163491, #417453.

### 7. Over-broad subdomain trust including HTTP scheme + missing CSRF protection
- **Endpoint shape:** `GET /profile` on `g-mail.grammarly.com`.
- **Payload that fired (verbatim):** `var xhttp = new XMLHttpRequest(); xhttp.onreadystatechange = function() { if(this.readyState == 4 && this.status == 200) { document.getElementById("response-node").innerHTML = this.responseText; } }; xhttp.open("GET", "https://g-mail.grammarly.com/profile", true); xhttp.withCredentials = true; xhttp...`
- **Root cause:** CORS trusts any subdomain AND allows the `http://` scheme (downgrade attack surface), while `/profile` lacks CSRF token validation — so both reads and writes (subscription changes) are honored cross-origin.
- **Impact proven:** Read victim's email address and subscription settings; change subscription settings on the victim's behalf.
- **Exemplar:** #629892 (Grammarly).
- Related record: #412490 (Grammarly) — permissive CORS/CSRF trusted **arbitrary browser-extension origins**, letting a malicious extension impersonate the user. Origin policies must consider `chrome-extension://` and similar schemes.

### 8. WordPress REST API endpoints as the CORS target (high-frequency target)
- **Endpoint shape:** `GET /wp-json`, `GET /wp-json/wp/v2/users/`, `GET /wp-json/wp/v2/users/{num}` (DoD, Sifchain, MTN Group, Publitas).
- **Payload:** XHR withCredentials PoCs as in sub-pattern 1; Publitas PoC (verbatim, partial): `function cors() { var xhttp=new XMLHttpRequest(); xhttp.onreadystatechange = function() { if (this.readyState == 4 && this.status ==200){ document.getElementById("emo").innerHTML=alert(this.responseText); ...`
- **Root cause:** Same reflection+credentials root cause, but wp-json is a reliably rich, unauthenticated-friendly target: it enumerates users and returns authenticated session data.
- **Impact proven:** MTN Group — credentialed GET to `https://www.mtn.com/wp-json/wp/v2/users/15` reads the logged-in user's sensitive data; **combined with the admin email leak this enables password brute-force toward administrator account takeover**. Publitas — cross-origin read of authenticated JSON; steal user info or force unwanted actions.
- **Exemplars:** #2450685 (MTN Group), #2332728 (Publitas), #896093 (DoD).

### 9. Cross-site trust boundary too wide (allowed non-company origins with credentials)
- **Endpoint shape:** `https://client.amplifi.com`, `https://protect.ubnt.com` (Ubiquiti).
- **Payload:** not stated.
- **Root cause:** CORS allowlist included origins outside `*.ubnt.com` / `*.ui.com` with credentials — the allowlist itself was wrong rather than absent.
- **Impact proven:** Logged-in user lured to an attacker page could have information stolen or be forced into unwanted actions.
- **Exemplar:** #430249 (Ubiquiti).

### 10. CORS on login/auth endpoints
- **Endpoint shape:** `POST /accounts/login/`.
- **Payload that fired:** `Origin: https://evil.com` → reflected with credentials true.
- **Root cause:** Reflection on the login endpoint itself; credentials enabled.
- **Impact proven:** Cross-origin exfiltration of victim's sensitive data.
- **Exemplar:** #1771149 (DoD). Also #867436 (BTFS): misconfigured CORS on a login page (`/login`, www.bitterrent.com) enabled a phishing flow to steal email/password and hijack the **csrf-token, which was also exposed in the URL**.

### 11. CORS enabling PII/IP leakage on mobile/app-adjacent domains
- **Endpoint shape:** `GET /{endpoint}` on `*.miui.com` (Xiaomi); TikTok Ads portal endpoint (unspecified, #1001951).
- **Payload:** not stated.
- **Impact proven:** Xiaomi — leakage of the user's IP address; TikTok — potential access to info about tickets opened on the Ads portal (weakest impact in the set: headers shown, no concrete exfiltration demonstrated).

## Bypass / chain notes
- **Suffix trick:** `https://target.com.evil.com` defeats contains-style checks (#1192147).
- **Subdomain takeover → CORS:** take over a dangling `*.acronis.com` subdomain (e.g. register.acronis.com), host the payload there, then the "trusted" origin reflects your credentialed requests (#1018621). Same shape on Myndr with `evil.myndr.net`.
- **CORS → CSRF nonce theft → admin takeover:** read CSRF nonce cross-origin via trusted-subdomain reflection, then CSRF the password change form (#3930957).
- **CORS + admin email leak → brute force:** read WP user data via CORS, combine with leaked admin email to brute-force the administrator (#2450685).
- **CORS + missing CSRF on the same app:** permissive CORS on `http://`-permitted subdomains plus no CSRF token means both read AND write (`/profile` subscription changes, #629892).
- **CORS → cache poisoning:** reflection without `Vary: Origin` lets a cached response generated for the attacker origin poison other users (#288912, #417453).
- **CORS → phishing/credential theft:** CORS bypass on a login page used to steal credentials and a csrf-token leaked in the URL (#867436).
- **Extension origins:** treat `chrome-extension://` origins as part of the origin policy surface (#412490).
- **Standard PoC pattern:** every confirmed read used `XMLHttpRequest` with `withCredentials = true` against the target URL from an attacker-controlled page, displaying or exfiltrating `responseText`.

## Gotchas / what NOT to do
- Do not report `Access-Control-Allow-Origin: *` alone as critical when the endpoint serves no authenticated data — pair it with a concrete sensitive response (the TikTok #1001951 report is the weak-impact baseline: no exfiltration demonstrated).
- Sending the Origin header via curl/Burp only proves reflection; the accepted proof is an in-browser `withCredentials = true` XHR from a real different origin reading a logged-in session's data.
- `ACAO: *` does NOT send cookies by browser spec — don't claim credentialed reads for wildcard responses; frame impact as security-context access as the Legal Robot record did.
- Remember `Vary: Origin`: its absence is itself a finding amplifier (cache poisoning), not just noise.
- Check the scheme policy: trusting `http://` subdomains is a real finding (#629892), since any plaintext subdomain or MITM position becomes a trusted origin.
- Test from actual subdomain shapes (suffix `.evil.com`, takeover-able subdomains) rather than only `evil.com` — naive validators pass `evil.com` reflection tests but the richer bug is the string-match bypass.
- State the chain explicitly (lure → withCredentials XHR → exfil) — reports that articulated the chain (Acronis, Myndr, MTN) carried the strongest impact.

## Real-world impact examples
- **Full admin account takeover (Myndr #3930957):** `Origin: https://evil.myndr.net` reflected with credentials on the admin panel → read CSRF nonces and session data → CSRF password change → admin takeover.
- **Account API compromise via takeover (Acronis #1018621):** takeover of register.acronis.com + `PUT /v2/account` with that Origin, credentials true → attacker subdomain controls account settings.
- **Subscription data theft (Semrush #769058):** cross-origin read of `/content-paywall/api/accesslevel` exposing `product_group`, `used_trial`, `is_custom`, `upgraded` of the logged-in victim.
- **User enumeration + brute-force path (MTN #2450685):** credentialed read of `wp-json/wp/v2/users/15` plus admin email leak → brute-force toward admin takeover.
- **Read + write on victim account (Grammarly #629892):** email address and subscription settings read; subscription settings changed on the victim's behalf.
- **PII exfiltration across DoD targets (#1092125, #1530581, #995144, #1771149):** WordPress usernames, personal info, and account data all readable cross-origin from attacker pages.
- **Cache poisoning (Semrush #288912, Chaturbate #417453):** origin reflection without `Vary: Origin` on `/blog/ws/` and `chatws25.stream.highwebmedia.com/ws/info` enabled cache poisoning on top of data theft.
- **Credential+CSRF theft via login page (BTFS #867436):** CORS bypass used for a phishing page that stole email/password and the URL-exposed csrf-token.