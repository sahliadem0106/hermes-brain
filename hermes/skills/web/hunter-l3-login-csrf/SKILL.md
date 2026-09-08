---
name: hunter-l3-login-csrf
description: "Use when hunting Login CSRF on a target. Loads the L3 technique sheet: Login CSRF is the class of bugs where an attacker can force a victim's browser to authenticate into the *attacker's* account, rather than the victim's own."
domain: cybersecurity
subdomain: web
tags:
- web
- login-csrf
- hunting
- l3
version: '1.0'
---

# Login CSRF — Technique Sheet

## Overview

Login CSRF is the class of bugs where an attacker can force a victim's browser to authenticate into the *attacker's* account, rather than the victim's own. The classic form is a login POST missing CSRF token validation; the modern and often more lucrative form abuses OAuth/OIDC flows where the `state` parameter (or the entire flow state) is not validated server-side. Impact is usually rated moderate on its own, but pays when combined with what victims type into an attacker-controlled session: payment details, personal information, organization connections, and project data all become visible to the attacker, and the victim's IP/activity can be logged in the attacker's account.

## Distinct sub-patterns

### 1. Plain login form with no CSRF token (classic form POST)

- Endpoint shape: `POST /login` or the site's login action (e.g. `POST login`, `POST /about/` on Liberapay).
- Parameters: `credentials` — e.g. `name,pass` / `email,password` plus whatever the form normally carries.
- Payload: attacker hosts an auto-submitting HTML form:
  ```html
  <html><body><form action="https://TARGET/login" method="POST">
    <input type="hidden" name="email" value="ATTACKER-EMAIL" />
    <input type="hidden" name="password" value="ATTACKER-PASSWORD" />
  </form><script>document.forms[0].submit()</script></body></html>
  ```
  (Liberapay record id=283482 / Infogram: same shape; payload not stated beyond form-based auto-submit.)
- Root cause: the login form has no CSRF token at all, so a cross-site form POST silently authenticates the victim as the attacker.
- Impact proven: victim silently logged into attacker's account; projects added/edited by the victim afterward are visible to the attacker (Infogram, id=283482); victim may enter payment/personal/organization info into the attacker's Liberapay account (id=1124540, proven with video PoC).
- Exemplars: id=283482 (Infogram), id=1124540 (Liberapay).

### 2. CSRF token present on the login form but not actually validated

- Endpoint shape: `POST /users/sign_in` (Rails-style apps).
- Parameters: `user[email]`, `user[password]`, `authenticity_token`.
- Payload (verbatim, HackerOne id=834366):
  ```html
  <html><!-- CSRF PoC --><body><script>history.pushState('', '', '/')</script>
  <form action="https://hackerone.com/users/sign_in" method="POST">
    <input type="hidden" name="user[email]" value="youremail" />
    <input type="hidden" name="user[password]" value="yourpassword" />
    <input type="hidden" name="user[r..." <!-- (truncated in record; rest of the sign_in fields) -->
  ```
  Note the `history.pushState('','','/')` trick to mask the referer/URL bar during the redirect dance.
- Root cause: the endpoint renders `authenticity_token` but does not verify it during login — the POST succeeds without it (or with any value).
- Impact: login CSRF without needing to fetch a token; victim may add sensitive payment info to the attacker's account; the victim's IP is recorded in the attacker's account, enabling brute-force framing / identity-theft claims.
- Exemplar: id=834366 (HackerOne).

### 3. CSRF token is fetched from an unauthenticated endpoint (protection defeated at the source)

- Endpoint shape: `POST /chat/login`, with token from `POST /chat/auth-formtoken` (IRCCloud).
- Parameters: `email`, `password`, `token`.
- Payload (verbatim, id=7531):
  ```html
  <html><body><form action="https://www.irccloud.com/chat/login" method="POST">
  <input type="hidden" name="email" value="ATTACKER-EMAIL" />
  <input type="hidden" name="password" value="ATTACKER-PASSWORD" />
  <input type="hidden" name="token" value="1397481736.3b1f59ae47e1a139e8a631b2589dfae2" />
  </form></body>...
  ```
- Root cause: the login CSRF token can be obtained by *anyone* (no session/origin binding) from `/chat/auth-formtoken`, so the attacker simply fetches a fresh token server-side (or via their own browser) and embeds it in the CSRF form. The token exists but provides zero protection because it isn't tied to the victim.
- Chain: obtain valid token from `POST /chat/auth-formtoken` → embed it in the login CSRF form → auto-submit.
- Impact: victim logged into attacker's account (proven).
- Exemplar: id=7531 (IRCCloud).

### 4. Login-CSRF defenses bypassed via JSON Content-Type + CORS proxy

- Endpoint shape: `POST /login` accepting JSON.
- Parameters: `name`, `pass`.
- Payload (verbatim): `{"name":"username","pass":"password"}`
- Root cause: no `csrf_token` validation on the login POST. The JSON `Content-Type` requirement and CORS restriction — which would normally block a cross-origin `application/json` form POST — were bypassed by sending the request via AJAX routed through a public CORS proxy (`cors-anywhere.herokuapp.com`).
- Chain (from record): no csrf_token validation → send via AJAX to set `Content-Type: application/json` → route through cors-anywhere.herokuapp.com.
- Impact: stated login CSRF (victim into attacker's account) enabling social engineering and activity monitoring; not fully end-to-end tested because the reporter had no account — note this is a weaker PoC.
- Exemplar: id=577920 (X / xAI).

### 5. Login protections (token + captcha) bypassed together

- Endpoint shape: `POST /login`.
- Parameters: `FCTX` token and `g-recaptcha-response`.
- Payload: not stated.
- Root cause: the endpoint validates login via the `FCTX` token and Google reCAPTCHA, but both were bypassable — meaning the request can be forged cross-site with neither defense in place, so CSRF protection is effectively absent.
- Impact: login CSRF possible; the g-recaptcha-response captcha can be bypassed without FCTX tokens.
- Exemplar: id=835142 (DRIVE.NET, Inc.).

### 6. OAuth login with no state maintained (full-flow login CSRF / session fixation)

- Endpoint shape: `GET /auth/login/{provider}:{domain}/?oauth_token={token}&oauth_verifier={verifier}` (Phabricator, Twitter provider).
- Parameters: `oauth_token`, `oauth_verifier`.
- Payload (verbatim template): `/auth/login/twitter:twitter.com/?oauth_token={attacker_token}&oauth_verifier={attacker_verifier}`
- Root cause: no state is maintained anywhere in the OAuth login flow — the callback accepts the attacker's own `oauth_token`/`oauth_verifier` pair, so the "session" being established is the attacker's identity.
- Impact: directing a victim to the crafted OAuth callback URL logs the victim in as the attacker — login CSRF and session fixation on Phabricator.
- Exemplar: id=2228 (Phabricator).

### 7. OAuth `state` parameter not validated server-side

- Endpoint shape: `GET /_oauth/google/callback?state={state}&code={code}` (Mixmax).
- Parameters: `state`, `code`.
- Payload (verbatim template): `https://app.mixmax.com/_oauth/google/callback?state={state}&code={code}`
- Root cause: the `state` parameter is accepted without server-side validation, so the callback will complete an OAuth login for whatever `code` is supplied — including the attacker's.
- Chain (from record):
  1. Attacker initiates Google OAuth against mixmax.com and drops the redirect, keeping the `state` and `code`.
  2. Attacker directs the victim to the callback URL with the attacker's `state` and `code`.
  3. Victim is authenticated as the attacker's Google-linked account.
- Impact: victim logged in as attacker; escalatable by attaching the attacker's account to the victim's profile and monitoring the victim's activity.
- Exemplar: id=233379 (Mixmax).

## Bypass / chain notes

- Token-fetch bypass (IRCCloud, id=7531): a "protected" login form is forgeable if its token comes from an endpoint callable without victim session binding — fetch the token yourself and ship it in the PoC form.
- Token-not-validated bypass (HackerOne, id=834366): test submitting the login POST with the `authenticity_token` field removed or garbage — many frameworks render the field but skip verification on specific routes. Include `history.pushState('','','/')` in the PoC to tidy the URL bar.
- Content-Type / CORS bypass (X, id=577920): if the login endpoint only accepts `application/json`, a plain HTML form can't send it — chain through a CORS proxy (e.g. cors-anywhere) with AJAX to set the Content-Type.
- Captcha + token combo bypass (DRIVE.NET, id=835142): when a login is defended by both a proprietary token (FCTX) and reCAPTCHA, test whether either alone (or replayed values) is enough — bypassing both removes all CSRF protection.
- OAuth flow hijack (Mixmax id=233379, Phabricator id=2228): the core chain is always: (1) complete OAuth as the attacker up to the final callback, (2) capture the callback URL (state/code or token/verifier), (3) get the victim to visit that URL — via link, open redirect, or embedded iframe/redirect. Phabricator shows the degenerate case where state is absent entirely; Mixmax shows the case where state is present but unvalidated.
- Escalation chain noted in Mixmax (id=233379): after forced login, attach the attacker's account to the victim's profile to persist monitoring of victim activity even after they notice.

## Gotchas / what NOT to do

- Don't assume a CSRF token in the HTML means login CSRF is fixed — verify the token is (a) actually validated (id=834366) and (b) bound to the victim, not freely obtainable (id=7531).
- Don't skip OAuth login flows when hunting classic form CSRF. Half the records in this set are OAuth-based (state/verifier handling), not form-based.
- Don't rely on the victim doing anything visible — every proven impact here is silent (auto-submitting form or a single crafted link).
- Don't submit an untested chain as fully demonstrated: the X/xAI report (id=577920) was explicitly flagged as not end-to-end tested due to no account available, which weakens it. Complete the PoC with a real attacker account where possible.
- Don't forget the credential capture angle: the biggest impact in these records is not the login itself but what victims do *inside the attacker's session* — payment info (Liberapay, HackerOne), project data (Infogram), and recorded victim IPs (HackerOne). Demonstrate this in the report.
- Don't confuse the direction of the attack: this is victim-into-attacker's-account, not attacker-into-victim's. Reports framed the other way will not match this class.

## Real-world impact examples

- Liberapay (id=1124540): victim clicking the crafted page is logged into the attacker's account and may add sensitive payment, personal, and organization information — all visible to the attacker. Proven with video PoC.
- Infogram (id=283482): silent login into the attacker's account meant every project the victim created or edited afterward was visible to the attacker — a direct data-theft vector.
- HackerOne (id=834366): beyond payment-info capture, the victim's IP address gets recorded in the attacker's account, enabling brute-force attribution framing / identity theft.
- Mixmax (id=233379): forced OAuth login escalatable to attaching the attacker's account to the victim's profile for continuous activity monitoring.
- Phabricator (id=2228): single crafted callback URL yields both login CSRF and session fixation.
- IRCCloud (id=7531): demonstrates that even a token-protected login is forgeable when the token endpoint is public — full login CSRF achieved.