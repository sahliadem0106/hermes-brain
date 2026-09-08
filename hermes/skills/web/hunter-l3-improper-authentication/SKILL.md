---
name: hunter-l3-improper-authentication
description: "Use when hunting Improper Authentication on a target. Loads the L3 technique sheet: Improper Authentication bugs are cases where the server (or client) accepts an identity or grants a session without properly verifying who is asking — missing credential checks, stale tokens that stay"
domain: cybersecurity
subdomain: web
tags:
- web
- improper-authentication
- hunting
- l3
version: '1.0'
---

# Improper Authentication — Technique Sheet

## Overview
Improper Authentication bugs are cases where the server (or client) accepts an identity or grants a session without properly verifying who is asking — missing credential checks, stale tokens that stay valid, auto-login flows, JWT/OAuth validation gaps, and unauthenticated admin surfaces. They pay at every severity tier: from unauthenticated access to internal dashboards and CI/CD systems (critical) down to widened TOTP windows and missing re-auth on destructive actions (low/medium). The recurring hunter workflow is: find every state transition that issues or consumes a credential (reset links, OAuth logins, invites, 2FA, device tokens) and test whether each one checks what it claims to check.

## Distinct sub-patterns

### 1. Unauthenticated exposed internal services / dashboards
- Endpoint shape: `http://{ip}:8080/` (Uchiwa), JIRA instances (`jiratest.starbucks.com`), Alertmanager instances, CI/CD systems — infra surfaces reached by IP/subdomain enumeration.
- Payload: none required; auth is simply absent or "anonymous access" is enabled.
- Root cause: internal tooling deployed without auth or with anonymous access enabled; hardened credentials discoverable inside the tool (hardcoded passwords in checks).
- Impact: full internal visibility — Uchiwa dashboards, a hardcoded Sensu password leading to RabbitMQ access (id=100926), browsing/editing internal JIRA issues (id=332586), CI/CD system access (id=410475), unauthenticated Alertmanager (id=2292236).
- Exemplars: id=100926 (Yelp), id=332586 (Starbucks), id=2292236 (IBM).

### 2. Token verification skipped on API/JWT/OAuth inputs
- Endpoint shape:
  - `POST https://platform.enjin.io/graphql` / `POST /wp-json/newspack-extended-access/v1/google/register` — JWT in request body/param.
  - `POST https://www.instacart.com/api/v2/users/google_login_auth` — `id_token` param.
  - `POST /-/push_from_secondary/{num}/{project}.git/...` — `Geo-GL-Id` + `Gitlab-Workhorse-Api-Request` headers.
- Payload (verbatim, id=2472798): a self-signed JWT whose claims just name the target:
  `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUub3JnIiwiaWF0IjoxNzEzNjY2NjQ5LCJleHAiOjE3MTM2NzAyNDl9.I8D18nWsn5H6AylwJdak8727APyiMCWkcnXH95vMF_k`
  and `Geo-GL-Id: key-1` (id=1040786).
- Root cause: server trusts the token's claims without verifying issuer (`client_id`/audience), signature, or binding to the caller. Instacart accepted any Google `id_token` not issued to its own client_id; Automattic accepted any unsigned/self-signed JWT with the target email; GitLab identified users by numeric SSH-key ID in a header with a replayable Workhorse JWT.
- Impact: full account takeover by email in a JWT claim (view billing address, register accounts — id=2472798); cross-app token acceptance (Meetup token on Instacart — id=202177); unauthorized push to master as another user's SSH key (id=1040786).
- Exemplars: id=2472798 (Automattic), id=202177 (Instacart), id=1040786 (GitLab).

### 3. Unauthenticated token/credential issuance (auth returns tokens with no check)
- Endpoint shape: `POST /v2/auth.json` with only an `email` param.
- Payload: not stated beyond the email parameter.
- Root cause: the auth endpoint issued a valid access token given only an email address — no credential or session check.
- Impact: valid access token for a victim's Zomato account using only their email → full account access, zero interaction (id=245408).
- Exemplar: id=245408 (Eternal/Zomato).

### 4. Password-reset flow failures (the largest cluster)
Four distinct failure modes appear:
- a) Reset works without a valid token — `GET /password-reset` with the `token` param removed still allows a password change (id=265775, Legal Robot).
- b) Old reset links not invalidated — issuing reset_2 doesn't kill reset_1; both usable simultaneously (id=22858, Phabricator); stale link still changes the password after a new reset (id=243842, Weblate); ALL reset links for all emails on the account remain valid, bypassing two prior fixes (id=244287, Weblate); reset links survive an email change on the account (id=17474, Phabricator).
- c) Auto-login after reset — clicking the reset link logs the user in without forcing a fresh password entry (id=164648, 180895 Legal Robot; id=223339, Weblate). Worst case (id=229417, Weblate): attacker generates reset tokens for their own account; victim clicking the links is logged out of their own account and auto-logged into the attacker's account.
- d) No rate limit / no ownership check on reset requests — `POST /forgot-password` with any `email` sends faulty reset links repeatedly to legitimate users (id=315512, Coalition).
- Impact: account takeover via stale/missing tokens; session hijack via auto-login chains; harassment/DoS via unthrottled resets.
- Exemplars: id=229417 (Weblate), id=17474 (Phabricator), id=265775 (Legal Robot).

### 5. OAuth / federated-login lifecycle gaps
- Endpoint shapes:
  - `GET /accounts/login/google-oauth2/` (login with a disconnected account — id=223427).
  - Profile authentication settings → disconnect third-party auth (sessions from those credentials stay alive — id=223475).
  - `POST /accounts/{num}/external-login/1` with `account_id` — linking an external login to an unverified account (id=1018489).
  - Shopify VPN/monitoring subdomain Google OAuth accepting non-`shopify.com` accounts (id=194836/194832).
  - `POST /oauth/token` (Sign in with Apple) issuing an effectively irrevocable, long-lived OIDC JWT (id=1593413, Cloudflare).
- Payload (verbatim, id=1018489): `<a href="/accounts/{num}/external-login/1" data-method="post">Connect to Google</a>` injected to link Google login to a victim's unverified account, then "Log in with Google" as a backdoor.
- Root cause: linked-identity state changes (disconnect, email change) don't revoke the credential or its sessions; client_id/audience restrictions unenforced; token lifetimes excessive.
- Impact: login with a removed Google identity; persistent sessions after unlink; backdoor into accounts whose email was never verified; impersonation across devices for the whole JWT lifetime.
- Exemplars: id=223427/223475 (Weblate), id=1018489 (Shopify), id=1593413 (Cloudflare).

### 6. Email-verification not enforced before session/2FA issuance
- Endpoint shape: any login endpoint; session issued pre-verification.
- Root cause: no email-verification check before issuing a session (id=2312320, Enjin — confirmed by program) or before enabling 2FA (id=1543259, Cloudflare — 2FA enabled on an account created with a victim's unverified email, locking the real owner out of login AND password reset).
- Impact: login without verifying email; denial-of-account against the legitimate email owner.
- Exemplars: id=2312320 (Enjin), id=1543259 (Cloudflare).

### 7. Missing re-authentication on sensitive/destructive actions
- Endpoint shapes: team deletion (`DELETE team` — id=2975, Slack); store close/sell in the Shopify mobile app under Settings > Plan and Permissions > Sell or Close (id=1087382); account deletion `POST /v1/account/destroy` with `{"email":"<email>","authPW":"<authPW>"}` (id=2197244, Mozilla); change-email settings (id=245334, WakaTime; id=2586616, DoD).
- Payload (verbatim, id=2197244): `{"email":"<email>","authPW":"<authPW>"}` — authPW derivable from public client-side crypto, no Authorization header, no 2FA requirement.
- Root cause: high-impact actions performed without password re-entry or 2FA; mobile app diverges from web parity.
- Impact: account/team/store deletion from an unattended session or unlocked device; email change → password reset → takeover (id=245334); claiming a victim's email to lock them out ("Invalid Credentials" — id=2586616).
- Exemplars: id=2197244 (Mozilla), id=1087382 (Shopify), id=2586616 (DoD).

### 8. 2FA / MFA weaknesses
- Endpoint shapes: `POST /login` TFA verification (`totp_code`); pam_ussh SSH login (`ca_file`); Basecamp 2FA backup-code login.
- Payload: none stated (the attacks are timing/protocol level).
- Root cause: TOTP acceptance window widened past validity (codes >1 min old accepted — id=2588810, HackerOne); pam_ussh not verifying the SSH certificate was signed by a CA in `ca_file` — any cert from any CA accepted (id=1177356, Uber); a replayable 2FA backup-code response remained valid after 2FA removal, allowing login with the OLD password after the victim changed it (id=1485788, Basecamp).
- Impact: unauthorized SSH login at scale; post-password-change login with stale credentials; reuse of expired TOTP codes (assessed low since credentials still required).
- Exemplars: id=1177356 (Uber), id=1485788 (Basecamp), id=2588810 (HackerOne).

### 9. Missing object/action-level authorization that masquerades as auth bypass
- Endpoint shapes:
  - `POST /api/screenhero.rooms.invite` with `room`, `responder` — no check that the caller belongs to the room (id=184698, Slack).
  - `POST /messages` with `user=[ANY USER ID]` — "must follow user" rule unenforced server-side (id=46113, Vimeo).
  - `GET /safety/report_story` with `reporter_user_id=<another_user>&reported_user_id=<target>` — identity of the reporter taken from params (id=47888, X).
  - DDP `deleteFileMessage` with `fileID` — authorization skipped when `Meteor.userId()` is null (id=3611837, Rocket.Chat).
- Payload (verbatim, id=184698): `is_video_call=false&responder=U0254GYNR&room=R36L2K8P6&set_active=true&should_share=true&token=<snip>` — replayed with a different room ID and responder.
- Payload (verbatim, id=46113): `name=Jens>&text=blaat&action=send_message&lightbox=true&user=[ANY USER ID HERE]&token=[CENSORED]`
- Payload (verbatim, id=47888): `reporter_user_id=<another_user_id>&reported_user_id=<target_user_id>`
- Root cause: server accepts caller-controlled IDs (room, user, reporter, fileID) without checking the caller's relationship/identity; null-user code paths skip checks entirely.
- Impact: joining/eavesdropping on private 1:1 calls; DMs to any user; acting under another user's identity; unauthenticated permanent file deletion by ID (IDs discoverable from public channels).
- Exemplars: id=184698 (Slack), id=3611837 (Rocket.Chat), id=47888 (X).

### 10. Stale token/session invalidation (beyond password reset)
- Endpoint shapes: new-device confirmation token (Coinbase, id=30238 — old 12:00 PM token confirmed a device at 12:30 PM after a newer one issued); password-protected share access (Nextcloud, id=146133 — old share password's session survives a password change); team invitation links `GET /invitations/{uuid}` (HackerOne, id=46429 — valid indefinitely, accepted by a third party); VK 'Молодец' bot leaving permanent Long Poll access after one historical login (id=337734).
- Root cause: new credential issuance doesn't revoke older ones; invitation/pairing tokens lack expiry; one-time associations become permanent.
- Impact: device confirmation with stale tokens; share access after password change; unauthorized team join as manager; permanent victim-account access.
- Exemplars: id=30238 (Coinbase), id=46429 (HackerOne), id=337734 (VK).

### 11. Client/app-side auth gate bypass
- Endpoint shapes: local storage boolean flags (Uber app — flip to edit firstname/lastname/email/mobile without auth, id=165561); `nc://login` Android intent — `adb shell am start -a android.intent.action.VIEW -d "nc://login/server:MY_SERVER\&user:ME\&password:PWD" --es "ACCOUNT" "not_valid"` (id=490946, Nextcloud); Brave iOS Playlist "Open in a new Private Tab" skipping the FaceID/passcode gate (id=3693295); Partner/Driver app login with no activation-state enforcement (id=127085, Uber); Windows Phone/iOS browser logins skipping the email-authorization step required on PC (id=148537/148538, Coinbase).
- Root cause: gates enforced only client-side, or inconsistently per platform/channel; deep-link intents bypass lock checks.
- Impact: local profile editing; lock bypass exposing installed accounts (data read/altered/uploaded); private-tab content without biometrics; wallet balance/transactions and settings (password change, account deletion) without the email-authorization step.
- Exemplars: id=490946 (Nextcloud), id=148537/148538 (Coinbase), id=3693295 (Brave).

### 12. Preview/secondary surfaces skipping storefront protection
- Endpoint shape: `GET /preview_bar` on a password-protected myshopify.com store.
- Root cause: preview-link generation required no authentication and `shopifypreview.com` preview domains weren't subject to storefront password protection.
- Impact: full content of a password-protected store viewed with zero authentication (id=421859, Shopify).
- Chain: visit the protected store → open `/preview_bar` → extract the shopifypreview.com URL from source → view content.
- Exemplar: id=421859 (Shopify).

### 13. Unauthenticated email spoofing via open relay / weak inbound policy
- Endpoint shape: SMTP relay `alt1.aspmx.l.google.com:25`.
- Payload (verbatim, id=144385): `sendemail -s alt1.aspmx.l.google.com:25 -o message-file=mail2.txt -t security@paragonie.com -f scott@paragonie.com -u "security testing of mail relay" -vvv`
- Root cause: mail server accepts unauthenticated `@paragonie.com → @paragonie.com` mail; no SPF/DMARC enforcement on inbound.
- Impact: spoofed internal spear-phishing from a company executive's address.
- Exemplar: id=144385 (Paragon Initiative).

### 14. Auth-bypass via HTTP-layer manipulation and protocol quirks
- Endpoint shapes: `GET /App/createappeal.aspx` — intercept the 302 response, change it to 200, and the client-side app proceeds unauthenticated (id=2666323, DoD); crafted URL bypassing file access control (id=203311, DoD); TLS session tickets not isolated per virtual host in nginx http/stream — a ticket issued for one host resumes at another, circumventing client-cert auth (id=2978267, Internet Bug Bounty); libcurl connection pool reusing a pooled connection with the previous user's `Authorization: Bearer token_alice` when `CURLOPT_XOAUTH2_BEARER` changes without `CURLOPT_FRESH_CONNECT=1` (id=3595753, curl); low-privileged web session IDs accepted as admin XML-RPC API session IDs because session context wasn't recorded (id=3672641, Revive Adserver, CVE-2026-34917).
- Impact: submitting appeals/spoofing emails as other users; cross-vhost client-cert bypass; cross-account credential leakage in multi-tenant apps; low-priv → admin API access.
- Exemplars: id=2978267, id=3595753, id=3672641.

### 15. Misc identity/flow abuse
- Slack support portal abuse of the support@ inbox to join many teams (id=239623).
- HackerOne sandbox team invitation links accepted by non-invitees (covered in sub-pattern 10).
- Livedoor CMS: accounts that haven't set a password lack authentication — attacker sees drafts or posts articles as the victim (id=1278881, per program summary).
- LinkedIn: OAuth consent forced via the button ID in the URL hash plus holding the space key, tricking the user into authorizing a third-party app (id=2649615).
- X `/account/not_my_account/{account_name}` — non-expiring, frequently regenerated notification codes with no rate limit, brute-forceable to disclose and remove a victim's email (id=35287).
- Unauthenticated blog editorial publishing (id=3356, Phabricator); DoD file-access-control bypass via crafted URL (id=203311).

## Bypass / chain notes
- Fix-bypass regressions are a proven hunting seam at Weblate: id=243842 bypassed the fix for #229987; id=244287 bypassed fixes for both #229987 and #243842; id=194832 was an incomplete fix of Shopify's report 143482. Re-test every patched auth flow with the original PoC plus a variant (multiple emails, multiple tokens).
- GitLab chain: leak the Gitlab-Workhorse JWT via a terraform state path traversal → replay it in `Gitlab-Workhorse-Api-Request` on the Geo push endpoint with `Geo-GL-Id: key-1` → push as another user's SSH key (id=1040786).
- Weblate session-hijack chain (id=229417): attacker generates two reset tokens for their own account → victim clicks link #1 (logged out of their own account) → victim clicks link #2 (auto-logged into attacker's account) → attacker observes/misuses the victim's subsequent actions.
- Yelp infra chain (id=100926): exposed Uchiwa → hardcoded Sensu password in a check → RabbitMQ on the same host.
- Client-side auth bypasses chain with device access: unlocked phone + missing re-auth (Shopify sell/close, Uber flag flip, Brave private-tab gate) all assume prior physical access — frame impact accordingly.
- Response manipulation (302→200) only worked where the app trusted client-side redirects; pair with further request tampering (dropdown responses) to walk multi-step forms (id=2666323).

## Gotchas / what NOT to do
- Don't assume a token is invalid just because its purpose is complete — nearly half these records are "old token still works" (reset links, device-confirmation tokens, invitation UUIDs, share sessions, 2FA responses). Always test staleness in both directions (new token issued; state changed).
- Don't test TOTP/2FA timing windows against production accounts casually — HackerOne assessed the widened-window report as LOW because full credentials were still required. Set expectations.
- Physical-access preconditions (unlocked device, unattended session) cap severity. Shopify's mobile close/sell and WakaTime's change-email were reported as such; don't overclaim RCE-style impact.
- Mobile-only divergences from web parity (Coinbase email-authorization skip, Shopify close/sell) are valid findings — don't skip testing mobile flows because "the web is fine".
- "Payload not stated" is common in this class (OAuth flows, infra exposure, reset flows) — the technique is the flow manipulation, not an injection string; reconstruct the request yourself.
- App-only changes that never reach the backend (Uber local flag flip, id=165561) were accepted but scoped to the client — verify backend state before claiming account compromise.
- Unauthenticated infrastructure findings (JIRA, Alertmanager, CI/CD) often get access blocked mid-investigation (Starbucks) — capture evidence immediately.

## Real-world impact examples
- Full account takeover with only an email address: a valid Zomato access token issued for the victim's email alone (id=245408).
- Arbitrary-user login via self-signed JWT: logged into a target account, viewed billing address, registered accounts with arbitrary details (id=2472798, Automattic).
- Unauthorized push to master of a readable-only project as another user's SSH key, with video POC (id=1040786, GitLab).
- Live eavesdropping on a private 1:1 Slack call by replaying an invite request with a different room ID (id=184698).
- Unauthenticated permanent deletion of any uploaded file by ID (id=3611837, Rocket.Chat).
- Lockout attack: 2FA enabled on an account built from a victim's unverified email, blocking both login and password reset for the real owner (id=1543259, Cloudflare).
- Cross-vhost client-cert bypass via TLS session ticket resumption — access to an unauthorized second site (id=2978267).
- Spoofed internal email from a CEO's address via unauthenticated relay (id=144385, Paragon Initiative).
- Password-protected Shopify store fully viewed without authentication through `/preview_bar` (id=421859).
- Account deletion without 2FA or an Authorization header, authPW derived from public client-side crypto (id=2197244, Mozilla).