---
name: hunter-l3-broken-access-control
description: "Use when hunting Broken Access Control on a target. Loads the L3 technique sheet: Broken Access Control is the bug class where a server performs an action or returns data without verifying that the requester is actually permitted to do it."
domain: cybersecurity
subdomain: web
tags:
- web
- broken-access-control
- hunting
- l3
version: '1.0'
---

# Broken Access Control — Technique Sheet

## Overview
Broken Access Control is the bug class where a server performs an action or returns data without verifying that the requester is actually permitted to do it. The records here cluster into two huge families: (1) **missing permission checks on privileged actions** — a low-privileged staff member, guest, or unauthenticated user reaches an endpoint that should have gated them, and (2) **client-trusted state** — the server trusts a flag, cookie, header, session ID, or client-supplied identifier that an attacker controls. It pays whenever a product has tiered accounts (staff roles, org members, collaborators), "internal-only" endpoints, or session/permission state that lives client-side.

## Distinct sub-patterns

### 1. Missing permission check on staff/admin GraphQL mutations (low-priv self-escalation)
- **Endpoint shape:** `POST /admin/internal/web/graphql/core`, `POST /{shop_id}/api/graphql`, `POST /:id/api/graphql` — org/shop-internal GraphQL resolvers.
- **Payloads that fired (verbatim):**
  - `mutation {retailUserDataUpdate(id:"gid://shopify/StaffMember/{num}",retailUserData:{posAccess:true,pin:"1423"}){staffMember{name canAccessPrivateApps authenticationSettings{tfaEnabled}}userErrors{message}}}` (id=1018094)
  - `mutation BillingChargesExport($id:ID!,$exportFormat:ExportFormat){billingChargesExport(id:$id,exportFormat:$exportFormat){message userErrors{field message}}}` (id=1010835)
  - `mutation{staffOrderNotificationSubscriptionCreate(notificationRecipientIdentifier:"testingforshopify@ngailong.com",notificationRecipientType:EMAIL){staffOrderNotificationSubscription{id}}}` (id=1102652)
  - `mutation{staffOrderNotificationSubscriptionDelete(staffOrderNotificationSubscriptionId:"gid://shopify/StaffOrderNotificationSubscription/82867191864"){userErrors{message}}}` (id=1102660)
  - `mutation { enforceSamlOrganizationDomains(domainIds:["REPLACE_ME"]) { userErrors{message} } }` (id=1084939)
  - `{"query":"{ serviceMetrics { totalEarnings { amount } } }"}` (id=1091380)
- **Root cause:** Individual resolvers lack per-mutation/per-query permission gates even though the top-level session is authenticated. The server answers "authenticated staff member" and skips "is this staff member allowed to do *this*".
- **Impact proven:** Manage-Locations-only staff enabled own POS access + set a PIN; Settings-only staff exported billing charges, created/deleted order-notification subscriptions; Store Management user enforced SAML org domains; no-permission staff read `serviceMetrics.totalEarnings` financial data.
- **Exemplars:** 1018094, 1010835, 1102652, 1102660, 1084939, 1091380.

### 2. Privilege-permission string injection in role updates
- **Endpoint shape:** role-update mutation (e.g., GraphQL `UpdateRole`) taking a `permissions` array.
- **Payload:** `"permissions":["DASHBOARD","ORDERS","GIFT_CARDS","FULL","REPORTS","OVERVIEWS"]` — inject the string `FULL` into the array (id=1088159).
- **Root cause:** The permissions array is client-supplied and not validated against the allowed set for the role; an undocumented enum value `FULL` is honored by the backend.
- **Impact:** Users received FULL access while the role UI showed partial permissions; removing it later left users with FULL.
- **Exemplar:** 1088159.

### 3. Client-trusted flag in request body (server trusts `is_internal` / client params)
- **Endpoint shape:** `POST /reports/{num}` (add-comment), `POST /reports/{num}/reply`.
- **Payloads:** `message=TEST COMMENT&substate=&is_internal=&reference=&add_reporter_to_original=false&reply_action=add-comment&reports_count=1&report_ids%5B%5D=102260` (id=106084); `is_internal=,` (id=107336).
- **Root cause:** The internal-comment flag is checked by raw string value or trusted directly from the client. In 107336 the check compared the literal string, so `is_internal=,` (comma appended) bypassed the internal-only restriction.
- **Impact:** Program-Management-only member posted a public comment and triggered admin notifications; a read-only "Post internal comments" member posted to all participants ("Comment was created successfully.").
- **Exemplars:** 106084, 107336.

### 4. Trusted forwarder header for internal-IP gating
- **Endpoint shape:** `GET /status`, `GET /swagger.json` behind an edge that decides "internal" by IP.
- **Payload:** header `X-Forwarded-For: 127.0.0.1`.
- **Root cause:** Server trusts `X-Forwarded-For` to compute `x-is-internal-ip-address: true` instead of the socket peer address.
- **Impact:** Accessed restricted internal endpoints (`/status` and `/swagger.json` of a business API backend) that are otherwise blocked.
- **Exemplar:** 1011767.

### 5. Unsigned / client-controlled session cookie with privilege flag
- **Endpoint shape:** `GET /secure-login` / `POST /secure-login` with a base64 session cookie.
- **Payload:** `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==` — decodes to `{"cookie":"...","admin":true}`; flip the `admin` field to `true`, re-encode, replay.
- **Root cause:** The gate is a client-side cookie flag (`admin:false`) with no signature; the server trusts it.
- **Impact:** Downloaded the admin-only zip `my_secure_files_not_for_you.zip`, cracked it with fcrackzip (password `hahahaha`), read the flag.
- **Exemplars:** 1066851, 1067037, 1068434, 1069141 (h1-ctf).

### 6. Serialization-offset privilege escalation via type-juggling input (scientific-notation age)
- **Endpoint shape:** `POST /signup-manager/index.php` / `POST /signup-manager` with `age` and `lastname` params.
- **Payloads:** `age=1e3` / `age=1e6` / `action=signup&username=test123&password=password&age=1e9&firstname=foo&lastname=mypayloaY`.
- **Root cause:** PHP `is_numeric` accepts scientific notation while `intval()` expands it (1e9 → 1000000000), overflowing the fixed-width serialized user record so the last byte — the attacker-controlled last name character `Y` — lands in the admin-flag position (flag is `Y` at position 112).
- **Impact:** Registered an account whose admin flag became `Y`; gained admin area, flags, and recon-server paths.
- **Exemplars:** 1068434, 1068880, 1068934.

### 7. Unauthenticated internal/admin/cron endpoints exposed on public host
- **Endpoint shapes:** `GET /internal/cron/refreshCaseStats` (WHO app, id=1066790); `GET /ADMIN/store/index.cfm` (Acronis, id=1164854); default servlets via `GET /{path}/..;/examples/servlets/servlet/SessionExample` (id=1004007); `GET /include/findusers.php?token=[TOKEN_VALUE]` (id=1081137); `GET /` on an AWS-hosted .mil site (id=1003455).
- **Payloads:** none needed for the cron/admin pages; `..;/examples/servlets/servlet/SessionExample` for the proxy-bypass; for findusers, harvest `XOOPS_TOKEN_REQUEST` from unauthenticated `/misc.php?action=showpopups&type=friend` and present it as the token.
- **Root cause:** Deployment/config mismatch — internal-prefixed routes reachable on the public host; admin pages with no auth check; proxy and Tomcat normalize `..;` differently so the proxy's access-control rule doesn't match the path the backend sees; findusers.php grants access to anyone holding a valid security token, and tokens leak on unauthenticated pages.
- **Impact proven:** Unauthenticated admin functionality (item add/edit, order search, promo-code management); 200 responses from cron after ~20s enabling repeated backend load/DoS; session manipulation, source and internal-IP disclosure via Tomcat examples; user enumeration with usernames and real names; FOUO government content exposed.
- **Exemplars:** 1066790, 1164854, 1004007, 1081137, 1003455.

### 8. Registration / signup gaps as access control (unverified or lookalike-identity accounts)
- **Endpoint shapes:** signup on a corporate-only portal (`GET /request-access` on eats-devicereturns.com); OAuth/Connect account creation API (Stripe); Alerta dashboard `GET /#/signup`.
- **Payloads:** lookalike-domain email passing a loose `uber.com` regex (id=1010787); `superadmin@michelin.com` via Connect OAuth flow (id=1121896); `anythings@khanacademy.org` for Alerta (id=1061664).
- **Root cause:** Loose email-domain regex, no email-verification requirement on an alternate account-creation path, and no central SSO integration — access control is delegated to registration rules that don't hold.
- **Impact:** Full control of Uber Eats device-returns platform incl. PII; a fully active Stripe account impersonating Michelin Group (invoices, subscriptions, payouts to attacker bank); sensitive alerting data from Khan Academy's dashboard.
- **Exemplars:** 1010787, 1121896, 1061664.

### 9. OAuth scope not enforced server-side
- **Endpoint shape:** `POST /fleets/v1/create` (api.twitter.com).
- **Payload:** `{"text":"Hey yo"}` sent with a read-only OAuth app token (twurl PoC).
- **Root cause:** `/fleets/v1/create` and `/fleets/v1/delete` never check whether the token's app actually holds write scope.
- **Impact:** A read-only OAuth application created a Fleet on the account.
- **Exemplar:** 1032468.

### 10. IDOR / object ownership not verified (payments, polls, depots, sessions)
- **Endpoint shapes & payloads:**
  - `POST /create-payment` with `{"merchant":"cardpay","amount":10}` using only the victim's Steam ID cookie (id=1021776) → created and cancelled a transaction (orderId 2034944) in the victim's history.
  - `POST /apps/setcommonredists` — add any depot by ID to an attacker-owned app (id=1018368) → accessed depot contents without the decryption key.
  - `GET /████/{session_id}` — replace the session-ID string in the URL with another member's valid ID (id=1150573) → viewed any service member's PII; IDs appeared static/enumerable.
  - VK community poll close — close another user's poll by supplying its topic/poll id (id=1129816).
- **Root cause:** Endpoints operate on an object identified by a client-supplied ID without verifying the requester owns or has rights to it.
- **Exemplars:** 1021776, 1018368, 1150573, 1129816.

### 11. Public/unauthenticated artifact storage (S3)
- **Endpoint shape:** `GET https://coinbase-tmp.s3.amazonaws.com/{hash}/...Transactions-Report...csv` (id=109815).
- **Root cause:** Generated CSV reports are written to a public S3 bucket with unrestricted object URLs and no authentication — the app's auth boundary ends at the download link.
- **Impact:** Anyone with the direct URL downloads a completed CSV transaction report.
- **Exemplar:** 109815.

### 12. Race / TOCTOU on permission revocation (replay after downgrade)
- **Endpoint shape:** `POST /admin/mobile_devices.json` (APNS device registration) (id=100938); `GET /{namespace}/{project}/-/archive/{branch}/{project}-{branch}.zip` (id=1043480).
- **Payloads:** replay of the original full-access registration POST; automated Selenium loop re-requesting the archive URL.
- **Root cause:** In 100938 the endpoint doesn't re-check the Settings permission on replay after privileges were removed. In 1043480, once a privileged user opens the archive link, subsequent unauthenticated requests to the same URL are served — access control is enforced only on the first request (a caching/one-time-authorization flaw).
- **Impact:** Unprivileged admin re-added their own APNS device and received order notifications; unauthenticated (incognito, different network/device) download of a members-only project's full master-branch archive.
- **Exemplars:** 100938, 1043480.

### 13. Template / placeholder injection to reach admin-only resources
- **Endpoint shape:** `POST /hate-mail-generator/new/preview` with `preview_markup` and `preview_data`.
- **Payload:** `preview_markup=Hello {{name}}....&preview_data={"name":"{{template:38dhs_admins_only_header.html}}"}` (URL-encoded variant: `preview_data={"name"%3a"{{template%3a38dhs_admins_only_header.html}}","email"%3a"alice%40test.com"}`).
- **Root cause:** The `{{template:...}}` reference is validated only in `preview_markup`; `preview_data` is unfiltered, so a placeholder value in the data can include an admin-only template discovered via directory listing on `/templates/`.
- **Impact:** Rendered the admin-only template and captured the flag.
- **Exemplars:** 1065731, 1065885.

### 14. Share/link token abuse (federated shares & OCM permission escalation)
- **Endpoint shapes:** `POST /apps/federatedfilesharing/createFederatedShare` with `shareWith=user2%40https%3A%2F%2Flocalhost&token=KP3wSTdNbxsLGnq` (id=1167929); `POST /index.php/ocm/notifications` with `{"notificationType":"RESHARE_CHANGE_PERMISSION","resourceType":"file","providerId":2,"notification":{"sharedSecret":"nOxdNJkb1xbI1VX","permission":["read","write","share"]}}` (id=1170024).
- **Root cause:** createFederatedShare accepts an upload-only (file-drop) public-link token and still creates a federated share granting create/read. The OCM notifications endpoint accepts permission-change requests authenticated only by the share's `sharedSecret` — which is present in the share link — without verifying requestor ownership.
- **Impact:** A file-drop link became a readable federated share; a read-only public link/federated share was elevated to READ+WRITE+UPDATE+CREATE+SHARE via an anonymous RESHARE_CHANGE_PERMISSION notification, enabling file overwrites. Related: 1167767 (public-link "add to your Nextcloud" silently creates a federated share on the owner's instance with no notification).
- **Exemplars:** 1167929, 1170024, 1167767.

### 15. Integration/app JWT issued without role verification
- **Endpoint shape:** `GET /plugins/servlet/ac/com.hackerone/get-started-with-hackerone-on-jira` → `GET /apps/atlassian/claim-app?jwt=<TOKEN>`.
- **Payload:** `https://hackerone.com/apps/atlassian/claim-app?jwt=<TOKEN>` (payload not fully stated; token harvested from the config page).
- **Root cause:** The integration issues its JWT without verifying the Jira user's role; the app config page also lacks a permission check.
- **Impact:** A basic-privilege Jira user linked the instance to their own HackerOne account, created issues in private Jira projects, injected comments on private issues, and leaked private project names.
- **Exemplar:** 1103582.

### 16. Session/permission state leaking across subsystems (shared-access carry-over & stored-credential mixing)
- **Shapes:** Streamlabs "acting as user" session carried into `GET /zendesk?brand_id=1&locale_id=1&return_to=https://support.stramlabs.com` (id=1071918) — moderator shared-access could view/create/edit owner-only tickets and profile. Nextcloud `GET /settings/users` (id=1061594... recorded as 1061664-sibling id=1061594; use id=1061594 as stated: record id=1061594 is the Nextcloud admin-credential one) — `oc_storages_credentials` stored the admin's LDAP/AD credentials for *every* user, so a normal user acting on SMB shares operates as admin. Lark shared-folder invites let view/modify invitees reach the directory structure of other users' folders (id=1025881); Lark file version history let a viewer of one version access all previous versions (id=1080700); Lark footer feature exposed private-file access (id=1169340); Lark order endpoint lacked access control (id=1050753); IBM insecure object permissions let a guest read internal documents (id=1089583); Azbuka Vkusa order endpoint exposed order info + status changes (id=1050753-class); Snapchat `POST /api/portal/graphql` (kit.snapchat.com) let a non-admin org member call `deactivateApp` (id=1103448).
- **Root cause:** Permission models are enforced in one surface but not propagated to adjacent surfaces (support portal, storage layer, version history, sub-features).
- **Impact proven:** Owner-only support access by moderators; normal users operating with admin credentials against internal resources; cross-user directory modification; non-admin deactivated the org's Snap Kit app.
- **Exemplars:** 1071918, 1061594, 1025881, 1080700, 1103448.

### 17. Banned/removed users retaining or regaining access paths
- **Shapes:** HackerOne report collaborator invites (id=1131306) — invites don't check whether the invitee is banned from the program; a banned hacker accepted collaborator access on new reports. Shopify dev-store signup (id=1167453): `GET /{num}/stores/signup_object/dev_store` + `POST /services/signup/create` with `signup[extra][organization_id]=1022333` — a staff member whose dev-store permission was removed could still create and log into dev stores. Shopify `POST /{num}/stores/create_managed_store` (id=1167753) — dev-store-add-only staff could create managed stores. Shopify `POST /payments/subscribe` with `{"planId":10}` (id=1084865) — Dashboard-only user downgraded the owner's paid plan to Free.
- **Root cause:** Legacy/duplicate endpoints (older signup flows, alternate subscribe paths) that never received the new permission checks.
- **Exemplars:** 1131306, 1167453, 1167753, 1084865.

### 18. Documented permission level not enforced (Reporter+/role floors ignored)
- **Shape:** `POST /{project}/error_tracking/issues` with `issue[title]=Title`, `issue[description]=Description`, `issue[sentry_issue_attributes][sentry_issue_identifier]=Error_Id`, `authenticity_token=your_auth_token` (id=1117768). GitLab API: `PUT /api/v4/projects/{num}` with body `{"visibility": "internal"}` (id=1086781) — admin-restricted visibility options not enforced server-side (also demonstrated making a project public on a school instance). Read-only HackerOne members could request/approve public disclosure and post public comments (id=109483), and manually trigger public disclosure even after the first fix (id=118718).
- **Root cause:** Docs state a role floor; the server doesn't implement it, or an admin-level policy setting is only enforced in the UI.
- **Impact:** Guest users referenced/tracked Sentry errors; non-privileged users set restricted visibility (200 OK with the option applied); read-only members public-disclosed reports.
- **Exemplars:** 1117768, 1086781, 109483, 118718.

### 19. Client-platform exported component / policy bypass (mobile & infra)
- **Shapes:** LINE Lite exported activity `com.linecorp.linelite.ui.android.share.SelectShareActivity` — no URI verification, third-party app with one user interaction copies private files to public storage (id=1094702). VK Android protected components not properly restricted → arbitrary code execution (id=1095633). TikTok live-video suggestion logic didn't exclude users who blocked the streamer (id=1067967). Kubernetes ValidatingAdmissionWebhook passes oldObject fields populated with the new node's values, so users bypass admission checks to change labels, taints, PodCIDRs, and schedulability (id=1095612).
- **Exemplars:** 1094702, 1095633, 1067967, 1095612.

### 20. WebSocket subscription without permission check
- **Shape:** `wss://argus.shopifycloud.com/graphql?shop_id={id}`; get a token via the `GetToken` operation with a no-permission staff account, then send `{"id":"1","type":"start","payload":{"variables":{"eventName":"conversation"},...,"operationName":"EventSubscription","query":"subscription EventSubscription($eventName: String!) { eventReceived(eventName: $eventName) { eventName shopId eventTimestamp eventUuid ... }"}` (id=1023669).
- **Root cause:** The Ping WebSocket endpoint never verifies the subscriber's permission to listen to conversation events.
- **Impact:** No-permission staff received customer conversation messages and customer order-status page links in real time across `conversation`, `message`, `message_status`, `participant`, `read_state` events.
- **Exemplar:** 1023669.

## Bypass / chain notes
- **Path-normalization confusion:** `..;` in the URL path (Tomcat-style) makes proxy access rules and backend routing disagree — check default servlets/examples behind proxies (1004007).
- **String-comparison bypasses:** appending a comma (`is_internal=,`) defeated an exact-string check (107336). Try trailing/leading delimiters, casing, and array vs scalar forms on any flag the server compares textually.
- **Type juggling to shift serialized fields:** `1e3`/`1e6`/`1e9` in numeric fields expand via `intval()` and overflow fixed-width records, relocating attacker-controlled bytes into privilege fields (1068434/1068880/1068934).
- **Chain pattern (storage tokens):** public link → read `sharedSecret`/token from the link or `oc_share_external` → replay it against a mutation endpoint that treats the token as full authorization (1167929, 1170024).
- **Chain pattern (replay after downgrade):** perform the privileged action with a full-privilege account, get permissions removed, then replay the captured request (100938); or loop the URL until an authorized user primes it (1043480).
- **Chain pattern (integration pivot):** unauthenticated config page → harvest JWT → claim the integration under your own account → pivot into the connected system's private resources (1103582).
- **Chain pattern (authz via adjacent surface):** moderator "acting as" session, storage-layer credentials, version history — test every sibling surface, not just the one with the UI (1071918, 1061594, 1080700).
- **Multi-step with cracking:** cookie-flip → download protected artifact → offline crack (`fcrackzip`, password `hahahaha`) → read data (1066851 family).

## Gotchas / what NOT to do
- Don't stop at "access denied" vs "Not found": in 1010835 the resolver returned *Not found* for the unprivileged user while still executing the search — a "Not found" on a real object ID from a low-priv account is itself a signal worth testing further.
- Don't assume admin-restricted settings are enforced server-side just because the UI hides them — 1086781 showed the API accepts restricted visibility options with 200.
- Don't test only the modern endpoint; legacy paths (`/payments/subscribe`, `/services/signup/create`, `create_managed_store`) often missed the new permission checks (1084865, 1167453, 1167753).
- Don't ignore the second argument of multi-part requests: validation covered `preview_markup` while `preview_data` was wide open (1065731).
- Don't fixate on HTTP: WebSocket subscriptions, exported Android activities, and k8s admission webhooks are access-control surfaces too (1023669, 1094702, 1095612).
- Don't trust one replay: for race/TOCTOU bugs, automate repetition (Selenium loop in 1043480) — a single unauthenticated request may fail until the authorized user primes the URL.
- Keep your own account as the target where possible (self-escalation: own POS PIN, own subscription, own device registration) — these records show programs confirm self-escalation readily and it avoids touching other users' data.

## Real-world impact examples
- **Government exposure:** Unauthenticated access to an Unclassified/FOUO Advanced Motion Platform on a .mil AWS host (1003455).
- **Full platform takeover via registration:** lookalike-domain email on a corporate-only portal yielded control of Uber Eats' entire device-returns platform including PII (1010787); a fully active Stripe account for `superadmin@michelin.com` could invoice, bill, and pay out — impersonating Michelin (1121896).
- **Financial/subscription damage:** Dashboard-only user downgraded an owner's paid Oberlo subscription to Free (1084865); no-permission staff read earnings data (1091380); Settings-only staff exported billing charges (1010835).
- **Persistent private-data access:** real-time customer conversation messages and order-status links streamed to a zero-permission staff account over WebSocket (1023669); admin's LDAP credentials usable by any user against internal SMB resources (1061594); unauthenticated archive download of a members-only GitLab project (1043480); victim's payment history manipulated via Steam-ID-only payment creation (1021776).
- **Self-escalation to admin:** POS access + PIN set with Manage-Locations-only (1018094); registered account became admin via `age=1e9` padding overflow (1068934); read-only OAuth app created a Fleet (1032468); non-admin deactivated the org's Snap Kit app (1103448); basic Jira user injected comments into private issues (1103582).