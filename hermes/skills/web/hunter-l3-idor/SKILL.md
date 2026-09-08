---
name: hunter-l3-idor
description: "Use when hunting IDOR on a target. Loads the L3 technique sheet: IDOR (Insecure Direct Object Reference / broken object-level authorization, BOLA) is the class where a server fetches or mutates an object by a client-supplied identifier without verifying the requester owns or may act on that object."
domain: cybersecurity
subdomain: web
tags:
- web
- idor
- hunting
- l3
version: '1.0'
---

# IDOR — Technique Sheet

## Overview
IDOR (Insecure Direct Object Reference / broken object-level authorization, BOLA) is the class where a server fetches or mutates an object by a client-supplied identifier without verifying the requester owns or may act on that object. It is the single highest-frequency, highest-yield API bug class in these records: fully unauthenticated mass PII dumps, account deletion, fund transfers, privilege escalation, and full account takeover chains all appeared. It pays anywhere an endpoint takes an ID — cookie value, path segment, GraphQL node id, base64 blob, uuid, or form field — and the only "auth" is possession of the identifier.

## Distinct sub-patterns

### 1. Numeric path/parameter ID substitution (classic)
- Shape: `GET /users/{num}`, `GET /profile?UID2=...`, `POST /support/ticket_edit.html?ID={num}`, `GET /reports/quizzes-taken-by-user.csv/{num}`, `POST /observe/v2/profiles/{num}`, `GET .../RegistrationConfirmation.aspx?stu={num}`
- Payload: verbatim — `UID2=4820036 (replacing UID2=4820038)` (HackerOne #1004745); `1226356` as USERID (GSA #1118638); `1001` as `stu` (DoD #1100383); `<victim_id>` as the `ID` multipart field (Acronis #1124974).
- Root cause: server trusts the identifier as identity. DoD profile page used the `UID2` *cookie* to select the user; Acronis ticket edit trusted the client-supplied `ID`; GSA quiz CSV download trusted `USERID`.
- Impact proven: view another user's full profile (#1004745); read any user's quiz results CSV including full name, agency, title (verbatim: `Sharon, Cly-Stryker, Department of the Interior, ... 100%`) (#1118638); enumerate thousands of candidates' names (#1100383); read all users' support tickets (#1124974); enumerate all topcoder users' email/name/profile_id via uid substitution on Chameleon `/observe/v2/profiles/` (#1073420).
- Exemplars: 1004745, 1124974, 1118638.

### 2. Unauthenticated enumeration → mass PII scrape / takeover chain
- Shape: any endpoint with a sequential numeric ID and *no auth at all*: DoD user-operations endpoint (`POST /██████` with `UID`, `sendingForm`), GSA `GET /user/tams/api/usermgmnt/pendingUserDetails/{num}`, DoD PII+reset-PIN endpoint, DoD `stu` parameter.
- Payload: sequential ID cycling (`curl ... --data-raw 'sendingForm=██████'`); numeric registration IDs; `getAttachmentBytes/{id}` for attachment download.
- Root cause: admin-only functionality left unauthenticated AND without per-object authorization; IDs are sequential.
- Impact proven: scrape full names, emails, military branches, ASVAB scores for all registered users (#1048540); registration details (email, address, phone, roles) + unauthenticated attachment download for arbitrary IDs (#1061292); and the killer chain — enumerate user IDs to get first/last name, mobile, email, AND the password-reset PIN, then use the PIN in forgot-password to reset any account: mass ATO (#1061736).
- Exemplars: 1048540, 1061292, 1061736.

### 3. Destructive IDOR — delete/transfer/mutate another user's object
- Shape: `DELETE /users/{num}` (Ubiquiti community), `POST /{thailand}/card/transfer` (Starbucks, params `CardNumber`,`FullAmount`), Lark bin delete via folder `token`, OpenMage address edit by `address id`, X/Revue `POST /app/items` with `issue:<id>`, Reddit GraphQL `updateSound` by `uuid`, Tumblr timeline GET by `post id`, Bumble `GET /api/user-list?folder_id=`.
- Payload: Starbucks: change `CardNumber` to a victim's valid card number and submit `FullAmount` — transfer succeeded even when the UI errored on oversized amounts; X: `{"item_type":"image","issue":347976,"id":null,"title":"Your account has been hacked",...}`; Bumble: `folder_id=7 (replacing folder_id=0)`.
- Root cause: write endpoints authenticate the user but never check object ownership — deletion by numeric user id, fund transfer by client-supplied card number, issue content injection by issue id, sound rename by public uuid.
- Impact proven: closed other users' accounts and deleted all their data (#156537); drained a victim's Starbucks card balance (#766437); viewer-role user permanently deleted files from an admin's bin with only the folder token (#1074420); added arbitrary titles/images to other users' issues — issue hijacking (#1096560); renamed another user's sound track (#1102365); read a private Tumblr post from a push-notification post ID (#2258950); enumerated deck folder contents with plaintext `user_id`, `vote`, `is_match` (#1005020).
- Exemplars: 156537, 766437, 1096560.

### 4. Cross-tenant IDOR / privilege escalation
- Shape: Uber `POST /_rpc?rpc=updateEmployees` (param `employeeUuid`); Stripe GraphQL `UpdateAtlasApplicationPerson`; Shopify GraphQL `UpdateOrganizationUserRole` / `UpdateOrganizationUserTfaEnforcement`; Uber restaurant GraphQL (no per-restaurant authz); Uber `GET /loyalty-program/analytics/{restaurant_id}`.
- Payload: verbatim Shopify mutations —
  `{"operationName":"UpdateOrganizationUserRole","variables":{"id":"Z2lkOi8vb3JnYW5pemF0aW9uL09yZ2FuaXphdGlvblVzZXIvMzQwNzE2MzI=","roleId":"Z2lkOi8vb3JnYW5pemF0aW9uL1JvbGUvNjYxAAA="}}`
  `{"operationName":"UpdateOrganizationUserTfaEnforcement","variables":{"id":"Z2lkOi8vb3JnYW5pemF0aW9uL09yZ2FuaXphdGlvblVzZXIvMzQwNzE2MzI=","enforced":false}}`
  (ids are base64 of `gid://organization/OrganizationUser/34071632` — decode, swap the numeric suffix, re-encode).
- Root cause: GraphQL mutations validated the caller's session but not the tenant/organization of the target node. Shopify's variants had a twist: even when the cross-org call *failed*, it emailed the victim's PII (first/last name, email, 2FA status, shop id) — an info-disclosure side channel on a rejected mutation.
- Impact proven: Business-tier "user" role escalated to admin and could edit other businesses' employees/invitations (#1063022); admin of one Stripe account added a co-founder to another merchant's Atlas application (#1066203); cross-org PII retrieval (#1084638, #1085042); any restaurant's sales statistics (#1116218/#1116387) and loyalty analytics across 3 endpoints (#1137819).
- Exemplars: 1084638, 1063022, 1066203.

### 5. GraphQL endpoint-level IDOR (CheckoutStatus-style enumerable queries)
- Shape: `POST /graphql` `CheckoutStatus(id: ID!)` on arrive-server.shopifycloud.com.
- Payload: verbatim `{"operationName":"CheckoutStatus","variables":{"id":"48805"},"query":"query CheckoutStatus($id: ID!) { checkoutStatus(id: $id) { ... on Checkout { id isShopPay payJsonParams status token url errorCode } ...` — IDs 1–48908 enumerated.
- Root cause: query returns checkout data for any sequential numeric checkout id with no ownership check.
- Impact: other users' checkout secret, token, payJsonParams, shopify_domain → access to the buyer's checkout page and shipping address. Exemplar: 1064869.

### 6. Encoded/obfuscated IDs that aren't authorization (base64 JSON, base64 GIDs, uuids)
- Shape: `GET /people-rater/entry?id={num}` where id = base64 of `{"id":N}`; Shopify `gid://` base64 node ids (sub-pattern 4); `GET /swag-shop/api/user?uuid={uuid}`.
- Payloads (verbatim): `id=eyJpZCI6MX0=` (= `{"id":1}`); variants that also worked: `eyJpZCI6MX0K` (with trailing newline), `eyJpZCI6MX0g` (with trailing space), `eyJpZCI6MX0%3d` (URL-encoded padding), and `eyJpZCI6MX0=` without padding context. Swag-shop: `uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043`.
- Root cause: encoding is confidentiality-theater; the server decodes and fetches without binding the id to the session. Note the malformed-padding/trailing-whitespace variants all returned the record — no strict validation.
- Impact: hidden/unlisted records (id=1, The Grinch) not exposed in any listing; h1-ctf flags `flag{b705fb11-fb55-442f-847f-0931be82ed9a}` and `flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}` (user `grinch`, full home address).
- Exemplars: 1065731, 1069039 (Reddit-attributed), 1069392. This pattern appears in ~20 records — extremely reproducible.

### 7. UUID/token-based IDOR where the secret is guessable or leaked
- Shape: `GET /swag-shop/api/user?uuid=...` fed by `GET /swag-shop/api/sessions` (leaks live session objects containing other users' uuids); Lark delete-by-folder-token.
- Chain (verbatim, #1069392): "Fuzzed /swag-shop/api/ and found sessions and user endpoints" → "Decoded leaked session token to get valid user uuid" → "Queried /api/user?uuid=<uuid>". Also found via gobuster (#1069141: enumerate hidden `/api/sessions`, base64-decode session objects, call `/api/user?uuid=`).
- Impact: any user's full profile (username, home address) unauthenticated; Lark viewer deleted admin's bin files with just the alphanumeric token.
- Exemplars: 1069392, 1074420.

### 8. Cross-account config/resource binding (Nextcloud Mail)
- Shape: `PUT /index.php/apps/mail/api/accounts/{id}` (full account update JSON: imapHost, imapUser, imapPassword, etc.); `POST /index.php/apps/mail/api/accounts/{num}/aliases` with `{"aliasName":"...","alias":"hellohello@test.local"}`.
- Payload: append another user's account id to the PUT body (verbatim full JSON in record #1094063); alias create against account id 2000 (#1129996).
- Root cause: no check that the account id belongs to the caller — or even exists (alias creation on id 2000).
- Impact: read another user's mailbox (subject, sender, meta) by then querying `/index.php/apps/mail/api/messages` for that account; create aliases on other users' mail accounts.
- Exemplars: 1094063, 1129996.

### 9. Missing/empty identifier fallbacks
- Shape: `GET https://delivery.shopifyapps.com/checkout/get_download_link?callback=jQuery&shop=<shop>&checkout_token=` (empty token); HackerOne `draft_sync` with `draft_id: "1"`.
- Payload: verbatim full URL in #1044285 — strip the jQuery callback suffix, checkout_token, and timestamp; server returns the most recent order's download link. HackerOne #1034346: unauthenticated `draft_sync` payload `{"draft_id": "1", "title": "...", "vulnerability_information":"..."}` modifying email-created drafts and attaching orphaned attachments (823 matched, `attachable_id` NULL).
- Root cause: nil/empty token → server defaults to "latest object" with no validation; draft lookup keyed by ID with `reporter/tracer` NULL and no auth.
- Impact: anyone incognito downloads the latest customer's paid digital assets (e.g. `WILD WOLF PG000892.zip`); attacker modified other users' report drafts and harvested orphaned attachments without authentication.
- Exemplars: 1044285, 1034346.

### 10. Logic-flavored IDOR — injection into the identifier field + stale-permission gaps
- Shape: Shopify `POST /api/storefront/conversations/{num}/order_lookup` with `order_number` accepting OR lists; Moneybird invoice/export download after permission revocation.
- Payload (verbatim): `{"order_lookup":{"email":"victim@example.com","order_number":"1000 OR 1001 OR 1002"}}` — first-order details retrieved by email alone, multiple orders enumerated per request (missing validation + rate limiting). Moneybird: no payload; download action skipped the permission re-check, so a user whose permissions were revoked kept downloading invoice exports from an open page.
- Impact: customer order enumeration (#1017576); unauthorized document download (#1137218).
- Exemplars: 1017576, 1137218.

### 11. IDOR as an enabler (username leak → bruteforce)
- Shape: DoD redacted path with `username` parameter; login panel with no rate limit.
- Root cause: IDOR leaks the otherwise-secret login username of other users (including `admin`); combined with no rate limiting on login.
- Impact: successful bruteforce against the admin login. Exemplar: 1093908.

## Bypass / chain notes
- Padding/whitespace variants on base64 ids all worked: `eyJpZCI6MX0=`, `eyJpZCI6MX0K` (newline), `eyJpZCI6MX0g` (space), `eyJpZCI6MX0%3d` (URL-encoded `=`). If a WAF blocks the exact re-encoded id, try these.
- Decode-then-mutate: base64 ids (`{"id":1}`, `gid://organization/OrganizationUser/34071632`) — decode, change the numeric suffix to 1 or to a target, re-encode.
- Leaked-reference chains: push-notification payloads leak private post IDs (#2258950); `/api/sessions` leaks live uuids (#1069392 et al.); own-session requests reveal your current id/attachment id for incrementing (#1034346); public profile pages leak target userIDs (#1073420).
- ATO chain: enumerate IDs → PII + reset PIN → forgot-password with leaked PIN (#1061736). Also IDOR-leak username → bruteforce (#1093908).
- Rejected-mutation side channel: cross-org GraphQL mutation fails but still emails the victim's PII (#1084638/#1085042) — even "failed" IDOR attempts can disclose data; check email notifications.
- Read-then-write: after hijacking a mail account id, query the messages endpoint for the mailbox to read mail (#1094063).
- State-dependent: permissions removed server-side can leave open pages/downloads authorized — test download/export actions after revocation (#1137218).
- OR-syntax in an identifier field (`1000 OR 1001`) turns one IDOR into bulk enumeration (#1017576).

## Gotchas / what NOT to do
- Do not mass-extract data beyond proof: the DoD researcher "unintentionally extracted data for a UID that was not their own" — automate carefully and stop at demonstration; a scraping mistake can turn a clean report into a legal problem (#1048540).
- Don't assume obfuscation = safe: base64, GID-style base64, and UUIDs were all defeated — either by decoding/encoding or by finding a leak of the uuid. Test both angles.
- Don't test destructive endpoints on real users: Ubiquiti (account deletion), Lark (permanent bin deletion), Starbucks (fund transfer) caused real state changes — use accounts/objects you control on both sides wherever possible, and report immediately.
- Don't stop at a 403-looking response on cross-tenant mutations — Shopify's mutations returned failure yet leaked PII by email.
- Don't forget unauthenticated variants: several of the worst findings (GSA pendingUserDetails, DoD user-ops, PIN disclosure, HackerOne draft_sync) required NO auth — always strip auth from an authenticated IDOR finding and retest.
- Empty/nil identifiers are valid test cases (empty `checkout_token` returned the latest order's link).
- An IDOR on an admin-only endpoint is still reportable even if the endpoint is "internal" — GSA's registration endpoints were admin-only but unauthenticated.
- Impact statements should name the actual data fields (email, address, ASVAB scores, checkout token) — that's what triage rated highly here.

## Real-world impact examples
- Mass account takeover: enumerated user IDs returned name, mobile, email and the password-reset PIN; PIN used in forgot-password to reset any account (DoD #1061736).
- Financial: transferred the full amount from a victim's Starbucks card by editing the `CardNumber` form field (#766437).
- Data destruction: deleted other users' community accounts and all data with only their numeric user id (Ubiquiti #156537).
- Bulk PII: full names, emails, military branches, ASVAB scores of all registered users (DoD #1048540); registration details + attachment downloads (GSA #1061292); thousands of candidate names (DoD #1100383).
- Privilege escalation: "user" role → admin cross-tenant via `updateEmployees` (Uber #1063022); co-founder added to another merchant's Atlas application (Stripe #1066203).
- Paid-content theft: latest customer's paid digital download link retrievable in an incognito browser (Shopify #1044285); checkout secrets/tokens/shipping addresses for IDs 1–48908 (#1064864/#1064869).
- Mailbox access: read another user's email subjects, senders, and metadata (Nextcloud #1094063); modify other users' report drafts and obtain 823 orphaned attachments unauthenticated (HackerOne #1034346).