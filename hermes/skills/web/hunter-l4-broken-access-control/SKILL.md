---
name: hunter-l4-broken-access-control
description: "Find and exploit broken access control / authorization flaws with real patterns."
domain: cybersecurity
subdomain: web
tags:
- web
- broken-access-control
- hunting
- l4
version: '1.0'
---
# L4 Playbook: Broken Access Control (hunter)

**L3 technique sheet:** `knowledge/sheets/broken-access-control.md` — (exists)

## When to use
Attack a target surface for Broken Access Control. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 1004007 [ajaysenr]
- endpoint: `GET /{path}/..;/examples/servlets/servlet/SessionExample`
- payload: `..;/examples/servlets/servlet/SessionExample`
- root cause: The proxy normalized the semicolon path segment '..;' differently from the backend Tomcat, bypassing the access-control protection and reaching defaul
- impact: Unauthenticated access to default Tomcat example scripts: session manipulation (potential admin account takeover), insecure cookie handling, source co

### 100938 [ajaysenr]
- endpoint: `POST /admin/mobile_devices.json`
- parameter: `device (APNS token)`
- payload: `Replay of POST /admin/mobile_devices.json (device/APNS token registration)`
- root cause: The mobile_devices.json endpoint did not re-check the Settings permission when a request was replayed after privileges were removed.
- impact: An unprivileged admin re-added their own APNS device and received order notifications despite lacking the Settings permission.

### 1010787 [ajaysenr]
- endpoint: `GET /request-access (eats-devicereturns.com)`
- parameter: `email`
- payload: `Lookalike-domain email satisfying the loose uber.com regex`
- root cause: Registration used a loose regex to verify uber.com emails and the platform had flat access control with no central Uber auth integration.
- impact: Registered with a lookalike-domain email, bypassed the uber.com-only registration, accessed site content, and gained control of the whole device-retur

### 1010835 [ajaysenr]
- endpoint: `POST /admin/internal/web/graphql/core`
- parameter: `id (BillingInvoice gid)`
- payload: `mutation BillingChargesExport($id:ID!,$exportFormat:ExportFormat){billingChargesExport(id:$id,exportFormat:$exportFormat){message userErrors{field message __typename}__typename}}`
- root cause: The billingChargesExport GraphQL resolver lacked a permission check for staff (returned 'Not found' instead of 'access denied' for an unprivileged mem
- impact: A low-privileged staff member could export billing charges (confirmed by Shopify); the query executed the resolver search for the BillingInvoice witho

### 1011767 [ajaysenr]
- endpoint: `GET /status, GET /swagger.json`
- parameter: `X-Forwarded-For (header)`
- payload: `X-Forwarded-For: 127.0.0.1`
- root cause: The server trusts X-Forwarded-For to decide internal-IP status (x-is-internal-ip-address: true), treating the attacker as internal.
- impact: Accessed restricted internal endpoints (/status and /swagger.json of the Business Owner App backend API) that are otherwise blocked.

### 1018094 [ajaysenr]
- endpoint: `POST /admin/graphql (retailUserDataUpdate)`
- parameter: `posAccess, pin`
- payload: `{"query":"mutation {retailUserDataUpdate(id:\"gid://shopify/StaffMember/{num}\",retailUserData:{posAccess:true,pin:\"1423\"}){staffMember{name canAccessPrivateApps authenticationSettings{tfaEnabled}}u`
- root cause: The retailUserDataUpdate GraphQL mutation lacked a permission check, so a Manage-Locations-only staff member could flip their own POS access.
- impact: A staff member with only Manage Locations permission enabled POS access and set a PIN for themselves without any admin interaction.

### 1018368 [ajaysenr]
- endpoint: `POST /apps/setcommonredists`
- parameter: `depot (app/depot id)`
- payload: `N/A (parameter-validation error)`
- root cause: A parameter-validation error on the redistributable-depot configuration endpoint allowed adding external depots to an attacker-owned app.
- impact: Added any depot to an attacker-owned app and accessed its contents without the decryption key.

### 1021776 [ajaysenr]
- endpoint: `POST /create-payment`
- parameter: `merchant, amount, steamid`
- payload: `{"merchant":"cardpay","amount":10}`
- root cause: /create-payment requires only the victim's Steam ID (cookie) to create a payment on their behalf, with no ownership verification.
- impact: With only the victim's Steam ID, the attacker created a cardpay transaction (orderId 2034944) and cancelled it via the cardpay cancel URL, inserting a

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

