---
name: hunter-l3-missing-authorization
description: "Use when hunting Missing Authorization on a target. Loads the L3 technique sheet: Missing Authorization (CWE-862) covers cases where an action is reachable and functional, but the server never asks \"is this actor allowed to do it?\" Unlike broken access control between tenants, thes"
domain: cybersecurity
subdomain: web
tags:
- web
- missing-authorization
- hunting
- l3
version: '1.0'
---

# Missing Authorization — Technique Sheet

## Overview
Missing Authorization (CWE-862) covers cases where an action is reachable and functional, but the server never asks "is this actor allowed to do it?" Unlike broken access control between tenants, these bugs are often found on *priveleged-looking* endpoints (GraphQL mutations, SQL statements, protocol/consent gates, game-service RPCs) where the developer assumed the UI would gate the action. It pays on targets with permission tiers (staff/roles/USAGE-only accounts), on rich client-side consent flows, and on internal service methods exposed to any authenticated session.

## Distinct sub-patterns

### 1. GraphQL mutation exposed to low-privilege users (billing/credit mutations)
- **Endpoint shape:** `POST /admin/api/2021-07/graphql` — the admin GraphQL endpoint, accessed via the Shopify GraphiQL app (a first-party dev tool that relays any mutation the user can reach).
- **Payload that fired (verbatim):**
  ```
  {"operationName":"AppCreditCreatePayload","variables":{"description":"Themes credits","amount":{"amount":500.00,"currencyCode":"USD"},"test":false},"query":"mutation AppCreditCreatePayload($description:String!,$amount:MoneyInput!,$test:Boolean){\n appCreditCreate(description:$description,amount:$amo...
  ```
  Note the `"test":false` — the credit was a real, non-test credit.
- **Root cause:** The `appCreditCreate` mutation (intended for partner/app developer tooling) was executable by store owners/staff holding only the low-sensitivity `apps` permission. The GraphiQL app acted as an authorized relay; the mutation itself had no capability check tying it to an app-developer relationship.
- **Impact proven:** Created a $500.00 application credit visible on the billing page; repeatable without limit → unlimited free application credits (direct monetary impact).
- **Exemplar:** id=1257428 (Shopify).

### 2. Database engine statement missing a privilege check (CWE-862 at the SQL layer)
- **Endpoint shape:** SQL statement on a SingleStore aggregator host: `SELECT ... INTO OUTFILE` — not an HTTP route at all, but a statement any connected client can issue.
- **Payload:** `SELECT ... INTO OUTFILE` (full statement not stated in the record).
- **Root cause:** The engine implements `INTO OUTFILE` but never enforces the `FILE WRITE` privilege (explicitly classified CWE-862). The privilege model documents the check but the code path skips it, so authorization for a documented privileged operation is simply absent.
- **Impact proven:** Any authenticated user — including one with only `USAGE` privileges (effectively no grants) — could write arbitrary files to the aggregator host at any filesystem path, as the engine's OS user. This is a direct path to RCE via cron/config/SSH-key writes.
- **Exemplar:** id=3780695 (SingleStore).
- **Lesson:** When testing database-like services, enumerate every statement that touches the filesystem and test it from a minimally-privileged account (`USAGE` only). "Privilege exists in docs" ≠ "privilege enforced in code."

### 3. Game-service RPC missing consent/permission gating
- **Endpoint shape:** An RDR2 game service method for creating a Posse and adding members (internal service method invoked by the game client; exact route/payload not stated).
- **Payload:** not stated — the bug is in the method's authorization, not the input.
- **Root cause:** The "create Posse" and "add member" service methods checked nothing about the target's consent or relationship. The client UI makes adding a member look opt-in, but the server-side method performs it unconditionally on any Social Club account ID.
- **Impact proven:** Attacker could create new Posses and add *any* Social Club account to them without the target's knowledge or consent — a forced-association/harassment vector against arbitrary users.
- **Exemplar:** id=1029594 (Rockstar Games).
- **Lesson:** In game/platform programs, hunt service methods where the *target* of the action never consented — "add user X to group Y," invites, follows, team joins. Test with an arbitrary third-party user ID, not your own accounts.

### 4. Client-side consent decision persisting beyond its permission scope
- **Endpoint shape:** None — browser UI: the "Remember this decision" checkbox on a protocol-launch permission prompt (e.g. `bitcoin:` / hardware-wallet handler).
- **Payload:** not stated; the trigger is one manual "Allow" on a protocol launch.
- **Root cause:** The persisted "remember" decision was scoped globally (all websites) rather than per-origin and per-permission. Once granted once from any site, the launch bypassed the permission system entirely thereafter.
- **Impact proven:** A bitcoin hardware wallet opened automatically with prefilled payment info across *any* domain, with no further confirmation — one legit-looking grant turns into a browser-wide auto-launch.
- **Exemplar:** id=416040 (Brave Software).
- **Lesson:** In browser/client programs, audit every "remember this choice" flow: does persistence respect per-origin scoping and the underlying permission model? Test from a *second, unrelated* origin after granting once.

## Bypass / chain notes
- The records show no multi-step chains, but each bug effectively *is* a bypass of an intended gate:
  - **Shopify:** the GraphiQL app functions as an authorized relay — the mutation never checks the caller's permission tier. Replay through any tool that can talk to the admin GraphQL endpoint; the UI is not the control.
  - **SingleStore:** the privilege is documented (`FILE WRITE`) but the statement path skips it — no filter to bypass, the check simply doesn't exist. Any authenticated connection works, `USAGE`-only included.
  - **Rockstar:** the target's consent is enforced only in the client UI; calling the service method directly bypasses it.
  - **Brave:** persistence bypasses the per-site permission check on every subsequent launch.
- Common thread for chaining: monetary mutations (Shopify) chain trivially into direct financial loss; arbitrary file write (SingleStore) chains into RCE on the host; forced group membership chains into phishing (attacker-controlled Posse branding reaching victims' clients).

## Gotchas / what NOT to do
- Don't stop at "the UI doesn't let me." All four bugs were reachable through legitimate surfaces (GraphiQL app, SQL client, game client, browser dialog) — the missing check lives server-side, so drive the action through whatever client you legitimately have.
- Don't test privileged mutations with `test:true` or dummy data and assume the check is equivalent — the Shopify payload used a real, non-test credit (`"test":false`) and verified it on the billing page before reporting.
- Don't test "add user to group/posse" style bugs against real third parties — use accounts you control, and demonstrate on a test target.
- Don't assume a documented privilege model means it's enforced (SingleStore: `FILE WRITE` existed in the model, not in the code path). Verify empirically from a least-privilege account.
- Don't conflate authentication with authorization: all of these were fully authenticated actions with zero permission validation.
- For browser consent bugs, demonstrate persistence from a *different origin* than the one you granted from — that cross-origin leap is the bug; a same-site remember is not.

## Real-world impact examples
- **Unlimited free credits (Shopify, id=1257428):** a staff member with only the `apps` permission minted a real $500.00 application credit, confirmed on the billing page — repeatable for effectively unlimited store credit.
- **Arbitrary file write as engine OS user (SingleStore, id=3780695):** a `USAGE`-only account wrote files to any path on the aggregator host — one step from full host compromise.
- **Forced membership on any user (Rockstar, id=1029594):** arbitrary Social Club accounts silently added to attacker-created Posses — harassment/spoofing vector requiring no target interaction.
- **Browser-wide auto-launch of a bitcoin wallet (Brave, id=416040):** after a single "Remember this decision," a hardware wallet opened with prefilled payment info on any domain — one origin's grant silently became a global grant.