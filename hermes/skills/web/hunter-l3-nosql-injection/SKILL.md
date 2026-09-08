---
name: hunter-l3-nosql-injection
description: "Use when hunting NoSQL Injection on a target. Loads the L3 technique sheet: NoSQL injection here means injecting MongoDB operators (`$regex`, `$ne`, `$where`, `{\"roles\": ...}` query objects) through parameters that the server passes directly into Mongo queries without type or operator validation."
domain: cybersecurity
subdomain: web
tags:
- web
- nosql-injection
- hunting
- l3
version: '1.0'
---

# NoSQL Injection — Technique Sheet

## Overview

NoSQL injection here means injecting MongoDB operators (`$regex`, `$ne`, `$where`, `{"roles": ...}` query objects) through parameters that the server passes directly into Mongo queries without type or operator validation. It pays wherever JSON/query parameters flow into `find()`/`findOne()` unvalidated — login forms, "custom query" APIs, Meteor RPC methods, and OAuth token lookups. Proven outcomes in these records range from blind credential/token brute-forcing to full account takeover and arbitrary command execution. The class is highly repeatable: 4 of 6 records are Rocket.Chat, suggesting Meteor/Node apps exposing Mongo queries via RPC or REST are prime hunting grounds.

## Distinct sub-patterns

### 1. Blind `$regex` operator injection on login (JSON body, boolean oracle)

- **Endpoint shape:** `POST /login` — any login handler accepting a JSON body with a user/email identifier field.
  Template: `POST /login` with body `{"loginEmail": {...}, "loginPassword": ...}`
- **Payload that actually fired (verbatim):**
  ```json
  {"loginEmail": {"$regex": "^<guess>"}}
  ```
  Sent as the `loginEmail` parameter of the login request. The `$regex` is grown character-by-character (`^a`, `^al`, `^ala`, ...) against a known-valid password (or by observing login error differentials).
- **Root cause:** The login handler passes JSON body parameters directly into a MongoDB query without type checks (a string is expected; an object containing Mongo operators is accepted) and without sanitization. `$regex` inside the object is interpreted by Mongo as a query operator.
- **Impact proven:** Enumerated ALL customer and administrator email addresses from the MongoDB database via blind field extraction — extracted `alan.k@example.com`, `alice.r@hotmail.com`, `ben76543@gmail.com`, `bob@test.com`.
- **Exemplars:** id=397445 (Node.js third-party modules program).

### 2. `$where` JavaScript injection on a "custom query" API parameter (blind JS oracle)

- **Endpoint shape:** REST API accepting a client-supplied Mongo query as a parameter.
  Template: `GET /api/v1/users.list?query=<urlencoded JSON>`
- **Payload that actually fired (verbatim):**
  ```json
  {"$where":"this.roles.includes('admin') && /^A/.test(this.services.password.reset.token)"}
  ```
  URL-encoded into the `query` parameter. The regex `/^A/` is iterated over a charset to extract the reset token character-by-character; the `roles.includes('admin')` predicate scopes the oracle to admin documents.
- **Root cause:** The `users.list` API passes an unsanitized custom query — including MongoDB's `$where` operator, which executes arbitrary server-side JavaScript against each document — straight to MongoDB. Any document field is testable via `/regex/.test(this.<field>)`, turning the endpoint into a blind per-character extraction oracle.
- **Impact proven:** Leaked the admin email, password hash, and password reset token; used them to reset the admin password and take over the admin account; then created an incoming webhook script to execute commands as the `rocketchat` user (`whoami` confirmed), giving full DB read/write/delete and control of the instance.
- **Exemplars:** id=1130874 (Rocket.Chat).

### 3. Plain query-object injection for unauthorized data reads (no operators needed)

- **Endpoint shape:** Same REST surface: `GET /api/v1/users.list?query=<JSON>`. The key insight: if the raw query is passed through, you don't need operators at all — just supply a Mongo filter the server would never apply itself.
- **Payload that actually fired (verbatim):**
  ```
  query={"roles":"admin"}
  ```
- **Root cause:** The `users.list` REST endpoint passes a client-supplied query directly to `Users.find` (MongoDB) without sanitization. Authorization is normally enforced by the server constructing its own filter; injecting a raw filter lets the client select documents outside its permission scope.
- **Impact proven:** An authenticated user with only `view-d-room` permission retrieved admin user metadata including emails via `query={"roles":"admin"}` (password hashes were excluded from the response). Assigned CVE-2022-32219.
- **Exemplars:** id=1140631 (Rocket.Chat).

### 4. `$regex` wildcard (`{ $regex: ".*" }`) on an ID-typed parameter → IDOR

- **Endpoint shape:** Meteor RPC method taking an identifier that is looked up in Mongo.
  Template: `getS3FileUrl` with param `fileId`.
- **Payload that actually fired (verbatim):**
  ```json
  { $regex: ".*" }
  ```
  Sent as the `fileId` value — an object where a string was expected.
- **Root cause:** `fileId` was not validated as a string and was passed directly into a Mongo query, so the regex matched arbitrary uploads. Compounding it, the returned S3 URL had no access check on retrieval — the injection bypassed the ID check and the URL itself granted access.
- **Impact proven:** An authenticated user enumerated and retrieved S3 file upload URLs for files they should not access, disclosing the file contents.
- **Exemplars:** id=1458020 (Rocket.Chat).

### 5. `$regex` character-class brute-force of session tokens + wildcard rid (unauthenticated, two-step)

- **Endpoint shape:** Meteor RPC methods for livechat: `livechat:loginByToken` (param `token`) and `livechat:loadHistory` (params `token`, `rid`).
- **Payload that actually fired (verbatim):**
  ```json
  token: { "$regex": "^${knownValid}[${guesses}]" }
  rid:  { "$regex": ".*" }
  ```
  The token payload is a prefix-anchored regex — concatenate the already-confirmed prefix (`${knownValid}`) with a character class of guesses (`${guesses}`) to extract the token one character per round-trip via the login success/failure oracle. The rid payload is a plain wildcard to match any room.
- **Root cause:** The `token` and `rid` parameters are passed directly into Mongo queries without type/operator validation, enabling `$regex` operator injection on both.
- **Impact proven:** An unauthenticated attacker brute-forced a livechat visitor token via `$regex` injection in `livechat:loginByToken`, then used a `$regex`-injected rid in `livechat:loadHistory` to load the full message history of a livechat room — leaking visitor traffic/data.
- **Chain (verbatim from record):**
  1. NoSQL-inject `$regex` into `livechat:loginByToken` token param to brute-force a valid visitor token
  2. With the leaked token, NoSQL-inject `$regex` (`.*`) into `livechat:loadHistory` rid to load the full room message history
- **Exemplars:** id=2580062 (Rocket.Chat).

### 6. Query-string operator injection (`[$ne]=null`) for authentication bypass

- **Endpoint shape:** OAuth login flow where the access token arrives as a query parameter.
  Template: `GET <rocket-chat-login>?access_token[$ne]=null` (PHP/Express-style param bracket syntax expands to the object `{"$ne": null}`).
- **Payload that actually fired (verbatim):**
  ```
  ?access_token[$ne]=null
  ```
- **Root cause:** A MongoDB operator passed as the `access_token` query parameter is deserialized into an object and matches the first OAuth token document in the database without supplying valid credentials — `token != null` is true for every stored token.
- **Impact proven:** Unauthenticated remote attacker bypasses authentication and performs account takeover; precondition is that at least one OAuth token exists in the database.
- **Exemplars:** id=3564655 (Rocket.Chat).

## Bypass / chain notes

- **Type-confusion is the universal bypass:** every record reduces to "server expects a string, attacker sends an object." No WAF signature needed — the payload is a legal JSON object or bracket-syntax query param. If a filter blocks `$regex` in one parameter, test siblings (loginEmail, token, rid, fileId, query, access_token all worked across these records).
- **Blind extraction loop (seen twice, ids 1130874 and 2580062):** anchor with `^`, grow prefix char-by-char with `[charset]` classes, use a response oracle (login success/failure or query match/no-match) as the boolean. With `$where` you can additionally scope and transform: `this.roles.includes('admin') && /^A/.test(this.<field>)`.
- **Post-extraction chains observed:**
  - Leaked password reset token → request reset → set admin password → account takeover → incoming webhook script → OS command execution as the app user (id=1130874). Full chain: leak target email via `$where` oracle → request password reset for target → leak reset token → leak TOTP/email 2FA secrets if needed → reset.
  - Brute-forced visitor token → wildcard `rid` → full room history read (id=2580062).
  - `$ne`-based auth bypass is a one-request account takeover when any OAuth token exists (id=3564655) — precondition matters for impact framing.
- **Injection + missing access check compounding:** in id=1458020 the regex matched arbitrary files AND the returned S3 URL had no access control — even a "metadata-only" injection became full file disclosure.
- **Don't need operators when the query is raw:** id=1140631 shows `{"roles":"admin"}` alone suffices. Test a plain filter object first; escalate to `$regex`/`$where` only if the server filters document selection for you.

## Gotchas / what NOT to do

- **Don't assume operators are stripped if the endpoint "sanitizes" obvious fields** — test every parameter independently; these records show email, token, rid, fileId, query, and access_token all accepted operators in the same codebases.
- **`$where` requires server-side JS enabled** (legacy `eval`-capable Mongo config); if it doesn't fire, `$regex` still works and is silent. Don't burn time on `$where` error messages — fall back to regex char-by-char.
- **Regex brute-force cost scales with token length × charset** — anchor with `^` and confirm each char before extending (the `${knownValid}[${guesses}]` shape), or you'll get false positives from partial matches.
- **Scope your extraction:** in id=1130874 the `$where` payload explicitly filtered `this.roles.includes('admin')` — unscoped `$regex: ".*"`-style extraction over a user collection is noisy and slower.
- **Impact framing matters:** id=1140631 leaked emails but hashes were excluded, and it was still CVE-worthy because of the authorization bypass; conversely, a NoSQL injection that only proves "query reflected in response" without data differential is weak — establish a two-response oracle (match vs. no-match) before reporting.
- **Password hashes excluded from one endpoint doesn't mean safe:** the same class of bug elsewhere (id=1130874) leaked hashes and reset tokens. Don't dismiss "only metadata leaked" — check what the primitive reaches.

## Real-world impact examples

- **Full server compromise (id=1130874):** blind `$where` extraction of admin email + password hash + reset token → password reset → admin takeover → incoming webhook script executing commands as the `rocketchat` user → full DB read/write/delete and command execution on the host.
- **Unauthenticated account takeover (id=3564655):** single unauthenticated request `?access_token[$ne]=null` logs the attacker in as the first OAuth-linked user.
- **Unauthenticated data breach (id=2580062):** token brute-force + `rid: {"$regex": ".*"}` → unauthenticated attacker reads entire livechat conversation histories.
- **Cross-tenant file disclosure (id=1458020):** `{"$regex": ".*"}` as fileId → S3 URLs for arbitrary uploads, contents disclosed.
- **Mass PII enumeration (id=397445):** all customer and admin emails extracted from the login endpoint's Mongo query.
- **Authorization bypass with CVE (id=1140631):** low-privilege user reads admin user records — CVE-2022-32219.