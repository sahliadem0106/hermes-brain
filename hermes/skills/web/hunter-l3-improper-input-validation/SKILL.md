---
name: hunter-l3-improper-input-validation
description: "Use when hunting Improper Input Validation on a target. Loads the L3 technique sheet: Improper Input Validation is the class of bugs where the server (or client parser) accepts data outside its expected domain — impossible coordinates, malformed identifiers, non-existent users, truncat"
domain: cybersecurity
subdomain: web
tags:
- web
- improper-input-validation
- hunting
- l3
version: '1.0'
---

# Improper Input Validation — Technique Sheet

## Overview

Improper Input Validation is the class of bugs where the server (or client parser) accepts data outside its expected domain — impossible coordinates, malformed identifiers, non-existent users, truncated strings, truncated ABI calldata, out-of-range numeric parameters — and then acts on it. The impact ranges from data-integrity pollution (fake analytics) to SSRF/LFI via parser confusion, forced action dispatch (SMS/call flooding), phishing-enabling UI desync (hidden ERC20 recipients), and in smart contracts, theft of entire collateral pools. It pays best where validation gaps feed directly into a business process: messaging, authentication, money movement, or geolocation.

## Distinct sub-patterns

### 1. Unvalidated geospatial coordinates stored server-side

- Endpoint shape / parameter: `POST /WhoService/putLocation` with JSON body params `latitude`, `longitude` (WHO COVID-19 Mobile App, reported twice: 1064149 and 838647).
- Payload (verbatim): `{"latitude": 22222222, "longitude": "9999999"}`
- Root-cause pattern: The server feeds the values into `S2LatLng.fromDegrees` (Google S2 library) and stores the result in the GAE datastore without ever checking the values are real Earth geometry (lat ∈ [-90, 90], lng ∈ [-180, 180]). S2 happily constructs out-of-domain cells; the library call is treated as validation when it isn't.
- Impact proven: HTTP 200 OK and the impossible coordinates persisted to the datastore. Attacker can falsify user location data and pollute downstream analytics — integrity and availability impact on aggregated data.
- Exemplar report IDs: 1064149, 838647 (same app; duplicate disclosure shows the pattern is robust to refactors).

### 2. Numeric-literal parsing deviation enabling downstream parser bypass (V8/eval/parseInt)

- Endpoint shape / parameter: Not an HTTP endpoint — `nodejs/V8` `eval`/`parseInt` semantics (Node.js program).
- Payload (verbatim):
```
console.log(08);
console.log(09);
```
- Root-cause pattern: Per ECMA-262, octal literals `08`/`09` containing digits 8/9 should be undefined (invalid octal). V8 instead evaluates them as defined values — `eval(08)` and `parseInt(08)` return `8`. Any downstream package that parses user input as a numeric string inherits the confusion: the canonical example is `netmask` IP-range parsing (CVE-2021-28918), where an octal-looking octet like `08` is interpreted inconsistently by validator vs. consumer.
- Impact proven: Octal-IP parsing bypasses in downstream packages, leading to SSRF / RFI / LFI.
- Exemplar report ID: 1141623.

### 3. Missing state validation: messaging from a banned entity

- Endpoint shape / parameter: `POST oauth.reddit.com/api/mod/conversations` (modmail send, Reddit). No special parameter — the flaw is contextual state, not a single field.
- Payload: not stated.
- Root-cause pattern: The API checks moderator permissions on the subreddit but does not check whether the subreddit itself is banned. Banned state is enforced at the site level, not at the conversation-send handler.
- Impact proven: Moderators could send messages "officially" from a banned subreddit — enabling ban circumvention, e.g. organizing a migration subreddit to reconstitute the banned community.
- Exemplar report ID: 1543770.

### 4. Calldata length/truncation desync between parser and warning UI (ERC20 signing)

- Endpoint shape / parameter: MetaMask browser extension ERC20 `transfer`/`approve` signing flow; the "parameter" is raw EVM `call data`.
- Payload (verbatim): `0xa9059cbb000000000000000000000000C588e338FdBB2CC523a1177f3D18e87FF5A16a6b00000000000000000000000000000000000000000000000000000000009897` — note this is a truncated `transfer(address,uint256)` calldata (short amount field; solc < 0.5.0 emits packed/truncated data).
- Root-cause pattern: MetaMask decoded calldata assuming fixed-length ABI fields. When the contract was compiled with solc < 0.5.0 (which packs tight variant data), the truncation shifts field boundaries — the decoder fails silently and the confirmation UI hides recipient, amount, and token symbol while still requesting signature.
- Impact proven: ERC20 Transfer/Approve transactions could be triggered without MetaMask showing the recipient, amount, or token symbol — phishing sites could induce users to sign blind token transfers/approvals.
- Exemplar report ID: 1651429.

### 5. No length/charset validation on email + database truncation

- Endpoint shape / parameter: `POST` account-settings, `email` field (Paragon Initiative Enterprises).
- Payload (verbatim): `a++++++++` (malformed charset); demonstrated further with 1000-character `+`-alias/suffix email variants.
- Root-cause pattern: No regex and no length check on the email field. Combined with MySQL `VARCHAR(128)` column truncation (silent truncation in non-strict mode), arbitrarily long `local+alias@domain` variants collapse to the same stored base address — yet still deliver to the same inbox via the mail transport.
- Impact proven: 1000-character and malformed emails accepted as valid; `+`-alias emails longer than 128 chars truncated in MySQL and still delivered to the base inbox (alias-collision / account-confusion primitive).
- Exemplar report ID: 226334.

### 6. No referential-integrity check: acting on non-existent entities

- Endpoint shape / parameter: Room moderator add/remove request (Chaturbate); the parameter is the target `moderator user`.
- Payload: not stated.
- Root-cause pattern: The server accepts adding/removing a non-existent user as room moderator — no existence validation of the target user before broadcasting the operation.
- Impact proven: Server broadcasts the add-moderator operation to the room for a non-existent user. No clear destructive side effects were identified — a valid but weak finding; severity hinges on downstream side effects.
- Exemplar report ID: 385239.

### 7. Overly permissive format regex (regression on a prior fix)

- Endpoint shape / parameter: `POST /attachments`, `tracer` field (HackerOne).
- Payload (verbatim): `zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzzzz`
- Root-cause pattern: The tracer validation regex was overly permissive — it accepted characters outside the UUID `a-f/0-9` range, bypassing the fix deployed for report #419896. Classic "fix the format check once, watch it regress" pattern; `z` is outside hex but matched the loose pattern.
- Impact proven: Server accepted a non-UUID-conforming tracer value in `/attachments`; believed to have an unknown cascading side effect.
- Chain (as recorded): (1) Submit a report with an attachment to capture the `/attachments` request; (2) replay the request with an invalid UUID tracer value and observe it is accepted.
- Exemplar report ID: 423073.

### 8. Loose pattern-match triggering forced server-side actions (SMS/call flood)

- Endpoint shape / parameter: `GET /method/auth.validatePhone`, params `sid` and `voice` (VK.com).
- Payload: not stated (any string matching a loose pattern suffices).
- Root-cause pattern: The `sid` parameter is not validated to be a legitimately issued format — any string matching a loose pattern causes the backend to dispatch an SMS activation code (and a voice call when `voice=1`), regardless of whether a verification flow was actually initiated.
- Impact proven: Endless SMS activation codes and calls could be triggered, even for users with 2FA disabled — cost and harassment impact on arbitrary phone numbers.
- Exemplar report ID: 64963.

### 9. Missing output-encoding on a profile field feeding an external client (Skype command injection)

- Endpoint shape / parameter: VK.com profile "Skype login" field, rendered into a `skype:` link.
- Payload (verbatim): `abr1k0s-helm?sendfile&`
- Root-cause pattern: The field does not filter characters such as `?`, so attacker-controlled text becomes Skype URI command parameters (`sendfile`) when a victim clicks the profile's Skype login link.
- Impact proven: A crafted Skype login triggers the file-send dialog on the victim's machine — a user who clicks it is induced to send their files to the attacker.
- Exemplar report ID: 65330.

### 10. Smart contract: public kick function with unvalidated bid parameter (MakerDAO MCD `flip.kick`)

- Endpoint shape / parameter: MCD `flip.kick` on-chain call; params `bid`, `lot`.
- Payload (verbatim as described): `flip.kick(bid >= total DAI supply, small lot)`
- Root-cause pattern: `flip.kick` lacks access control and does not validate the bid value, and can be called during liquidation; the `end` contract blindly trusts the bid recorded on the flip.
- Impact proven via modified `end.t.sol` test: steal ALL collateral stored in the MCD `end` contract in a single transaction via free DAI issuance.
- Chain (as recorded): (1) Create fake auction with arbitrarily large bid via `flip.kick`; (2) call `end.skip` to issue free DAI; (3) call `end.pack`/`end.cash` to convert DAI to all collateral.
- Exemplar report ID: 684092.

### 11. Smart contract: same pattern on surplus-auction `flap.kick`, cashed out post-cage

- Endpoint shape / parameter: MCD `flap.kick` on-chain call; params `bid`, `lot`.
- Payload (verbatim as described): `flap.kick(arbitrary large bid, small lot)`
- Root-cause pattern: `flap.kick` is public and does not validate the bid parameter. Fake auctions with forged bids can be created and later cashed out via `flap.yank` after `end.cage` (yank returns bid collateral = MKR at the forged bid value).
- Impact proven via modified `end.t.sol` test: steal arbitrary amounts of MKR deposited in the flap contract.
- Chain (as recorded): (1) Create fake flap auctions with large bid values; (2) wait for `end.cage`; (3) call `flap.yank` to receive MKR equal to forged bids.
- Exemplar report ID: 684152.

### 12. Business-logic validation gap: wrong password accepted for a security-sensitive action

- Endpoint shape / parameter: Authenticated account settings flow (8x8) — 2FA removal; endpoint not specified in the record.
- Payload: not stated.
- Root-cause pattern: Missing server-side validation allowed 2FA removal on the authenticated account while supplying a wrong password — the password re-check on the 2FA-removal action didn't actually enforce correctness (business logic flaw, not crypto).
- Impact proven: 2FA removed from the authenticated account using a wrong password — an attacker with session access (or the user themselves) can strip 2FA without knowing the account password.
- Exemplar report ID: 893085.

## Bypass / chain notes

- Regression bypass: the HackerOne tracer bug (423073) is a bypass of an earlier fix (#419896) — when testing format-validated fields, always probe with characters adjacent-but-outside the expected alphabet (`z` vs hex `a-f/0-9`), not just empty/garbage strings.
- Library-as-validation: both WHO reports (1064149, 838647) show parsers/geometry libraries (S2LatLng) being mistaken for validators. Test numeric fields with wildly out-of-domain values (22222222, "9999999") — note the mixed types in the payload: one number, one string; permissive deserialization accepted both.
- Value-confusion chains: the Node.js 08/09 bug (1141623) only becomes SSRF/RFI/LFI through downstream consumers (netmask, CVE-2021-28918) — chain validator-vs-parser disagreement into whatever consumes the value.
- Contract chains: both MCD bugs require multi-step execution — flip: `kick → end.skip → end.pack/end.cash`; flap: `kick → end.cage → flap.yank`. The unvalidated input alone is inert; the theft comes from a second contract trusting the forged value.
- Cross-application trust chains: the VK Skype bug (65330) chains a weakly-validated profile field into a third-party client's URI handler — validation gaps become RCE-adjacent when output crosses application boundaries.

## Gotchas / what NOT to do

- Don't stop at "accepted with 200" alone. 385239 (non-existent moderator) was accepted as valid but the reporter found "no clear side effects" — impact hinged on demonstrating what the broadcast actually does. Prove the downstream effect before reporting.
- Don't assume the validation fix held. 423073 shows a prior fix being bypassed with a trivially different character. Re-test patched parameters with edge-of-alphabet inputs.
- Don't treat library calls as validation. If the app parses/converts input (S2, parseInt, ABI decode), the parse succeeding says nothing about domain validity.
- Don't forget mixed-type fuzzing. The working WHO payload mixed an integer latitude with a string longitude — try type variations, not just value variations.
- Don't report truncation without delivery proof. The email bug (226334) mattered because truncated aliases still delivered to the base inbox — demonstrate the observable effect of the truncation.
- Contract findings need executable proof: both MakerDAO reports were validated by modified `end.t.sol` tests, not theoretical reasoning about `bid` checks.

## Real-world impact examples

- Total collateral theft (single tx): `flip.kick` with `bid >= total DAI supply` → steal ALL collateral in the MCD `end` contract (684092); arbitrary MKR theft via forged flap auctions (684152).
- Blind token theft enabler: MetaMask signed ERC20 transfers/approves with recipient, amount, and token symbol entirely hidden from the user (1651429).
- Parser-confusion SSRF/RFI/LFI: `eval(08)`/`parseInt(08)` returning 8 enabled octal-IP bypasses in netmask (1141623).
- Forced action / harassment: endless SMS codes and voice calls to arbitrary numbers via a loosely-validated `sid` on `/method/auth.validatePhone` (64963).
- File exfiltration via social click: `abr1k0s-helm?sendfile&` in a Skype profile field opens the file-send dialog toward the attacker (65330).
- Data integrity at scale: impossible coordinates (lat 22222222) stored with 200 OK in a pandemic-contact-tracing app, falsifying analytics (1064149, 838647).
- Auth bypass: 2FA removed with a wrong password (893085); official messaging from a banned subreddit (1543770).