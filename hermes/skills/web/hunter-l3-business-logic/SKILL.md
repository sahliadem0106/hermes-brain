---
name: hunter-l3-business-logic
description: "Use when hunting Business Logic on a target. Loads the L3 technique sheet: Business logic bugs are flaws where the server fails to enforce a rule the application clearly intends to enforce — a price, a limit, an entitlement, an ownership check, a state transition, or a validation gate."
domain: cybersecurity
subdomain: web
tags:
- web
- business-logic
- hunting
- l3
version: '1.0'
---

# Business Logic — Technique Sheet

## Overview

Business logic bugs are flaws where the server fails to enforce a rule the application clearly intends to enforce — a price, a limit, an entitlement, an ownership check, a state transition, or a validation gate. Unlike injection classes, there is no malicious payload signature; the request is syntactically valid, it just violates the policy the UI or docs claim exists. This class pays consistently across fintech/e-commerce (payment amount tampering, discount stacking), SaaS (plan-gating bypass, seat-billing rounding), and platform programs (API-vs-UI enforcement gaps). The universal hunting method visible in these records: **drive the intended flow once, intercept every state-changing request, then mutate one field, boolean, or ID at a time — and always test the raw API even when the UI blocks you.**

## Distinct sub-patterns

### 1. API accepts what the UI blocks (server-side enforcement gap)

The single most frequent pattern in the records: the front-end enforces a rule, the API does not.

- **Endpoint shape:** any state-changing API called by a gated UI. Concretely:
  - `POST /federation/graphql` (Sorare) — payload `"captain":true` on *every* player via `CreateOrUpdateLineupMutation`. UI enforces single captain; API accepted multiple captains → 50% score bonus on all players. Report 2067247.
  - `PATCH /api/v2.0/accounts/{num}/ads/{num}` (Reddit Ads) — payload `{"data":{"configured_status":"ACTIVE","effective_status":"ACTIVE","admin_approval":"APPROVED"}}`. Client-supplied `admin_approval` was accepted → ad delivered with no payment and no admin review, plus confirmation email sent. Report 1543159.
  - `POST /voyager/api/publishing/contentSeries` (LinkedIn) — email-unverified user created a Newsletter via direct API call; verification enforced only in UI. Report 1691603.
  - `POST /api/screenhero.rooms.create` (Slack) — changed the `channel` form field to a target channel ID on a free account → started calls in paid-feature channels. $100 bounty. Report 147369.
  - Nextcloud Talk `POST /ocs/v2.php/apps/spreed/api/v1/chat/{id}/share` — the `metaData` JSON inside a deck-card share had an unvalidated `link` field, rewritable to any URL. Report 1358977.
  - HackerOne sandbox: `POST /{program}/team_members` (param `invitee`) and `POST /organizations/{org}/users/new_invite` (param `email`) both accepted invites the UI/docs forbade for sandbox programs. Reports 1088966, 1486417.
- **Root cause:** the rule lives only in client code; the API never re-checks entitlement/verification/review state.
- **Impact:** paid features for free, unauthorized state changes, moderation bypass.
- **Method:** trigger the action in the UI once where allowed, capture the request, replay against the restricted target/state.

### 2. Client-trusted response manipulation (booleans enforced client-side)

- **Endpoint shape:** `GET /api/v5/user/prime/subscription` (Logitech/Streamlabs). Payload: a Burp **Match and Replace** rule — response body `Match: false` → `Replace: true`.
- **Mars appointment flow:** intercept the email-verification response and flip `false` → `true` ("Change false to true" — verbatim payload) to pass the code check with a random code.
- **Root cause:** entitlement/verification status returned as a plain boolean that the client consumes without server revalidation at the action boundary.
- **Impact:** free Streamlabs Prime (reward coupon code, RTMP URL + stream key for multistreaming) — report 1070510; verification-code bypass — report 1943252.
- **Gotcha:** this only pays when a *subsequent server action* honors the client-side state (redemption endpoints, booking confirmation). Flipping a purely cosmetic response is noise.

### 3. Payment / amount parameter tampering

Client-controlled money fields with no server-side reconciliation:

- **Shopify POS:** `POST /admin/api/unstable/checkouts/{uuid}/payments.json` — client-controlled `amount_in` (2.09), `amount_rounding` (-1.0), `amount_out` (0) not validated against cart total → overcharge a customer or push money store→client. Report 1089978.
- **Reddit coins:** `POST /api/v2/gold/paypal/create_coin_purchase_order`, param `order_id` — order ID not bound to package/price; create a $1.99 order, substitute it into a $3.99 purchase, pay 1.99 and receive 1100 coins. Report 1213765.
- **LinkedIn Jobs:** payment flow ignored the server-configured minimum price → unlimited jobs at Rp 10,000 vs. Rp 93,151 floor. Report 1808149.
- **LinkedIn Premium:** pricing parameters tamperable → subscription at IDR 10,000 vs 462,400/month. Report 1808719.
- **FantasyTote:** deposit `amount` — 150 limit not enforced server-side; deposited 2000 on video PoC. Report 147220.
- **bitaccess:** bitcoin sell `amount` unvalidated → withdraw any amount. Report 144526.
- **Root cause:** price/order identity is decided client-side and trusted at settlement.
- **Method:** map every numeric/monetary field in the request; swap IDs across price tiers; set values above/below server limits.

### 4. Numeric-type confusion (overflow via scientific notation / rounding mismatch)

- **Endpoint shape:** `POST /signup-manager/` (h1-ctf). Verbatim payload: `action=signup&username=w31rdtest&password=password&age=1e5&firstname=loadsofys&lastname=abcdefgabcdeYYY` (variants: `age=9e9`, `age=1e9&lastname=smithYYYYYYYYYY`).
- **Root cause:** `age` validated with `is_numeric`/`strlen`, but converted with PHP `intval()` — `'1e5'` → 100000, overflowing the fixed-width 113-char record and overwriting the trailing admin flag `N` with `Y` in `users.txt` → admin login → flag. Reports 1065731, 1065885, 1069141.
- **Krisp seats:** `PUT /v2/seats`, param `seats`, payload `1.9` — server adds `Math.ceil(1.9)=2` seats but bills `Math.floor(1.9)=1` → second seat free. Report 1446090.
- **Lesson:** any numeric field that passes a string-length/regex check but is later *coerced* is a candidate; so is any ceil/floor pair straddling an integer boundary.

### 5. Unauthenticated/unowned cross-object reference (ID or token substitution)

Substituting someone else's (or another state's) identifier into a valid flow:

- **Tumblr Post+ checkout:** `GET https://{blog}.payment.tumblr.com/checkout/`, params `token`, `blogMembershipsId` — swap the active creator's ID for an inactive (opted-out) creator's inside the token → subscribe to and re-activate a creator who left Post+. Report 1322334.
- **VK polls:** poll-edit API never verified the editor was the poll's creator or group admin — get poll id via `wall.getById`, repost via `wall.post`, then edit answer options; changes propagate to the original live post. Report 107664.
- **EXNESS KYC:** `PATCH /kyc_back/api/v2/surveys/personal_info` (params `first_name,last_name,dob,address`), payload `{"first_name":"test-1","last_name":"test-2","test-3":"","dob":"1990-01-01","address":"test-4"}` → verified identity mutable post-verification (200 `{"status":"OK"}`); separately, document review never checked documents matched the account holder → trade under someone else's identity. Report 1446107.
- **Root cause:** state (ownership, verification, enrollment) checked at one step but not re-checked at the mutation step.

### 6. Missing single-use / redemption-limit enforcement (no race needed)

- **Stripe:** `POST /ajax/accept_fee_discount_offer`, param `fdo_` id — the endpoint enforced no single-redemption; called 30 times, 30 discounts applied instantly → **$600,000** of fee-free processing (intended: $20,000). No race condition required. Report 1849626.
- **X/Twitter Blue:** verified-badge restore flow never re-validated subscription expiration after the review cycle → free verified badge after canceling. Report 1841064.
- **Method:** find any "redeem/accept/claim" endpoint and simply repeat it.

### 7. Rate-limit absence enabling abuse or DoS

- **Stripo:** `POST /cabinet/stripeapi/v1/plugin/{num}/plugins` (params `email, name, webUrl`, payload includes a Burp Collaborator host `pxqx0kafueopargwjcp9bmtiv91zpo.burpcollaborator.net`) — no rate limiting even after a prior fix (#1047119); 100 rapid plugin creations consumed disk, 503 under concurrency, repeatable. Report 1076047.
- **Shopify 2FA:** resend-code endpoint on accounts.shopify.com had no rate limit → flooding exhausted the victim's OTP quota and locked them out of login for 24 hours (zero-click DoS). Report 1406495.
- **Root cause:** quota/cost-bearing operations without throttling.
- **Gotcha:** for OTP-flood DoS, impact framing (lockout duration, zero-click) is what makes it pay.

### 8. Limit / quota enforcement bypass via flow manipulation

- **Uber Partner:** the 3-consecutive-cancel limit (logout + deny going online) could be bypassed so it never triggered — confirmed by program. Report 125218.
- **Uber surge:** fare estimate reuses a stale pickup from a non-surge area; select non-surge pickup, switch into the surge zone, book → UberPool 191.48 instead of 249.91 at 1.3x surge. Reporter personally used it. Report 125250.
- **Root cause:** limit computed against one input but the flow allows changing the condition after the check.

### 9. Validation-string mismatch across flows (policy inconsistency)

- **Enjin:** reset-password page enforced 6-char policy while registration/change-password enforced 8 → weaker post-reset password. Report 1083531.
- **UPchieve:** `POST reset-password` never verified new ≠ old password. Report 1296597.
- **Nextcloud admin toggle:** `POST /nextcloud/index.php/settings/ajax/togglegroups.php`, payload `username=admin&group=admin ` (trailing space, verbatim) — no trimming meant the trailing-space value bypassed the protection against removing the default admin from the admin group. Report 145745.
- **Root cause:** two code paths implement "the same" rule differently; whitespace, casing, and length policy drift are the exploit primitives.

### 10. Reserved-name / reserved-path protection gaps

- **HackerOne:** username change accepted `h1_analyst_refo` — the `h1_analyst_*` prefix reserved for staff → impersonation of analysts. Report 1770797.
- **Shopify linkpop:** reserved-path check blocked `/graphql` but allowed creating a page at `/performance_report`, conflicting with a live backend POST endpoint (`POST /performance_report`). Report 1459338.
- **Root cause:** denylist incomplete; enumerate sibling reserved names/paths and probe each.

### 11. Entitlement derivation from user-controlled attributes

- **Glovo:** `POST signup` with param `email`, payload `admin_@glovoapp.com` — a `@glovoapp.com` address was classified as internal/team → "FREE delivery Glovo Team ∞" on a fresh account, while a regular email at the same location got nothing. Report 1296584.
- **Root cause:** entitlement inferred from email domain/prefix rather than a server-side role flag.
- **Method:** signup with lookalike internal addresses (`admin_@`, `team@`, `support@` on the company's own domain).

### 12. State-machine / destructive-action defects

- **DigitalSellz:** account deletion silently no-ops unless a product was added, while showing success — account persisted with data. Report 20305.
- **Nextcloud bookmarks import:** `POST /apps/bookmarks` importing a bookmark.html containing `<a href="">Bookmark</a>` (verbatim) made `addBookmark` select *all* the user's bookmarks and overwrite them with blank URLs → mass data loss. Report 154529.
- **curl `--no-clobber --remove-on-error`:** payload `curl -m 3 --no-clobber --remove-on-error --output foo http://testserver.tld:9999/` — remove-on-error unlinked the pre-existing `foo` instead of the partial `foo.1` (CVE-2022-27778, data loss). Reports 1553598, 1565623.
- **Root cause:** bulk/batch operations applied to the wrong scope; error-path cleanup operating on stale state.

### 13. Authorization-hash / verification-token weaknesses in server-to-server flows

- **h1-ctf attack box:** `GET /attack-box/launch?payload={base64}` — payload `{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}`; hash = `md5(salt+target)` with dictionary salt `mrgrinch463` cracked from rockyou (hashcat mode 0) → forge arbitrary targets. Second variant: **TOCTOU** — hostname checked as non-local pre-attack but re-resolved without the check during the attack; DNS rebinding via `rbndr.us` (payload: `https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS4xNDE0MTQxNC5yYm5kci51cyIsImhhc2giOiIxZmEyZjM0NjA2YjlkMjFhNzNjZDYyNDI1OTVhOGNlZSJ9`) or local `dnschef -i 0.0.0.0 --fakeip 127.0.0.1` → DDoS 127.0.0.1. Reports 1065731, 1065885, 1069141.
- **Root cause:** weak/forgeable MAC over the parameter, and check-then-use separation between validation and action phases.

### 14. Cryptographic / protocol round-trip logic errors (library-level)

- **Ruby REXML:** parse→`to_s`→parse round-trip changed document structure (first child `<Y/>` became `<Z/>`) using `<!DOCTYPE x [ <!NOTATION x SYSTEM 'x">]"><!--'> ]>` and CDATA/comment interleaving → SAML auth bypass/priv-esc (CVE-2021-28965). Report 1104077.
- **curl schannel:** static `algIds` array in `set_ssl_ciphers` let the last `CURLOPT_SSL_CIPHER_LIST` leak into concurrent connections (CVE-2021-22897). Report 1172857.
- **curl metalink:** hash-mismatch only warned; tampered file kept on disk. Report 1213175.
- **Root cause:** validation state (parser, cipher config, hash result) not carried through the full operation lifecycle.

### 15. Review-workflow signal gaming (platform-specific)

- **HackerOne self-close:** creating and self-closing a report still moved the reporter's signal score, contrary to the documented 0-baseline (`POST /reports/{id}/close`). Reports 106305, 108928.
- **HackerOne mediation:** `POST /reports/{id}/hacker_help`, payload `message=&mediation_type=resolution` / `message=Example+Message&mediation_type=resolution` — frontend blocked mediating too-old reports but backend accepted forged requests with an old report id → repeated spam of support emails. Reports 156948, 159512.
- **Root cause:** frontend/backend validation divergence on workflow transitions.

## Bypass / chain notes

- **UI → API replay:** the dominant chain. Where the UI refuses (gated plan, unverified email, sandbox restriction, disabled form control), capture the equivalent API call from an allowed context and replay modified. Coinbase legal-name change (report 131192) is the purest case: only the front-end control was disabled; a crafted POST with correct parameter names worked.
- **Match-and-Replace rules:** preconfigure Burp rules for `false`→`true` on JSON booleans in verification/entitlement responses; one rule produced two payouts here (Logitech, Mars).
- **Multi-step state chains:** VK polls (get id → repost → edit → propagates to original), Tumblr checkout (obtain active URL → swap `blogMembershipsId` → complete), h1-ctf attack box (extract hash → crack salt → forge → rebind DNS → fire), Stripo rate-limit (prior fix #1047119 showed the endpoint remained open — re-test after every fix).
- **Numeric coercion bypasses:** scientific notation (`1e5`, `9e9`, `1e9`) to slip past string-length validation, fractional values (`1.9`) to split ceil/floor billing, and trailing whitespace (`admin `) to dodge exact-match protections.
- **DNS rebinding / TOCTOU:** where a hostname is validated before use and re-resolved after, `rbndr.us` or `dnschef` flipping between a pass-check IP and the internal target closes the gap.

## Gotchas / what NOT to do

- Don't stop at the UI error: the Uber photo-change bug (report 101063) paid precisely because the server applied the change despite a "Failed to update account details" message — verify server state after every "failed" request.
- Don't flip client-side booleans without proving a server-honoring downstream action; the record shows payout required real entitlement consumption (coupon code, stream key).
- Don't assume fixes are complete: Stripo's rate limit was missing *after* a related fix — re-test patched endpoints.
- Don't test payment manipulation on production stores: the Shopify POS reporter used a test store, and Shopify still flagged it as not fully verified — scope your money-tampering evidence carefully.
- Don't ignore "documented restriction" claims — HackerOne sandbox invite bans were bypassed twice via different endpoints (1088966, 1486417). Docs are a checklist, not ground truth.
- Don't overlook exact-match protections: try whitespace, case, and Unicode-adjacent variants (`admin ` worked on Nextcloud; `h1_analyst_*` prefix worked on H1).
- Note honestly when a payload isn't applicable — many records here (DELETE flows, cancel limits, fare estimates) are pure flow-manipulation bugs with no payload at all; the technique is the request sequence, not a string.

## Real-world impact examples

- **$600,000 fee-free Stripe processing** from 30 repeated calls to one endpoint (1849626) — the largest single-figure impact in the set, achieved with no race.
- **Free Streamlabs Prime** including a physical-goods coupon and multistream RTMP credentials from a single response replace rule (1070510).
- **1100 coins for $1.99** (priced $3.99) on Reddit by substituting an order_id (1213765).
- **Full admin takeover of a CTF user store** via `age=1e5` scientific-notation overflow flipping an `N` flag to `Y` (1065731).
- **All players as captains** in a competitive fantasy-football lineup — unfair advantage from one GraphQL boolean (2067247).
- **Ads delivered unpaid and unreviewed** with Reddit's own approval email sent (1543159).
- **24-hour zero-click account lockout** via OTP-resend flooding (1406495).
- **Surge pricing avoided on a real, personally-used ride:** 191.48 vs 249.91 (125250).
- **Verified trading account operating under a false identity** on EXNESS via post-verification PATCH (1446107).
- **CVEs from logic errors in core tooling:** CVE-2021-28965 (REXML/SAML auth bypass), CVE-2021-22897 (curl cipher leak), CVE-2022-27778 (curl file deletion), CVE-2022-29163 (Nextcloud forced-password bypass via circle shares).