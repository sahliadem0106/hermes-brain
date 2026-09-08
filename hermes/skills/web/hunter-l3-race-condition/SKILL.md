---
name: hunter-l3-race-condition
description: "Use when hunting Race Condition on a target. Loads the L3 technique sheet: Race condition bugs arise when a server performs a check (quota, uniqueness, one-per-user, balance) and then an action (create, grant, redeem, insert) without atomicity between the two — the classic check-then-act / TOCTOU gap."
domain: cybersecurity
subdomain: web
tags:
- web
- race-condition
- hunting
- l3
version: '1.0'
---

# Race Condition — Technique Sheet

## Overview
Race condition bugs arise when a server performs a check (quota, uniqueness, one-per-user, balance) and then an action (create, grant, redeem, insert) without atomicity between the two — the classic check-then-act / TOCTOU gap. In bug bounty this class pays whenever a "limited" resource can be multiplied: free credits, trial periods, gift cards, promo codes, votes, invitations, seats, and payout endpoints. The winning move is almost always the same: find a request whose response represents a one-time grant or a limit check, then replay it 10–50 times in parallel with near-identical timing (Turbo Intruder, `race.py`, HTTP/2 single-packet attack, or backgrounded curl loops) and compare the aggregate result against the intended limit.

## Distinct sub-patterns

### 1. Monetary credit / payout multiplication
- **Endpoint shape:** any endpoint that grants money once per event — survey credit, retest confirmation, bounty payout. E.g. POST account-creation survey endpoint (Slack), retest confirmation email link converted to curl (HackerOne).
- **Payload that fired:** for the H1 retest case, the email's retest confirmation request copied verbatim as a curl command, executed concurrently 5 times. Slack: two concurrent survey submissions from a fresh account.
- **Root cause:** no synchronization or idempotency key around the payment path; multiple payout requests for the same event are all processed before any deduplication runs.
- **Impact proven:** Slack: $100 credited twice ($200 total). HackerOne retest: $500 paid multiple times (id=429026). HackerOne also paid duplicate bounty payouts due to a race in payments code (id=220445).
- **Exemplars:** id=429026, id=165570 (also id=220445).

### 2. Gift card / promo code / coupon redemption replay
- **Endpoint shape:** `POST /fi/redeem` (Reverb, param `token`), `POST /promo_codes` redeem (Instacart, param promo code).
- **Payload that fired:** Reverb: `utf8=%E2%9C%93&authenticity_token=<CSRF token>&token=<GIFT card>&commit=Redeem+Now` — replayed concurrently. Instacart: coupon code `dallas20`, replayed asynchronously.
- **Root cause:** redemption lacks idempotency/locking; concurrent async requests each see the card/code as unredeemed.
- **Impact proven:** a single $25 Reverb gift card redeemed 7 times = $175 of Reverb bucks (id=759247). Instacart: same coupon redeemed repeatedly with savings stacked, "yielding virtually any discount" (id=157996).
- **Exemplars:** id=759247, id=157996.

### 3. In-app purchase / transaction verification replay
- **Endpoint shape:** `POST /api/v2/gold/android/verify_purchase` (Reddit), params `transaction_id`, `token`, `package_name`, `product_id`, `correlation_id`.
- **Payload that fired (verbatim, truncated):** `transaction_id=GPA.3390-9967-2355-57063&token=effmpcoplmjonhljkheipnce.AO-J1OyQ3ZXb7XM7JwoJPJqpNP3LgWYqHYUUmOE7o5hCzQtf4TC8GL0i71zvRVeZKl-I5rlQCfM0ID3Z0P8CTFSUmhbdbPvQwOIN0164LBE647_lDvB9aHzk2naeC59hSFrtJJYkYj2b&package_name=com.reddit.frontpage&product_id=com.reddit.coins_1&correlation_id=394e65c9-...`
- **Root cause:** the endpoint never enforced that a Google Play `transaction_id` is redeemed only once.
- **Impact proven:** 10 parallel verify requests on the same transaction — 9 succeeded, granting ~9x the purchased coins.
- **Exemplar:** id=801743.

### 4. Trial / free-tier / quota-limit bypass (check-then-create)
- **Endpoint shapes and payloads that fired:**
  - Bumble free-premium: `POST /webapi.phtml?SERVER_PROMO_ACCEPTED` with body `{"$gpb":"badoo.bma.BadooMessage","body":[{"message_type":402,"p_string":{"value":"delete_account_trial_spp_new_flow"}}],"message_id":101,"message_type":402,"version":1,"is_background":false}` — 3 concurrent requests yielded 9 days of Premium instead of 3 (id=1037430).
  - Weblate: `POST /trial/` with `csrfmiddlewaretoken`, raced via Turbo Intruder race.py — 6 trials from one account (50,000 x 6 strings, 100+ languages) (id=1087188).
  - Cosmos faucet: `POST /` with `{"address":"ALICE_ADDRESS"}` — 50 concurrent requests pushed balance to 30 tokens vs an 11-token `coins_max` (Go map not concurrency-safe) (id=1438052).
  - Krisp: `POST /v2/seats` — seat-limit check and allocation non-atomic, max-seat bypass confirmed (id=1418419).
  - Shopify: `POST create new store location` — 12 locations created on a 4-location plan (id=413759). Chaturbate: whitelabel subdomain add — soft 5-subdomain TOCTOU limit bypassed (id=395351).
  - Dust: `POST /api/w/{id}/knowledge/spaces/{id}/folders` — delete one folder, then fire simultaneous creations to exceed the 10-folder cap (id=3104355).
  - Enjin: cloud.enjin.io team invitation, and `POST /api/{create key}` — exceeded plan member limit and created API keys beyond the defined limit (id=1108291, id=2682392).
- **Root cause:** a quota check (count rows / read a limit) followed by a create, with no transactional lock, atomic counter, or unique constraint. The Dust variant is notable: the race window opens around a delete + re-create.
- **Exemplars:** id=1037430, id=413759.

### 5. One-time token / invitation / join-link double-spend
- **Endpoint shapes and payloads that fired:**
  - H1 invitation accept (id=119354): click accept in two browsers simultaneously — same token consumed twice, two separately logged-in accounts authenticated.
  - H1 CTF group join (id=1540969): `GET /group/join?invite=<token>` — 30 concurrent requests all returned 200; user appears repeatedly in the member list.
  - H1 group post_join (id=604534): `POST /group/post_join` with `csrf=...&invite=...` (verbatim: `csrf=391aecf0c3125e90c437d04c18204ab6&invite=bb5c42ab578b12c63e5d868b3e03816c8c45597262aaf095ca2be19116b8fd0a`) — added self twice, creating a permanent membership even the group leader couldn't delete.
  - FetLife: `POST /users/invitation` with `authenticity_token={token}&user%5Bemail%5D={email}`, 10 concurrent requests — 10 invites for the cost of 1; canceling sent invites enabled unlimited invites (id=1460373).
  - Omise: `POST /team/memberships` with `authenticity_token=<TOKEN>email=<INVITED-EMAIL>&membership%5Badmin%5D=0&membership%5Badmin%5D=1&membership%5Btechnical%5D=0&membership%5Btechnical%5D=1&commit=Send+invitation` — same email invited multiple times in one race (id=1285538).
- **Root cause:** token consumption / membership-insertion not atomic; every parallel request passes the "not yet a member / token unused" check.
- **Exemplars:** id=604534, id=1540969.

### 6. OAuth code / refresh-token multi-redemption
- **Endpoint shape:** `POST /oauth/token`, `grant_type=authorization_code`, params `code`, `client_id`, `client_secret`, `redirect_uri`.
- **Payload that fired (verbatim):** `curl --data "grant_type=authorization_code&code=AUTHORIZATION_CODE_VALUE&client_id=APPLICATION_ID&client_secret=APPLICATION_SECRET&redirect_uri=APPLICATION_REDIRECT_URI" "https://OAUTH_PROVIDER_DOMAIN/oauth/token" &` repeated ~20x.
- **Root cause:** token endpoint not atomic — concurrent redemptions of a single-use code each mint a fresh valid token pair.
- **Impact proven:** multiple valid access_token/refresh_token pairs; revoking access in the UI invalidates only one pair, the rest stay active (access-revocation bypass). Reproduced in 6 of 11 OAuth providers tested (id=55140).
- **Exemplar:** id=55140.

### 7. Vote / like / follow / reputation inflation
- **Endpoint shapes and payloads that fired:**
  - H1 report upvote: `POST /reports/{num}/votes` — concurrent replays returned vote_id 865 and 866, vote_count 48→49 from one account (id=146845).
  - Urban Dictionary: `GET /v0/vote?defid=3889203&direction=up&key=ab71d33b15d36506acf1e379b0ed07ee` — 11 parallel requests all returned `'status':'saved'`, up count 6429→6433 (id=183837).
  - Zomato/Eternal like/upvote on review comments — upvote count inflated (id=1409913). Judge.me like/follow — fake follower inflation (id=1566017). Rockstar "This Rocks" API — post rocked multiple times + victim's notification inbox flooded (id=474021). H1 `/hacker_reviews` feedback (params `hacker_username`, `report_id`, `positive`, `behavior`, `private_feedback`; payload `hacker_username=kijkijkoijkijkijkijkijki&report_id=1132085&positive=false&behavior=rude&private_feedback=Testing`) — 8 feedback emails and 3 records for one report (id=1132171).
- **Root cause:** vote/like/follow actions keyed on user but not enforced idempotently; each parallel request passes the one-action check before any insert lands.
- **Exemplars:** id=146845, id=183837.

### 8. One-time reward / credential / flag claim
- **Endpoint shapes:** H1 `POST /graphql` claimCredential mutation (`mutation Claim_credential_mutation ... claimCredential ...`); H1 `POST /flags/submit` (param `flag`).
- **Payload:** payload not stated beyond the mutation shape (claimCredential); flags/submit — same flag POSTed 70 times concurrently.
- **Root cause:** claims processed against an un-decremented counter; flag submission lacks synchronization so each concurrent submission counts.
- **Impact proven:** 22 parallel claim requests → one `was_successful:true` with a distinct credential set, multiple test credentials obtained (id=488985). 70 concurrent flag submissions earned extra points and 2 private-program invitations (id=454949). Similar: VK sticker race granted paid stickers without payment (id=1035320); Coinbase OAuth app review submitted multiple times (id=106360).
- **Exemplars:** id=488985, id=454949.

### 9. Email / notification bombing via non-atomic state check
- **Endpoint shape:** `POST /api/internal/graphql/requestAuthEmail` (Khan Academy), param `email`.
- **Payload:** payload not stated.
- **Root cause:** endpoint checks email state then sends; 30 parallel requests all pass the "already sent/already added" check.
- **Impact proven:** a random user received 30 "Finish signing up" emails in a short window, mostly with invalid links (id=1293377).
- **Exemplar:** id=1293377.

### 10. Account-state races (logout, 2FA reset, permissions)
- **Endpoint shapes / payloads:**
  - Shopify session race (id=340435→id=340435 listed as 340435's sibling id=340435; record id=340435 is id=340435 in records as id=340435 — record id=340435 appears as id=340435; the record is id=340435 in the data as id=340435): logout request raced against an in-flight product creation from the same session — logout fails while a request is in progress, session remains valid after logout (id=340435... in records: id=340435 is recorded as **id=340435**; see record id=340435). Payload: logout request racing an in-progress product creation request.
  - H1 2FA reset (id=2598548): multiple parallel 2FA reset requests; after the user cancels one, extras stay active — a canceled reset still led to unauthorized 2FA removal after 24 hours.
  - GitHub GHES (id=2357443): `POST /graphql` updateTeamsRepository mutation raced against the repo-update REST API while a repo was detached — an admin covertly retained admin permissions on a detached repo (CVE-2024-2440).
  - WordPress.com (id=2616045): `public-api.wordpress.com/rest/v1.1/me/transactions`, duplicated free-domain claim requests in parallel with a changed `meta` parameter — multiple free custom domains on one account.
- **Exemplars:** id=2598548, id=2357443.

### 11. Library-level / memory races (research-grade, lower bounty tier)
- **Shapes:** libcurl parallel DNS resolution in `docs/examples/10-at-a-time.c` — verified with `valgrind --tool=helgrind --log-file=helgrind_%p.log ./10-at-a-time`; nondeterministic SSL/HTTP2 framing failures, risk of connecting to the wrong IP (id=1019457). libcurl synchronous resolver `alarm()/siglongjmp` global-buffer race → DoS in multithreaded apps (CVE-2023-28320, id=1990421).
- **Exemplars:** id=1019457, id=1990421.

## Bypass / chain notes
- **Tooling seen in the records:** Turbo Intruder with `race.py` and a marker header (Weblate used `Test: %s`); intercepting an email link and converting it to curl for N-way concurrent execution (H1 retest: 5 concurrent executions); backgrounding curl with `&` repeated ~20x (OAuth token race); manual multi-browser double-click (invitation token); 22–70 parallel requests via intruder-style replay.
- **Request counts observed:** anywhere from 2 (Slack credit) to 70 (flags/submit). 20–50 parallel is the common sweet spot; the Cosmos faucet needed 50 to beat an 11-token cap; Reddit needed 10 to get 9 successes.
- **Delete-then-race chain (Dust):** delete one folder to open headroom, then fire simultaneous creations — the counter re-check happens after delete but the creates all pass together.
- **Cancel-doesn't-revoke chain (H1 2FA):** racing reset creation leaves orphaned active requests that survive cancellation — combine with the 24-hour auto-execution for full account takeover of 2FA removal.
- **Revocation-bypass chain (OAuth):** race redemption first, then note that UI "revoke access" only kills one token pair — demonstrate persistence post-revocation.
- **Invite-cancel loop (FetLife):** race invites (10x for 1), then cancel sent invites to regenerate inventory — the race plus the refund mechanic compounds into unlimited invites.
- **HTTP-layer tip implied by records:** payloads preserved CSRF tokens and session cookies verbatim across all parallel copies — authenticity_token/csrf values are fetched once and reused; only the racing parameter stays identical.

## Gotchas / what NOT to do
- Not every race target is a web endpoint: two records are C-library races (libcurl DNS/resolver) — report those with deterministic repro tooling (helgrind logs), not request replays.
- Some programs treat small-impact races as informative (vote/follow inflation on low-value counters); the records that clearly paid well involved money, quota bypass, or account security — prioritize those.
- Don't assume one success proves the bug: Reddit got 9/10 successes, but claimCredential got exactly 1/22 — demonstrate the *aggregate* excess (balance, count, duplicated records, emails received) as evidence.
- Preserve CSRF/authenticity tokens exactly as captured; several winning payloads (`utf8=%E2%9C%93&authenticity_token=...`) fail if the token is regenerated per-thread.
- Parallel GETs can race too (Urban Dictionary `/v0/vote`, H1 `/group/join?invite=`) — don't restrict yourself to POSTs.
- Destructive side effects exist: the H1 post_join race created an irremovable membership — on live programs, demonstrate on accounts/objects you control and stop at proof of excess.
- Record exact before/after numbers (vote_count 48→49, balance 11→30, $25→$175) — programs confirmed these races on the strength of quantified deltas.

## Real-world impact examples
- $25 Reverb gift card → $175 in Reverb bucks (7x redemption, id=759247).
- Reddit: one Google Play purchase → ~9x the coins (9 of 10 parallel verifications succeeded, id=801743).
- HackerOne retest confirmation raced 5x → $500 paid multiple times (id=429026); separate payments-code race produced duplicate bounty payouts (id=220445).
- Slack: $100 survey credit doubled to $200 from two concurrent requests (id=165570).
- Weblate: 6 free trials from one account = 300,000 strings across 100+ languages (id=1087188).
- Bumble: 9 days of free Premium from 3 requests on a 3-day grant (~$5/week product, id=1037430).
- Cosmos faucet: 30 tokens minted against an 11-token cap with 50 concurrent requests (id=1438052).
- Shopify: 12 store locations on a 4-location plan — billing limitation bypassed (id=413759).
- OAuth (Internet Bug Bounty): duplicate live token pairs surviving UI revocation across 6 of 11 providers (id=55140).
- H1 2FA: canceled reset still resulted in unauthorized 2FA removal after 24 hours (id=2598548).
- GitHub GHES: covert persistent admin on a detached repository, CVE-2024-2440 (id=2357443).
- H1 flags: same flag counted 70 times → extra points + 2 private-program invitations (id=454949).