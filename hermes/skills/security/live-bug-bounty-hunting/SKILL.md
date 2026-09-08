---
name: live-bug-bounty-hunting
description: "Use when hunting a live authorized bug-bounty target."
version: 1.0.0
tags: [security, bug-bounty, live-hunting, graphql, idor, recon]
---

# Live Bug Bounty Hunting (operational)

Class-level skill for actively hunting an authorized program once scope is locked. Strategy/theory lives in hunter-l3-*/hunter-l4-* skills; THIS covers live operations, operator protocol, and mechanical lessons of session-driven hunting.

## Operator protocol (binding — operator defined Sep 1 2026)
- Two models, one operator: GLM-5.3-flash = judgment/planning, DS v4-flash = bulk execution via `scripts/delegate_to_worker.py`. The session agent is the SYNCHRONIZER: executes plans, reports faithfully, relays between operator and models. Do NOT autonomously launch a separate GLM agent session to judge — operator called that a waste of time; judge in-session.
- Operator order: "once locked in, never stop phase-to-phase until something interesting or you need input" — keep executing consecutive phases; only pause for operator input (credentials, decisions) or a candidate finding.
- Per-target folder: `~/bugagent/targets/<program>/{recon,evidence,notes,findings,logs}` + README.md with program rules verbatim. scope.yaml must be filled before any request (validate_finding.py refuses otherwise).
- Operator bounty strategy (Sep 1 2026): stack many SMALL paid findings ($100-500, real impact, never informative) over chasing one big bug — volume of valid lows first. For heavily-excluded programs, diff the exclusion list against expected bug classes FIRST and target only what remains viable.

## Session-token workflow (short-lived tokens)
- Modern platforms mint 5-minute access tokens (HttpOnly) + 1-year refresh tokens. Every operator paste = one ~5-min hunting window. Prepare the exact request sequence BEFORE asking for a paste; fire immediately on arrival.
- Ask for `Copy as cURL` (DevTools → Network → first request → right-click → Copy as cURL) — full untruncated cookie set. DevTools UI pastes often elide mid-value (`eyJjIj...Mzh9`) which silently breaks auth; full cURL never does.
- Store sessions at /tmp with chmod 600, never in git. Tell operator to rotate (log out/in) after testing.
- If an access token expired: don't burn the window guessing refresh endpoints — Next.js middleware refresh runs browser-side only, not replayable server-side. Ask for a fresh paste.
- JWTs may stay valid server-side after logout until natural expiry (stateless). Check whether the program explicitly excludes JWT-lifetime behavior before reporting — most do.

## Browser-assisted traffic capture (CDP) — for crypto-signature / wallet / SDK flows
When the target's security model is a CLIENT-SIDE signature scheme (wallet RPC, authorization signatures), static SDK analysis gets you the model but you need REAL captured requests. Workflow validated Sep 1 2026 on Privy:
1. Headless chromium (`--headless=new --remote-debugging-port=9222 --remote-allow-origins='*'`) drives pages and captures traffic — but logins behind Cloudflare Turnstile/hCaptcha get REJECTED headless. Don't burn time retrying.
2. Use the OPERATOR's visible browser as the capture target: have them run `chromium --remote-debugging-port=9223 --remote-allow-origins='*' --user-data-dir=/tmp/<profile> <url>`. Operator passes the CAPTCHA/OTP interactively; the session persists in the profile dir, so browser restarts need no re-login. The `--remote-allow-origins` flag is REQUIRED — plain `--remote-debugging-port` gives WebSocket 403 Forbidden on attach.
3. Python CDP driver (websocket-client): Network.enable + requestWillBeSent/responseReceived pairs + `Network.getRequestPostData` for POST bodies. Working template lives at `~/bugagent/missions/privy/cdp.py` (navigate, drain events, eval_js, get_body, get_req_post).
4. Trigger flows by clicking real buttons via `Runtime.evaluate` (find by innerText regex, `.click()`); React-controlled inputs need the native value setter + input event; modal forms respond to Enter-key dispatch + `form.requestSubmit()`.
5. Capture the authed request ONCE, save headers+body verbatim to JSON, then replay OUT-OF-BROWSER with python-requests. Copy captured headers VERBATIM (authorization, app-id, signature, expiry, privy-client/ca-id + Origin/Referer/UA) — hand-rebuilt header sets get 403 missing_origin.
6. OTP relay: operator pastes the 6-digit code from their forwarded inbox (~30s each). Budget 1-2 relays per session; access JWTs expire in ~1h.
7. State-changing probes on the operator's own account (logout, revoke) are safe and reveal session semantics — verify aftermath via API, not UI (the SDK may hold independent state and auto-recover).

## Client-side authorization-signature testing (wallet/SDK signing schemes)
Schemes where the client signs {url, method, headers, body} with a user key and the server verifies — test the BINDING MATRIX, not just replay:
- Exact replay (same sig, same body) → establishes the retry window (often deliberate, ~30min). Replay-success alone is NOT a finding when body/path are bound.
- Tampered body, same signature → 401 = body-bound. Test method changes AND param changes.
- Path/object-id swap, same signature → 401 = URL-bound. This is the critical cross-tenant test: use a FOREIGN object id from a public JS bundle or a second owned account.
- Cross-chain/cross-key: EVM signature replayed against a Solana object → isolates key scoping.
- Expiry in past / extended future → verifies clock enforcement (past-expiry 401 with a distinct error = enforced; future-expiry ACCEPTED would be a finding).
- Replay-allowed-within-window + full binding = correct design → record as clean negative.
- Also probe: refresh-token rotation on reuse (absence usually by-design, note only), logout invalidation of refresh tokens (survival = real finding), post-logout JWT validity (usually program-excluded — check before reporting).

## GraphQL hunting without introspection
- Introspection open? Dump schema in 2-3 requests (queryType fields, mutationType, __type walks) — the schema is the IDOR map. Check sibling services for INCONSISTENT config (one exposed, one disabled = config miss worth noting).
- Introspection disabled? Use the ERROR ORACLE with aliased batch guessing: one request with 8-10 aliased fields (`a: livestream{__typename} b: orders{...}`) returns "Cannot query field 'X' on type 'Y'" per miss — names types for free. Confirmed hits need follow-up field walks.
- Global IDs: base64("Type:numericId") patterns are IDOR-ready (sequential numeric underneath). Test node()/typed resolvers with own ID first (null = restricted), then neighbors only with a second owned account.
- Role-layered APIs are common: viewer may authenticate while data queries demand a seller/supplier role. Decode session JWT claims to see your role; clean "Not authenticated" on role-gated endpoints is correct behavior, not a finding.
- Second account via program email plus-aliasing (user+tag@wearehackerone.com) enables true cross-account BOLA tests — ask operator to create it early.

## Evidence + limits discipline
- Every finding: candidate file in findings/ with raw evidence, request counts, explicit next-test plan. "Not proven" and clean negatives are recorded results.
- Program PII rules override everything: on touching real user PII → stop, save nothing, report.
- Track daily request budget (programs cap e.g. 10k/day); report usage every round.
- Bot walls: try browser UA + full headers before assuming IP blocking (Whatnot's wall was UA-only).
- gau/waybackurls can hang/return empty from some IPs — don't burn the window; pivot to JS-bundle endpoint extraction (download chunks with browser UA, grep paths, graphql ops, `*Id` fields).

## References
- references/whatnot-session-notes.md — worked example: subdomain→alive→JS-map→GraphQL-introspection→role-gate→buyer-surface mapping, with exact request shapes and dead ends.
- references/privy-session-notes.md — worked example: OpenAPI→object model→boundary probes→CDP capture of wallet auth-signature flow→binding matrix results; includes the noise-filter lesson for programs with ~20 excluded classes and the H1 alias domain gotcha (@wearehackerone.com, not @hackerone.com).
