# Privy H1 session notes (Sep 1 2026) — worked example: hardened crypto-infra program

Mission dir: ~/bugagent/missions/privy/ (openapi.json, ATTACK-SURFACE.md, sign_request*.json, npm/ extracted SDKs).

## Program shape
- In-scope: recovery/home/dashboard/auth/api.privy.io + npm @privy-io packages + controlled namespace deps. OUT: privy.io, docs/demo/blog. ~20 excluded classes incl. app-ID config viewing, CORS any-domain, feature-gating bypass, client-SDK postMessage origin, self/own-team exploitation, JWT session expiry (low-timeout JWT policy). Bounties $100-500 / $500-2500 / $2500-5000.
- Signup gate: dashboard name must contain "(BBP)", org "HackerOne", email = username@wearehackerone.com (program text says @hackerone.com but H1 aliases are @wearehackerone.com — that mismatch cost the operator multiple failed signups).

## What was done (order that worked)
1. scope.yaml from program text (exclusions verbatim). 2. OpenAPI spec (151 paths) = object model: wallets/users/policies/key_quorums/organizations by cuid-ish IDs `^[a-z]{2}[a-z0-9]{22,26}$` (not enumerable → IDOR must be authorized-but-wrong-tenant, not ID prediction). 3. DS worker passive recon: 8.5k wayback URLs, JS bundle endpoint extraction (js_endpoints.txt: init/authenticate/link/unlink/transfer families + recovery endpoints under auth.privy.io). 4. Unauth boundary probes (clean 401/403/429 everywhere, nonces random, OTP rate-limit ~5 attempts). 5. App-secret boundary: foreign object IDs (stale from public JS + fake) → consistent tenant-scoped 404s. 6. npm tarballs: no secrets, no install scripts, both namespace deps (@privy-io/encoding, @privy-io/web-storage) live+owned. 7. User JWT boundary: aud-bound, alg=none/empty-sig rejected. 8. CDP capture → auth-signature binding matrix.

## Auth-signature scheme (the deep-dive target)
Wallet RPC auth: client signs {version:1, url(path incl wallet_id), method, headers{privy-app-id, privy-request-expiry=now+30min}, body} with the user's embedded-wallet key → headers privy-authorization-signature + privy-request-expiry.
Verified server-side: body-bound (tamper→401), path-bound (wallet-id swap→401), key-per-chain, expiry enforced (past→distinct error), replay OK within window (retry semantics, deterministic). Cross-wallet replay = correct design, NOT a finding.
Session semantics: refresh token does NOT rotate on reuse (by design); logout kills refresh token server-side; access JWT valid post-logout until 1h expiry (EXCLUDED by program).

## Capture mechanics that worked
- Headless chromium blocked by Turnstile at login → operator's visible chromium --remote-debugging-port=9223 --remote-allow-origins='*' --user-data-dir=/tmp/privy-live. Session persists across restarts in profile dir (no re-OTP).
- CDP attach via websocket-client; capture Network.requestWillBeSent/responseReceived + getRequestPostData; trigger flows by innerText-regex button clicks; React email input needs native value setter + input event.
- Replay must copy captured headers VERBATIM (authorization, privy-app-id, signature, expiry, privy-client, privy-ca-id + Origin/Referer/UA) — hand-built header sets get 403 missing_origin.
- OTP relay: operator pastes code from forwarded inbox (~30s). Budget 1-2 per session; access JWT ~1h.

## Noise filter (lesson for excluded-class-heavy programs)
Before ANY finding work, diff the exclusion list against expected bug classes — this program pre-excluded the majority of standard classes, so the only viable surface was (a) API auth-boundary correctness and (b) the wallet-signature scheme. Result: fully hardened, zero reportables after deep testing — recorded as a correct negative. Don't grind excluded classes for a 'with-impact' workaround without operator sign-off.

## Untested remains (if resumed)
- Wallet EXPORT flow authorization (returns private key; needs active session; most sensitive path left)
- Cross-user tests with second identity (foutabax2+victim@wearehackerone.com alias) on link/transfer/unlink family
- /api/v1/recovery/* + init_icloud internals (needs a user with recovery configured)
- Rotate the test app secret (pasted in chat) before closing
