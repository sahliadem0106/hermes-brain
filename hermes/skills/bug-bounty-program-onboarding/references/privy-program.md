# Privy (HackerOne) — session detail, Sep 1 2026

## Assets
- In-scope: recovery/home/dashboard/auth/api.privy.io + npm @privy-io packages + controlled namespace deps.
- recovery.privy.io: NXDOMAIN (dead) yet listed in-scope Critical; recovery flow moved into auth.privy.io paths (/api/v1/recovery/*, embedded_wallets recovery).
- home.privy.io = second console (/apps, /account), less hunted. dashboard + auth same Next.js app (Vercel+CF+hCaptcha).

## API model
- Tenant = App (cuid-like ID cm…). Auth = privy-app-id header + app-secret (HTTP basic) for api.privy.io.
- 151 paths captured: wallets (raw_sign/export = critical targets), users, policies, key_quorums, intents, organizations (kyb/fiat).
- Object IDs: cuid `^[a-z]{2}[a-z0-9]{22,26}$` — not enumerable; IDOR testing = authorized-cross-tenant only.

## Observations (Sep 1)
- Unauth: all sensitive endpoints 401 properly. SIWE /api/v1/siwe/init nonces random.
- Cross-app config read with any app ID works — explicitly excluded by program, do not report.
- /v1/wallets/{id}/transactions validates chain/asset params BEFORE wallet existence/tenant check; chains return "Unsupported chain" on a fresh app (feature-gated) — retest after app has chains enabled.
- Stale foreign IDs from their public JS bundle all gave clean 404s — no IDOR evidence yet.

## Exclusions to remember (do not report)
App-ID config viewing, CORS any-domain, OAuth any-domain redirect, billing/feature-gating bypass, client-SDK postMessage origin (embedded-wallet bridge posts to "*" — excluded), self/own-team exploitation, races on soft limits.

## State at session end
- Operator signup done: org "HackerOne (BBP)", alias @wearehackerone.com. App ID cmtiyvg7j008b0bi35qbeh4xv + secret stored in mission .env.privacy.
- Pending: user-level JWT test (needs token from demo.privy.io login), npm namespace/tarball pass (P3), chain-enabled retest of /transactions.
- Mission dir: ~/bugagent/missions/privy/ (openapi.json, ATTACK-SURFACE.md, urls_*.txt, js_endpoints.txt).
