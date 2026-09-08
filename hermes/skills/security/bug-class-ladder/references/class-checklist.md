# Bug-class checklist (audit before declaring a target exhausted)

Tick every class during planning; mark DEAD only after exhausting variants.
Sources: OWASP/WSTG classes + what actually came up in Privy and Blend missions (Sep 2026).

## Tested-in-this-session template (copy into ATTACK-SURFACE.md)

- [ ] Horizontal IDOR — READ on every object class, cross-account, real foreign IDs
- [ ] Horizontal IDOR — WRITE ops cross-account (PATCH/PUT/POST; reads passing 403 says nothing about writes)
- [ ] Vertical privesc (borrower->lender->admin; role checks on API, not just UI)
- [ ] Multitenancy / cross-tenant data (org-level isolation)
- [ ] Business logic — state-machine jumps (skip steps server-side), amount/price manipulation
- [ ] Business logic — feature-gating (often excluded; check program list first)
- [ ] Auth flows — magic-link token entropy/reuse, reset-token rotation, session fixation on login
- [ ] Auth flows — OTP/2FA: bypass, opt-out endpoints, rate limits (429 threshold testing)
- [ ] Registration logic — role injection at signup, email-verification bypass, duplicate handling
- [ ] File upload — filename traversal/XSS, content-type spoof, unauth access to uploaded files
- [ ] SSRF — any URL-fetch config fields (JWKS URLs, webhook URLs, logo URLs); check exclusions first
- [ ] XSS — stored surfaces, DOM sinks, reflection encoding, CSP effectiveness
- [ ] SQLi/injection — free-text fields, search, sort/filter params, custom headers
- [ ] Access control — WRITE vs READ asymmetry (test both)
- [ ] CSRF — which state-changing endpoints skip the CSRF token
- [ ] Websocket/realtime — token issuance authz (can you mint tokens for other users' channels?),
      channel-binding, event payload sensitivity
- [ ] Info leak — JS bundle secrets, build manifests (route disclosure), verbose errors,
      internal IDs/keys in API responses, existence oracles (404-vs-403/500 differentials)
- [ ] GraphQL — endpoint discovery, introspection, authz on resolvers
- [ ] Race conditions — double-submit, concurrent state changes
- [ ] Second API hosts — check CSP connect-src/frame-src for additional API hostnames in scope
- [ ] Subdomain surface — crt.sh/hackertarget on parent domain; dead children = takeover checks
- [ ] npm/supply chain — tarball secret scan, install scripts, namespace deps, build manifests
- [ ] Session lifecycle — refresh rotation, logout revocation, post-logout JWT validity (often excluded)

## Recon toolkit (per asset)

- DNS (dig @8.8.8.8 A/CNAME/TXT), TLS SANs (openssl s_client), hackertarget hostsearch, crt.sh (often 502s — retry/rapiddns)
- httpx tech-detect; curl headers (CSP connect-src/frame-src = extra API hosts)
- waybackurls/CDX per host
- OpenAPI specs (often at /api/v1/openapi.json on multiple hosts)
- JS bundle download + endpoint regex mining (login/auth bundles are goldmines)
- Next.js _buildManifest.js — leaks internal console routes not linked in UI
- Zod/schema-error mining: POST {} with junk keys, read 'Unrecognized key(s)' errors to map accepted fields
- npm registry + tarballs of the target's SDKs
- hackertarget subdomain list; classify children of in-scope assets vs out-of-scope staging stacks

## Error-class differential analysis

Error-message deltas reveal which checks exist and in what order:
- 'No such loan: {id}' vs 'Not authorized' = existence oracle (weak, unguessable IDs) + ownership check
- 'User is not a signer on the wallet' = signer registry exists
- 'Could not find an account' after header tamper = membership validated against session, not header
- Validation-order inconsistencies (params checked before object resolution) can hide object-existence leaks
