---
name: bugbounty-program-evaluation
description: "Use when evaluating or selecting bug bounty programs."
version: 1.0.0
author: Sahli adem
license: MIT
metadata:
  hermes:
    tags: [security, bugbounty, recon, methodology, target-selection]
    related_skills: [hunter-mission, browser-cdp-hunting]
---

## When to Use
Load when the operator names candidate programs and asks to evaluate/rate them, or when starting a new mission and the target program must be scoped, profiled, and mapped before the hunt begins. Also governs the hunt itself once a target is chosen.

## THE OPERATOR'S METHODOLOGY LAW (overrides any repo-file workflow)
1. Read the program's scope/assets/exclusions FIRST — before any request leaves the VM.
2. Per-asset recon + super-scan with tools chosen per asset (not a fixed pipeline).
3. Then hunt bug-class BY bug-class in a ladder (IDOR → SSRF → XSS → SQLi → WCD → subdomain → business logic → upload → ...). For each class: enumerate EVERY variant/scenario, test them all, reach a GENUINE dead end before moving on. Depth-first exhaustiveness — do not "prioritize away" a class or declare the mission closed after testing only the high-EV classes. The operator corrected this explicitly: an 8-class ladder means all 8 classes get dead-end depth, not just the top 4.
4. Show the operator the class ladder so they can reorder/inject classes.
5. bugagent repo files (MASTER.md etc.) are reference only — the operator's prompts are the brain. Only pull from the repo when the operator explicitly says so.

Operator strategy rule: stack SMALL paid findings ($100–500, real impact, never informative) over chasing heroes.

## PROGRAM BRIEF (produce this for every candidate)
HackerOne program pages are JS SPAs — curl/web_extract return an "enable JavaScript" stub. Render them in the debug browser (see browser-cdp-hunting gotchas: `c.navigate(url)` + `eval_js("document.body.innerText")`). For each program capture:
- In-scope assets (domains, wildcards, npm packages) + out-of-scope list
- Bounty table + payout DISTRIBUTION (% of reports per severity) — distribution calibrates expectations better than the ceiling
- Exclusion list — count how many classic classes are pre-excluded; a 20+ exclusion list (e.g. Privy) signals a hardened, well-hunted target
- Signup/access friction: self-serve vs approval forms, phone/KYC requirements, sanctioned test data, allowed-roles model (self-signup borrower + form-issued lender = ideal two-tier setup)
- Scanning policy (banned/throttled/allowed) and rate limits
- Tech stack hints from the policy text (e.g. "ReactJS/Express microservices" = app-layer authz lane)
- Average response/triage/bounty times
Then a comparison table across candidates: friction | our skill fit | payout reality | surface size | scanning rules. Recommend one.

Good-fit signals for our machine: vertical/horizontal authz focus, real privilege tiers, sanctioned test data, no KYC for testing, app-layer stack. Poor fit: programs whose money is in VM/container escape or engine-level privesc we can only black-box. If a second model (e.g. another AI) already produced a brief, verify its claims against the live page before endorsing — one session found ~90% accuracy with a detail drift (wrong hardcoded-credential string).

## MISSION START CHECKLIST
1. Write `scopes/<target>.yaml` (the law: in-scope, out-of-scope, excluded classes, signup rules, rate limits) — active testing only against the scope file.
2. Mission dir `missions/<target>/` with `ATTACK-SURFACE.md` (append-only paper trail: every test, every negative, why each class died) + `openapi.json` if a spec exists + captured request JSONs (chmod 600).
3. Signup: account name per program rules (e.g. "(BBP)" string, HackerOne org), operator does signup; agent records app IDs, keeps secrets in `.env.privacy` chmod 600. NEVER touch fiat/KYC endpoints. H1 email alias = `username@wearehackerone.com` (program texts that say @hackerone.com are wrong); `+victim` sub-addressing gives a second identity on the same inbox.
4. Secrets pasted in chat get rotated by the operator at mission close — put this on the checklist at mission END.

## RECON TECHNIQUES (proven)
- DNS/hosts first: `dig` vs 8.8.8.8 (dead in-scope assets are a finding themselves — check children, a dead root can have live per-tenant children), `openssl s_client` cert SANs (wildcards reveal sub-subdomain surface), `httpx` tech-detect, `waybackurls`+CDX per host, hackertarget/rapiddns when crt.sh is down (502s are common)
- OpenAPI spec: if the product publishes one, it IS the object model — pull every path, group by object-ID endpoints (IDOR candidates)
- **Build-manifest mining**: any Next.js app leaks internal routes at `/_next/static/<buildId>/_buildManifest.js` — hidden pages + API namespaces not in any public spec (this found an undocumented /teams/{id}/secrets API and a whole console route map)
- **SDK/tarball analysis**: download npm tarballs of the product's SDKs; grep for endpoint paths, auth-scheme strings, hardcoded hosts; check install scripts + namespace deps for takeovers; secret-scan (expect clean on mature targets)
- **JS chunk endpoint extraction**: cat all chunks, regex for `"/api/v1/..."` and interpolated concat route templates (`.concat(...)` patterns enumerate subpaths)
- **Schema-error mining**: send `{"probe":1}` to modern APIs — zod "Unrecognized key(s)" errors enumerate accepted fields; "Invalid enum value" enumerates allowed values. Fastest way to explore unknown endpoints without guessing
- **Error-class differential analysis**: same request across object IDs/origins/timestamps — which error class changes reveals which checks exist ("Wallet not found" vs "User is not a signer on the wallet" = resolver passes but signer-registry check exists)

## AUTH LAYER MAPPING (before deep testing)
For each API host: unauth probes → app-ID-header probes → app-secret probes → user-JWT probes (decode claims: aud binding, alg, sid) → console/cookie session probes. Identify WHICH credential layer each endpoint actually honors (cookie vs bearer vs signature header) — SPAs routinely gate UI client-side while the API honors a different credential than you assume.

## CLASS LADDER REFERENCE DEPTHS (from the Privy worked example)
- IDOR/tenant isolation: object-ID probes with each credential tier + live cross-user matrix with two identities
- SSRF: find config surfaces where the product's SERVER fetches operator-supplied URLs (JWKS/OIDC config, webhooks, SAML metadata); check whether feature gates unlock them and whether the gate is hard (enterprise) or soft (free-tier toggle)
- XSS: stored-field write routes (may be unreachable — 405/schema-locked), unauth reflection encoding, DOM sinks in downloaded JS
- SQLi: schema-validation stack (zod-style typed errors) usually means parameterized — verify on free-text fields then close honestly
- WCD: PII endpoints + cacheable suffixes, both unauth and authed
- Business logic: feature-gate toggles (may work but be program-excluded — log as not-reportable), invite/admin flows, transfer/link/unlink

## VALIDATION LAW (unchanged)
Every finding: raw req+resp, PoC, impact chain, confidence >= 0.85, human submits. Excluded-class findings get LOGGED as not-reportable, not dropped silently — exclusions are data for target selection next time.