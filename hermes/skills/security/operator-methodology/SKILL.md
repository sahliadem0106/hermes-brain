---
name: operator-methodology
description: "Use at mission start on any bug-bounty target. Loads ladder."
version: 1.0.0
author: Sahli adem
license: MIT
metadata:
  hermes:
    tags: [security, methodology, bugbounty, workflow]
    related_skills: [hunter-mission, browser-cdp-hunting]
---

## When to Use
Load at the START of every bug-bounty mission, before recon. This is the operator's methodology - it defines HOW to work, overriding any repo files (MASTER.md etc. are reference only).

## The Ladder (in order)

### Phase 0 - Scope (before any request)
1. Fetch program page + scope + exclusions. Write scope.yaml in ~/bugagent/scopes/.
2. Note signup requirements (phone/KYC/email aliases/invite codes) - report to operator with exact steps.
3. Note test-account credentials provided by the program.

### Phase 1 - Recon per asset (super-scan, but respect program scanning rules)
1. DNS, CNAMEs, cert SANs (wildcards = sub-surface), subdomain enum (hackertarget/crt.sh/rapiddns).
2. Root pages, headers, CSP (connect-src/frame-src = API host list), tech fingerprint.
3. OpenAPI/swagger specs; _buildManifest.js leaks hidden SPA routes; JS bundles = endpoint goldmine.
4. npm/GitHub exposure, wayback archive.
5. Map the OBJECT MODEL: what entities exist (loan/user/document), what ID format, what endpoints.

### Phase 2 - Bug-class ladder (ONE class at a time, every variant, genuine dead-end before next)

**MANDATORY: before starting class N, load its hunter skill sheets.** The map is in
~/bugagent/missions/SKILL-MAP.md (e.g. class 1 IDOR -> skill_view('hunter-l3-idor') + skill_view('hunter-l4-idor')).
L3 = technique knowledge with real payloads, L4 = hands-on exploitation. Do NOT run a class from memory alone -
the sheets contain sub-patterns and gotchas that memory misses (this was proven on Blend: 6 IDOR variants were
missed until the sheet was read).

Order (adjust per target's focus areas):
1. Horizontal IDOR - read AND write, all object classes, real 2nd account required. Also: unauth variants (strip auth), empty-id fallbacks, encoded-id decode-mutate, rejected-mutation side channels.
2. Auth flows - magic-link/reset token entropy+reuse, session fixation, login logic.
3. Registration logic - role injection, dup email, verification bypass.
4. Vertical privesc - needs 2nd role account; role checks on every endpoint tier.
5. Business logic - state-machine jumps, amount manipulation, feature gating (check exclusions!), workflow bypass.
6. File upload - filename XSS/traversal, content-type, stored payloads, download authz (read+write).
7. Websocket/realtime - channel token issuance authz, cross-user subscription, event payloads.
8. SSRF - URL-fetch params, webhook configs, import features, SAML metadata.
9. XSS - stored sinks (names, metadata, filenames), DOM sinks, reflections (encoded?).
10. Injection - search fields, filters, headers (low prob on modern stacks, schema errors = parameterized).
11. CSRF - which state-changing endpoints skip CSRF tokens.
12. Race conditions - double-submit, concurrent state ops.
13. GraphQL - endpoint discovery, introspection, node-id IDOR, batch queries.

### Ladder rules
- Every variant per class. '403 everywhere' = only after testing READ+WRITE+DELETE+unauth+encoded variants.
- Track per-class VARIANT SUBCLASSES explicitly - e.g. IDOR has: read, write, delete, unauth strip, empty-id, encoded-id, side-channel (email/WS on rejected mutation), state-dependent (download after perm change). A class is only 'done' when every subclass is tested.
- Cross-user STORED payloads (filenames, names, metadata) render in OTHER roles' views - always upload/enter marker payloads and check the other account's rendering (stored-XSS lead).
- Differential responses (404 vs 403, 200 vs 500) = document as info-leak findings even if low.
- A class is dead only when every discovered endpoint/variant returned the expected rejection.
- Log every result (even negatives) in the mission ATTACK-SURFACE.md - prevents re-testing.
- When blocked (missing account/creds): note the blocker, MOVE TO NEXT CLASS, return when unblocked.
- Show the operator the ladder + status when asked, or when a phase completes.
- Session end: output the FULL ladder status table (tested/partial/not-tested/blocked + missing variants) - the operator audits it; 'done' claims get challenged.

## Operator's strategy rules
- Stack SMALL paid findings ($100-500, real impact) - never informative reports.
- Reputation > single big bounty. No noise submissions.
- Zero-babysitting preference: batch authed testing into one browser session; one-time setups OK.
- Cost transparency: state what costs $0 vs money/KYC per step.
- Validate before claiming: evidence gate, two-skeptic for findings, confidence >= 0.85.

## Mission state management
- Mission dir: ~/bugagent/missions/<target>/ - ATTACK-SURFACE.md (living doc), scope in ~/bugagent/scopes/.
- Sessions/cookies/tokens saved to mission dir (chmod 600), credentials operator-owned.
- Each session end: update ATTACK-SURFACE.md with 'what was tested / what died / what's parked / blockers'.
- Memory: store mission state summary + pending items for cross-session resume.
