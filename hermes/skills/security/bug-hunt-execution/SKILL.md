---
name: bug-hunt-execution
description: "Use when executing a live bug-hunt session."
version: 1.0.0
metadata:
  hermes:
    tags: [security, bugbounty, methodology, ssrf, webhook, execution]
---

# Bug-Hunt Execution (curator-owned operational layer)

The operator's own skills (operator-methodology, hunter-mission, browser-cdp-hunting, hunter-l3/l4 sheets) are the LAW and the technique bank. This skill captures execution lessons learned from live sessions that those files do not yet carry. When they conflict, the operator's files win.

## Class-closure discipline (the 'minimal test' correction)

**A minimal test proves a hypothesis, never a class.** A class may only be marked DEAD when the full sub-surface matrix has been tested. Do not write 'Class N DEAD' after one hypothesis returns negative.

- Before declaring a class dead, enumerate its sub-surfaces explicitly — use the matrix template in references/class-closure-matrix.md (generic rows + class-specific examples for import/SSRF/XSS).
- Typical rows: READ/WRITE/DELETE cross-tenant, unauth strip, empty-id, encoded-id, side-channel on rejection, state-dependent access, feature-gate vs authz, alternate code path (import/batch/legacy), parser-500 hunt, race.
- If only some sub-surfaces are tested, the honest status is PARTIAL with the untested list spelled out — never DEAD.
- When the operator challenges 'did you do your best', re-run the class with the full matrix and file a HARDENED verdict that traces every sub-surface to a result.
- Falsify the strongest alternative explanation first: e.g. import may not be a weaker validation door, but the real question is whether it OVERWRITES existing objects (create-only vs merge) — test that before concluding.

## Ask-the-operator principle

Do not paper over blockers or conclude from a first denial when operator input would materially change the test:
- Reauth walls / passwords / account switches / paid infra / a VPS for redirect tests → ask, with exact click-by-click steps and cost ($0 vs money/KYC). The operator WILL type a password when told exactly where.
- State honestly what you did NOT do and what you need, instead of quietly stopping at a denial pattern (see the 407 lesson below).

## Cost honesty

'$0' refers to API/subscription spend only. Every tool round burns model tokens on this conversation; estimate and say so when context is large. Never repeat a flat '$0' for a long session.

## Outbound-webhook SSRF testing
See references/webhook-ssrf-recipe.md for the full recipe (callback capture, config binding, egress-proxy detection, cleanup).

## Browser-session continuity
- CDP debug chromium dies mid-hunt → relaunch with the SAME --user-data-dir (session cookie survives), same --remote-debugging-port + --remote-allow-origins='*'. Do not assume the session is lost.
- CLI-token mint without a terminal: generate code (api), approve via dashboard /auth/cli in the browser (fill Auth code -> Next -> name -> Finish Login), then POST authorize with the polling_code to receive the token. Save tokens chmod 600, revoke at session end.
- DEVICE-AUTH CODES EXPIRE FAST (Doppler: minutes): a code generated then filled a few steps later returns 'Invalid CLI auth code'. Generate a FRESH code and approve it in ONE tight sequence (same script), never reuse a stored code after any delay.
- Device-auth testing recipe (generic): generate is unauth + rate-limited (observed 25/300s with explicit message); the human-readable code alone CANNOT authorize — the high-entropy polling/secondary code is the real key and requires user approval; single-use enforced (reuse -> same uniform error, no oracle); roll invalidates the previous token instantly; revoke is immediate. Test each lifecycle step and note the rate-limit message verbatim.
- ANOMALY RETEST RULE: one anomalous success through a mitigation (e.g. a single 200 to a metadata IP through an egress proxy that otherwise 407s) is NOT evidence until reproduced. Re-fire fresh cycles and check whether the anomaly reappears; if all fresh attempts hit the mitigation, downgrade to 'one-off artifact' and append the retest result to the verdict file.
- SSR dashboards (Doppler-style): every route is server-rendered HTML with inline hydrationData JSON — there are NO data XHRs on load. Read hydration from the HTML doc; mutations are same-origin POSTs needing a per-page CSRF from hydrationContext plus X-Requested-With/x-doppler-source headers. Fetch in page context (credentials:include) beats curl for authed same-origin calls.

## Verdict calibration (TESTED / ATTEMPTED / INCONCLUSIVE, never overclaim)

- Only 'DEAD' survives an external reviewer when it means: full sub-surface matrix run AND multiple rendering/parsing contexts checked. Everything else gets an honest label.
  - TESTED = variant matrix actually run against the surface.
  - ATTEMPTED = probed, then stopped on a blocker or evidence gap — say so.
  - INCONCLUSIVE = surface exists, testing incomplete (e.g. SQLi payloads prepared but never fired; second-order sinks unexercised). Parameterized/schema-validated stack is evidence of hardening, NOT proof of injection absence.
- A ~150-request 2-day effort is a METHODOLOGY SWEEP, not a pentest. Real engagements log thousands. Say 'sweep' in the title and summary so 0 findings reads as informative, not as full-clear.
- Do not claim 'all set-able sinks' from 2 rendering contexts per sink: emails, export surfaces, and audit views are separate rendering paths and were the actual miss when a reviewer pushed back.

## Second-order sinks (the 'stored but not rendered where I looked' trap)

When a field accepts and STORES raw attacker HTML (webhook name, secret note, display name):
- Check ALL downstream rendering surfaces, not just the page where you set it: activity-log titleHtml (may STRIP tags server-side), notification EMAILS (operator must check the H1-alias inbox and report render-vs-escaped), export/CSV/JSON views, audit views, change-request diff views.
- Cross-user rendering needs a second account/role to confirm — say what that requires instead of declaring the class done.
- A raw-storage sink with safe rendering in 2 contexts = INCONCLUSIVE for XSS/injection until the email/export/audit paths are exercised; those paths often need an operator tap (reauth) + email-observable flow. State that need.

## Product-level gap checklist (secrets/platform targets)

Before closing a mature SaaS target, name the product-level surfaces even if untestable now — see references/product-level-gaps.md. Minimum set: service-token scope confusion (token minted for config/workplace A reading B), in-scope CLI/binary as attack surface (login MITM, update-channel integrity), invite-accept pre-auth flows (unverified-email -> ATO), SAML/IdP self-enablement, share-link GET enumeration rate limits, second-order rendering of raw-storage sinks. A senior reviewer will ask why these were not in the report.

## Verdict hygiene
- Per-class verdict files in the mission dir: what was tested (with payloads), result per variant, evidence file names, cleanup done, and an explicit status line (DEAD / PARTIAL / OPEN / INCONCLUSIVE). Commit them.
- Clean up test artifacts (test projects, secrets, webhooks, tokens) before closing a class; verify deletion returned 200 and revoke tokens.
- Never submit: WAF-bypass-only, info-only parser fingerprints, or SSRF whose only proof is a single anomalous 200 through an egress proxy.
