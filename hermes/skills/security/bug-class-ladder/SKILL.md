---
name: bug-class-ladder
description: "Use when planning a bug-bounty hunt's testing phase."
version: 1.0.0
author: Sahli adem
license: MIT
metadata:
  hermes:
    tags: [security, bugbounty, methodology, planning]
    related_skills: [browser-cdp-hunting, hunter-mission]
---

## When to Use
Load when starting a new bug-bounty target's testing phase, when resuming a parked mission, or when
about to declare a target 'exhausted'. Governs the operator's class-by-class, depth-first methodology.

## The Methodology (operator's law — overrides EV-guessing and repo-file workflows)

1. **Scopes/assets first**: read the program page fully (in-scope, exclusions, signup requirements,
   bounty table, payout distribution, test-account provisions). Write scope.yaml — it is the law.
2. **Recon per asset**: super-scan (passive + allowed active), object model, JS/build-manifest mining,
   OpenAPI specs. See references/class-checklist.md for the recon toolkit.
3. **Then hunt bug-class by class**: for EACH class enumerate every variant/scenario, test them all,
   and reach a genuine dead end before moving to the next. Depth-first exhaustiveness beats
   expected-value prioritization.
4. **Park, don't drop**: when a class is blocked on an external dependency (missing account tier,
   async credential delivery), record it as PARKED with the exact unblock condition — never as DONE.
5. **The honest ledger**: maintain ATTACK-SURFACE.md per class (DEAD / PARKED / BLOCKED / OPEN with
   evidence). Before declaring a target exhausted, run the untested-class audit
   (references/class-checklist.md) — declaring 'squeezed' at 6-of-19 classes is a fail.

## Operator-specific rules (Sep 2026)

- Bounty strategy: stack SMALL paid findings ($100-500, real impact, never informative) over heroes.
- Zero-babysitting: batch all authed testing into one browser session per sitting; one-time setups OK,
  constant token/OTP paste loops NOT. Tell the operator exactly what to click/paste, then wait.
- Answer-then-wait: when the operator asks a question mid-hunt, answer it and wait for explicit 'go'.
- When stuck or blocked, say so plainly and let the operator choose continue-vs-park vs next target.
- H1 alias is username@wearehackerone.com (program pages often mis-state it); '+tag' sub-addresses
  work for second test identities unless the program forbids them.

## Common blocking dependencies and how to handle them

- **Lender/admin tier via async form**: submit on day one (the wait clock starts only then); park
  vertical-privesc and lender-view classes with PARKED status; keep hunting other classes meanwhile.
- **Captcha-walled consoles**: hCaptcha drops CDP-attached browsers at network level (stealth flags
  don't help). Fallback: operator logs in on their normal browser and pastes session cookies;
  inject via CDP `Network.setCookie`. Cloudflare Turnstile passes fine in a visible CDP browser.
- **Test-credential mismatches**: programs sometimes mis-document test creds (e.g. listing a 2FA
  code where a password goes). Try documented value AND the plausible alternates (user==pass),
  then note the doc gap — not a security finding.

## Support files

- `references/class-checklist.md` — full bug-class audit checklist + recon toolkit + error-differential analysis. Run the audit BEFORE declaring any target exhausted.
- `references/cdp-capture-cookbook.md` — live-session capture patterns: React form automation, download interception, Faye websocket authz testing, session cookie injection, mission-dir layout.

## Evidence discipline
Every probe: raw request + raw response, saved to the mission dir. Negative results logged with
what was proven. A correct negative beats a fabricated bug; duplicate-awareness protects reputation.
