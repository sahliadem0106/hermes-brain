# Product-Level Gap Checklist (secrets / SaaS platform targets)

From a senior-review pushback on the Doppler sweep (2026-09-03). When a class-checklist
hunt ends at 0 findings, a reviewer will ask what a senior tester would have done instead.
Have this list answered (tested / blocked-by / not-applicable) BEFORE writing the rapport.

## Minimum set to answer
1. **Service-token scope confusion** — can a token minted for workplace/config A read or
   mutate B? (Secrets product crown jewel.) Requires minting a real service token and a
   second scope/account. On Doppler: CLI user tokens + session are workplace-bound and
   marker-verified; service tokens were never minted -> stated as a gap.
2. **In-scope CLI / binary as attack surface** — login flow MITM (5-word code display vs
   44-char polling code), redirect-URI handling, update-channel integrity. Source audit is
   free; dynamic testing may need a local proxy.
3. **Invite-accept pre-auth flows** — unverified-email -> ATO is the highest-probability
   class on invite products. Needs a 4th email (account caps often block this -> say so).
4. **SAML / IdP self-enablement** — if any tenant can flip SAML on and redirect auth flow;
   reauth URL references it.
5. **Share-link GET /s/ enumeration rate limits** — password oracle on reveal is one test;
   bulk GET enumeration of the token space is a different surface. Token space may be
   cryptographically large -> state that the rate-limit question is what matters, not brute
   force.
6. **Second-order rendering of raw-storage sinks** — see SKILL.md 'Second-order sinks'.

## How to write it up
- New rapport section 'Product-Level Gaps — identified, not tested' with per-item status.
- NEVER inflate: a gap list is honest reporting, not a finding. 'Not tested because X' is
  the correct sentence.
- Retest-priority flagging: an anomaly (e.g. 1x200 through an egress proxy) is a TOP
  retest-priority artifact, not a footnote.

## Rapport framing that survived review
- Title: '2-day methodology sweep', not 'full pentest'.
- Per-class labels TESTED / ATTEMPTED / INCONCLUSIVE (see SKILL.md Verdict calibration).
- Class 9/10 style corrections: raw-storage sink found but downstream (email/export/audit)
  untested = INCONCLUSIVE, even if 2 UI contexts rendered safe.
