---
name: hunter-l3-supply-chain
description: "Use when hunting Supply Chain on a target. Loads the L3 technique sheet: This class targets the trust path between a vendor and its dependencies: self-hosted plugins whose identity is only guaranteed by a public registry, CI/CD tokens that can trigger release pipelines, an"
domain: cybersecurity
subdomain: web
tags:
- web
- supply-chain
- hunting
- l3
version: '1.0'
---

# Supply Chain — Technique Sheet

## Overview

This class targets the trust path between a vendor and its dependencies: self-hosted plugins whose identity is only guaranteed by a public registry, CI/CD tokens that can trigger release pipelines, and unpinned ("floating") dependencies that inherit whatever lands on an upstream main branch. It pays when a product ships build-time- or config-time-consumed content to a large user base, because poisoning one artifact propagates to every user on every platform. All techniques below come from four verified findings across three reports (Traffic Factory, Node.js org, DuckDuckGo) — every one resulted in or demonstrated product-wide compromise of tens of millions of users.

## Distinct sub-patterns

### 1. Plugin slug squatting / claim-and-backdoor (self-hosted WordPress plugin)

- **Endpoint shape / target:** Not an HTTP endpoint — the WordPress Plugin Directory SVN registry. Target shape: `plugins/{slug}` where `{slug}` is a plugin used internally but NOT distributed via wordpress.org. Verbatim target from records: plugin `tf-elementor` at `trafficfactory.com`.
- **Payload:** none stated in the record — no code payload required to prove the vuln. The researcher demonstrated the flow by registering the slug with a custom plugin and simulating shipping a malicious update.
- **Root cause:** The site runs a plugin that cannot live in the public plugin directory (it's custom/internal), but its update mechanism still trusts the slug name. Because `tf-elementor` was absent from the WordPress Plugin Directory, anyone could claim the slug. WordPress update checks are name-based: once an attacker owns the slug and pushes a version higher than the installed one, the victim site treats the attacker's package as the legitimate update.
- **Impact proven:** Confirmed `tf-elementor` installed on `trafficfactory.com` while unclaimed in WP SVN; the claim-and-backdoor-update flow was successfully simulated end-to-end with a custom plugin. Realistically: arbitrary PHP backdoor on the production site at next update check.
- **Exemplar reports:** id=1364851 [ajaysenr], Traffic Factory.

**Hunter recipe:** Fingerprint self-hosted WordPress sites for plugin slugs (e.g. `/wp-content/plugins/{slug}/` directory enumeration), then check each slug against wordpress.org. Any internal-only slug that is unclaimed is a claimable identity. Highest value: plugins with versioned update checks.

### 2. Semver-label release trigger via over-scoped GITHUB_TOKEN (`pull-requests:write`)

- **Endpoint shape / target:** GitHub Actions workflow chain in the Node.js org: `semver-label.yml` -> `semver-release.yml` -> `build.yml` (the release pipeline). The attacker-controlled input is the **semver label** (`patch`/`minor`/`major` style labels) on a pull request.
- **Parameter:** the default `GITHUB_TOKEN`, granted `pull-requests:write`.
- **Payload:** none stated — the attack is a label add, not a code injection. Verbatim chain step: "add semver label to PR via GITHUB_TOKEN".
- **Root cause:** A PR-triggering workflow ran with the default `GITHUB_TOKEN` scoped with `pull-requests:write`. Any GitHub user who can open a PR can, from the fork context, use that token to add labels to *their own* PR — and the label is what the downstream release workflow keys on. So a fully external attacker can mark their PR with a semver label, and when it merges, the automated release pipeline fires and publishes a new version containing (or influenced by) attacker-controlled content.
- **Impact proven:** Attacker controls the timing of releases and can chain into the automated release pipeline to publish a poisoned `content-scope-scripts` release — consumed by every DuckDuckGo browser and extension across all platforms, i.e. tens of millions of users.
- **Exemplar reports:** id=3618831 [ajaysenr], Node.js program.

**Hunter recipe:** On a target org, diff the `permissions:` blocks of every workflow triggered by `pull_request` / `pull_request_target`. Default-token grants of `pull-requests:write` (or `contents:write`) on PR-triggered workflows are the smell. Then trace what the workflow keys on: labels, comments, review state — anything a fork-PR author can influence through the token.

### 3. Ungated `pull_request_target` workflows (privileged context reachable by any user)

- **Endpoint shape / target:** 10 GitHub Actions workflows across the DuckDuckGo org, all triggered by `on: pull_request_target`.
- **Parameter:** none in particular — the vulnerability is the trigger + absence of access controls.
- **Payload:** none stated. Entry action per the record: "open fork PR against any of 10 workflows".
- **Root cause:** `pull_request_target` runs in the **base repo's** privileged context (base checkout, access to `secrets.*`, sometimes a mutable-ref checkout). If the workflow doesn't gate on approval, label, or branch restrictions, any GitHub user can open a fork PR and have the workflow execute in that privileged context — "privileged context with secrets exposed" per the record's chain.
- **Impact proven (as recorded):** Broad exposure surface — 10 `pull_request_target` workflows triggerable by any GitHub user. In context of the sibling finding (same report id=3618831), this is the broad top of the funnel leading toward release-pipeline compromise.
- **Exemplar reports:** id=3618831 [ajaysenr], Node.js program (record names the DuckDuckGo org).

**Hunter recipe:** Org-wide grep for `pull_request_target` in `.github/workflows/`. For each hit, check: does it check out the PR ref (mutable)? Does it expose secrets to PR-influenced code? Is there any approval gate? Count of ungated instances = severity multiplier.

### 4. Floating/unpinned dependency consumed from upstream main + over-privileged config PAT

- **Endpoint shape / target:** Dependency edge where a product build consumes another repo's **main branch with no tag or SHA pin** — verbatim target: `privacy-configuration` main branch, floating reference. The credential that protects that edge: `PRIVACY_CONFIG_PAT`.
- **Parameter:** `PRIVACY_CONFIG_PAT` (a PAT with rights to approve/merge PRs into privacy-configuration).
- **Payload:** none stated — this is an account/credential-level finding, not an injection payload.
- **Root cause:** Two defects compose: (a) the PAT-holder can approve and merge a malicious PR to `privacy-configuration` main (over-broad credential, no second approver / protection preventing self-merge of malicious changes); (b) every downstream product pulls `privacy-configuration` via floating `main`, so whatever lands on main — trusted implicitly — is shipped with the next build. No tag/SHA pinning means no integrity boundary between "someone edited config" and "product ships config".
- **Impact proven:** A poisoned privacy configuration propagates directly into the next build of every DDG product (Android, iOS, macOS, Chrome/Firefox extensions); silent disable of tracker blocking and fingerprint protection for all users.
- **Exemplar reports:** id=3619288 [ajaysenr], DuckDuckGo.

**Hunter recipe:** For any shipped product, map its config/dependency ingestion points and ask: is the source pinned (tag/SHA) or floating? Who can merge to the floating source? Are self-approval or single-PAT paths enough to land a change? The unpinned edge converts any upstream repo compromise into zero-click product compromise.

## Bypass / chain notes

Chains seen in the records, verbatim where available:

1. **Label -> release chain (id=3618831):**
   "add semver label to PR via GITHUB_TOKEN" -> "trigger automated release pipeline on merge" -> "publish poisoned content-scope-scripts release" -> "propagate..." (chain truncated in record; propagation to all DDG browser/extension users across all platforms is the stated impact). Note the attacker never needs code execution in CI — a *label* is the injection vector, and the pipeline itself does the shipping.
2. **Fork PR -> privileged context (id=3618831):** "open fork PR against any of 10 workflows" -> "privileged context with secrets exposed". The `pull_request_target` trigger is itself the bypass: it grants base-repo trust to untrusted PRs by design, and "without access controls" (no approval/label gates) removes the last boundary. Exposed secrets then feed the other findings (e.g. config PATs).
3. **Credential -> config -> all products (id=3619288):** "steal PRIVACY_CONFIG_PAT" -> "approve and merge malicious PR to main" -> "floating main dependency pulls poisoned config" -> "silent privacy degradation i..." (chain truncated; stated impact: silent disable of tracker blocking/fingerprint protection for all users). This is the canonical unpinned-dependency chain: single credential compromise = fleet-wide content control.
4. **Slug claim -> update backdoor (id=1364851):** claim unclaimed slug in WP SVN -> attacker's plugin update becomes the "official" update for the victim's installed plugin -> production backdoor. The "bypass" here is entirely identity-level: no exploit needed, just being first to register a name the victim uses.

Cross-cutting observation: findings 2/3 and finding 4 compose — a `pull_request_target` secret exposure is a plausible "steal PRIVACY_CONFIG_PAT" primitive, and the floating-main consumption is what converts it to fleet impact.

## Gotchas / what NOT to do

- **Do not actually publish a poisoned release.** Every payload-free finding here was proven by *simulating* the flow (id=1364851: "successfully simulated with a custom plugin") or by demonstrating the trigger path without shipping. Reproduce the trigger mechanism; document the propagation path; stop before altering real artifacts.
- **Don't treat "no exploit code" as "no impact."** Three of four findings carry zero payload — the vuln is authorization/identity, not injection. Write reports around the attacker-controlled step (label add, slug claim, PAT merge) and the propagation edge.
- **Don't report gated `pull_request_target` as a vuln.** The record's finding is specifically "pull_request_target without access controls" — the missing gate is the issue. Also scope claims to what's demonstrable: id=3618831's second record honestly reports *exposure* (10 triggerable workflows) rather than inflating it to a completed release poisoning.
- **Check the registry before assuming a plugin slug is claimable** — the finding depended on confirming `tf-elementor` was absent from the WordPress Plugin Directory *and* installed on the target. Both halves were verified.
- **Distinguish token scopes carefully:** the finding is the default `GITHUB_TOKEN` carrying `pull-requests:write` in a PR-triggered workflow — not a stolen personal token. Default-token over-scoping is a distinct, reproducible class; don't conflate with leaked secrets.
- **Floating dependency ≠ automatically vulnerable.** The record pairs floating main with a merge-path weakness (PAT can approve+merge malicious PR). The report must show the merge path, not just the unpinned edge.

## Real-world impact examples

- **Fleet-wide browser poisoning (id=3618831):** A single semver label added via the workflow's own `GITHUB_TOKEN` triggers `semver-release.yml`/`build.yml`, publishing a poisoned `content-scope-scripts` release consumed by every DuckDuckGo browser and extension on all platforms — tens of millions of users. Attacker also controls *release timing*.
- **Org-wide CI exposure (id=3618831):** 10 `pull_request_target` workflows across the DuckDuckGo org triggerable by any GitHub user, each executing with base-repo privileges and secret access.
- **Silent privacy kill-switch for all users (id=3619288):** Stealing `PRIVACY_CONFIG_PAT` and merging one PR to `privacy-configuration` main propagates (via the unpinned main-branch dependency) into the next build of DDG Android, iOS, macOS, and Chrome/Firefox extensions — silently disabling tracker blocking and fingerprint protection for every user, with no pinned-artifact integrity check to detect it.
- **Production WordPress backdoor via slug claim (id=1364851):** `tf-elementor` confirmed installed on trafficfactory.com and unclaimed in WP SVN; researcher claimed the slug, built a custom plugin, and successfully simulated shipping a malicious update through the normal update flow — arbitrary code delivery to production by exploiting name-based update trust.