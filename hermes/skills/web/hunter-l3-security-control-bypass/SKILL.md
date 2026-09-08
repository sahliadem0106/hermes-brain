---
name: hunter-l3-security-control-bypass
description: "Use when hunting Security Control Bypass on a target. Loads the L3 technique sheet: This class covers defeating an explicit security control — a blocklist, a rate/time limit, an IAM deny policy, or a detection/logging configuration — without needing to break the underlying authentication."
domain: cybersecurity
subdomain: web
tags:
- web
- security-control-bypass
- hunting
- l3
version: '1.0'
---

# Security Control Bypass — Technique Sheet

## Overview
This class covers defeating an explicit security control — a blocklist, a rate/time limit, an IAM deny policy, or a detection/logging configuration — without needing to break the underlying authentication. The control exists, is enabled, and the attacker walks around it. It pays when the bypass defeats a paid security feature (browser safe-browsing, VPN enforcement) or a cloud provider's published hardening guidance, because the vendor must then patch the control itself. The recurring root cause across these records is **inconsistency between two planes/surfaces that are supposed to enforce or observe the same rule**: a URL normalization mismatch, a client-side clock vs server-side limit, a different IAM action namespace on a new API plane, and a different log field path on that same plane.

## Distinct sub-patterns

### 1. FQDN trailing-dot normalization bypass of a blocklist
- **Endpoint shape / parameter:** Any blocklist/allowlist lookup keyed on a hostname string — here, Brave iOS's safe-browsing (phishing/malware) blocklist check on the URL host before navigation.
- **Payload that actually fired:** `http://3e1.cn./` — verbatim. The payload is the trailing dot (`.`) appended to the registrable domain, forming the absolute FQDN form of the same host.
- **Root cause:** The safe-browsing blocklist lookup did not normalize the trailing dot. `3e1.cn.` and `3e1.cn` are the same host per DNS semantics, but as strings they differ, so the exact-match lookup against the blocklist missed the FQDN form.
- **Impact proven:** Bypassed Brave iOS phishing/malware blocking and loaded the blocked domain `3e1.cn.` via the trailing-dot hostname while the safe-browsing feature was enabled.
- **Exemplar:** id=1068505 [ajaysenr], Brave Software.

### 2. Client-side clock manipulation to extend a disconnected-time limit
- **Endpoint shape / parameter:** Cloudflare WARP Android — local device settings; the parameter is the **system date/time**, not an API field.
- **Payload:** Payload not stated (the action is changing the device clock backward/forward so the elapsed-time check against the override code never trips).
- **Root cause:** Missing server-side validation of the local clock. The "maximum allowed disconnected time" enforced by an admin override code is computed against the device's own clock, so whoever controls the device controls the elapsed time.
- **Impact proven:** An attacker with local access extended the maximum allowed disconnected time of WARP beyond the admin override-code limit. Assigned CVE-2023-3747.
- **Exemplar:** id=2043885 [ajaysenr], Cloudflare Public Bug Bounty.

### 3. IAM action-namespace drift: Deny policy misses the new plane's action
- **Endpoint shape / parameter:** `POST https://bedrock-mantle.{region}.api.aws/v1/chat/completions`, parameter: **Bearer token** (ABSK / `bedrock-api-key-*` tokens).
- **Payload:** "Deny bedrock:CallWithBearerToken IAM policy bypass" — i.e. apply the AWS-published SCP/IAM deny statement verbatim, then call the mantle plane with a Bedrock API key.
- **Root cause:** The mantle plane authorizes with the IAM action `bedrock-mantle:CallWithBearerToken`, which does not match the AWS-published `Deny bedrock:CallWithBearerToken` statement. The policy is namespace-scoped to the standard plane only.
- **Impact proven:** With the explicit deny in place, the standard plane returned 403 but mantle returned 200; ABSK and `bedrock-api-key-*` tokens authenticated and produced **billable inference on 38 of 39 premium models** (e.g. `mistral.voxtral-mini-3b-2507`, total_tokens 13/7… recorded in the report).
- **Exemplar:** id=3702072 [ajaysenr], AWS VDP.
- **Chain seen:** generate Bedrock API key (ABSK) provisioning a phantom IAM user with `AmazonBedrockLimitedAccess` → apply AWS-recommended SCP/IAM `Deny bedrock:CallWithBearerToken` → call mantle plane (deny is not enforced there).

### 4. Detection-rule field-path drift: log events land at a different JSON path
- **Endpoint shape / parameter:** CloudTrail **data events** with `eventSource: bedrock-mantle.amazonaws.com`.
- **Payload:** `requestParameters.callWithBearerToken = true` — this is the actual field/value emitted in the mantle data event, as opposed to `additionalEventData.callWithBearerToken` on the standard plane.
- **Root cause:** Mantle data events place the bearer-token attestation at `requestParameters.callWithBearerToken` instead of the `additionalEventData.callWithBearerToken` path that AWS-published detection rules filter on. A SIEM rule written exactly per AWS guidance therefore never matches.
- **Impact proven:** A SIEM rule filtering on `additionalEventData.callWithBearerToken=true` (the AWS-published example) matched **zero** mantle events; a leaked-key attacker pivoting to mantle is invisible to detection built per AWS guidance.
- **Exemplar:** id=3702072 [ajaysenr], AWS VDP.
- **Chain seen:** leaked Bedrock API key authenticates to bedrock-mantle.api.aws → mantle emits CreateInference data event with the field at `requestParameters.callWithBearerToken` → SIEM rule misses it.

### 5. Logging-plane coverage gap: no managed log capture on the new plane
- **Endpoint shape / parameter:** `bedrock-mantle` inference logging configuration — specifically the absence of any customer-facing equivalent of `put-model-invocation-logging-configuration` for the mantle plane (that API covers only `bedrock` / `bedrock-runtime`).
- **Payload:** `vdp-paired-test-1777329695` — a unique paired marker string sent through both planes in a live test.
- **Root cause:** There is no customer-facing mantle prompt/response logging; no `aws bedrock-mantle` equivalent of the invocation-logging configuration exists, so mantle content never reaches `BedrockModelInvocationLogs`.
- **Impact proven:** Paired-marker live test: bedrock `InvokeModel` logged **1 hit** of the marker in `BedrockModelInvocationLogs` while mantle `CreateInference` with the same marker logged **0 hits** — mantle prompt/response content is not retrievable from any AWS-managed logging destination, so IR/forensics on a leaked key finds nothing.
- **Exemplar:** id=3702072 [ajaysenr], AWS VDP.
- **Chain seen:** leaked key runs inference via bedrock-mantle plane → configured `put-model-invocation-logging-configuration` does not capture mantle → grep of the destination log store finds zero mantle hits.

## Bypass / chain notes
- **Two-plane inconsistency is the master pattern.** Three of the five sub-patterns (3, 4, 5) come from one report about one new API plane: enforcement (IAM deny), detection (CloudTrail field path), and forensics (invocation logging) all exist on the standard plane but are absent or differently-shaped on the new plane. When a vendor launches a second endpoint/plane/version, systematically re-check every control published for the first one.
- **Chain shape for the AWS finding:** provision credentials (ABSK key creating a phantom IAM user with `AmazonBedrockLimitedAccess`) → apply the vendor's own recommended deny policy → demonstrate it does not bind to the alternate plane (403 vs 200) → then show the *detection* and *forensic* gaps with a paired-marker test. Stacking enforcement + detection + logging evidence in one report dramatically raised its value.
- **Paired-marker methodology** (record 3702072, sub-pattern 5): send a unique marker (e.g. `vdp-paired-test-1777329695`) through both planes and grep the expected log destination. A 1-hit vs 0-hit result is undeniable, quantified proof of a coverage gap — no vendor interpretation needed.
- **String-normalization bypasses** (sub-pattern 1) generalize: trailing dot, percent-encoding, Unicode confusables, case — any canonicalization the *resolver* performs but the *filter* does not. Here the check was string-exact while DNS canonicalized the host.
- **Clock-based limit bypass** (sub-pattern 2) needs only local access, no network payload — the "payload" is an OS settings change. Time-limited overrides/grace windows enforced client-side are the target shape.

## Gotchas / what NOT to do
- Do not test blocklist bypasses with random domains — record 1068505 used a domain already on Brave's blocklist (`3e1.cn`), so the "before" state (blocked) was demonstrable. You must first prove the control blocks the canonical form, then show the variant loads it.
- The WARP bypass requires **local device access** — disclose it as a design/validation weakness (which is why it got a CVE), and scope your impact claims to attackers with local access; do not overstate remote exploitability.
- Do not assume a deny policy "doesn't work" from reading docs — record 3702072 verified empirically: standard plane 403, mantle 200, with the deny active, and enumerated model coverage (38/39). Quantify.
- Don't stop at the enforcement bypass: the same report also showed the SIEM miss (sub-pattern 4) and the logging gap (sub-pattern 5). Reporting only the 403-vs-200 would have been a weaker, arguable finding; the full triad is a control-suite failure.
- These are control bypasses, not auth bypasses — tokens were legitimately issued. Frame impact around policy violation + billable abuse + undetectability, not "unauthorized access to someone's account."

## Real-world impact examples
- **Brave iOS (id=1068505):** A domain on the phishing/malware blocklist loaded in a user's browser while safe-browsing was enabled, via `http://3e1.cn./` — the flagship protection of the browser silently defeated by a trailing dot.
- **Cloudflare WARP (id=2043885):** Admin override-code enforcement of maximum disconnected time bypassed by changing the device date/time; assigned CVE-2023-3747.
- **AWS Bedrock mantle (id=3702072, one report, three proofs):** (1) With AWS's own published `Deny bedrock:CallWithBearerToken` SCP in place, ABSK/`bedrock-api-key-*` tokens still produced billable inference on 38 of 39 premium models via `bedrock-mantle.{region}.api.aws` (403 on standard plane vs 200 on mantle); (2) AWS-published detection rules matched zero mantle events because the flag sits at `requestParameters.callWithBearerToken` not `additionalEventData.callWithBearerToken`; (3) paired-marker test proved mantle prompts/responses appear in no AWS-managed log — a leaked-key attacker operating on mantle is simultaneously billable, undetectable, and uninvestigable.