---
name: hunter-l3-resource-injection
description: "Use when hunting Resource Injection on a target. Loads the L3 technique sheet: Resource Injection here covers attacks where an attacker supplies (or influences) a *resource* that a trusted component then loads, trusts, or decodes on the victim's side — a remote definition URL in"
domain: cybersecurity
subdomain: web
tags:
- web
- resource-injection
- hunting
- l3
version: '1.0'
---

# Resource Injection — Technique Sheet

## Overview
Resource Injection here covers attacks where an attacker supplies (or influences) a *resource* that a trusted component then loads, trusts, or decodes on the victim's side — a remote definition URL injected into a trusted web UI, an attacker-crafted binary resource handed to a daemon/wallet parser, or an unauthenticated remote procedure invoked directly. It pays when the injected resource is processed in the context of a trusted origin or a high-value backend (government systems, game backends, cryptocurrency daemons). Impact ranges from phishing/credential theft (Swagger UI configUrl), to remote DoS and state corruption (unauthenticated RPCs), to direct financial theft via crafted parsing (counterfeit wallet balances). Note: this is a narrow class in these records — three very different surfaces, so pattern-match by *shape* (injected/trusted resource → victim-side parsing), not by product.

## Distinct sub-patterns

### 1. Swagger UI remote definition injection via `configUrl`
- **Endpoint shape / parameter:** Any self-hosted Swagger UI instance whose URL accepts the `configUrl` query parameter, e.g.:
  `GET /swagger/index.html?configUrl=<attacker-controlled OpenAPI definition URL>`
- **Payload that fired (verbatim):** `?configUrl=<attacker-controlled OpenAPI definition URL>`
- **Root cause:** Swagger UI versions before 4.1.3 allow importing remote OpenAPI definitions via the `configUrl` parameter without restriction. The UI fetches and renders whatever definition the URL points to, inside the trusted self-hosted instance's origin.
- **Impact proven:** A crafted URL with `?configUrl=` loaded a remote OpenAPI definition inside the trusted instance context, opening a phishing vector — a victim visiting the "official" Swagger page sees attacker-controlled UI/content in the trusted domain. Reported against a U.S. Dept of Defense target.
- **Exemplar report IDs:** 2297561 [ajaysenr] (U.S. Dept Of Defense)

### 2. Unauthenticated/unvalidated remote RPC exposure
- **Endpoint shape / parameter:** Remote Procedure Call (RPC) surface exposed by a game backend (Xenoblade Chronicles X: Definitive Edition). No specific parameter or payload template was stated in the record — the weakness is the exposure itself.
- **Payload that fired:** payload not stated.
- **Root cause:** RPCs are exposed without proper authorization or validation — anyone who can reach the RPC endpoint can invoke the underlying procedures directly.
- **Impact proven:** Unrestricted remote invocation of the RPCs caused denial of service and allowed writing arbitrary flags (state corruption on the game/service side). Reported to Nintendo.
- **Exemplar report IDs:** 3062122 [ajaysenr] (Nintendo)

### 3. Crafted resource defeating parser validation (zero-amount RCT miner transaction)
- **Endpoint shape / parameter:** Monero wallet/daemon — specifically the daemon's miner transaction parsing path within block verification. No HTTP-style parameter; the "input" is a crafted block/transaction.
- **Payload that fired:** payload not stated (the record describes the construction: a zero-amount miner transaction that carries RCT signatures).
- **Root cause:** A verification gap: the daemon accepts a miner transaction with a zero amount that carries RingCT (RCT) signatures, and the wallet, when it sees amount = 0, decodes the actual amount from the RCT data. An attacker therefore controls the decoded amount via their own crafted RCT portion, so a crafted block yields a wallet balance of the attacker's choosing.
- **Impact proven:** The attacker can convince a victim wallet it received an attacker-chosen amount of XMR. Practical monetization: an exchange that auto-credits deposits would credit the counterfeit amount, enabling theft. The record notes the issue was verified as exploitable on master (Monero's master branch).
- **Exemplar report IDs:** 501585 [ajaysenr] (Monero)

## Bypass / chain notes
- No multi-step chains were present in these records (all three have `chain: (none)`).
- Sub-pattern 1 is itself a *context* bypass: the injected remote definition runs inside the trusted self-hosted Swagger origin, so the trust boundary of the hosting domain is crossed purely via a query parameter. If a target strips `configUrl`, note that this specific finding was fixed in Swagger UI 4.1.3 — anything at or above that version closes the documented vector, so version-fingerprint the UI first.
- Sub-pattern 3 is a *validation* bypass in spirit: the zero-amount representation is the mechanism — the "amount = 0" value is treated as "decode from RCT" rather than "reject/ignore", which is exactly the gap the attacker steers through.

## Gotchas / what NOT to do
- Don't assume all three sub-patterns share tooling: the only one with a classic HTTP probe is the Swagger UI `configUrl` injection (sub-pattern 1). Sub-patterns 2 and 3 are binary/protocol-level — RPC fuzzing and block/transaction crafting respectively.
- For Swagger UI: check the version before reporting. The vuln is scoped to < 4.1.3; a modern instance honoring `configUrl` in a non-abusable way is not this finding.
- For RPC exposure (sub-pattern 2): the record's proven impact is DoS + arbitrary flag writes. Do not escalate beyond what the target's policy allows (Nintendo in particular) — demonstrating DoS on production game infrastructure must follow the program's rules.
- For the Monero-style parsing bug: this was reported with a claim of verified exploitability on master — parsing/cryptography findings of this kind require real reproduction (a crafted block actually decoded by a wallet), not a theoretical writeup. Payload and exact construction details were not stated in the record, so don't fabricate one from this sheet alone.
- The Nintendo and Monero records state no parameters/payloads — do not extrapolate generic payload lists from other bug classes onto them.

## Real-world impact examples
- **U.S. Dept Of Defense (id 2297561):** A single URL parameter (`?configUrl=`) on a self-hosted Swagger UI (pre-4.1.3) let an attacker load their own OpenAPI definition into the government-hosted trusted page — a working phishing vector from a trusted .gov context.
- **Nintendo (id 3062122):** RPCs with no authorization/validation could be invoked remotely on Xenoblade Chronicles X: Definitive Edition, producing denial of service and arbitrary flag writes.
- **Monero (id 501585):** A zero-amount miner transaction carrying RCT signatures passed daemon verification, and the wallet decoded the attacker-chosen amount from the RCT data — counterfeit deposits of arbitrary XMR value, directly usable to steal from an exchange that credits deposits automatically. Verified exploitable on master.