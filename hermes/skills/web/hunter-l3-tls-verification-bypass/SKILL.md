---
name: hunter-l3-tls-verification-bypass
description: "Use when hunting TLS Verification Bypass on a target. Loads the L3 technique sheet: This class covers bugs where a TLS peer's certificate chain is accepted without proper verification — not because the attacker broke crypto, but because the application's own verification state is misapplied, stale, or never evaluated."
domain: cybersecurity
subdomain: web
tags:
- web
- tls-verification-bypass
- hunting
- l3
version: '1.0'
---

# TLS Verification Bypass — Technique Sheet

## Overview
This class covers bugs where a TLS peer's certificate chain is accepted without proper verification — not because the attacker broke crypto, but because the application's own verification state is misapplied, stale, or never evaluated. All four verified records here are in libcurl (program=curl), and they cluster around one high-yield hunting insight: **TLS configuration is treated as connection-scoped state that outlives or mismatches the request that set it**. These pay well because the impact is a silent credential-theft MitM primitive: the victim library accepts a rogue or attacker-influenced cert while the calling application believes verification succeeded (and API-level signals like `CURLE_OK` / `X509_V_OK` confirm that false belief).

## Distinct sub-patterns

### Sub-pattern 1: Verification-usage never evaluated on the manual custom-CA path (missing EKU / policy check)
- **Endpoint shape:** Not an HTTP endpoint — a code path. libcurl's Schannel backend, manual custom-CA path: `Curl_verify_certificate`, reached when the app sets `CURLOPT_CAINFO` or `CURLOPT_CAINFO_BLOB` instead of using the native Windows trust store.
- **Payload that fired (verbatim):**
  ```c
  memset(&ChainPara, 0, sizeof(ChainPara));
  ChainPara.cbSize = sizeof(ChainPara);
  ```
- **Root cause:** `CERT_CHAIN_PARA` is passed to `CertGetCertificateChain` with `RequestedUsage` unset, and no `CERT_CHAIN_POLICY_SSL` check is performed afterward. Consequence: the `serverAuth` EKU is never evaluated on this path — the check that would normally reject a certificate minted for a non-server purpose.
- **Impact proven (source review / PoC-predicted, not empirically tested on Windows):** a hostname-valid certificate signed by a trusted custom CA that contains only `id-kp-clientAuth` (no `serverAuth`) is predicted to pass Schannel peer verification. An attacker who can get a client-auth cert from a custom CA can impersonate any server to apps using this path.
- **Exemplar:** id=3734992 [ajaysenr], curl.

### Sub-pattern 2: Late `CURLOPT_SSL_VERIFYPEER` write poisons an already-established pooled connection
- **Endpoint shape:** Two sequential transfers on one easy handle: T1 connects with verification loosened; T2 requests `CURLOPT_SSL_VERIFYPEER=1` and picks up T1's pooled connection.
- **Payload that fired (verbatim):**
  ```c
  rc = curl_easy_setopt(ctx->easy, CURLOPT_SSL_VERIFYPEER, 1L);
  ```
- **Root cause:** `Curl_ssl_conn_config_update` writes the new verifypeer value into `conn->ssl_config` even after the handshake has already completed — there is no lifecycle guard. That late write poisons the pooled connection's reuse metadata, so a subsequent "verify everything" request matches a connection that was established without verification.
- **Impact proven (PoC, exit code 1):** T2 requesting VERIFYPEER=1 reused T1's pooled connection (same `conn_id=0`, log line `Reusing existing https: connection`) and accepted a self-signed certificate. The control — the same verifypeer=1 request with no pooled connection — correctly failed with `CURLE_PEER_FAILED_VERIFICATION`. The pool made a hard fail become a silent accept.
- **Exemplar:** id=3735276 [ajaysenr], curl.

### Sub-pattern 3: Session-cache/connection-match compares only `ssl_primary_config`, ignoring the extended ssl_config flags
- **Endpoint shape:** TLS connection/session reuse across a `curl_share` interface or `curl_multi` connection pool — handle A loosens TLS config, handle B (strict) shares the pool.
- **Payload that fired:** `./poc https://localhost:14443/` (PoC driver; the interesting data is in the config flags, not the URL).
- **Root cause:** `match_ssl_primary_config()` and the session-cache key compare only `ssl_primary_config` fields. Differing `ssl_config_data` flags are ignored when deciding whether a pooled TLS connection is compatible: `fsslctx`, `auto_client_cert`, `earlydata`, `no_revoke`, `no_partialchain`, `native_ca_store`. Two handles with materially different security postures look "the same" to the matcher.
- **Impact proven:** Handle B with strict `CURLOPT_SSL_VERIFYPEER=1` silently reused handle A's loosened TLS session through a shared connection pool — rc=0 versus control rc=60 (the classic peer-verification-failed exit). This is a MitM verification bypass. The same matching defect was additionally demonstrated to enable client-cert confusion and revocation-check bypass — i.e., one root cause, three impact classes.
- **Exemplar:** id=3761647 [ajaysenr], curl.

### Sub-pattern 4: setopt from a callback (write callback) mutates pooled connection config mid-flight
- **Endpoint shape:** A transfer whose write callback calls `curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, ...)` while a pooled connection exists, followed by a second, strict request.
- **Payload:** not stated in the record (the exploit is the callback-time setopt call itself).
- **Root cause:** Same core defect as sub-pattern 2 — `Curl_ssl_conn_config_update` overwrites `conn->ssl_config.verifypeer` with no handshake-state guard — but triggered from inside a callback rather than between transfers, making it easier to hit in real applications that adjust options dynamically during a transfer.
- **Impact proven:** A verifypeer=1 request silently reused a TLS connection established without chain verification. Observable forensic markers: `result=0`, `connects=0` (no new TCP/TLS setup), and `CURLINFO_SSL_VERIFYRESULT` returning a false `X509_V_OK`. Credentials flow over a rogue-cert connection while the application believes TLS verification passed.
- **Chain (3 steps, from the record):**
  1. Connect with `verifypeer=0`, accepting a rogue cert.
  2. Flip verifypeer to 1 inside a write callback, mutating the pooled connection's config.
  3. A second verifypeer=1 request reuses the now "legitimately configured" unverified connection.
- **Exemplar:** id=3831432 [ajaysenr], curl.

## Bypass / chain notes
- **The universal chain shape across records:** establish one connection with verification disabled or weakened → trigger a config write/reuse path that makes the strict request match that connection → harvest credentials on the unverified channel. Nothing cryptographic is attacked; only the connection-matching and config-lifecycle logic.
- **False-success amplifiers:** the strict request genuinely fails (`CURLE_PEER_FAILED_VERIFICATION`, rc=60) when no poisoned connection exists — so an attacker's first job is ensuring the pool contains a loosened connection. Once reuse happens, success signals are all green: `result=0`, `connects=0`, `X509_V_OK` from `CURLINFO_SSL_VERIFYRESULT`. Applications that check these signals get no warning.
- **Cross-flag confusion extends the blast radius (id=3761647):** because `match_ssl_primary_config()` ignores `fsslctx`, `auto_client_cert`, `earlydata`, `no_revoke`, `no_partialchain`, and `native_ca_store`, the same reuse defect also yields client-certificate confusion (one handle's client cert sent on another handle's session) and revocation-check bypass — test all of these, not just verifypeer, when you find pool-sharing between handles with divergent TLS configs.
- **EKU-laundering variant (id=3734992):** rather than breaking verification entirely, abuse a cert that is *legitimately signed by a trusted custom CA* but carries only `id-kp-clientAuth`. The missing `CERT_CHAIN_POLICY_SSL` check does the attacker's work for them. This requires no rogue CA at all — only a CA willing to issue client-auth certs (including public ones that issue free client certs).

## Gotchas / what NOT to do
- **Don't report sub-pattern 1 as empirically proven unless you tested on Windows.** The record itself flags it as source-review/PoC-*predicted* and "not empirically tested on Windows." Frame impact accordingly; overclaiming here weakens the report.
- **Don't test verifypeer poisoning with a fresh handle.** The control case correctly fails. You must establish the loosened connection first (same handle, or via `curl_share` / `curl_multi` pool) and then issue the strict request — the bug only manifests on reuse.
- **Don't assume `CURLOPT_SSL_VERIFYPEER` is request-scoped.** All three runtime records show it behaves as if it were, but it actually mutates connection-level state with no handshake guard — and it can be flipped from inside a write callback (id=3831432), not just between transfers.
- **Don't stop at verifypeer.** The matching defect in id=3761647 ignores six additional ssl_config flags; a verifypeer-only PoC under-reports the impact.
- **Don't look for these in a single-request HTTP fuzzer.** Every runtime bug here requires connection reuse, shared pools, or callbacks — stateful, multi-step, in-process behavior. Plain request/response scanners will never see it.

## Real-world impact examples
- **Self-signed cert accepted by a "strict" request (id=3735276):** `conn_id=0` reused, log shows `Reusing existing https: connection`; self-signed cert accepted; control request without a pooled connection fails with `CURLE_PEER_FAILED_VERIFICATION`. PoC exits 1 precisely to highlight the discrepancy.
- **Silent unverified reuse with green forensic signals (id=3831432):** verifypeer=1 request on a rogue-cert connection returns `result=0` with `connects=0` and `CURLINFO_SSL_VERIFYRESULT` = `X509_V_OK`. Credentials flow over the attacker-cert channel; the app's own TLS self-check reports success.
- **Strict handle inherits loosened session across a share/multi pool (id=3761647):** strict handle rc=0 on the poisoned session vs rc=60 in the control; same defect additionally demonstrated as client-cert confusion and revocation-check bypass.
- **Predicted server impersonation via client-auth-only cert (id=3734992):** a custom-CA-signed, hostname-valid cert lacking `serverAuth` passes the manual `CURLOPT_CAINFO`/`CURLOPT_CAINFO_BLOB` Schannel path — a full server-impersonation MitM against any app that configured a custom CA on Windows.