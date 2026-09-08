---
name: hunter-l3-weak-prng
description: "Use when hunting Weak PRNG on a target. Loads the L3 technique sheet: Weak PRNG bugs occur when security-relevant values — passwords, tokens, keys, nonces, seeds — are generated from non-cryptographic randomness sources (`Math.random()`, unchecked entropy failures, seed"
domain: cybersecurity
subdomain: web
tags:
- web
- weak-prng
- hunting
- l3
version: '1.0'
---

# Weak PRNG — Technique Sheet

## Overview

Weak PRNG bugs occur when security-relevant values — passwords, tokens, keys, nonces, seeds — are generated from non-cryptographic randomness sources (`Math.random()`, unchecked entropy failures, seeded deterministic generators) instead of a CSPRNG. The bug is invisible in normal use: the code "works," output looks random, and reviewers rarely trace the entropy source. It pays when the weak value is the only thing protecting an asset (share-link passwords, session identifiers, keying material), because an attacker who can predict or reproduce the generator output bypasses the control entirely — often with no authentication required.

## Distinct sub-patterns

### Sub-pattern 1: `Math.random()` as sole entropy for generated passwords

- Endpoint shape / parameter: Client-side password generator fallback in file-sharing UIs — `GeneratePassword.js` (e.g. Nextcloud `files_sharing` app), triggered when the password-policy app is disabled. Param: `Math.random()`.
- Payload that actually fired (verbatim):
  ```
  Array(10).fill(0).reduce((prev, curr) => { prev += passwordSet.charAt(Math.floor(Math.random() * passwordSet.length)); return prev }, '')
  ```
- Root cause: When the password-policy app is disabled, the default share password generator falls back to `Math.random()`, which is not cryptographically secure (V8's implementation is seeded and, critically, its output is predictable from a small amount of observed output — multiple outputs can be recovered by solving the internal xorshift128+ state).
- Impact proven: Share-link default passwords were predictable/brute-forceable. An attacker could access files shared via password-protected links without knowing the password set by the user.
- Exemplars: 1745702 [Nextcloud, ajaysenr]

### Sub-pattern 2: `Math.random()` inside a crypto library's "random" primitive

- Endpoint shape / parameter: `crypto-js` `lib.WordArray.random(n)` — a function that consumers assume is CSPRNG-backed. Param: seed (via the process-level V8 seed flag).
- Payload that actually fired (verbatim):
  ```
  node --random_seed=42 -e "console.log(require('crypto-js').lib.WordArray.random(16))"
  ```
- Root cause: `Math.random()` is the sole entropy source inside `WordArray.random`. V8 exposes `--random_seed=N`, which makes `Math.random()` fully deterministic — so the "random" bytes become a pure function of the seed. Even without the flag, V8's PRNG is recoverable from observed outputs.
- Impact proven: `WordArray.random` produces identical, predictable output given the same seed. Users of crypto-js (keys, salts, IVs, tokens) receive values they perceive as crypto-secure but that are entirely predictable.
- Exemplars: 678989 [Node.js third-party modules, ajaysenr]

  Note the demonstration technique: because the weakness is in a *library*, the report proves it with a deterministic-seed flag on the runtime — a low-effort, verifiable PoC showing byte-for-byte identical output across runs. Reuse this when auditing third-party crypto wrappers: check what feeds `WordArray.random` / equivalents (`crypto.getRandomValues` or `Math.random`) before trusting the API name.

### Sub-pattern 3: Unchecked CSPRNG failure at key generation (native layer)

- Endpoint shape / parameter: Native keygen path — `src/crypto/crypto_keygen.cc` `SecretKeyGenTraits::DoKeyGen()` (OpenSSL-backed key generation). Param: none; the flaw is the missing return-value check on `EntropySource()`.
- Payload: payload not stated (the proof is a system-state setup, not an input string).
- Root cause: `EntropySource()`'s return value is unchecked; on a fresh boot or a system where `/dev/random` is missing/unavailable, OpenSSL's CSPRNG may fail to initialize, and key generation proceeds anyway with unmodified or predictable keying material instead of failing closed.
- Impact proven: Key generation can output unmodified or fully predictable keying material — complete breakdown of confidentiality and integrity for anything encrypted with or authenticated by those keys (CVE-2022-35255).
- Exemplars: 1690000 [Node.js, ajaysenr]

  Hunting angle: this is not an HTTP param you fuzz. It is a *conditional* bug — you must reproduce the failure condition (fresh boot, no `/dev/random`, restricted container) and then call the keygen API. Report style: demonstrate that key material repeats or is guessable under the failure condition, and cite the missing return-value check as the root cause.

## Bypass / chain notes

- Deterministic-seed bypass (record 678989): `node --random_seed=42` turns a probabilistic argument into a deterministic proof — same seed, same "random" output. This is the cleanest way to demonstrate `Math.random()`-based crypto weaknesses to triage.
- State-condition bypass (record 1690000): the vulnerability only manifests under CSPRNG-init failure; the "bypass" is environmental (fresh boot / missing `/dev/random`), not payload-based.
- No multi-step chains were present in these records — each finding stands alone. But note the natural chain shape for the password cases: predictable default share password → direct read of password-protected shares → internal file access.

## Gotchas / what NOT to do

- Don't trust API names. `WordArray.random`, "generatePassword", and keygen functions that wrap OpenSSL can all be weak underneath. Trace the entropy source one level down (does it call `crypto.getRandomValues` / `RAND_bytes` / read `/dev/urandom`, or does it call `Math.random` / an unchecked source?).
- Don't report "Math.random is used" abstractly. These findings succeeded because they showed *the specific security-relevant consumer* (share-link passwords, keying material) and *proven predictability* (identical output under a fixed seed, or key material unchanged under CSPRNG failure).
- For the native/conditional class, don't test on a healthy running system and conclude "not reproducible" — the bug requires the failure state (fresh boot, no `/dev/random`, hardened container).
- Watch the fallback paths, not the happy path. Record 1745702 fired only when the password-policy app was disabled — the default-on path was fine. Configuration-dependent fallbacks are where CSPRNG discipline is weakest.
- Scope check: client-side `Math.random` for non-security values (UI shuffling, sampling) is not a finding; only flag it when the output gates access or protects secrets.

## Real-world impact examples

- Nextcloud share links (1745702): default passwords protecting shared files were generated with `Math.random()` when the password-policy app was disabled — an attacker could predict or brute-force the password and read shared files without ever seeing it.
- crypto-js (678989, CVE referenced): `WordArray.random(16)` produced byte-identical output across runs under `--random_seed=42` — every key, salt, IV, or token derived from it was predictable, while users believed they were calling a CSPRNG.
- Node.js keygen (1690000, CVE-2022-35255): unchecked `EntropySource()` meant TLS-certificate/key-generation APIs could emit unmodified or fully predictable keying material when OpenSSL's CSPRNG failed to initialize — a total confidentiality/integrity failure for affected processes.