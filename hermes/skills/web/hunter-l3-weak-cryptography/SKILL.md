---
name: hunter-l3-weak-cryptography
description: "Use when hunting Weak Cryptography on a target. Loads the L3 technique sheet: This class covers the use of broken, weak, or non-cryptographically-secure primitives where strong ones are required: weak TLS parameters (short DH groups, undersized RSA keys), deprecated ciphers (DE"
domain: cybersecurity
subdomain: web
tags:
- web
- weak-cryptography
- hunting
- l3
version: '1.0'
---

# Weak Cryptography — Technique Sheet

## Overview
This class covers the use of broken, weak, or non-cryptographically-secure primitives where strong ones are required: weak TLS parameters (short DH groups, undersized RSA keys), deprecated ciphers (DES), and — the most reliably exploitable sub-class — authentication/security tokens generated with predictable PRNGs (`Math.random()`, PHP `rand()`) or hashed with fast, unsalted digests (`md5`). It also includes "entropy leak" bugs where a nominally secure RNG is used with a needlessly small alphabet, shrinking effective entropy. Most of these are found by source review (open-source / exposed code), config scans (SSL Labs, testssl.sh), or by reasoning about generator math. They pay best in programs with security-sensitive scope (TLS endpoints, token generation, crypto libraries) and are typically reported as medium severity unless a full token-guessing or MITM chain is proven.

## Distinct sub-patterns

### 1. Weak Diffie-Hellman key exchange in TLS config (Logjam-class)
- Endpoint shape: any TLS-enabled host, e.g. `grtp.co:443`, `gratipay.com TLS`. No parameter or payload in the HTTP sense — the "payload" is the handshake the server accepts.
- Payload that actually fired: SSL Labs / scan output showing weak suites, e.g. verbatim: `DH 1024 bits (p: 128, g: 128, Ys: 128)` (id=76303, Gratipay). For id=117458 the report simply demonstrates grtp.co "permits weak Diffie-Hellman key exchange parameters" (no raw scan dump quoted in the record).
- Root-cause pattern: server TLS configuration accepts DHE_EXPORT / short-DH (1024-bit or weaker) cipher suites. A MitM can force downgrade to the weak suite and, with precomputation against the 1024-bit group, passively or cheaply actively decrypt traffic.
- Impact proven: exposure of connections to downgrade/MitM (Logjam-class) attacks (id=117458); confirmation via SSL Labs that the server supports weak DH 1024-bit cipher suites (id=76303).
- Exemplars: id=117458, id=76303 (both Gratipay).

### 2. TLS certificate with public key shorter than 2048 bits
- Endpoint shape: any TLS host's certificate; here `iandunn.name` (id=150078, Ian Dunn program). Discovery is certificate inspection, not an HTTP request.
- Payload: not stated — the finding is the certificate property itself (observed key < 2048 bits).
- Root-cause pattern: cert/key generated with a 1024-bit (or smaller) RSA key. Sub-2048-bit RSA keys are within reach of well-funded attackers and violate modern baseline requirements.
- Impact proven: existence of a TLS certificate with a <2048-bit public key on a program asset.
- Exemplar: id=150078.

### 3. Auth tokens generated with `Math.random()` (JS)
- Endpoint shape: token generation code in the app, e.g. `lib/common/index.js` (joola.io, id=31166). Applied surface: whatever consumes the token — session tokens, API keys, reset links.
- Payload: not stated — the demonstration is code review showing the token path calls `Math.random()`; the report demonstrated tokens are predictable/guessable as a result.
- Root-cause pattern: `Math.random()` is a non-cryptographic PRNG (typically xorshift128+ in V8) with small internal state (128 bits) and deterministic seeding; with a few observed outputs an attacker can recover state and predict future tokens.
- Impact proven: auth tokens produced by a predictable `Math.random()`-based generator, making them guessable — i.e., authentication bypass by predicting another user's token.
- Exemplar: id=31166 (joola.io).

### 4. Auth tokens generated with PHP `rand()` + `md5()`
- Endpoint shape: server-side token generation, e.g. `concrete/authentication/concrete/controller.php` (Concrete CMS, id=31171).
- Payload that actually fired (verbatim):
```php
private function genString($a = 20)
{
    $o = '';
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+{}|":<>?\'\\';
    $l = strlen($chars);
    while ($a--) {
        $o .= substr($chars, rand(0, $l), 1);
    }
    return md5($o);
}
```
- Root-cause pattern: two stacked weaknesses: (a) PHP `rand()` is a seeded Mersenne-style PRNG, not CSPRNG — output is predictable, especially if the seed is recoverable; (b) the result is collapsed into an unsalted MD5 hex digest (128 bits, fast to brute-force) regardless of the input alphabet. Also note the off-by-one `rand(0, $l)` — inclusive upper bound can index one past the string.
- Impact proven: tokens from this generator are demonstrably guessable.
- Exemplar: id=31171.

### 5. Deprecated cipher in a crypto library (DES in NTLMv1)
- Endpoint shape: library source, `lib/curl_ntlm_core.c` (curl, id=3116935). The "parameter" is the cipher choice in the NTLM authentication code path.
- Payload: not stated — proof was code-level confirmation that libcurl uses `kCCAlgorithmDES` (56-bit key) for NTLMv1 cryptographic operations.
- Root-cause pattern: NTLMv1's design requires DES; DES's 56-bit key is brute-forceable. A client library implementing NTLMv1 forces users into broken crypto during authentication.
- Impact proven: confirmed DES usage in NTLM auth, exposing NTLM traffic to brute-force, MITM impersonation, and unauthorized access.
- Exemplar: id=3116935.

### 6. Reduced-entropy IV/randomness via restricted charset (entropy leak)
- Endpoint shape: crypto helper class, `OC\Security\Crypto::encrypt` IV generation in Nextcloud (id=852841). The parameter is the charset argument to `SecureRandom::generate` — instead of raw bytes it uses a 64-character alphabet (`a-Z0-9+/`).
- Payload: not stated — the "payload" is the entropy math: a 16-byte IV drawn from 64 symbols has only 64^16 permutations = 96 bits of effective entropy instead of 128.
- Root-cause pattern: encoding randomness as characters from a restricted alphabet instead of emitting raw CSPRNG bytes silently divides entropy. In CBC mode, low-entropy IVs make birthday-bound IV collisions (breaking confidentiality of identical plaintexts) far more likely, and any cache-timing side channel against the generator leaks secret values with higher probability.
- Impact proven: reduced IV entropy raising IV-reuse probability, weakened encryption key strength, and a cache-timing attack vector against `SecureRandom::generate`.
- Exemplar: id=852841.

## Bypass / chain notes
The records contain no multi-step exploit chains (`chain: (none)` in all 7). The practical "chains" are implicit single-step escalations you can attempt when validating:
- Token-prediction bugs (sub-patterns 3, 4): the natural chain is predict token → session hijack / account takeover. Severity in the reports rests on demonstrated predictability; pairing with a live account takeover raises it.
- TLS weaknesses (sub-patterns 1, 2): chain is MitM position → force weak suite (Logjam) or exploit small key. Requires network position, so reports stopped at scan/code proof.
- DES/NTLM (sub-pattern 5): chain is capture NTLM exchange → offline brute-force of the 56-bit DES key → impersonate the user.
- Charset-entropy bug (sub-pattern 6): chain candidate is a cache-timing side channel on the generator, per the report itself.

## Gotchas / what NOT to do
- Do not report weak TLS parameters without evidence: both TLS records were backed by concrete confirmation (SSL Labs output like `DH 1024 bits (p: 128, g: 128, Ys: 128)` or direct certificate inspection). A hunch is not a report.
- Distinguish server-config from code bugs: TLS DH/cert-size issues are config fixes; PRNG/charset issues need code changes. Misframing leads to N/A triage.
- `Math.random()` findings need the actual token path — prove the token handed to users comes from the insecure generator (id=31166 traced it to `lib/common/index.js`), not from an unused helper.
- Don't overlook layered weakness: in id=31171 the report wins because it flagged both `rand()` (predictable PRNG) and `md5()` (fast, unsalted digest) in the same function — one alone might be downgraded.
- Charset-entropy bugs require the exact math: state the alphabet size, the byte length, and the effective bits (64^16 = 96-bit for a "16-byte" IV, id=852841). "It feels less random" gets rejected.
- Library cipher findings (DES in curl) must pinpoint the code (`lib/curl_ntlm_core.c`, `kCCAlgorithmDES`) and the protocol context (NTLMv1) — generic "DES is bad" is not actionable for the maintainer.
- Several of these records are single-program, config-level findings (a lone 1024-bit DH or a small cert key); expect medium/low severity and duplicate-prone triage — check for prior reports of the same host's TLS config.

## Real-world impact examples
- Gratipay (id=117458, id=76303): grtp.co / gratipay.com accepted weak DH 1024-bit key exchange, exposing user connections to downgrade and MitM (Logjam-class) attacks — confirmed by scan output `DH 1024 bits (p: 128, g: 128, Ys: 128)`.
- Ian Dunn (id=150078): iandunn.name served a TLS certificate whose public key was below the 2048-bit baseline.
- joola.io (id=31166): authentication tokens generated by `Math.random()` in `lib/common/index.js` were predictable, making them guessable by an attacker.
- Concrete CMS (id=31171): the `genString()` routine in `concrete/authentication/concrete/controller.php` built auth tokens from `rand()` over a char pool and collapsed them with unsalted `md5()`, yielding guessable tokens.
- curl (id=3116935): libcurl's NTLMv1 implementation used 56-bit DES (`kCCAlgorithmDES`), exposing NTLM-authenticated traffic to brute-force, MITM impersonation, and unauthorized access.
- Nextcloud (id=852841): `SecureRandom::generate` with a 64-char charset gave `OC\Security\Crypto::encrypt` IVs only 64^16 ≈ 96-bit effective entropy instead of 128-bit, raising IV-reuse risk and opening a cache-timing vector against generated secrets.