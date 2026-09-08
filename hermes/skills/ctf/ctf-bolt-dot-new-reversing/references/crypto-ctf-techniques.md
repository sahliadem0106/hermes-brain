# Crypto CTF Techniques from Session

## Oracle Distinguishing via Generator Manipulation

**Challenge**: "False Witness" — discrete-log-based bit oracle where AES key bits determine whether the oracle returns PK values or random noise.

**The Trick**: Set the generator G = P-1 (≡ -1 mod P).

**Why it works**:
- H(msg) = G^msg mod P = (-1)^msg mod P
- Result is either 1 (msg even) or P-1 (msg odd)
- All PK values collapse to {1, P-1}
- Oracle for KEY_BIT=1 returns only 1 or P-1
- Oracle for KEY_BIT=0 returns full-range random (almost never 1 or P-1)

**One query per bit sufficient**.

## Bit Ordering Gotcha

Sage `Integer.bits()` is LSB-first; Python `int(bin_str, 2)` is MSB-first.
When reconstructing from bit vector: **reverse the bits** before converting.

## MQ over GF(2) — Ashen Field

**Challenge**: Multivariate quadratic cryptosystem over GF(2) with x_i^2 = x_i.

**Critical insight**: In GF(2), squaring (x_i^2 = x_i for all variables) AND the Frobenius automorphism ((a+b)^2 = a^2 + b^2) mean that F^4 + F^2 + 1 collapses to:
- F^2 has same coefficients as F at doubled t-exponents
- F^4 has same coefficients at quadrupled t-exponents
- After reduction mod g(t), ALL coefficients remain LINEAR in the original x variables
- The PK is therefore an AFFINE map: c = A*m + b

**Attack**: Gaussian elimination over GF(2). Dim = 137, rank may be 135 (2 free vars).

## RSA Partial Key Recovery — Fractured Seal

**Challenge**: RSA-2048 private key PEM where sections are replaced with `***`/non-ASCII junk.

**Workflow**:
1. Extract first base64 segment before asterisks → decode DER → get n (2040 bits) and e=65537
2. Find fragments between asterisk blocks that contain valid base64 chars
3. Second fragment typically starts with `da 6b 02 81 81 00` followed by 74 bytes = HIGH 592 BITS of p
4. p_high = bytes_to_long(fragment_bytes[5:]) (74 bytes, 584 bits effective)
5. k = 8 * (128 - len(p_high_bytes)) = 432 unknown low bits
6. Use Coppersmith: f(x) = x + (p_high << k) over Zmod(n)
7. Call: `f.small_roots(X=2^k, beta=0.5)` — bound is satisfied (432 < 510)

**Tools needed**: SageMath (for `small_roots`). Not installable via conda/pip on Windows — use https://sagecell.sagemath.org/ or a Docker container.

## Coppersmith Lattice Construction (for reference)

When Sage is unavailable, the polynomial h(x) from the reduced lattice should satisfy h(x0) = 0 AS AN INTEGER for the correct root x0. The lattice construction for m=1 (2x2) is:
```
B = [[n, 0],
     [A, X]]
```
where A = (p_high << k) % n and X = 2^k. The m=2 (3x3) construction adds an extra shift for better bounds.
