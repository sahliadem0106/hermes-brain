# GLM Quality-Audit Pattern

Audit LLM-extracted records with a second model before trusting them. GLM-5.3-flash
(hunter profile, MEDIUM effort) rates random samples. This catches provenance
mismatches and missing-field records that would otherwise bake into downstream
sheets/skills.

## When
- After any LLM extraction pass, before spending on L3 sheet synthesis or merging.
- The 2.5k writeup extraction got 5 rounds x 10 records audited; the verdict drove the
  single-file re-extraction decision.

## Prompt shape (works well)
Give GLM the raw records and ask it to rate each 1-10 on:
- ACCURACY: is class correct? does endpoint/payload/root_cause/impact match a real bug?
- USEFULNESS: could a hunter apply this (endpoint+payload+impact present/actionable)?
- FABRICATION: any sign of hallucination/invented detail? (penalize hard)

Then a SUMMARY: average, count hunt-ready (>=7), noisy/incomplete (4-6), garbage (<=3),
one-paragraph verdict on the extraction's main weakness.

## What to look for in the verdict
- **Provenance/source mismatch** (record id points to writeup A, content is from bug B):
  the worst failure — looks plausible, sends a hunter after a false lead. Tells you the
  batch extraction cross-attributed; fix with single-file extraction.
- **Missing endpoint/payload** on records where no request artifact existed: caps below
  hunt-ready even when the class is right. Tolerable if annotated "(not applicable)".
- **Off-domain material** (pure research/CVE/desktop-engine writeups) forced into the web
  schema: skip via a source-type filter.

## Script
`~/bugagent/scripts/audit_writeups_glm.py --rounds 5 --sample 10` — pulls random samples
of `source='writeup'` records, formats them, sends to GLM, saves each round to
`~/bugagent/audits/glm-audits/round{N}.txt`. Aggregate the SUMMARY lines across rounds.

## Scoring reality check (measured)
A real 5-round audit of 2.5k writeup records averaged ~6.1/10: ~38% hunt-ready, ~48%
noisy/incomplete, ~14% garbage. Aggregate the rounds; don't trust a single round.

## Interpreter note
Run with `~/memenv/bin/python`, not system python (PEP-668 protects system python; all
pipeline deps — fastembed/sqlite-vec/trafilatura — live in the memenv venv).
