# Report Storage Architecture — the "pyramid" + GLM independent review (2026-08-29)

How to store 13k disclosed bug-bounty reports so a hunter agent actually USES the
techniques mid-hunt, given a hard context limit (~128k–1M tokens) and a ~$2 budget.
This feeds the operator's pending storage decision. Proposed by the volume agent,
independently reviewed by GLM 5.3 Flash (hunter profile, one-shot `-z`). Both agree
on the shape; GLM's verdict was REVISE with concrete additions below.

## The core constraint (why compression, not retention)

An agent cannot hold 13k techniques in context. "Remembering" = techniques live in
an external vector store + SQLite, and per-hunt search pulls the top-k into context.
So the design goal is: retrieve the RIGHT LEVEL for the task, with everything linked
so you can drill down to evidence. Compression is lossy on prose, near-lossless on
technique — because reports within a class repeat the same ~5-10 patterns. The 300th
IDOR report teaches almost nothing the 3rd didn't.

## The pyramid (4 layers, all linked by report_id / file path)

- **L1 Evidence** — the 13k reports + 813 writeups as `.md` files on disk. Never
  embedded wholesale, never read in full. Source of record for verification.
- **L2 Technique records** — one distilled record per FINDING (see below) embedded
  in vectors; metadata in SQLite `reports_meta`. Answers "show me a real IDOR with a
  UUID param that paid $X". The mid-hunt retrieval workhorse.
- **L3 Canonical technique sheets** — per weakness class, synthesized from the top
  reports of that class (~60-100 sheets, 200-1000 tokens each): canonical endpoints,
  payloads that fired, root-cause patterns, bypass chains, 2-3 exemplar report links.
  The loadable layer (whole sheet fits in context).
- **L4 Skills** — top 10-20 payout-dominant classes promoted to SKILL.md playbooks,
  injected every turn with NO retrieval step. The always-on layer.

Retrieval flow mid-hunt: L4 already in context → query L2 for real exemplars matching
the target → open L1 file for raw req/resp to verify a repro → load L3 sheet when
attacking an unfamiliar class.

## GLM 5.3 Flash's REVISE verdict (independent, no conversation memory)

Directionally correct; four concrete changes:

1. **L2 must be multi-finding, not one-record-per-report.** Disclosed reports
   routinely chain 2-3 findings (SSRF → AWS metadata → RCE). N findings → N records
   sharing `report_id`. Otherwise bypass chains — the most valuable part — get flattened.
2. **Don't fix the sheet count as a number.** Derive it from real classes: 196 classes
   in by-weakness, ~50-100 web-actionable → ~60-100 sheets. CUT any class with <5 good
   reports (thin evidence → hallucinated canonical payloads).
3. **FTS5 + vectors is enough; no graph DB.** Add one cheap join instead: a
   `params_matched` key (method+path+param template, e.g. `GET /api/*/user id`) — the
   dedup key that answers "is this endpoint pattern burned?" (duplicate analysis).
4. **Sheets rot without a rebuild trigger.** Add `sheets_meta` (source report_ids,
   build date, report count) so sheets are regenerable, not hand-authored artifacts.
   Feed the 813 writeups into L3 synthesis preferentially (already curated).

## reports_meta v2 schema (GLM additions in bold)

`report_id, title, program, severity, bounty, **asset_type**, **has_bounty** (distinguish
$0 from unknown), **reported_date** vs **disclosure_date** (time-to-bounty = payout
difficulty), **weakness_id** (H1 CWE code → joins by-weakness), **finding_count**,
**params_matched**, **is_chain**, researcher (demoted — low value for hunting)`,
plus `report_path` for L1 linkage.

## Extraction minimum-viable set (per finding)

KEEP (mandatory): `weakness_class`, `endpoint+param`, `payload` (verbatim),
`root_cause` (one sentence), `impact_proof` (MANDATORY — separates real finding from
theoretical; what the agent quotes in its own reports), `bypass_chain` (ordered list,
optional).
CUT: `title` (redundant with class+endpoint — debatable, a title is ~5 tokens and makes
hits greppable; the volume agent argued to keep it), full req/resp (keep only request
line + 2-3 relevant headers + the response fragment proving the finding).
NOT extracted: CVSS math, reporter commentary/persona, program policy text, remediation
advice (only record if it leaks a bypass), acknowledgement threads, images/captions,
votes/dates/researcher (except in reports_meta for payout analytics).

## Value per dollar ranking (budget $2)

1. Per-class sheets — highest reuse per token (one 500-token sheet = 50 reports' pattern).
2. Structured L2 records in vectors — the mid-hunt retrieval workhorse.
3. L4 skills for top-10 ubiquitous classes (IDOR, SSRF, XSS, access control) — zero
   latency, but only where the class appears on nearly every target.
4. Raw-chunk re-embedding — near-zero marginal value once 1-3 exist; L1 on disk suffices.

## Recommended pipeline (GLM's)

1. Move by-* tables, link lists, off-domain, stack traces OUT of vectors → SQLite (no LLM cost).
2. One-pass multi-finding LLM extraction over 13k reports on DeepSeek volume tier (~$0.50-1.70).
3. Build `reports_meta` + `params_matched` index; embed L2 records.
4. Synthesize sheets for classes with ≥5 reports, writeups as seeds, mark provenance.
5. Promote top-10 payout classes to SKILL.md.
6. RE-TEST the four benchmark queries + "high severity paid bounty" BEFORE deleting anything
   (the payout query should now hit SQL, not vector table rows).

## Cost math (Nous Portal, verified prices)

One-time extraction of 13k reports: ~13M–65M input + 2.6M–5.2M output tokens.
- DeepSeek V4 Flash ($0.02/$0.08 per 1M): **~$0.50–$1.70** total (1k–5k tok/report).
- GLM 5.3 Flash ($0.06/$0.20): ~$1.30–$4.94.
- Embedding: $0 (local fastembed ONNX). Per-hunt retrieval ~8k tok → ~$0.001/query.
Volume-tier DS is the routing-correct choice for the bulk extraction (T1).
