# Batch LLM extraction runner — `hermes -z` subprocess recipe

How to drive the bugagent report-extraction runner (`scripts/extract_reports.py`)
and, more generally, call `hermes` as an LLM subprocess from a Python batch job
and get CLEAN structured output back. Validated live Aug 29, 2026 (sample 30
reports → 33 findings, 33 rows, exit 0) and Aug 30, 2026 (2.5k writeup extraction).
Three non-obvious lessons below, plus a fourth that costs hours if missed.

## 1. The invocation that works (G2-frozen)

```python
cmd = ["hermes", "-p", "hunter-bulk", "--safe-mode", "--ignore-rules", "-z", prompt]
res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
```

- `-p hunter-bulk` = the DS volume-tier profile (deepseek-v4-flash via Nous).
- **`--safe-mode --ignore-rules` is the critical part.** Without them, `hermes -z`
  behaves like a full agent: it can write files ("saved to ~/findings.json"), wrap
  JSON in prose, or emit `Done.` text — all of which break `json.loads`. These flags
  force clean stdout-only response. This was discovered after the naive `hermes -p
  hunter-bulk -z "<prompt>"` returned an agent-wrapped file path instead of JSON.
- Add `-p hunter -z ...` + `--safe-mode --ignore-rules` the same way when routing a
  batch to GLM (brain profile) for judgment/synthesis.

## 2. Flag ordering — `-z` consumes the rest of argv

```bash
hermes -p hunter-bulk --safe-mode --ignore-rules -z "$(cat prompt.txt)"   # WORKS
hermes -p hunter-bulk -z --safe-mode --ignore-rules "$(cat prompt.txt)"   # FAILS
#   error: argument -z/--oneshot: expected one argument
```

All flags must come BEFORE `-z`. `-z` takes the prompt as its argument and eats
everything after it, so any trailing flags become part of the prompt string and
the parser errors on the first one.

## 3. Attribution shape is UNSTABLE across batch size — require report_id per finding

The single biggest hidden bug class. With ~5 reports per call the model returns a
flat array of finding dicts; with 30 reports it can return nested `[path, findings]`
pairs, a per-report keyed object, or flat dicts that carry an `id`/`impact` field
instead of `report_id`/`impact_proof`. NEVER assume a stable outer shape.

Robust design:
- **Prompt**: require every finding to carry `report_id` (from the `--- REPORT <id> ---`
  separator line above its report text). "Return ONLY a flat JSON array of findings."
- **Parser**: normalize once into `rid_to_findings` by reading `report_id`/`id` off each
  dict, then map back to sources by matching the report filename's numeric id
  (also accept keys ending with the id). Handle `impact` → `impact_proof` aliasing.
- **Persist raw stdout every batch** (`/tmp/extract_last_stdout.txt`) BEFORE parsing, so a
  0-result batch is diagnosable from disk instead of a silent empty list.
- **Make silent skips loud**: log non-dict findings, missing `impact_proof` drops, and
  parse errors with counts — a `+0` run must be explainable.

## 4. PITFALL — `OSError: [Errno 7] Argument list too long` (argv ARG_MAX)

Feeding the source text through the `-z` single argument means the WHOLE prompt is one
argv string. Linux caps a single argv string at `MAX_ARG_STRLEN` = 128KB. When a batch
of source documents (writeups/reports) pushes the prompt past that, the subprocess
raises `OSError: [Errno 7] Argument list too long: 'hermes'` — silently killing the
batch with NO rows written and NO partial output. Bit the 2.5k-writeup extraction
THREE times.

Fixes (both required — one alone is not enough):
- **Cap per-file size.** A single large document (a 500KB PDF-derived writeup exists
  in the corpus) blows past the limit even if the accumulated batch is small. Truncate
  each file to `MAX_FILE_CHARS = 30000` (the technique lives in the head of a writeup;
  you lose nothing). Without this, one big file in the batch = guaranteed crash.
- **Cap the accumulated batch byte-budget** well under the limit, e.g.
  `MAX_BATCH_BYTES = 25000`, so prompt + content stays far under 128KB. 90KB seemed
  safe but still failed — be conservative. (The 10k report extraction ran fine at
  larger batches because those files are small; writeups are not.)

Signature that ARG_MAX is the cause (not a model/parse bug): the process dies with
that OSError, batches already committed are kept (idempotency saves you), and no
`[done]` line prints. Fix both caps, re-run — it resumes past already-done W<id>s.

## The actual 0-result bug that ate the session (2026-08-29)

`for (rel, fm), findings in zip(sources, results)` where `results` elements are
`(src, findings_list)` tuples — this bound the WHOLE tuple to `findings`, so the
insert loop saw `findings = (".../192127.md", [])` and dropped everything as
non-dict. Fix: unpack the tuple explicitly:

```python
for (rel, fm), (_src, findings) in zip(sources, results or []):
```

Sign it took: run_batch returned 30 non-empty entries, raw stdout was clean JSON,
yet the DB stayed at 0. The corrupt shape only appears in the main-loop binding,
so debug by printing `type(findings)` at the drop site, not just in the parser.

## Multi-finding + data-safety gates (built in, keep them)

- `ensure_schema()` must run before any query — the runner is self-initializing
  (schema was specced but absent on first run → `no such table: reports_meta`).
- `impact_proof` is a MANDATORY field: drop + log any finding missing it.
- Idempotent on `UNIQUE(report_id, finding_index)`; skip reports already extracted.
- Never run destructive steps (prune) without a verified backup
  (`cp db/memory.db db/memory.db.bak-<date>` + matching `sha256sum`) per data-safety law.
- Sample is re-runnable (`random.seed(42)` + `--sample --limit N`) for a cheap
  pre-full-run validation on the SAME reports every time.
- Sanity-check output quality after a sample: row count, classes present, zero
  missing impact_proof, verbatim payloads. Watch for `weakness_class` drift toward
  raw CWE-ish names (cosmetic; normalize later via `params_matched` grouping).

## Cheap-first debugging order for a "+0 rows" batch job

1. Verify `hermes -z --safe-mode --ignore-rules` returns valid JSON on ONE report
   (RC 0, parse clean).
2. Probe the raw persisted stdout structure programmatically (top-level type, elem
   type counts) — is it flat, keyed, or nested?
3. Reproduce `run_batch` alone against that raw output; print each source's
   `type(findings)` — the corruption may live in the main-loop binding, not the parser.
4. Fix the specific shape/type mismatch, re-run the SAME seed sample, confirm rows
   land before scaling batch size up.

## Quality-audit pattern: GLM random-sample rating (validated Aug 30 2026)

After a big extraction, don't trust the yield blindly — audit it with the brain
model BEFORE merging. Pattern that caught real contamination:

- Pull N random records (e.g. 5 rounds × 10 records) from the new extraction.
- Feed each to GLM (`-p hunter --safe-mode --ignore-rules -z`) with a prompt that
  rates each record on ACCURACY / USEFULNESS / FABRICATION, scores 1-10, then gives
  a SUMMARY: average, count hunt-ready (≥7), noisy (4-6), garbage (≤3), + one-paragraph
  verdict.
- Save each round to `audits/glm-audits/round<N>.txt` for the record.

This is what revealed the **provenance/source-mismatch contamination** in batched
writeup extraction: a record whose `W<url>` id pointed to one writeup but whose
content described a DIFFERENT bug (the model cross-attributed content between docs
in the same batch). Aggregate verdict across 5 rounds ≈ 38% hunt-ready / 48% noisy /
14% garbage, average ~6.1 — enough good material to keep, but NOT enough to merge
blindly. Lesson: batched multi-doc extraction risks content-cross-contamination at
the source; audit with a second model before trusting/merging, and if contamination
is material, re-extract single-file or isolate the writeup records from the clean corpus.
