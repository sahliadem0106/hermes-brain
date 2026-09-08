---
name: knowledge-memory-audit
description: "Audit bugagent SQLite+vector memory DB content quality."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [memory, sqlite, sqlite-vec, fts5, rag, audit, bugagent, knowledge]
    related_skills: [ops-repo-provisioning, hermes-kali-box-ops]
---

# Knowledge Memory Audit

Audit the content QUALITY of the bugagent semantic memory DB (`~/bugagent/db/memory.db`) — the SQLite + sqlite-vec + FTS5 stack from `MEMORY-STACK.md`. This is an AUDIT (classify content types, rate beneficial vs noise, recommend what the TRUE thing to extract from reports is), NOT a benchmark, NOT hunting. No targets, no scanning, no cron, no scope.yaml edits. Validated live Aug 29, 2026.

## When to Use

- Operator issues the memory-audit brief (repo has `prompts/kali-memory-audit.md` — the reusable prompt).
- Re-audit after re-indexing or after writeup ingestion (`WRITEUP-INGEST.md` phase).
- Any "is our RAG worth it / what should vectors hold" decision for the memory stack.
- Counting/querying the vec index when the `sqlite3` CLI can't.

## Stack layout (memory.db)

- `knowledge_chunks(id, source, chunk, embedding BLOB, ts)` — the corpus.
- `knowledge_fts` — FTS5 virtual table (keyword fallback), same row count.
- `knowledge_vec` — sqlite-vec virtual table, one row per embedded chunk.
- `observations`, `sessions` — episodic memory (not part of the audit).
- Scripts run with `~/memenv/bin/python` (`memory_search.py`, `log_note.py`). Never system python.

## PITFALL — counting vectors: sqlite3 CLI lacks sqlite-vec

`sqlite3 memory.db "SELECT count(*) FROM knowledge_vec;"` FAILS with
`Parse error: no such module: vec0` — the CLI binary does NOT have the extension
loaded, this is NOT a broken index. Count via the venv instead:

```bash
~/memenv/bin/python - "$DB" <<'EOF'
import sqlite3, sys, sqlite_vec
db = sqlite3.connect(sys.argv[1]); db.enable_load_extension(True); sqlite_vec.load(db)
print("knowledge_vec rows:", db.execute("SELECT count(*) FROM knowledge_vec").fetchone()[0])
EOF
```

`knowledge_chunks.embedding IS NOT NULL` is a decent proxy if you just need a number.

## Audit workflow (7 steps)

### STEP 0 — pull & orient
`cd ~/bugagent && git pull` (fail → STOP and report exact error, per MASTER.md session rule). Read `MASTER.md` + `MEMORY-STACK.md`. MASTER.md wins over older files.

### STEP 1 — DB stats (no full dumps)
```bash
sqlite3 $DB "SELECT count(*), sum(length(chunk)) FROM knowledge_chunks;"
sqlite3 $DB "SELECT substr(source,1,60) src, count(*) FROM knowledge_chunks GROUP BY src ORDER BY 2 DESC LIMIT 15;"
du -sh $DB
```
Always also split the dominant source internally (e.g. disclosed-reports by-*/reports/…) — the source-name split drives the keep/move decision. `substr(source,1,60)` truncates — get longer prefixes (`substr(source,1,40)` top-40, or CASE on subdir) before sampling.

### STEP 2 — stratified sampling (bounded)
Cap ~120 chunks total, per major source, `ORDER BY random() LIMIT N`, NEVER scan everything. Pattern (writes tab-separated samples, newline→space to keep one row per chunk):
```bash
sqlite3 -separator $'\t' "$DB" "SELECT source, length(chunk), substr(replace(chunk, char(10), ' '),1,200) FROM knowledge_chunks WHERE <source filter> ORDER BY random() LIMIT N;"
```
Then read the sample files back in batches for classification. Classify over the head-200-chars and say so (full-chunk type may differ at the tail).

### STEP 3 — classify every sample (taxonomy)
1. Technique prose (how-to/methodology)
2. Code / payload / request blocks (executable knowledge)
3. Report body narrative (real bug: what/where/impact)
4. Table / metadata rows (severity/bounty/date/votes)
5. Stack traces / logs / raw dumps
6. Link lists / index entries
7. Markdown artifacts (nav, frontmatter, boilerplate, submission-form templates)
8. Off-domain (irrelevant to web bug bounty — macOS, SAP, windows LPE, binary exploitation, AI/LLM architecture)

Produce a table: type → samples seen → rating (BENEFICIAL/PARTIAL/NOISE) → why.

**Automated variant (validated Aug 31 2026):** `scripts/audit_chunks_sample.py --n 120` classifies a stratified
sample with GLM-5.3-flash in batches of 20 chunks per `hermes -p hunter` call, labels each
BENEFICIAL/PARTIAL/NOISE, and appends JSON verdicts to `logs/audit_chunks.log`. Run it FOREGROUND
(background wrapper is flaky for short runs) and watch for the sampling bug fixed 2026-08-31:
`conn.close()` was inside the source loop — close AFTER collecting all sources. On a 120-chunk
sample the split was ≈56% beneficial / 24% partial / 20% noise, matching the manual 8-type audit's
conclusion that the by-* index tables are the noise cluster. Use this when the operator wants a
quick ratio, reserving the manual taxonomy for the full deliverable.

### STEP 4 — rate honestly + keep/move/exclude
Per type ask: does it teach technique? is it useful evidence? is it searchable? does it help target/payout decisions?
- **KEEP in vectors**: technique prose, code/payload blocks, report narrative (types 1–3).
- **MOVE to SQLite table (out of vectors)**: metadata rows, link lists/indexes (types 4, 6) — e.g. disclosed `by-*` tables, `reports.txt/.md` indexes, writeup README link lists, bounty-targets domains. This was ~21% of the DB in the 2026-08 audit.
- **EXCLUDE from vectors (file-only)**: stack traces/raw dumps, off-domain (types 5, 8).
- **EXCLUDE entirely**: markdown artifacts (type 7).

### STEP 5 — test what the agent actually gets
Run `~/memenv/bin/python ~/bugagent/scripts/memory_search.py "<query>" --k 3` on ~4 representative queries (technique class, bypass technique, payload, and one metadata/payout query). Tag each top hit with its type. Expect: technique/narrative queries hit great content; **metadata/payout queries hit raw table rows** — that is the evidence that metadata belongs in SQL, not vectors.

### STEP 6 — the true extraction (deliverable)
Recommend the report-extraction schema for future ingestion — what a "clean report entry" should contain based on what actually teaches:
`weakness_class, title, endpoint+parameter, request/response evidence (trimmed/redacted), payload, root_cause/why it worked, impact_proof (data/access), bypass_chain/notes, program`.
What NOT to extract: votes, dates, researcher names (except in a reports_meta table for payout analytics), contextless stack traces, submission-form template filler, marketing, screenshots (store paths not pixels).
Verdict on index tables: move to SQLite `reports_meta(report_id,title,program,severity,bounty,researcher,date,weakness_class,report_path)` so payout questions are 1-line GROUP BY, not vector noise. Full schema + rationale in `references/extraction-and-baseline.md`.

### STEP 7 — write + report
Write the full audit to `~/bugagent/audits/memory-audit-<YYYY-MM-DD>.md` (create audits/ dir): stats, classification table with ratings, query test results, extraction schema, keep/move/exclude list. Report numbered summary in chat. Never push to git (no auth on Kali by design) — report paths + summary; operator mirrors.

### STEP 8 — independent model review (two-model check)
The operator may ask for a brain-tier second opinion on the architecture/extraction verdict. Launch the brain model (GLM 5.3 Flash, `hunter` profile) as a one-shot reviewer — self-contained prompt, NO conversation memory:

```bash
cd ~/bugagent && hermes -p hunter -z "$(cat /tmp/prompt.txt)"
```

Write the prompt to a file first (long prompts break as inline args). Include: the audit numbers, the proposed extraction schema/architecture, and 4 explicit questions (verdict / schema gaps / min viable extraction / value-per-dollar ranking). Treat its verdict as evidence, not authority — multi-model agreement is the signal, disagreements get resolved by test.
**Pitfall — `hermes chat -Q "..."` with a long prompt FAILS** with `error: unrecognized arguments` (positional prompt + wrong flag). Working form is the global one-shot `-z` flag with the prompt file via `$(cat ...)`; `-p hunter` selects the brain-tier profile/model. Capture `---exit:$?---` after, and strip ANSI if piping.

## Pipeline execution discipline (operator preference — validated Aug 30 2026)

Long-running corpus/extraction jobs (10k reports, 6.5k writeups, embedding runs)
are gated the same way every time. The operator's core demand: **never run a
long/expensive step on the hope it produces results — write the plan + a state
report first, validate on a small chunk, and back up at every phase.**

1. **Report first, then run.** Before any long/expensive step, write a state
   report (verified current counts, what each step does, time, cost, and honest
   confidence it produces usable output). The operator explicitly fears "run
   everything, then boom, no results" — a written plan + a sample-proven result
   is the antidote.
2. **Sandbox-validate on small chunks** before each full run (e.g. probe+fetch
   10 URLs, embed 20 writeups, extract 20-30 files). Show the real output + an
   honest quality verdict, get approval, THEN run the full job. This is what
   catches source-specific problems (e.g. Medium 403-blocking) before wasting hours.
3. **Backup before EVERY major phase — copy, not cut.** `sha256sum` original +
   copy must match; dated folder under `~/backups/`; a `BACKUP-NOTES.md` saying
   what changed/why/from-what-state; keep ≥2 generations; back up memory.db before
   every write to it.
4. **Report each phase before starting the next.** "From a phase to another with
   a report about the previous phase."
5. **Never trust `pgrep -f`** alone for "is my background job alive" — it matches
   the running wrapper's own command text. Confirm with `ps aux | grep ... | grep
   -v grep` + the script's own `[done]`/`[ok]` log line + stable artifact counts.

## Pitfalls

- sqlite3 CLI + `vec0` = parse error, not broken index (see above).
- `hermes -z "<prompt>"` for a batch/extraction subprocess MUST add `--safe-mode
  --ignore-rules` or the agent wraps/rewrites/fills output (files, prose) and JSON
  breaks. Flags go BEFORE `-z` (`-z` consumes the rest of argv). Full recipe +
  the attribution-shape instability + the tuple-binding zero-row bug in
  `references/extraction-runner.md`.
- **`OSError: [Errno 7] Argument list too long`** when the batch prompt exceeds
  Linux's 128KB `MAX_ARG_STRLEN` (single `-z` argv string). It silently kills a
  batch with no rows written. Fix: cap per-file size (`MAX_FILE_CHARS=30000`) AND
  the accumulated batch (`MAX_BATCH_BYTES=25000`) — one alone is not enough when a
  corpus has a giant file (e.g. a 500KB PDF-derived writeup). See
  `references/extraction-runner.md` §4.
- **Audit a big extraction with GLM BEFORE merging** — random-sample N records,
  GLM scores accuracy/usefulness/fabrication, aggregate. This caught
  provenance/source-mismatch contamination (batched multi-doc extraction
  cross-attributes content between docs). 5×10 rounds ≈ 38% hunt-ready / 48%
  noisy / 14% garbage. Pattern in `references/extraction-runner.md`.
- Source names truncate at 60 chars — resolve real prefixes before sampling filters.
- Respect caps: ≤120 sampled chunks, ≤4 queries, no full DB dumps, no DB writes.
- Never print secrets/keys. Never report success where a command failed — show exact errors.
- Don't treat a 200-char head sample as the whole chunk; note the limitation.
- **Pruning noise chunks must delete from ALL THREE mirrors** (`knowledge_chunks` +
  `knowledge_fts` by rowid + `knowledge_vec` by rowid) in ONE transaction, or the FTS/vec
  tables desync. Script: `scripts/prune_noise_chunks.py` (backs up + sha256-verifies first,
  then deletes by captured id list). Noise = by-severity/by-program/by-year/by-weakness/
  by-asset-type/reports.txt/reports.md/domains.txt/README sources (~11.4k chunks, ~17.6%).
- **"database is locked" on the prune is a REAL finding, not a retry hiccup** (hit live Aug
  31 2026): a long writer job (re_extract_writeups.py) is committing to the SAME memory.db,
  and its commit is not error-wrapped — fighting the lock risks killing hours of work. Do NOT
  prune/delete/write while a writer job holds the DB. Run the prune after the writer finishes.
- **The sneaky lock holder: your own execute_code kernel** (root cause of a double crash, Aug 31
  2026). When a write transaction inside an `execute_code` call errors mid-way (e.g. `vec0`
  module missing → traceback), the kernel's sqlite3 connection does NOT roll back on error —
  it keeps the write transaction open, and the connection persists ACROSS execute_code calls
  as `hermes_kernel_runner.py`. So after the error, that kernel silently holds the write lock
  indefinitely, and every restart of the writer crashes again within ~a minute with the same
  `database is locked` on its first DELETE. Symptoms that point here: writer dies repeatedly
  with no visible competing job; `fuser -v db/memory.db` shows a `python` PID that is
  `.../hermes_kernel_runner.py`, not the writer.
  **Recovery sequence (works):** `fuser -v db/memory.db` → identify the holder → `kill <holder>`
  → verify `fuser` returns nothing → `PRAGMA wal_checkpoint(TRUNCATE)` → harmless write test
  (`BEGIN; INSERT INTO observations ...; ROLLBACK;`) → restart the writer with its correct
  `--start-idx` resume point. Do NOT retry the writer while any non-writer PID still shows in
  `fuser`.
- **Never run a DB-write from execute_code against a live writer's DB.** Read-only queries
  (SELECT/COUNT) are safe while a writer runs; any write that can error (including the vec0
  delete path) is not. Keep all writes in the memenv script and only run them after the writer
  finishes.

## References

- `references/extraction-and-baseline.md` — exact commands (stats/sampling/vec count), the 2026-08-29 baseline numbers, the extraction schema sketch, and keep/move/exclude details to diff future audits against.
- `references/report-storage-architecture.md` — the L1–L4 "pyramid" for storing 13k disclosed reports (evidence on disk / distilled records in vectors / per-class sheets / skills), GLM 5.3 Flash's independent REVISE verdict (multi-finding extraction, `params_matched`, `sheets_meta`, ≥5-reports sheet threshold, reports_meta v2 fields), and the batch-extraction cost math. Feeds the operator's pending storage decision.
- `references/extraction-runner.md` — the WORKING batch-extraction runner recipe: `hermes -p <profile> --safe-mode --ignore-rules -z` subprocess invocation (clean JSON), flag ordering before `-z`, the attribution-shape instability across batch size + report_id-per-finding fix, the tuple-binding zero-row bug, and the cheap-first debugging order for a "+0 rows" batch.
- `references/podcast-transcript-extraction.md` — the podcast/video-transcript → structured technique `.md` workflow: GLM engineers the strict extraction prompt (lives at `~/bugagent/prompts/podcast-to-md-extraction-prompt.md`), a separate LLM (Claude/ChatGPT) runs it on transcripts to produce one-.md-per-technique files with `[explicit]/[inferred]` confidence tags, then the agent stages them into `~/bugagent/knowledge/recon-podcast/` and indexes. Pitfalls: dead "transcript" files, workflow/mindset tag drift, transcription-garbled tool names (flag, don't silently correct).
- `references/web-writeup-corpus-building.md` — building a corpus from a structured writeup-LINK index (e.g. `pentester.land/writeups.json` → probe REACHABLE/BLOCKED/DEAD → trafilatura text-extract → embed on Kaggle T4 → LLM extract on DS → merge with synthetic `W<index>` report_ids). Includes the reachability-vs-content-filter distinction (operator correction), the Medium 403-blocking yield finding, the **Kaggle CLI terminal-driven T4 offload** (the answer to "can't I just link you to Kaggle" — `kaggle datasets/kernels/output` + `~/.kaggle/kaggle.json`), and the report-first/sandbox-gate/backup discipline.
