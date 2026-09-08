---
name: bug-bounty-knowledge-pipeline
description: "Operate bugagent knowledge-extraction pipeline."
domain: cybersecurity
subdomain: memory
tags:
- bug-bounty
- memory
- extraction
- pipeline
- llm
version: '1.0'
---

# Bug-Bounty Knowledge Pipeline

## When to Use
- Building/extending the bugagent structured-knowledge memory: extracting disclosed reports
  or writeups into `reports_meta`, normalizing classes, synthesizing L3 technique sheets,
  building L4 SKILL.md playbooks, or auditing extraction quality.
- Any task where raw bug reports/writeups must become searchable, structured technique
  records the hunter can query mid-hunt.
- Companion to `knowledge-memory-audit` (which audits an already-built index); this is the
  construction pipeline that builds it.

How to build and operate the structured-knowledge pipeline for the bugagent hunter: turning
raw disclosed reports + writeups into searchable `reports_meta` records (endpoint / payload /
root_cause / impact_proof / class), then into L3 technique sheets and L4 skills. This is the
*construction* companion to `knowledge-memory-audit` (which audits the result).

## The core model
- The value is STRUCTURED RECORDS in a SQLite `reports_meta` table, queried via SQL/FTS5.
- VECTOR EMBEDDING / chunking is OPTIONAL and often unnecessary. Do NOT default to it. Chunks
  only serve semantic search; structured records + FTS5 keyword search deliver the hunt value.
  If the environment makes embedding slow (CPU-bound, memory-tight), drop it — you lose nothing
  that matters.
- Sources get a `source` tag (`ajaysenr` = disclosed reports, `writeup` = fetched writeups) and
  synthetic `W<slug>` ids for writeups so they never collide with numeric H1 report ids.

## Pipeline stages (in order)
1. **Fetch** — for link-index sources (e.g. pentester.land/writeups.json): probe reachability,
   fetch reachable pages with `curl --max-time` + trafilatura extraction, clean artifacts, backup.
2. **Extract** — LLM (DS volume tier) pulls `weakness_class/endpoint/parameter/payload/root_cause/
   impact_proof/bypass_chain` from each file into `reports_meta`.
3. **Normalize** — collapse fragmented class labels into canonical classes (alias map).
4. **Synthesize L3 sheets** — GLM synthesizes per-class technique sheets from the records.
5. **Build L4 skills** — top payout classes -> SKILL.md playbooks enriched with real exemplars.
6. **Wire L3 sheets as loadable skills** — `scripts/wire_l3_skills.py` registers each sheet as
   `hunter-l3-<slug>` in `~/.hermes/skills/web/` so they auto-trigger by description during
   hunts. **PITFALL — YAML frontmatter quoting (hit live Aug 31 2026):** the `description`
   field is a double-quoted YAML scalar, so any sheet Overview sentence containing `"` (e.g.
   `target="_blank"`, `"2FA required"`, `"ebay"`) breaks the frontmatter parse and the skill
   SILENTLY fails to register — `skills_list` count drops below expected and the skill never
   triggers. Fix: escape the description with a `yaml_dquote()` helper
   (`s.replace('"','\\"').replace('\\','\\\\')` + newline/tab escapes) in the wiring script, then
   re-run with `--force`. ALWAYS verify after wiring: parse EVERY generated frontmatter with
   `yaml.safe_load` (catches unbalanced quotes the old line-based check missed), check
   `skills_list` count == expected, and `skill_view()` one previously-broken skill to confirm
   it loads. A skill that "exists as a file" but isn't in `skills_list` is dead weight.
6. **Audit** — GLM audits extraction quality on random samples (see references/glm-audit-pattern.md).

## Critical pitfalls (all hit for real)

### 1. `OSError: [Errno 7] Argument list too long: 'hermes'`
When driving `hermes -p <profile> --safe-mode --ignore-rules -z "<big prompt>"`, the entire prompt
is ONE argv string. Linux `MAX_ARG_STRLEN` = 128KB per single arg. A batch of large files exceeds it.
**Fix (bulletproof):** cap each single file's text (e.g. 30KB) AND cap batch byte-budget (e.g. 25KB).
The technique is in the head of a writeup, so truncating oversized files is safe.
**Symptom it's this:** script dies mid-run with the above OSError even though small batches work.

### 2. Provenance contamination in batch extraction
Feeding MULTIPLE source files into ONE LLM prompt causes the model to cross-attribute content to
the wrong file (record tagged W<urlA> contains technique from fileB). GLM audit catches this as
"source/content mismatch" — the worst failure mode because it looks plausible.
**Fix:** either (a) SINGLE-FILE extraction (one file per LLM call — slow but correct), or
(b) if batching, have the model return a `report_id` field taken from an explicit per-file marker
line, and attribute by that. When re-extracting, do NOT skip based on existing records — old
contaminated ones must be reprocessed.

### 3. Medium bot-block (403)
Medium.com / infosecwriteups.com return 403 to bots. They're a large fraction of link-indexes.
Either skip them and take the non-Medium value, or use a Medium-specific fetch (fragile). Record
blocked/dead URLs in a reachability file so nothing is silently lost.

### 4. `pgrep` false positives / unreliable background notifications
`pgrep -f "script.py"` matches your OWN terminal wrapper command (which contains the string), so
it reports RUNNING when the job is dead — and Hermes background-process "exited code None"
notifications fire while the process is still alive. **Verify with `ps aux | grep -v grep`** and
check the script's own log tail + DB row counts, never a single pgrep/wait.

### 5. Low-memory VM thrashes parallel model jobs
Running two DS/GLM jobs at once on a memory-tight VM slows both. Sequence heavy jobs or check
`free -h` before launching a second.

### 6. GLM audit quality gate
Before spending on L3 sheets, GLM-audit the extraction on random samples (see
references/glm-audit-pattern.md). Gate downstream spend on the verdict. The audit catches
provenance mismatches and missing-field records that would otherwise bake into sheets.

### 7. Token/cost estimation for extraction runs (validated Aug 31 2026)
The user asks "how much will it cost / how many tokens" — answer with measured numbers, not
guesses. Method that worked for the writeup re-extraction (2397 files, deepseek-v4-flash-0731):
- Measure avg file size over the actual corpus (`os.path.getsize` on each input file), cap at
  `MAX_FILE_CHARS` (30000), estimate tokens ≈ chars/4.
- Input/file ≈ prompt-template tokens + capped-file tokens (~1930/file here). Total remaining
  input ≈ Σ over remaining files (~1.41M tokens for 737 files).
- Output ≈ findings/file × tokens per finding (observed ~2.4 findings/file → ~0.4M tokens).
- Money = input_tokens/1e6 × in_rate + output_tokens/1e6 × out_rate (DS $0.02/$0.08 per M →
  ~$0.06 for the whole remaining job; the ENTIRE 2397-file re-extraction ≈ $0.20).
- Always state the REAL cost is wall-clock (single-file-per-call, 600s timeout on giant files),
  not tokens — the model spend is pennies; the time is hours.
- Verify progress by DB row count + newest records (e.g. `ORDER BY rowid DESC`), NOT by "process
  is running" — a live process proves nothing; climbing committed rows prove extraction.

### 8. Wrapper "exited (exit code None)" is NOT a signal
Hermes background-process notifications fired repeatedly this session for processes that were
genuinely still running (false alarms all session). The ONE time the job actually died, the log
showed a FRESH traceback after the last `[run]` line AND the PID was gone — that combination is
the real signal. Verify with `ps aux | grep <script> | grep -v grep` + a fresh log line + a DB
count that moved; never act on the wrapper notification alone.

### 9. Speed up extraction jobs: parallel workers + WAL + busy_timeout (validated Aug 31 2026)
The extraction loop is bottlenecked on the per-file `hermes -p <profile>` model call (network
round-trip + 600s timeout on giant files), NOT on the SQLite write — so you can run N workers
over disjoint slices and get ~2.5-3x wall-clock speedup for ~zero token cost (money is pennies
either way; TIME is the constraint). Do this cleanly:

- Add `--worker-id` / `--worker-count` args that slice the file list ROUND-ROBIN
  (`files[args.worker_id::args.worker_count]`), so giant files are spread across workers and no
  worker is starved by a run of big files.
- In each worker: `conn.execute("PRAGMA busy_timeout=60000")` and
  `conn.execute("PRAGMA journal_mode=WAL")` BEFORE the loop. Concurrent writers then QUEUE on the
  tiny per-file commit instead of throwing "database is locked" (which previously killed the job).
- Launch N workers each redirecting to its own log (`logs/re_extract_wN.log`), same `--start-idx`.
- Verify REAL speedup, not just "3 processes running": children cycling (child PID changes across
  two snapshots ~100s apart = calls completing), per-worker `[run]` progress lines, DB record
  count climbing. One worker hit its first `[run] 20/246` checkpoint in ~7 min where the single
  worker took ~10 min for 20 files.
- Caveat: if the model provider rate-limits N concurrent calls, workers just degrade to serial —
  you lose nothing, keep the structure.
- **Worker-count ceiling (validated Aug 31 2026):** do NOT over-parallelize. "Let's launch 100
  workers!" fails for measurable reasons, not vibes. First compute files-per-worker for the
  REMAINING workload (737 files → 3 workers = 246 each, 8 workers = 93 each, 100 workers = ≤8
  each — you pay 100x process startup to finish what 3 already do in ~2h). Then bound by the box:
  ~8-core VM with ~5GB free fits only ~8-12 concurrent worker stacks (each worker = Python +
  full `hermes` subprocess) before memory thrash; and N>~8 writers hammering ONE SQLite DB make
  commits queue so hard throughput collapses (WAL prevents crashes, not queueing). Real sweet
  spot on this hardware ≈ 6-8 workers ≈ 2-3x over 3. Test the provider's concurrency tolerance
  with a small burst before scaling, and remember parallelism does NOT change token cost (pay
  per token; every file processed once) — it only buys wall-clock.

### 10. "database is locked" after a kernel/agent crash = stale connection holds the write lock
Real incident (Aug 31 2026): the re_extract job died TWICE at its first `DELETE FROM reports_meta` with
`sqlite3.OperationalError: database is locked`, even right after a clean restart. Root cause was NOT
the extraction job and NOT another worker — it was a STALE execute_code kernel (`hermes_kernel_runner.py`)
that had hit a mid-transaction error during a prune attempt and left an uncommitted write transaction
dangling on memory.db, holding the SQLite write lock for 30+ minutes. The extraction job was blameless.

Diagnosis + fix flow (use this whenever a DB-writing job dies with "database is locked"):
1. Find the lock holder: `fuser -v <db>.db` → shows the PID + command holding it. It is often NOT your
   job — it's a stale kernel/session. Identify it with `ps -o pid,ppid,etime,cmd -p <pid>`.
2. If it's a stale `hermes_kernel_runner.py` (execute_code kernel), `kill <pid>` it. That releases the lock.
3. Verify the DB is actually writable BEFORE restarting the job: a harmless test transaction
   (`BEGIN; INSERT INTO observations(category,content) VALUES('_lt','x'); ROLLBACK; SELECT 'write OK';`)
   and optionally `PRAGMA wal_checkpoint(TRUNCATE)` to fold the WAL back.
4. Only then restart the job at its correct `--start-idx`.
NEVER restart a DB-writing job on a lock error without finding the holder first — it will crash again
in seconds. Also: never run an execute_code write against memory.db while a background extraction is
live; if a script dies mid-transaction, the lock can outlive it.

## GLM effort = MEDIUM (operator decision)
L3 sheet synthesis and audits run on GLM-5.3-flash at MEDIUM effort, never max. Budget rule:
only two models (glm-5.3-flash brain, deepseek-v4-flash volume) via Nous Portal.

## Backup + audit discipline (operator's hard rule)
- Backup memory.db (copy + sha256 verify) before EVERY big step. Copy, never cut.
- Audit after each phase to track quality, not just at the end.
- Never compress the session chat; if ever needed, export the full session to a file first.

## Supporting files
- `references/glm-audit-pattern.md` — GLM quality-audit prompt + scoring rubric.
- `references/pipeline-scripts.md` — the working scripts and their exact invocation.
- `references/resume-long-jobs.md` — resuming L3 sheets + re-extraction after power cut/crash: exact restart commands, `--start-idx` resume point, per-job model routing, and the false-alarm verification procedure.
- `references/two-agent-orchestration.md` — the master/worker hunt architecture (built Aug 31 2026): GLM-5.3-flash = brain/master, DS V4 Flash = hands/worker, role files in `~/bugagent/agents/` (GLM-MASTER.md / DS-WORKER.md / MACHINE-CONTEXT.md / TASK-RANKING.md), the `delegate_to_worker.py` launch mechanism, Tier-1/2/3 task ranking (closed checkable tasks to DS; anything needing judgment stays with GLM), and the operator decisions that changed the plan (labs cancelled, weekly digest approved, knowledge graph + CVE cron deferred, single HackerOne account). Load this before orchestrating any hunt delegation.
