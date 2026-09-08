# Building a Web-Writeup Corpus from a Structured Link Index

Recipe for turning a structured index of external bug-bounty writeup LINKS (e.g.
`pentester.land/writeups.json`) into an indexed, extractable corpus — without
wasting hours on dead/paywalled pages. Validated Aug 30 2026 against
pentester.land's ~6.5k-link dataset. This is the WRITEUP-INGEST realization and
the sibling of `podcast-transcript-extraction.md` (transcripts) and
`extraction-runner.md` (the LLM extraction pass).

## Key distinction (operator correction — do not re-learn this)

The **reachability probe is a reachability check, NOT a content-quality filter.**
You do NOT judge a page "real report vs junk" by its first paragraph. You only
ask: is the page reachable and does it return content? Reachable URLs get text-
extracted; dead/blocked URLs are recorded in a status file and skipped. Content
quality is decided LATER by the LLM extraction pass's `impact_proof` gate, not by
a first-paragraph heuristic (paywalled Medium posts show an intro but hide the
technique, so a paragraph heuristic both admits junk and drops real writeups).

## The pipeline (staged, sandbox-gated — see SKILL.md "Pipeline execution discipline")

### Phase A — build the corpus (local, $0 model cost)
1. **Build the index.** Parse the JSON (`{"data":[{Links,Authors,Programs,Bugs,Bounty,PublicationDate,AddedDate}]}`), dedupe by URL into a TSV: `url \t title \t bugs \t program \t bounty \t date`. pentester.land: 6,421 entries → 6,527 unique links.
2. **Reachability probe** (`writeup_probe.py`): HTTP GET with a browser UA + timeout; classify `REACHABLE` (200 + bytes) / `BLOCKED` (403/429/Cloudflare) / `DEAD` (404/5xx/conn-refused/timeout). Write ALL results to `reachability.tsv` — dead/blocked are recorded, NOT dropped (re-checkable later). Polite sleep between requests. No model tokens.
3. **Text extraction** (`writeup_fetch.py`): for REACHABLE URLs only, `trafilatura.extract(fetch_url(...))` → `raw/<slug>.txt`. Idempotent (skip existing non-empty). trafilatura install: `~/memenv/bin/pip install trafilatura`.
4. **GATE #1 before full run:** probe+fetch a ~10-URL diversified sample (mix of medium.com, blog, infosecwriteups, github) and show the operator the extracted text quality. Approve → full run.
5. **Backup** the raw folder (tar + sha256).

### Phase B — embed on GPU (T4), Phase C — LLM extract, Phase D — merge
- **Embed on Kaggle T4 — PREFERRED PATH: drive it entirely from the terminal via the `kaggle` CLI** (no manual notebook round-trip). The `kaggle` CLI does the whole flow: upload the raw files as a dataset, push the embedding script as a kernel, set the T4 accelerator, run, and download the output DB back to the VM. This is the answer to "can't I just link you to Kaggle" — yes, via the CLI. See the Kaggle-CLI subsection below.
- **Manual-notebook alternative** (if no CLI/credentials): notebook reads the .txt, runs `fastembed` ONNX (minutes vs 1.5-5h CPU), emits a writeups-only `memory.db`. NO API keys in the notebook (hard rule). Sample-verify on ~20 before the full run (GATE #2).
- **LLM-extract** (DeepSeek, hunter-bulk profile): reuse the `extraction-runner.md` batch recipe on the .txt files, tag source='writeups'. Sample ~20-30 files first (GATE #3) to confirm payload verbatim + impact_proof present.
- **Merge** (local, $0): `sqlite3 ATTACH writeups.db` + `INSERT OR IGNORE ... ON content_hash` (dedupe-safe). Writeup records get SYNTHETIC report_ids like `W<index>` so they can't collide with numeric HackerOne ids. Rebuild FTS + re-embed new chunks. Run audit queries after merge (GATE #4) to confirm both report and writeup technique retrieve, no duplicates.

### Kaggle CLI — terminal-driven T4 offload (validated Aug 30 2026)
The `kaggle` CLI (pip: `~/memenv/bin/pip install kaggle`) is the way to run GPU jobs on a free T4 from this VM without browser interaction. Subcommands that matter: `datasets create|version` (upload files), `kernels push|status|pull|output` (run a kernel + grab its output), `quota` (weekly T4 hours — free tier is ~30h/wk).

Setup (the ONLY thing the operator must do — a real secret):
1. Operator gets `~/.kaggle/kaggle.json` = `{"username":"<u>","key":"<k>"}` from kaggle.com → Settings → API → Create New Token. Best practice: the OPERATOR places the file at `~/.kaggle/kaggle.json` themselves; the agent should NOT handle the raw key in chat.
2. Verify auth: `~/memenv/bin/kaggle datasets list` (or `kaggle quota`).

End-to-end flow from the terminal:
1. `kaggle datasets create -p <dir-with-raw-files> -u <owner>/<dsname>` (or `kaggle datasets version`) — upload the `.txt` corpus.
2. Write the embedding script to read `/kaggle/input/<owner>/<dsname>/...` and emit `/kaggle/working/writeups.db` (same schema as `index_corpus.py`: `knowledge_chunks` + `content_hash UNIQUE` + `vec0 float[384]`, model `BAAI/bge-small-en-v1.5`).
3. `kaggle kernels push` with `kernel-metadata.json` setting the dataset input + `enable_gpu: true` — run on T4.
4. `kaggle kernels status <owner>/<kernel>` until Succeeded, then `kaggle kernels output <owner>/<kernel>` downloads `writeups.db` back to the VM.
5. Merge per Phase D above.

Pitfalls: the `-z`/flag-ordering and `--safe-mode --ignore-rules` rules from `extraction-runner.md` apply to any `hermes` subprocess, not to `kaggle`. Don't embed the kaggle.json key into a notebook that gets pushed (the hard NO-API-keys rule still holds for the notebook content — only the CLI uses the key, locally).

## Tooling notes
- `trafilatura` is the free text extractor of choice (handles Medium/blogs). Install into the memenv (never system python on Kali, PEP-668).
- **Use the FAST fetch path — `curl` + `trafilatura.extract`, NOT `trafilatura.fetch_url()`.** The built-in `fetch_url()` hangs/slow-blocks on redirects and slow sites (a 7-URL fetch never finished; a plain-curl run did 6 in 57s). Pattern: `curl -sL --max-time 15 --connect-timeout 8 -A <browser-UA> -o tmp.html -w "%{http_code}" URL`; only if `%{http_code}` == 200, run `trafilatura.extract(open(tmp.html,'rb').read())`. `extract` is fast; the fetch was the bottleneck.
- **Parallelize the fetch** with `ThreadPoolExecutor` (`--workers 20`) + a hard per-URL timeout. Measured: 8 workers = 1.4/s at 58% ok; 20-30 workers = 3.0-3.3/s but ok-rate drops to ~47% (timeouts). Then run a **retry pass** at low concurrency (4 workers) over the failures — it recovered ~55-70% of them. Net: ~2,397 clean files from 3,768 non-Medium links in ~1h total (first pass ~19 min + retry ~36 min).
- Run the fetch as `background=true + notify` (it still takes tens of minutes at scale), never a foreground 120s command (it times out).
- Cost model: fetch/extract/merge = $0 (no model). Only the LLM extraction pass (DS, ~$0.30-1) and the L3 sheets (GLM, ~$1-3) cost money.
- **Cleanup artifacts after fetch**: drop files <150 bytes and known error-page signatures (e.g. "internet archive services are temporarily offline" = pure error page; "Access Denied You don't have permission to access" + <400 chars = Akamai block page). BUT check before deleting — a file may merely MENTION the pattern inside real content (e.g. a writeup titled about access-denied); only remove it if the whole file IS the error page. Of 2,610 fetched, 213 were artifacts.

## Known source-specific yield (validated)
- **Medium + infosecwriteups return HTTP 403 to direct bot fetches** — in pentester.land they are the two biggest sources (medium ~1,713, infosecwriteups ~194 ≈ ~29% of links). Decide up-front: skip them (keep the ~4.6k non-Medium) or invest in a Medium-specific fetch workaround (fragile, not guaranteed). Default: skip for now, revisit later.
- Honest reachability expectation: ~3-5k of 6.5k reachable (dead links, paywalls, Cloudflare). The status file records exactly what was got, so nothing is silently missing.

## User workflow preferences that govern this class of job
- **Report first, then run.** Before any long/expensive pipeline step, write a state report: what we have now (verified counts), what each step does, time/cost, and honest confidence it produces usable output. The operator explicitly does NOT want "run everything, then boom, no results."
- **Sandbox-validate on small chunks** before each full run; show real output + honest quality verdict; get approval before proceeding.
- **Backup before EVERY major phase** (copy, not cut): `sha256sum` original + copy must match, dated folder, a BACKUP-NOTES.md stating what changed/why/from-what-state, keep ≥2 generations, and back up memory.db before every write to it.
- Report a summary of each phase before starting the next ("from a phase to another with a report about the previous phase").
