# Pipeline Scripts (bugagent) — exact invocations

All run with `~/memenv/bin/python` from `~/bugagent`. Inputs live in
`~/bugagent/knowledge/...`; DB is `~/bugagent/db/memory.db`; logs go to `~/bugagent/logs/`.

## Fetch (writeup link-index -> raw .txt)
- `scripts/writeup_probe.py --index <idx.tsv> --out reachability.tsv` — HTTP reachability
  check (REACHABLE/BLOCKED/DEAD), records ALL URLs so nothing is silently dropped.
- `scripts/writeup_fetch_par.py --skip-medium --workers 20 --raw-dir knowledge/writeups/raw`
  — PARALLEL curl+trafilatura fetch. `--skip-medium` drops medium.com/infosecwriteups (403).
  Add `--limit N` for a gate test. ~2.6-3.3 urls/s at 20 workers.
- `scripts/writeup_retry.py --skip-medium --workers 4` — retry failures at low concurrency;
  recovers ~55% of timed-out links.
- Artifact cleanup: delete files <150 bytes and those whose head matches error-page
  signatures ("internet archive services are temporarily offline", "you don't have
  permission to access" + <400 chars). Do this in Python, not a giant inline grep.

## Extraction -> reports_meta
- Reports (10k disclosed): `scripts/extract_reports.py [--sample --limit N]` — batch, byte-budgeted.
- Writeups: `scripts/extract_writeups.py [--limit N]` — batch with W<slug> ids. BEWARE
  provenance contamination (see SKILL.md pitfall #2); prefer single-file re-extraction.
- Single-file (correct, fixes provenance): `scripts/re_extract_writeups.py` — one writeup per
  DS call. Slow by design. Deletes+reinserts per record. Do NOT skip existing records.
- Payload recovery: `scripts/recover_payloads.py --batch 15` — fills empty payload fields.
  Expect low yield (~17%): many empty-payload records are legitimately endpoint-only classes.

## Normalize / sheets / skills
- `scripts/normalize_classes.py` — collapse fragmented `weakness_class` labels via alias map.
- `scripts/synthesize_sheets.py --source ajaysenr --min-records 3` — GLM L3 sheets per class.
  `--source` isolates clean reports from contaminated writeups. ~140s/class.
- `scripts/build_l4_skills.py` — generates `hunter-l4-<slug>` SKILL.md playbooks in
  `~/.hermes/skills/web/` with 8 real exemplars each.
- `scripts/wire_l3_skills.py` — registers ALL sheets in `knowledge/sheets/*.md` as loadable
  `hunter-l3-<slug>` skills in `~/.hermes/skills/web/hunter-l3-<slug>/SKILL.md` (frontmatter +
  sheet body). Idempotent; `--force` rewrites, `--slug <x>` wires one. **YAML pitfall:**
  descriptions containing double-quotes (`"2FA required"`, `target="_blank"`) break the
  frontmatter and the skill silently fails to register — descriptions must be escaped with
  `yaml_dquote()` (backslash-escape `"` and `\`). After wiring, verify with a YAML
  `safe_load` on every SKILL.md and confirm the count in `skills_list`, not just file count.
  Re-run `--force` after re-extraction adds new classes.

## Audit / search
- `scripts/audit_writeups_glm.py --rounds 5 --sample 10` — GLM quality audit; saves rounds to
  `~/bugagent/audits/glm-audits/round{N}.txt`.
- `scripts/audit_l3_sheets.py <sheet.md> ...` — GLM audit of SYNTHESIZED L3 sheets (the
  deliverable), NOT extraction records. 7 dimensions scored 0-10 (actionability,
  technique_density, grounding, evidence_quality, bypass_chain, structure_fit,
  gotchas_safety) + overall, verdict KEEP/MINOR_FIX/REBUILD/LOW_VALUE, fabrication_risk,
  worth_hunting. Runs per-sheet (~45s each, GLM hunter profile). Logs JSON verdicts to
  `logs/audit_l3_sheets.log`; script stderr/stdout can interleave — parse with brace-matching
  JSON extraction, not naive json.loads per line. Pick the top-30 payout classes by
  high-severity count first (SQL over reports_meta), then decide on the full 190 after the
  sample. Sheet-level audits are cheap and give per-class KEEP/MINOR_FIX verdicts plus
  fabrication-risk confidence.
- `scripts/memory_search.py "<query>" --k 3` — hybrid search.
- `scripts/memory_search.py --class "IDOR" --paid --k 5` — SQL-filter mode over reports_meta
  (Addition B). `--severity`, `--program`, `--sql` also available.
- `scripts/eval_retrieval.py` — golden-query smoke test (NOT a benchmark).

## Schema (reports_meta)
Columns: report_id, finding_index, title, program, severity, bounty, has_bounty, researcher,
reported_date, disclosure_date, weakness_id, weakness_class, asset_type, asset, endpoint,
parameter, payload, root_cause, impact_proof, bypass_chain, params_matched, finding_count,
is_chain, report_path, source, distilled_path, extraction_ts. UNIQUE(report_id, finding_index).
Writeup records use source='writeup' and report_id='W<slug>' (never collides with H1 numeric ids).

## Model profiles
- DS volume (extraction, payload recovery, writeup fetch LLM): `hermes -p hunter-bulk ...` = deepseek-v4-flash.
- GLM brain (L3 sheets, audits): `hermes -p hunter ...` = glm-5.3-flash, MEDIUM effort.
- Always pass `--safe-mode --ignore-rules` for deterministic raw JSON output.
