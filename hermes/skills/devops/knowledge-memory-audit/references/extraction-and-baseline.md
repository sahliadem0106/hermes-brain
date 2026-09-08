# Memory Audit — Baseline & Commands (2026-08-29)

Reference for the bugagent memory DB audit. Baseline measured live Aug 29, 2026 on the Kali VM.
Future audits should diff against these numbers and update this file.

## Baseline (2026-08-29)

| Metric | Value |
|---|---|
| chunks | 64,717 |
| total chars | 45,168,194 (~45.2M) |
| knowledge_fts rows | 64,717 |
| knowledge_vec rows | 64,717 (all chunks embedded) |
| DB size | 439M (459,788,288 bytes) |
| disclosed-reports share | 33,024 chunks = **51%** of DB |

### disclosed-reports internal split
| Group | Chunks | Share of disclosed |
|---|---|---|
| reports/ (narrative) | 19,777 | 59.9% |
| by-program/ | 2,608 | 7.9% |
| by-asset-type/ | 2,312 | 7.0% |
| by-year/ | 2,272 | 6.9% |
| by-severity/ | 2,173 | 6.6% |
| by-weakness/ | 2,077 | 6.3% |
| other (reports.txt/.md indexes etc.) | 1,805 | 5.5% |

→ ~35% of the disclosed-reports source is by-* index tables + raw index files (metadata, not technique).
Total by-* index chunks = 11,442 ≈ **17.7% of the whole DB**.

## Exact commands used

### Vec count (CLI can't — use venv)
```bash
~/memenv/bin/python - "$DB" <<'EOF'
import sqlite3, sys, sqlite_vec
db = sqlite3.connect(sys.argv[1]); db.enable_load_extension(True); sqlite_vec.load(db)
print("knowledge_vec rows:", db.execute("SELECT count(*) FROM knowledge_vec").fetchone()[0])
EOF
```

### Stats
```bash
sqlite3 $DB "SELECT count(*), sum(length(chunk)) FROM knowledge_chunks;"
sqlite3 $DB "SELECT substr(source,1,60) src, count(*) FROM knowledge_chunks GROUP BY src ORDER BY 2 DESC LIMIT 15;"
du -sh $DB
# table existence + embedded proxy:
sqlite3 $DB "SELECT name, type FROM sqlite_master WHERE name IN ('knowledge_vec','knowledge_chunks','knowledge_fts');"
sqlite3 $DB "SELECT count(*) FROM knowledge_chunks WHERE embedding IS NOT NULL;"
```

### Stratified sampling (bounded, per source, random)
```bash
sqlite3 -separator $'\t' "$DB" "SELECT source, length(chunk), substr(replace(chunk, char(10), ' '),1,200) FROM knowledge_chunks WHERE <filter> ORDER BY random() LIMIT N;"
```
Source filters used (2026-08): `LIKE '%hacktricks/%'` (30), `LIKE '%wstg/%'` (10),
`LIKE '%PayloadsAllTheThings/%'` (15), `LIKE '%AllAboutBugBounty/%'` (5),
`LIKE '%disclosed-reports/%'` (40), `(LIKE '%Awesome-Bugbounty-Writeups/%' OR LIKE '%bug-bounty-reference/%')` (10),
misc = NOT any of the above (10). Total 120.

## Query-test results (memory_search.py, top-3, Aug 29)

| Query | Top hits | Rating |
|---|---|---|
| "IDOR uuid object reference" (23 hits) | PAT IDOR README, AABB IDOR, PAT tools section — technique prose | USEFUL |
| "SSRF filter bypass localhost" (21 hits) | disclosed 1608039 narrative, hacktricks url-format-bypass, disclosed 1702864 (IPv6/IPv4 nesting) | USEFUL |
| "stored XSS payload" (20 hits) | disclosed 1595905/221380/145246 — narrative w/ real payloads | USEFUL |
| "high severity paid bounty" (19 hits) | 3× by-severity raw table rows | MEH |

Lesson: technique/narrative queries hit gold; **metadata/payout queries hit raw table rows** →
metadata belongs in SQL, not vectors. This is the empirical evidence for the reports_meta move.

## Extraction schema (the "true thing" to extract from reports)

```json
{
  "report_id":        "H1-1028332 or source file path",
  "weakness_class":   "Stored XSS (WSTG/CWE-aligned)",
  "title":            "short title",
  "endpoint":         "full URL",
  "parameter":        "name + location (body/header/query)",
  "severity":         "Medium",
  "bounty":           1500,           // nullable
  "date":             "2018-...",
  "program":          "HackerOne",
  "request_evidence": "trimmed raw request, redacted",
  "response_evidence":"trimmed raw response, redacted",
  "payload":          "the exact payload that fired",
  "root_cause":       "why it worked (input reflected unencoded into X...)",
  "impact_proof":     "what data/access (admin session, other users' reports)",
  "bypass_chain":     "e.g. IPv6-nested-IPv4 to beat filter_var",
  "notes":            "preconditions, gotchas"
}
```

### What NOT to extract
- votes, duplicate counts, resolution-status boilerplate
- researcher names (except in reports_meta for payout analytics)
- raw stack traces without root-cause line + repro context
- submission-form template placeholders, marketing, program-summary filler
- table rows (severity/bounty) without the linked report
- screenshots (store paths, not pixels)

### Verdict on index tables (operator's pending decision)
Move to SQLite:
`reports_meta(report_id, title, program, severity, bounty, researcher, date, weakness_class, report_path)`
- answers payout questions with 1-line GROUP BY instead of vector noise
- keeps by-* navigation data (11,442 rows) fully useful
- shrinks vectors ~20%, cutting retrieval dilution
- preserves narrative linkage via report_path → reports/<id>.md

## Classification taxonomy (8 types, reuse verbatim)
1. Technique prose — BENEFICIAL — KEEP vectors
2. Code/payload/request blocks — BENEFICIAL — KEEP vectors
3. Report body narrative — BENEFICIAL — KEEP vectors
4. Table/metadata rows — PARTIAL — MOVE to SQL
5. Stack traces/logs/raw dumps — NOISE — EXCLUDE vectors (file-only)
6. Link lists/index entries — NOISE in vectors — MOVE to SQL
7. Markdown artifacts — NOISE — EXCLUDE entirely
8. Off-domain (macOS/SAP/Win-LPE/bin-exploit/AI) — PARTIAL→NOISE — EXCLUDE vectors

## Keep/move/exclude summary
- KEEP in vectors: hacktricks `pentesting-web/` + selected `network-services`/`generic-methodologies`,
  wstg, PayloadsAllTheThings, AllAboutBugBounty, disclosed `reports/` narrative (~19.8k chunks).
- MOVE to SQLite (then EXCLUDE from vectors): disclosed `by-*` tables (11,442), `reports.txt/.md`
  indexes (1,368), writeup README link lists (171), bounty-targets domains (796).
- EXCLUDE from vectors (file-only): stack/backtrace dumps, off-domain hacktricks.
- Filter frontmatter/TOC/boilerplate at ingest.

Net effect: vectors 64,717 → ~45–48k chunks of teachable content only.
