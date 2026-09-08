# Two-Agent Master/Worker Orchestration (built Aug 31 2026)

Session detail of the vertical-hierarchy hunt architecture the operator designed and we
implemented on the Kali box. Distinct from the generic community "4-agent evidence gating"
pattern (see the user-owned `ai-bug-bounty-agent` umbrella) — this is what is actually installed.

## The hierarchy (operator-defined, non-negotiable)

```
GLM-5.3-flash (hunter profile)    = MASTER / BRAIN — plans, judges, directs, validates
        │  issues ONE task at a time
DS V4 Flash (hunter-bulk profile) = WORKER / HANDS — executes, observes, reports
        │  returns TASK/RAN/OUTPUT/OBSERVED/ANOMALIES
GLM verifies → accept or redirect → repeat → evidence gate → human submits
```

- GLM has FULL authority. DS has ZERO judgment authority: it does not decide what is a bug,
  does not argue, does not invent. It executes and reports faithfully.
- DS's only refusal right is scope/law violations.
- Escalation is always up: GLM → human. Never down.

## Files (all git-tracked in ~/bugagent/agents/)

| File | Purpose |
|---|---|
| GLM-MASTER.md | GLM's role: core loop, task ranking, laws, session start |
| DS-WORKER.md | DS's role: output contract, anti-hallucination rules, lane |
| MACHINE-CONTEXT.md | Shared auto-loaded reminder: inventory (12,369 records, 53k chunks, 201 skills, 17 tools, scripts), the 8 laws, how to start a hunt |
| TASK-RANKING.md | Tier 1 easy / Tier 2 medium / Tier 3 hard — what GLM hands DS vs keeps |

## Auto-load wiring (the "remind them of their mission" mechanism)

Profile SOUL files now point at the role files, auto-loaded every session:
- ~/.hermes/profiles/hunter/SOUL.md → GLM-MASTER.md + MACHINE-CONTEXT.md + TASK-RANKING.md + MASTER.md + scope.yaml
- ~/.hermes/profiles/hunter-bulk/SOUL.md → DS-WORKER.md + MACHINE-CONTEXT.md + TASK-RANKING.md + scope.yaml

So both agents re-ground in role + machine inventory + laws before any hunt work.

## Delegate mechanism (GLM fires the worker)

`~/memenv/bin/python ~/bugagent/scripts/delegate_to_worker.py "<task>" [--tier easy|medium] [--timeout N]`

- Loads DS-WORKER.md + MACHINE-CONTEXT.md + TASK-RANKING.md into ONE hunter-bulk shot, returns
  the worker's stdout faithfully. GLM (hunter) is the one who initiates DS.
- Exit codes: 0 = returned something, 2 = refused (scope), 124 = timeout.
- Long tasks: use `--file /tmp/task.txt` to dodge argv MAX_ARG_STRLEN (128KB).
- Verified end-to-end: worker ran memory_search.py, returned hits verbatim + an accurate
  OBSERVED summary + flagged a real anomaly (HF Hub model-fetch delay). The contract works.

## Task ranking (what GLM hands DS vs keeps)

- TIER 1 EASY (DS-safe, ~$0.001): endpoint extraction, subfinder/httpx/gau/waybackurls, nuclei
  runs, arjun, ffuf, curl -i a URL, extract/filter/dedupe from file/DB, run any
  ~/bugagent/scripts script with exact args.
- TIER 2 MEDIUM (DS with guardrails, ~$0.002-0.005): apply a GIVEN payload to a GIVEN endpoint
  and return the exact response; sqlmap with FIXED flags on ONE confirmed param; gf-filter a
  list; one nuclei template family. Every medium task must include the exact command + expected
  outcome + "if you see anything else, return it verbatim and flag it".
- TIER 3 HARD (STAYS WITH GLM — never hand DS): interpreting whether a response is a bug,
  chaining, scope/authorization decisions, PoCs/reports, severity/impact, and ANY open-ended
  "find bugs on X".
- Decision rule: if you can state the exact expected output → Tier 1/2 → DS. If you can't → it's GLM's.
- WHY: DS hallucinates under ambiguity — audit showed ~14% cross-contaminated + ~44% missing
  endpoint/payload on open-ended extraction. Closed, checkable tasks remove the room to invent.

## Operator decisions (Aug 31 2026) — changes vs older plan text

- Practice labs (Docker/Juice Shop/DVWA/PortSwigger) — PERMANENTLY CANCELLED. The 190 L3 sheets
  + 11 L4 skills + 12k real records ARE the training. Consequence accepted: first real hunt is
  where we learn; validate_finding.py untested end-to-end until then.
- Learning loop (retrospectives, weekly read-own-history) — the heavy version is OUT, BUT a free,
  short, automatic weekly digest WAS approved: cron `weekly-hunter-digest` (Mon 09:00, local
  delivery) writes a <150-word digest to ~/bugagent/audits/weekly-digest-<date>.md (new findings,
  observations, machine state, next action). Local-only delivery = it's a file, not a
  notification; needs a gateway (Telegram etc.) to be messaged.
- Knowledge graph (Graphiti/Neo4j) — deferred indefinitely: entities it links (targets, findings)
  = 0; SQLite + sheets + memory_search already answer faster. Skip until real hunt data exists.
- CVE-digest / recon-delta cron — premature with zero targets; only future-worthy cron is
  knowledge-sync (git pull + incremental reindex).
- HackerOne: NO ID verification needed to hunt or receive bounties (normal). ONE account only —
  a second account for reporting risks both being banned (ToS). Two test accounts you own for
  IDOR testing is fine (attacker vs victim) — not the same as a second reporting account.
- Cost: the loop is directionally cheaper than all-GLM (DS is 3x cheaper) but adds GLM
  per-iteration thinking. Give the $ math before a real hunt batch; money is trivial vs wall-clock.

## Gating reality (as of Aug 31 2026)

- scope.yaml still PLACEHOLDER (empty in_scope) — THE single blocker to a real hunt.
- validate_finding.py exists + scope-gated but never exercised on a real finding.
- First real flow: operator gives target brief → GLM reads it → memory_search first → load
  skills → plan → delegate Tier 1/2 to DS → verify → evidence gate → validate → human submits.
