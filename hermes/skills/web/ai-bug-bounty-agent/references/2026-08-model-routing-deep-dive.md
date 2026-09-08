# Model Routing Deep-Dive — VERIFIED Aug 2026 (bugagent project)

Project-specific, fact-checked model + routing knowledge for the user's bug bounty agent.
Source of truth: `C:\Users\sahli\bugagent\` docs (GLM-5.3-FLASH-RESEARCH.md, MODEL-ROUTING.md, ATTACK-CHAIN-CRITERIA.md). Refresh prices via OpenRouter API before use.

## Decided stack (user, Aug 27 2026)
- **Brain (default):** GLM-5.3-Flash ("Ox Alpha") — 320B/18B active MoE, 1M ctx, 131K out, MIT, multimodal in. OpenRouter `z-ai/glm-5.3-flash` $0.075/$0.25 (promo through **Sep 9, 2026**, then list $0.15/$0.50; cache $0.015).
- **Volume:** DS V4 Flash 0731 — 284B/13B active, 1M ctx, 384K out, text-only, MIT. OpenRouter `deepseek/deepseek-v4-flash-0731` flat $0.05/$0.10.
- **Escalation (R2 only):** Fable 5 `claude-fable-5` ~$10/$50. NEVER volume.
- **Validator:** DS second-skeptic → GLM max → human.

## DS direct API repriced LIVE (Aug 16, 2026, 16:00 UTC) — the trap to avoid
V4-Flash direct: off-peak $0.22 in / $0.66 out; peak $0.44 / $1.32; cache-hit $0.007/$0.014.
Peak hours: 01:00–04:00 & 06:00–10:00 UTC Mon–Fri (17 off-peak hours). → **Always route DS volume through OpenRouter flat price; never DS direct.**
Re-verify: `curl -s https://openrouter.ai/api/v1/models`

## Key vendor benchmarks (vendor-reported unless noted)
| | GLM-5.3-Flash | DS V4 Flash 0731 |
|---|---|---|
| Terminal-Bench 2.1 | 84.3 | 82.7 |
| AutomationBench | **48.8** | 25.1 ← the gap that justifies the combo |
| Toolathlon | **78.4** | 70.3 |
| DeepSWE | 63.4 | 54.4 |
| HLE w/ Tools | 55.3 | 37 |
| CyberGym (vendor) | n/a | 76.7 (GLM flagship 84.5 #1) |
| AIkido independent (32 fresh CVEs) | n/a (flagship 25/32, 18 consistent, best open pass@1) | 24/32 pooled @ $108 |

## Fable 5 vs Mythos 5 (accessibility split — answered)
- **Fable 5** (Jun 9, 2026) = "Mythos with guardrails", PUBLIC API/Claude Code. SWE-Bench Pro 80.3%, HLE/Max 39.5% (top of Z.ai chart). Escalation model.
- **Mythos 5** = no-classifier cyber/bio model, **vetted US orgs only** (Project Glasswing), suspended Jun 12–27 by US gov, not on public API. CyberGym 83.8 / ExploitBench 78.0 / ExploitGym 181/247 = industry ceiling, not an option. Anthropic: Mythos-class wide in 6–12 months → re-check 2027.

## Attack-chain ladder (what "good at chains" actually means)
- R0 Trigger: CyberGym/Cybench/Patch-to-PoC — cheap models are frontier-class (GLM 84.5 vs Mythos 83.8)
- R1 Escalate: ExploitGym — Mythos 181/247 vs GLM 105/130
- R2 Chain: ExploitBench (5-tier, 41 V8) — Mythos 78.0 vs GLM 54.4 (~24-pt gap; the structural weak flank)
- R3 Ship: DeepSWE/Terminal-Bench — Sol 72.7
Criteria ranked: ExploitBench depth → DeepSWE → AutomationBench → Toolathlon/TB → reasoning (HLE) → long context → consistency/precision.

## When to switch (decision table)
- T1 volume/mechanical → DS Flash (single-step; TB 82.7 ≈ GLM 84.3)
- T2 brain (hunt loop, hypotheses, IDOR playbook) → GLM Flash low/high
- T3 deep think (PoC, disproof) → GLM Flash max
- T4 exploitation on confirmed high-value finding → Fable 5 or human
- Validator → DS skeptic → GLM max → human. Never DS alone as judge (consistency 10/32 vs GLM 18/32 in AIkido).
- Economics: one frontier pass on a single $500+ target = a few dollars of API (the $450–590 figure is the full 32-CVE harness, not one target).

## Phase 1.5 self-benchmark (verified plan) — CANCELLED Aug 28 (operator decision, MASTER.md): NO solo benchmarking ever. This section is historical only.
- Leg 1: **CyberGym official 10-task subset** (sunblaze-ucb/cybergym, ICLR 2026; 5 solvable + 5 hard) — crash-class R0 only, comparable to Berkeley leaderboard. Needs Docker + task data (~hours, not "under an hour").
- Leg 2: **custom logic-bug mini-set** (IDOR/authz — CyberGym CANNOT measure these).
- Measure the SYSTEM (GLM+DS+gate+pooling), not the raw model. Target: ≥8/10 recall, ≥90% precision after gate.

## Resource triage (from external-review fact-check, all verified)
- **Adopt now:** BBOT 3.0 (blacklanternsecurity/bbot, v3.0.0 Jul 2026, AGPL, 10k★ — event-driven data plane, target/seeds scope split, FINDING events w/ severity; 3.0 not drop-in from 2.x), arkadiyt/bounty-targets-data (hourly scope JSON), EdOverflow/can-i-take-over-xyz (takeover YAML), 1ndianl33t/gf-patterns (param triage), CISA KEV + trickest/cve (watchlist), writeups→SKILL.md playbooks.
- **Steal pattern, not tool:** xvulnhuntr (CompassSecurity, ARCHIVED — iterative context-fetch for big code; reimplement, don't install). CAI/Strix = reference patterns.
- **Later:** Stagehand (browser AI primitives), Graphiti+Neo4j (temporal memory).
- **Safety:** nomi-sec/PoC-in-GitHub has documented fake-PoC malware → NEVER auto-execute fetched PoCs; sandbox + read-only.
- Memory verdict: SQLite+sqlite-vec now; skip Mem0-as-a-service (second meter).

## Bootstrap mechanics (git, the user's preferred path)
- Repo: `github.com/sahliadem0106/bugagent` (private) — username `sahliadem0106` (NOT `sahliaadem0106`).
- Windows edit → push; Kali `git pull`. Kali identity = operator soul + `MISSION-BRIEF.md` (as a skill: `cp MISSION-BRIEF.md ~/.hermes/skills/hunter-mission/SKILL.md` + frontmatter).
- Git auth on a fresh Windows box: `git config --global credential.helper manager` → next push pops Git Credential Manager sign-in (GCM ships with Git for Windows but is often unset).
