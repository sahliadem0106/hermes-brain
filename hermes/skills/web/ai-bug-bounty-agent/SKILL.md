---
name: ai-bug-bounty-agent
description: "Use when building an AI-assisted bug bounty workflow."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, bug-bounty, ai-agent, llm-selection, pentesting]
    related_skills: [web-research, reddit-archive-recon]
---

# AI-Assisted Bug Bounty — Agent Architecture, LLM Selection, Learning Path

Umbrella for the user's ongoing bug-bounty project (started Aug 2026: learn hunting + build an AI agent to assist). Sits ABOVE the per-vuln-class exploitation skills (`exploiting-*`, `testing-for-*`, `ctf-*`, `burpsuite`) — those are the technique layer; this is the workflow/orchestration/LLM-selection layer. Complementary, not overlapping.

## When to Use
- User asks to build/configure an AI agent for bug bounty or pentesting
- User asks which LLM to use for security work (or any agentic/tool-use work)
- Any continuation of the bug-bounty project: learning path, methodology, agent build, model choice

## The 2026 market reality (shapes every decision)
- AI slop flood: Apple limited bug-bounty submissions (Aug 2026); Internet Bug Bounty paused (Apr 2026); report volume up ~76% while programs shut down. Same models also find real zero-days humans missed for decades.
- **The moat is VALIDATION, not discovery.** Hunters who verify + write clean reports win; submitters of AI noise get banned.
- Community consensus (Reddit r/bugbounty): AI amplifies proven methodology, does not replace it. Strong at recon / idea-lists / code analysis / PoC drafting; weak at exploitation and impact proof.
- Practitioner datapoint (chudi.dev): first automation run → 47 "critical" → 12 submitted → 12/12 false positives. Rebuilt with evidence gating → FP rate 90% → ~0 over 3 months.

## The working architecture: 4-agent evidence gating
Proven in production across HackerOne/Intigriti/Bugcrowd (3 months, human-reviewed):

1. **SCOPE GATE** — parse program scope, blocklist out-of-scope, NEVER test unauthorized targets
2. **RECON agent** (cheap model) — subfinder/httpx/gau/waybackurls/asnmap → attack-surface map. JS-file endpoint extraction is the highest-value recon
3. **TESTING agent** (mid model) — per-vuln-class hypotheses (SQLi/XSS/SSRF/IDOR/auth/upload); nuclei + ffuf + burp
4. **EXPLOIT/PoC agent** (frontier model) — craft PoC, prove impact with real request/response evidence
5. **VALIDATION agent** (a DIFFERENT frontier model) — adversarial disproof: treats the finding as WRONG until proven; confidence ≥0.85 gate; evidence bundle
6. **REPORTING agent** — duplicate-check, program-format report
7. **HUMAN REVIEW** — always, never skipped; reputation is the asset

Load-bearing rule: **"Detection is not exploitation. The validation agent tries to BREAK the finding, not confirm it."** Cross-model verification (different LLMs for test vs validate) is standard community practice.

Supporting state: SQLite memory layer of confirmed/failed findings so the system measurably improves over time.

## LLM selection criteria for security agents (priority order)
1. **Low hallucination / factuality** — fabricated vulns = reputation death. Benchmarks: AA-Omniscience, FACTS, CritPt, HALC-Bench (long-context), Vectara HHEM
2. **Agentic / tool-use reliability** — Terminal-Bench 2.1, τ³-Banking, SWE-bench Pro/Verified, GDPval-AA, DeepSWE, A-CODE-LLM
3. **Long context** (1M is standard in 2026) + context-cache price (`input_cache_read`)
4. **Structured output / function calling** — evidence JSON must parse every time
5. **Reasoning depth** for exploit chains — HLE, GPQA, AIME
6. **Price** — volume economics; spread can be ~160x between frontier and flash tiers
7. **Open weights / license** — MIT/Apache vs custom (revenue-share, US/EU-exclusion, CC-BY-NC)
8. **Reasoning-effort control** — cheap fast mode for recon, deep mode only for exploitation

## Live model data (OpenRouter — refresh when used)
`curl -s https://openrouter.ai/api/v1/models` → JSON with: `context_length`, `pricing.prompt/.completion/.input_cache_read` (per-token; ×1M = per-1M), `top_provider` (`max_completion_tokens`, `is_moderated` — moderated models may refuse exploit payloads), `architecture.modality`, `supported_parameters`, `knowledge_cutoff`. Also `:free` and `:batch` variants (~50% off), Fusion (multi-model synthesis). Composite benchmark to cite: **Artificial Analysis Intelligence Index** (v4.x — 9 evals incl. Terminal-Bench, GDPval, τ³, HLE, GPQA, AA-Omniscience).

### Model tier template (Aug 2026 snapshot — full catalog + prices in references/2026-open-llm-landscape.md)
- **Brain / validator:** Kimi K3 (best open-weights on AA index, ~$3/$15 per 1M) or closed Claude Opus 5 / GPT-5.6 Sol ($5-10/$25-50)
- **Workhorse:** GLM-5.3 (MIT, $1.40/$4.40), DeepSeek V4 Pro (MIT), Qwen3.8-2.4T
- **Volume:** DeepSeek V4 Flash (~$0.06/$0.12, MIT, self-hostable), GLM-5.3-Flash, MiniMax M3
- **Local:** Qwen3.8-27B (Apache 2.0, one 24GB GPU), DeepSeek V4 Flash (MIT)
- Route by task tier; validator = different model than tester

## Learning path (Reddit consensus, Aug 2026)
1. **Web fundamentals FIRST, tools later** — HTTP structure, how JS sends requests (fetch/XHR), DOM, server/DNS/db, one backend language. *"Learn JS so you can understand the explanations AI gives you about JS code."*
2. **PortSwigger Web Security Academy — every lab** (universally called the best prep; people who did labs found bugs within days on real targets)
3. **Recon mastery** — JS-file endpoint extraction + subdomain enumeration (Nahamsec / Jhaddix videos)
4. **Practice:** HTB, PentesterLab, Hacker101, OWASP Juice Shop, your own lab site
5. **Real targets:** low-competition VDPs / private programs; specialize in ONE bug class (IDOR / broken access control = beginner goldmine)

Timeline reality: first accepted bug = 3-6 months of grinding (real datapoints: "5 months of 4h/day → $350"; "6+ months part-time → valid critical on VDP, no money"); duplicates are the default; first bugs are usually IDOR / user enum / access control.

## Methodology repos (live stars Aug 2026; full list + URLs in references)
- **daffainfo/AllAboutBugBounty** (6.8k — renamed from awesome-bugbounty-bounty) — master index by phase
- **HackTricks-wiki/hacktricks** (12k) — the bible; markdown tree = agent-friendly knowledge base
- **OWASP/wstg** (9.8k) + **OWASP/CheatSheetSeries** (33k) — canonical methodology
- **nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters** (12k), **EdOverflow/bugbounty-cheatsheet** (6.5k)
- **vavkamil/awesome-bugbounty-tools** (6.2k), **devanshbatham/Awesome-Bugbounty-Writeups** (6.1k)
- **daffainfo/bash-bounty** + **Oneliner-Bugbounty** — one-liner recon = ideal for agent execution
- **0xacb/recollapse** (1.4k) — source-map → JS endpoint recovery
- AI projects to study: **GreyDGL/PentestGPT** (15k), **0x4m4/hexstrike-ai** (11k); **promptfoo** (24k) for evaluating your agent
- Note: `0xacb/awesome-bug-bounty-checklists` does NOT exist — EdOverflow's cheatsheet is the canonical one

**The user's own Hermes security skills ARE the machine-readable methodology layer** (`exploiting-*`, `testing-for-*`, `ctf-*`, burpsuite, etc.) — feed them to the agent instead of re-writing methodology.

## Compute & budget (free-first — the $0 path)
- Free API tiers: Google AI Studio (no card), OpenRouter `:free` (~20 req/min; **50 req/day until you ever buy $10, then 1000/day**), Groq, GitHub Models, Cloudflare Workers AI, Mistral, Cerebras.
- Cheapest paid: DeepSeek V4-Flash ~$0.06-0.14/1M — a $2 top-up is months of volume. This user's Hermes already runs on DeepSeek (key exists — reuse it).
- Free GPU (no card): Kaggle T4 16GB 30h/wk, Colab T4 ~12h sessions, Azure for Students $100, AWS Educate ~$100. GCP $300/90-day trial needs a card; **budgets are ALERTS not brakes**; some accounts get a refundable ~$10 prepayment (keep total usage under $300).
- **GPU burst rule**: 24/7 L4 on-demand ≈ $530/mo — never. Spot burst (L4 ~$0.25/hr, T4 ~$0.12/hr, A100 ~$1/hr) = $3-5 per session with auto-shutdown. For models >30B, an API is ALWAYS cheaper than self-hosting.
- Local CPU inference (no GPU): 24GB RAM + i7 runs ≤9B Q4 at 5-12 tok/s; 14B ≈ 8.5GB at 3-5 tok/s. Check free disk before pulling models.
- Free cloud-"hosting" trick: Colab/Kaggle session + llama.cpp/Ollama + cloudflared tunnel = OpenAI-compatible endpoint for an agent at $0 (sessions die after 9-12h — burst only).

## User's decided stack (REVISED Aug 27, 2026 — GLM decision reversed)
- **Brain: GLM-5.3-Flash ("Ox Alpha", MIT, 320B/18B MoE, 1M ctx, $0.15/$0.50 per 1M, 50% promo through Sep 9)** via Nous Portal ($0.06/$0.20 — MASTER.md §4). Launch Aug 26, 2026. #1 on GDPval-AA v2 + Toolathlon; inherited cyber lineage from GLM-5.3 (CyberGym 84.5 #1 vendor-reported; AIkido independent: 25/32 fresh-CVE recall, 18/32 consistent, best pass@1 of open models; ExploitBench 54.4 = weak flank). No Flash-specific cyber scores published yet — no self-benchmarking (MASTER.md: labs = skill, not score).
- **REVERSED:** v1 stack (Qwen3.8-27B on GCP L4 VM, "no DeepSeek/Gemini/GLM anywhere") is dead. No VM. API-only brain.
- Validator (upgraded Aug 27): **two skeptics + human** — DS V4 Flash as cheap second skeptic (different training lineage = catches GLM's correlated blind spots; fractions of a cent per candidate), GLM-5.3-Flash at max effort as judge, human always. GLM-5.3 flagship later as final judge (cross-SKU within family).
- **Escalation tier (R2 exploitation, confirmed high-value only): `claude-fable-5`** (~$10/$50 per MTok) — the PUBLIC Mythos-class model ("Mythos with guardrails"). **Mythos 5 itself is restricted to vetted US orgs (Project Glasswing) — NOT callable**; treat its ExploitBench 78 as the industry ceiling, not an option. Anthropic says Mythos-class goes wide in 6-12 months.
- **DS V4 Flash 0731 = volume tier via OpenRouter flat $0.05/$0.10** — DS direct API repriced Aug 16, 2026 (peak/off-peak $0.22–0.44 in / $0.66–1.32 out; peak 01:00–04:00 & 06:00–10:00 UTC). Always route volume through OpenRouter; re-verify via OpenRouter API before big runs.
- **Local-first (user decision Aug 27):** Kali 2026.2 VM (VirtualBox) + Hermes CLI inside; no cloud for now. Azure for Students $100/12mo (no card) = later 24/7 option (CLOUD-24-7.md); DigitalOcean student credit DEAD (Jul 31, 2026).
- **Instance bootstrap + sync (Aug 27):** all docs live in a private git repo — `github.com/sahliadem0106/bugagent` (**username is `sahliadem0106`, NOT `sahliaadem0106`**) — Kali clones with `git clone ... ~/bugagent`; Windows edits → `git push`, Kali → `git pull`. User explicitly wants the SIMPLE git path over shared folders/scp ("lets not complicate it"). Kali instance identity = the operator-installed soul file (character) + `MISSION-BRIEF.md` (orders: phase state, routing table, seven laws, session-start procedure) + security skills; `SOUL.md` in the repo is the alternate identity doc, reference only.
- **External-review workflow:** user sometimes pastes reviews from other LLMs (GLM-5.3-Flash in browser, Claude) for arbitration — ALWAYS fact-check their factual claims against primary sources before adopting. Verified sample: review was ~90% right (caught stale DS pricing); 2 overclaims corrected (xvulnhuntr archived not "Feb 2026"; CyberGym kit crash-class only).
- Docs: `C:\Users\sahli\bugagent\` — ROADMAP.md (v2), GLM-5.3-FLASH-RESEARCH.md (benchmark dossier), AGENT-BLUEPRINT-v2.md (architecture, IDOR module = "A door" first bug class, self-learning loop), MODEL-ROUTING.md (tier routing), ATTACK-CHAIN-CRITERIA.md (community ref, R0–R2 ladder, Fable/Mythos access), VM-SETUP.md, RESOURCE-UPGRADES.md (verified review triage: BBOT 3.0 data plane, feeds, Phase 1.5 = readiness (no benchmarks)).
- Preferences (embedded — he will say "nuh nuh nuh" if violated): cost-first framing; **system-level answers** (where does it run, how does it learn) over component/model detail; honest probabilities, NO fake percentages; human always submits; labs (Juice Shop, PortSwigger) before any real program; local session-based > 24/7 cloud until he asks.

## Methodology blueprint to teach the agent
- 12-step blueprint (canonical, r/bugbounty): subdomain enum (subfinder/amass/waybackurls) → spider (zap/katana) → robots.txt → permutation brute (altdns) → alive filter (httpx) → tech fingerprint → hidden params (arjun) → dir fuzz (ffuf) → port scan (nmap) → dorking → **logic bugs FIRST (away from WAFs)** → technical vulns last.
- Bug focus order (beginner goldmine): IDOR / broken access (A01 — 2-account object-ID swaps, highest hit rate) → business logic → SQLi → XSS → auth (JWT/session/MFA) → known CVEs (nuclei + OSV) → later SSRF/SSTI/upload/deserialization.
- Knowledge/memory stack: skills (the `exploiting-*` playbooks) + SQLite findings DB + vector RAG (Qdrant/sqlite-vec over HackTricks/PayloadsAllTheThings) + optional GraphRAG/Neo4j; CVE feeds: nuclei-templates (YAML = executable spec), OSV API, cvelistV5.
- Local cron only fires while Hermes is open; 24/7 later = Azure for Students credit (~$0–15/mo, no card) — see CLOUD-24-7.md. DigitalOcean student credit is dead (Jul 31, 2026).

## Pitfalls
- **wmic returns EMPTY on Windows 11** — hardware checks must use `powershell.exe -NoProfile -Command "Get-CimInstance Win32_VideoController | Select Name,AdapterRAM"` (also Win32_ComputerSystem, Win32_Processor). Always check the user's actual GPU/RAM before recommending local hosting.
- Never submit without human review; reputation is the asset
- Respect program scope AND program rules on automation/AI (many programs restrict AI scanning — check before running)
- Never point the agent at unauthorized targets (legal + ban risk)
- Tracker/blog model rankings = orientation, not contracts — refresh prices via the OpenRouter API
- **Git is the user's preferred doc-transfer path** (git push/pull over shared folders/scp) — keep bootstrap instructions to ONE simple path unless asked
- GitHub username is `sahliadem0106` — verify before constructing repo URLs (memory once held `sahliaadem0106`, which 404s)
- Division of labor: agent does recon + triage; the HUMAN does validation and final reports (the 2026 market explicitly rewards this)
- AI finds mostly shallow/known bugs; novel technique in ONE area beats breadth (community consensus: "success isn't amassing knowledge, it's creating novel techniques in at least one area")
- Check licenses before commercial use: Kimi K3 (custom), Qwen3.8-Max (revenue-share), MiniMax H3 (excludes US/EU commercial), Tiny Aya (CC-BY-NC)

## References
- `references/2026-open-llm-landscape.md` — full Jan–Aug 2026 open-weights release catalog (verified dates + licenses), live OpenRouter price table, excluded-2025 releases list, key Reddit thread pointers
- `references/compute-budget-2026.md` — free-API-tier limits, GCP $300 trial math, GPU spot prices, local-CPU model sizes/speeds, Windows hardware-check commands
- `references/2026-08-model-routing-deep-dive.md` — verified Aug 2026 model facts for THIS project: GLM-5.3-Flash + DS V4 Flash 0731 benchmark tables, live DS peak pricing, Fable 5 vs Mythos 5 access, R0–R2 attack-chain ladder + criteria, Phase 1.5 readiness gate (no benchmarks), resource triage
