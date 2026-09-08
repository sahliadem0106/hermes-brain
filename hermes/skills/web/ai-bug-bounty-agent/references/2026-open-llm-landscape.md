# 2026 Open-Weights LLM Landscape + Live Prices

Snapshot compiled Aug 26, 2026 (session research: ~50 searches, release-tracker cross-checks, OpenRouter live API, 3 delegated period-sliced subagents). Dates verified against official HF model cards / lab blogs where possible; `~` = approximate or disputed. Re-verify dates/prices when used later — trackers re-date old models (see web-research skill pitfalls).

## Verified open-weights releases Jan 1 – Aug 26, 2026 (~62 total)

### January
- NousCoder-14B — Nous Research — Jan 6 — 14B dense, olympiad-coding RL on Qwen3-14B — Apache 2.0
- Kimi K2.5 — Moonshot — Jan 27 — 1T MoE ~32B active, native multimodal — Modified MIT
- DeepSeek-OCR 2 — DeepSeek — Jan 27-28 — OCR/vision, DeepEncoder V2 — Apache 2.0 (adjacent, not LLM)
- Trinity Large — Arcee AI — Jan 27 — 400B MoE / 13B active — OpenMDW-1.1

### February
- Step-3.5-Flash — StepFun — Feb 1-2 — 196B MoE, reasoning+agentic, MTP-3 — Apache 2.0
- Voxtral Transcribe 2 / Voxtral-Mini-4B — Mistral — Feb 4 — 4B real-time ASR (speech, adjacent) — Apache 2.0
- HY-1.8B-2Bit — Tencent Hunyuan — Feb 9 — 1.8B on-device, 2-bit QAT — Hunyuan license
- GLM-5 — Z.ai — Feb 11-12 — 744B MoE / 40B active, 205K ctx — MIT
- MiniMax M2.5 — MiniMax — Feb 12 — 230B MoE, SWE-V 80.2% — Modified MIT
- Hibiki-Zero — Kyutai — Feb 12 — 3B speech-to-speech (adjacent) — MIT
- Qwen3.5 family — Alibaba — Feb 16 (397B-A17B, 122B-A10B, 35B-A3B, 27B), Mar 2 (9B/4B/2B/0.8B) — native multimodal, 201 langs — Apache 2.0
- Ling-2.5-1T + Ring-2.5-1T — Ant Group (inclusionAI) — Feb 16 — both 1T MoE (Ring = hybrid linear-attention reasoning) — MIT
- Xiaomi-Robotics-0 — Xiaomi — Feb ~ — 4.7B VLA (adjacent) — Apache 2.0
- Steerling-8B — Guide Labs — Feb 23 — 8B masked-diffusion interpretable LM

### March
- Phi-4-reasoning-vision-15B — Microsoft — Mar 4 — 15B multimodal reasoning — MIT
- Sarvam 30B + 105B — Sarvam AI — Mar 6 — 30B-A2.4B / 105B-A10.3B MoE, Indian-languages reasoning — Apache 2.0
- Nemotron 3 Super — NVIDIA — Mar 10-11 — 120B-A12B hybrid Mamba-Transformer MoE, LatentMoE — NVIDIA Open Model License
- Mistral Small 4 — Mistral — Mar 16 — 119B MoE / 6.5B active (128e), 256K — Apache 2.0
- Leanstral — Mistral — Mar 16 — 119B MoE, Lean 4 formal-proof agent — Apache 2.0
- Voxtral TTS — Mistral — Mar 23-26 — 4B TTS (adjacent) — CC-BY-NC
- Cohere Transcribe — Cohere — Mar 26 — 2B ASR, 14 langs (adjacent) — Apache 2.0
- Gemma 4 (E2B, E4B, 31B, 26B-A4B) — Google — weights Mar 31 / announced Apr 2 — multimodal, 256K — Apache 2.0

### April
- Granite 4.1 — IBM — Apr 21 — enterprise refresh
- GLM-5.1 — Z.ai — Apr 7 — 744B/40B — MIT
- EXAONE 4.5 — LG — Apr 9 — 33B first open VLM from LG — Apache 2.0
- Kimi K2.6 — Moonshot — Apr 13 preview / Apr 20 GA — 1T/32B, 262K, 300-agent swarms, SWE-Pro 58.6 — Modified MIT
- Qwen3.6-27B + 35B-A3B — Alibaba — Apr 22 — Gated DeltaNet hybrid — Apache 2.0
- DeepSeek V4 Pro (1.6T/49B) + V4 Flash (284B/13B) — Apr 23-24 — 1M ctx, sparse attention, text-only — MIT
- Hy3preview / Hunyuan 3.0 — Tencent — Apr 23 — 295B/21B, 256K, fast+slow thinking
- Mistral Medium 3.5 — Apr 28-30 — 128B dense, 256K, multimodal merged flagship — Modified MIT

### May
- Command A+ — Cohere — May 20 — A-line flagship open refresh
- MiniCPM5-1B — OpenBMB — May — 1B edge

### June (biggest month, ~14 releases)
- MiniMax M3 — Jun 1 → weights Jun 7 — 428B/23B MoE, 1M ctx, MSA attention, native multimodal + computer use — Apache 2.0
- Zamba2-VL — Zyphra — Jun 2 — vision-language Mamba hybrid
- Gemma 4 wave 2 (12B Unified + MTP variants) + TranslateGemma (4B/12B/27B) + MedGemma 1.5 (4B) + FunctionGemma (270M) — Google — Jun 3 — Apache 2.0
- Nemotron 3 Ultra — NVIDIA — Jun 4 — 550B/55B, best of Nemotron 3 family
- Llama 4.5 — Meta — early Jun — mid-cycle open refresh of Llama 4 family
- DeepSeek V4.1 Flash + Pro — early Jun — iterative V4 refresh
- Kimi K2.7-Code — Moonshot — Jun 12 — 1T/32B, long-horizon coding — Modified MIT
- GLM-5.2 — Z.ai — Jun 13 — ~750B/40B, 1M ctx — MIT
- North-Mini-Code — Cohere — Jun — open MoE coding model
- Laguna M.1 — Poolside — Jun — 225B-A23B — OpenMDW
- Ornith 1.0 (9B + 397B), Moebius — new labs — Jun (thin sourcing)
- Nemotron-Labs-3-Puzzle-75B-A9B — NVIDIA — Jun — pruned MoE
- FastContext 1.0 4B — Jun (thin sourcing)
- Qwen-AgentWorld-35B-A3B — Alibaba — Jun — native language world model
- Yi-Lightning 2 — 01.AI — Jun ~ — frontier at 1/15 cost

### July
- Laguna XS 2.1 — Poolside — Jul 2 — 33B-A3B, 256K, SWE-V 70.9% — OpenMDW-1.1
- Laguna S 2.1 — Poolside — Jul ~ — 118B MoE — OpenMDW
- Nemotron-3 (compressed) — NVIDIA — Jul 6 — 120B-A12B pruned via "Iterative Puzzle"
- Inkling — Thinking Machines — Jul 15 — 975B/41B, 1M ctx, multimodal, controllable reasoning — Apache 2.0
- Kimi K3 — Moonshot — announced Jul 16, weights Jul 26-27 — 2.8T/104B (896 experts), 1M ctx — custom Kimi K3 license
- Inkling-Small — Jul 30 — 276B/12B — Apache 2.0
- DeepSeek-V4-Flash-0731 — Jul 31 — 284B/13B, official Flash + speculative decoding — MIT
- K-EXAONE 2.0 — LG — Jul 31 — 750B/37B, 256K, 10 languages — Apache 2.0

### August
- MiniMax H3 — hosted Jul 31, weights Aug 3 — 33B omni-modal (text+image+video+audio gen) — license EXCLUDES US/EU commercial
- Qwen3.8-Max — GA Aug 3, weights Aug 12 (Qwen3.8-2.4T-A95B) — 2.4T/95B, largest open release ever — revenue-share license, text-only weights
- Muse Glimmer 30B — Meta — Aug 10 — 29.6B dense multimodal, distilled from Muse Spark — Apache 2.0
- Nemotron 3.5 Lightning — NVIDIA — Aug 11 — 30B MoE/~3B active, 1M ctx, laptop GPU
- DeepSeek V4-Pro-0813 — Aug 12-13 — 1.6T/49B GA checkpoint — MIT
- Qwen3.8-27B — Aug 14 — 27.8B dense, 262K→1M, native vision-language — Apache 2.0
- GLM-5.3 — Aug 14 — 743B, coding SOTA + cyber capabilities — weights PROMISED ~Aug 28 (held for safety hardening)
- Intern-S2-Preview + 397B — Shanghai AI Lab — Aug — 35B-A3B scientific multimodal agentic
- DeepSeek-V4-Flash-Vision-Exp — Aug — multimodal Flash (open-weights status unconfirmed)
- Apodex 1.1 — Aug 24 — 35B (self-reported claims)

## Excluded — 2025 releases that sloppy trackers re-date as 2026
Phi-4 Mini (Feb 2025 per Microsoft HF card), Llama 4 Scout/Maverick (Apr 2025), gpt-oss 20b/120b (Aug 2025), DeepSeek V3.2 (Dec 2025), OLMo 3 (Nov 2025), Devstral 2 (Dec 2025), SeaLLMs-v3 (2024), Ministral 3, Nemotron 3 Nano, Trinity Mini-Nano, Grok-2.

## Closed in 2026 (for orientation — NOT open)
Grok 4.5/4.6 (and 4.20, 2M ctx), Gemini 3.5-3.7 line, Claude Fable 5 / Opus 5 / Sonnet 4.6, GPT-5.4-5.6 (Sol/Terra/Luna), Muse Spark 1.1/1.2 (weights promised "coming weeks" from Aug 10 — no HF repo as of Aug 26), MAI-Thinking-1 (Microsoft), ERNIE 5.1, ByteDance Seed 2.1 (Pro/Turbo — open never confirmed), Qwen3.7-Max/Plus/Flash, OX Alpha (anonymous OpenRouter model, hosted only).

## OpenRouter live prices (per 1M tokens, pulled Aug 26, 2026)
| Model | In / Out | Context |
|---|---|---|
| Claude Fable 5 | $10 / $50 | 1M |
| Claude Opus 5 | $5 / $25 | 1M |
| GPT-5.6 Sol / Terra / Luna | $2/$10, $2/$12, $0.20/$1.20 | 1M |
| Grok 4.20 | $1.25 / $2.50 | 2M |
| Kimi K3 | $3 / $15 | 1M |
| GLM-5.3 | $1.40 / $4.40 | 1M |
| Qwen3.8-2.4T-A95B | $2 / $6 | 1M |
| DeepSeek V4-Pro-0813 | $1.32 / $3.96 | 1M |
| Muse Spark 1.2 | $1.25 / $4.25 | 1M |
| Inkling / Inkling-Small | $0.95/$4.05, $0.45/$1.20 | 1M |
| MiniMax M3 | $0.30 / $1.20 | 1M |
| Qwen3.8-27B | $0.425 / $2.55 | 1M |
| GLM-5.3-Flash | $0.075 / $0.25 | 1M |
| DeepSeek V4-Flash-0731 | $0.06 / $0.12 | 1.3M |
| Llama 4 Scout | $0.11 / $0.34 | 1.3M |

Pricing fields: `pricing.prompt`, `pricing.completion`, `pricing.input_cache_read` (per token — ×1M). `top_provider.is_moderated` = content-filtered. `:batch` ≈ 50% off, `:free` variants exist.

## Benchmark notes (what measures what)
- Composite: Artificial Analysis Intelligence Index v4.1.1 (GDPval-AA v2, τ³-Banking, Terminal-Bench v2.1, SciCode, HLE, GPQA, CritPt, AA-Omniscience, AA-LCR). Aug 2026: Claude Opus 5 ~63 leads; Kimi K3 #3 overall / #1 open (ahead of every proprietary except Fable 5 and GPT-5.6 Sol); K3 also #1 Frontend Code Arena.
- Hallucination: frontier range ~4-19% depending on benchmark (Vectara, FACTS, AA-Omniscience); Claude lowest (~4% in one 2026 study); HALC-Bench = long-context retrieval hallucination.
- Agentic coding: A-CODE-LLM Bench (Opencode harness via OpenRouter, 10 tasks × 3 runs — Fable 5 on Claude Code CLI, Inkling via TM API).

## Key Reddit threads (learning-path gold, Aug 2026)
- r/bugbounty "I have over $1M bounty from HackerOne [AMA]" — 1ae6az5 (117 comments)
- r/bugbounty "I Spent 18 Hours Creating This Bug Bounty Roadmap for Beginners" — 1mqtsap (s=282; note: several comments call it AI-generated)
- r/bugbounty "Beginner trying to get into web bug bounty. What roadmap did you follow?" — 1rthkd2
- r/bugbounty "Lost In Bug Bounty" — 1kwkugm; "LT;DR: Learning Application Security by Studying Systems, Not Just Tools" — 1qjkfgv
- r/bugbounty "How long did it take you to get your first bug?" — 14f79iz
- r/bugbounty "How useful are AI tools like ChatGPT for bug bounty" — 1otba3b; "Did AI ever help you exploit" — 1o6ipca; "Ai will replace our hunter jobs?" — 1bjypim
- r/bugbounty "this is how you can write a professional bug bounty report" — 1dngq46
- Raw archives: C:\Users\sahli\reddit_mining\ (deep_posts.jsonl, deep_comments.jsonl, sweep.jsonl)

## AI-bug-bounty articles worth citing (2026)
- chudi.dev "Bug Bounty Automation Framework: Zero False Positives" (Mar 6/Apr 14) — the 4-agent evidence-gating architecture
- Bugcrowd blog "What I learned building AI agents for bug bounty hunting" (Feb 18, 2026) — CrewAI example, methodology-first
- "Everyone Is Using AI for Bug Bounty in 2026. Almost Nobody Is Using It Correctly." (Medium, Mar 16)
- Apple submission limits (macrumors Aug 4 / bitdefender Aug 5, 2026); Internet Bug Bounty pause (Apr 7, 2026); "76% more reports, programs shutting down" (dev.to, May 20)
