# Compute & Budget for an AI Bug Bounty Agent — 2026 snapshot

Verified Aug 26, 2026. The user has NO local GPU (Intel Iris Xe iGPU, 23.6GB RAM, i7-13700H),
$0 API budget, and a GCP $300/90-day trial credit.

## Free API tiers (no card)
| Provider | What | Limits (2026) |
|---|---|---|
| Google AI Studio (Gemini) | Gemini 3.5-flash-lite / 3.1-flash etc. | 10-30 req/min free, no card |
| OpenRouter `:free` models | inkling:free, minimax-m3:free, ... | ~20 req/min; 50 req/day until ever buying $10, then 1000/day |
| Groq | open models, very fast | generous free tier |
| GitHub Models | GPT-5.x, Llama, DeepSeek | rate-limited free tier, no card |
| Cloudflare Workers AI | daily allowance | per-day |
| Mistral / Cerebras / NVIDIA NIM / HF Inference | free tiers | various |

Community guidance: "when you outgrow the free limits, the cheapest paid step is DeepSeek's API."
Definitive list repo: amardeeplakshkar/awesome-free-llm-apis.

## Cheapest paid
- DeepSeek V4-Flash official API: ~$0.06-0.14 per 1M tokens. A $2 top-up = months of volume.
- OpenRouter: buying $10 once permanently lifts the :free daily cap 50 → 1000 (and credits pay for cheap volume).
- User already has a DeepSeek key (Hermes runs on the deepseek provider) — reuse it.

## Free GPU (no card) — also useful for hosting small models
- Kaggle: T4/P100 16GB, 30 GPU-hr/week (sessions ~9h max)
- Google Colab free: T4 16GB, ~12h sessions, 15-30h/week dynamic
- Azure for Students: $100, no card (edu email / GitHub Student Pack) — persistent T4 VM ~200h
- AWS Educate: ~$100, no card (student)
- GCP $300 trial: card REQUIRED; budgets are alerts not brakes (no hard stop); some accounts get a refundable ~$10 prepayment — keep usage under $300 to get it back; set alerts at $100/$200/$250; STOP (not close) VMs.

## GCP GPU pricing (on-demand / spot, USD/hr, 2026)
| GPU | VRAM | On-demand | Spot |
|---|---|---|---|
| T4 | 16GB | ~$0.35 | ~$0.12 |
| L4 | 24GB | ~$0.74 | ~$0.25 |
| V100 | 16GB | ~$2.48 | ~$0.75 |
| A100 40GB | 40GB | ~$3.67 | ~$1.00 |
| H100 80GB | 80GB | ~$6.69 | ~$2.00 |

Renting (Vast.ai community / RunPod): RTX 4090 24GB ~$0.27-0.34/hr; 3090 similar. Card required (prefund).
Rules: burst not idle (24/7 L4 on-demand = $530/mo); auto-shutdown after N hours; API beats self-hosting for any model >30B.

## What fits what (Q4 quant)
| Model | Size | Fits |
|---|---|---|
| MiniCPM5-1B | ~0.8GB | anything |
| Qwen3.5-4B / Gemma 4 E4B | 2.6-4GB | CPU 24GB RAM, 8-12 tok/s |
| Qwen3.5-9B | ~5.5GB | CPU, 5-8 tok/s |
| NousCoder-14B / Phi-4-rv-15B | 8.5-9.5GB | CPU, 3-5 tok/s |
| Gemma 4 26B-A4B | ~15GB | T4 16GB (tight) |
| **Qwen3.8-27B** (Apache 2.0) | ~17GB | **L4 24GB — the pick** |
| GLM-5.x / Kimi K3 / DeepSeek V4 | 100GB+ | never self-host; use API |

## Free cloud-"hosting" trick (no card)
Colab/Kaggle session + llama.cpp/Ollama + cloudflared tunnel → OpenAI-compatible endpoint.
Sessions die after 9-12h; fine for burst agent sessions, not for persistent servers.

## Windows environment notes
- wmic is deprecated/empty on Win11 — hardware checks via PowerShell:
  `powershell.exe -NoProfile -Command "Get-CimInstance Win32_VideoController | Select Name,AdapterRAM"`
  (`Win32_ComputerSystem` for RAM, `Win32_Processor` for CPU).
- Recon tools are Linux-first: WSL2 (Ubuntu) is the standard setup; git-bash is a stopgap.
- Check free disk before pulling models (this user: 28GB free — only 2-3 small models fit).
