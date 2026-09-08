User: security researcher (bug bounty/CTF) on Kali; Hermes hunting agent (persona ~/.hermes/SOUL.md), repo ~/bugagent.
§
HARD BUDGET RULE: only two models ever, Nous Portal (OAuth sahliadem0106@gmail.com): z-ai/glm-5.3-flash ($0.06/$0.20, brain/hunter) + deepseek/deepseek-v4-flash ($0.02/$0.08, volume/hunter-bulk). No other model/fallback/MoA. GLM at MEDIUM effort (Aug 29 2026).
§
If user handles a piece themselves, stop that workstream, report, don't probe.
§
Session-start rule (#1 correction): before ANY work `cd ~/bugagent && git pull`, read ~/bugagent/MASTER.md (source of truth). If pull fails or MASTER.md missing, STOP and report exact error.
§
English only; evidence-grounded, not reassurance; show data/samples; honest calibration; explicit $/token cost math before long LLM batches.
§
Operator decisions: NO practice labs (Docker/JuiceShop/DVWA/PortSwigger) ever. Weekly digest ADOPTED (lightweight, cron weekly-hunter-digest). Knowledge graph + CVE/recon cron deferred. Priority: improve the machine until a real scope lands.
§
Two-agent hunting machine (Sep 1 2026): GLM-5.3-flash = MASTER (plan/judge/validate, no grunt); DeepSeek v4 flash = WORKER (one closed task at a time, no judgment, anti-hallucination output contract); DS never judges GLM. Role files ~/bugagent/agents/. HackerOne first, single account.