# Claude Session Findings — July 16, 2026

Claude independently researched the landscape and generated 2 separate responses. This file captures both.

## New Discoveries Verified

| Finding | Verified? | Source |
|---------|-----------|--------|
| PhysicEdit uses state transitions from video (PhysicTran38K dataset) | ✅ Verified | GitHub + arXiv paper |
| Longitudinal-MIMIC exists (26,625 patients, repeat CXR) | ✅ Verified | PhysioNet |
| No Arabic medical VLM exists (Italian/German/Spanish/Turkish do) | ✅ Verified | Searched multiple angles |
| Tunisian Derja NLP resources exist (TunSwitch, TARIC) but NOT medical/vision | ✅ Verified | ACL anthology, GitHub |
| DFU classification is crowded (DFUC 2020-2022) | ✅ Verified | MICCAI proceedings |
| No public Maghreb CXR dataset exists | ✅ Verified | Multiple searches, zero results |
| Sub-Saharan Africa has CXR data (Ethiopia, Uganda) but North Africa has none | ✅ Confirmed |
| MiniGPT-Med needs ~11.5GB in 8-bit on T4 (fits) | ✅ Verified | GitHub README |
| Medical VLM uncertainty/grounding filling up (uMedGround, MedSIGHT) | ✅ Confirmed | Multiple papers |
| VisionEncoderDecoderModel still current in HF | ✅ Verified | HF docs |
| MAPIE (conformal prediction) actively maintained | ✅ Verified | GitHub, docs |
| Zech et al. 2018 — CXR CNNs learn hospital shortcuts | ✅ Verified | Nature MI paper |
| NIH ChestX-ray14: 880 images, 984 boxes, 8 diseases | ✅ Verified | Paper |

## Session 1 — 5 Creative Projects
See `System/Hermes/claude-sessions/2026-07-16-full-response.md`

## Session 2 — 6 Candidates at PP3 Level
Response to prompt asking for projects at 🟡 4-6/10 difficulty.

### Top Recommendations
- **PPA-2 (Shortcut Detection)** — App Weight: 🔴 8/10. Shows research thinking.
- **PPB-2 (Uncertainty/Conformal)** — App Weight: 🔴 8/10. "Model knows when it's wrong."

### Best Story Arc
PP1 → PPA-2 → PP3 → PPB-2 = one continuous narrative about trustworthy AI.

## Things Killed That Our List Didn't Cover
- Anemia smartphone detection (10+ papers, PNAS 2025)
- Generic 3D VLM extension (VividMed 2024)
- Diabetic retinopathy screening (APTOS = dozens)
- PPA-3 Federated (non-IID convergence too hard at this level)
- PPB-3 Structured Findings (questionable clinical value, tight timeline)
