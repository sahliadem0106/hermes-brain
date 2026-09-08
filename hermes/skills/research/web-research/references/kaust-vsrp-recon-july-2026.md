# KAUST VSRP Recon — July 2026

## Target
Undergraduate Tunisian student (2nd year bachelor, 11/20 GPA) targeting VSRP at KAUST in Prof. Mohamed Elhoseiny's VisionCAIR lab. Research identity: generative/creative AI, few-shot learning, vision & language, applied to Gulf/MENA healthcare.

## Key Findings

### VSRP Requirements (Official vs Third-Party)
| Source | GPA Requirement | Notes |
|--------|----------------|-------|
| Official KAUST VSRP page | **Not stated** | Requires: 3rd/4th year bachelor or master's, transcript, 1 LoR, valid passport, English proficiency |
| Third-party scholarship sites | "3.5/4.0 or 14/20" | This is MS/PhD admission min, repeated by blogs, not confirmed on VSRP page |
| KAUST MS/PhD entry requirements | "Competitive GPA" — 90% have >3.3, 75% >3.5, **minimum 3.0** | Holistic review — "academic scores are not the only measure" |

**Key insight:** The 14/20 number appears on third-party sites (scholarship blogs, DAAD pages) but is NOT listed on the official KAUST VSRP page. The MS admissions page explicitly says they take a holistic view.

### The Professor-Invitation Route
- Multiple Reddit threads confirm: contacting a professor directly is the primary way in
- Pattern: apply through portal AND email professor → if professor wants you, they pull you through
- Reported response times: "within a week" from professors who are interested
- Anti-pattern: applying without professor contact = higher rejection rate

### VisionCAIR Lab Members (Elhoseiny's Group)
| Person | Role | Before KAUST | After KAUST |
|--------|------|-------------|-------------|
| Deyao Zhu | PhD (2019-2023) | MS background | ByteDance California (Research Scientist) |
| Ivan Skorokhodov | PhD (2019-2023) | MS background | Snap California (Research Scientist) |
| Kai Yi | MS (2020-2022) | Bachelor | Thesis on Zero-Shot Learning |
| Yuchen Li | MS (2021-2023) | Bachelor | 3D Computer Vision |
| Asad Alghamdi | MS (2020-2022) | Saudi national | Swansea University (Faculty) |
| Zhongyu Yang | Remote Intern (2024-2026) | Unknown | Remote from China |
| Yesmeen Khattab | Research Technician | Unknown | Still at KAUST |

**Pattern:** No VisionCAIR member had papers or Kaggle medals before joining. They gained papers *during* their time at KAUST.

### Real VSRP Intern Profiles (Non-VisionCAIR)
| Person | Field | Before KAUST | Papers Before? | Kaggle? |
|--------|-------|-------------|---------------|---------|
| Abdulaziz Al-Tayar | CV/ML (Saudi) | Saudi undergrad | No | No |
| Shanmugarajan B | EE/Wireless (India) | B.Tech, ML certs | No | No |

Both had **zero papers, zero Kaggle medals**. They applied and got in.

### Elhoseiny's Research Identity (2026 Snapshot)
| Era | Focus | Key Paper |
|-----|-------|-----------|
| **Origin (2013)** | Zero-shot learning | "Write a Classifier" (ICCV 2013) — learning classifiers from text alone |
| **Growth (2017-2023)** | VLMs, creative AI | MiniGPT-4, MiniGPT-v2, MiniGPT-Med, art/fashion generation |
| **Current (2025-2026)** | Generative AI, diffusion | PhysicEdit (ICML 2026) — physics-aware diffusion editing. NeurIPS 2025 keynote on Neural Cataloging |

**What impresses him:** Novel generative approaches > evaluations of existing models. Building > auditing.

### Updated Project Viability (End of July 2026 — After Deeper Recon)

Key change: PP2 was re-evaluated and killed. Initial assessment (valid) was overruled by deeper search revealing 10+ hallucination benchmarks (MedVH, MedHEval, MedHallBench, CARES, ClinHallu, Med-StepBench, UniVRSE, HEAL-MedVQA, MedHallMark). Also: relationship risk of cold-auditing target advisor's shipped model is real and uninsurable.

| Project | Status | Why |
|---------|--------|-----|
| PP1 — TB screening eval | ✅ Reframed and kept | Reframed to "calibration failure under population shift + few-shot recalibration." Ktena et al. (Nature Medicine 2024) covers generative models for fairness — need different angle (recalibration, not generation). |
| PP2 — MiniGPT-Med audit | ❌ KILLED (Jul 2026) | Crowded field (10+ hallucination benchmarks). CAMEL-Bench (NAACL 2025) covers Arabic multimodal eval. MedArabiQ (MLHC 2025) covers Arabic medical text. Relationship risk of cold-auditing target advisor's model outweighs the upside. |
| PP3 — Few-shot BiomedCLIP | ⚠️ Needs sharpening | More crowded: BiomedCoOp (CVPR 2025), Biomed-DPT (2025), BiomedCCPL (CVPR 2026), Medical Knowledge Intervention Prompt Tuning (close to ontology init idea). Saved by: Gulf-endemic diseases + corpus-frequency analysis of PMC-15M + ontology init. |
| PP4 — Synthetic diffusion | ❌ Core killed | Published May 2026 (arXiv 2605.11898) — identical pipeline. |

### Unverified Claims (found during Jul 2026 recon)
- "NeurIPS 2025 keynote on Neural Cataloging" — could NOT verify. LinkedIn shows spotlight paper presentation, not keynote. Do not cite without verifying directly.
- MiniGPT-Med + SDAIA — VERIFIED. Saudi Press Agency and multiple news sources confirm.
- PhysicEdit (ICML 2026) — VERIFIED. Elhoseiny senior author, KAUST/CUHK/Krea/HuggingFace collaboration.
- LongVU (ICML 2025) — VERIFIED. Real Vision-CAIR project.

### Backup Professors (Jul 2026)
| Professor | Institution | Lab | Fit | Mechanism |
|-----------|-------------|-----|-----|-----------|
| Bernard Ghanem | KAUST | IVUL | High — CV, co-authored with Elhoseiny (PointNeXt). Karen Sanchez postdoc does healthcare AI. | Same VSRP |
| Mohammad Yaqub | MBZUAI | BioMedIA | Very high — medical AI, general chair MICCAI 2026 | Direct email (UGRIP program is 4wk, 4% acceptance, avoid) |

## Sources Used
- Official KAUST pages: admissions.kaust.edu.sa (VSRP, entry requirements)
- VisionCAIR group page: vision-cair.github.io/people.html
- LinkedIn profiles (public view only)
- Reddit: r/KAUST threads
- Google Scholar: Elhoseiny's publication list
- arXiv: 2605.11898 (PP4 competitor)
- CVF Open Access: Elhoseiny ICCV 2013 paper
- ICML 2026: PhysicEdit paper
