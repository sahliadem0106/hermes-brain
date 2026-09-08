# Project Viability Assessment — July 2026

## Method
Ran Phase 5 Project Viability Assessment from web-research skill on each PP project:
1. Searched for direct competitors (same pipeline, datasets, evaluation)
2. Compared framing, datasets, methods
3. Issued verdict

## Results

### PP1 — Calibration Failure Under Population Shift + Few-Shot Recalibration

**Hypothesis (reframed Jul 2026):** CNN models trained on Western CXR data are overconfident when wrong on non-Western populations. How many locally-sourced examples are needed to fix calibration via few-shot recalibration?

**Previously (original, killed):** NIH-trained models fail WHO sensitivity thresholds on MENA populations.

**Searches (new round):** "calibration medical imaging population shift", "few-shot recalibration chest X-ray", "temperature scaling domain shift"

**Found (new):**
- Ktena et al. (Nature Medicine 2024) — "Generative models improve fairness of medical classifiers under distribution shifts" — uses synthetic data to improve fairness. Relevant but different angle (generation vs recalibration).
- Calibration under distribution shift in medical imaging is underexplored.
- Temperature scaling + few-shot fine-tuning on small target samples is NOT published for CXR + MENA framing.

**Verdict (updated):** ✅ Still valid with reframe

**Required reading before committing:** Ktena et al. 2024 Nature Medicine paper in full. Explicitly differentiate: recalibration (yours) ≠ synthetic generation (theirs).

### PP2 — MiniGPT-Med Clinical Reliability Audit

**Hypothesis:** MiniGPT-Med hallucinates, fails on Gulf diseases, degrades on Arabic

**Searches (deeper round, Jul 2026):** "medical VLM hallucination benchmark 2026", "CAMEL-Bench Arabic", "MedArabiQ"

**Found (deeper round):**
- CAMEL-Bench (NAACL 2025) — comprehensive Arabic multimodal benchmark including medical imaging, evaluates GPT-4V, LLaVA-NeXt, Gemini, InternVL2 on Arabic medical tasks
- MedArabiQ (MLHC 2025) — Arabic medical LLM benchmark (text-only, no images)
- MedVH (Advanced Intelligent Systems 2026) — systematic medical VLM hallucination evaluation
- MedHEval (2025) — medical VLM hallucination + mitigation strategies
- MedHallBench (2024/2025) — comprehensive hallucination framework
- ClinHallu (2026) — stage-wise hallucination diagnosis in medical MLLM reasoning
- Med-StepBench (2026) — hierarchical reasoning for medical VLM hallucination
- CARES, HEAL-MedVQA, MedHallMark, MedHallTune, UniVRSE — additional benchmarks
- Cross-lingual hallucination analysis (Apr 2026 blog) — documents systematic problem

**Verdict (updated):** ❌ KILLED (Jul 2026)
**Why:** The field now has 10+ medical VLM hallucination benchmarks. CAMEL-Bench covers Arabic multimodal (including medical) — so Arabic + medical alone isn't novel. Running an existing framework on one more model (MiniGPT-Med) is thin as a contribution. Additionally: the relationship risk of cold-auditing your target advisor's shipped model is real — some PIs find it presumptuous from an unknown undergrad, and you don't get to retry a first impression.

### PP3 — Few-Shot BiomedCLIP for Gulf-Endemic Diseases

**Hypothesis:** Few-shot adaptation of BiomedCLIP benefits Gulf-endemic rare diseases, and medical ontology embedding initialization improves linear probing

**Searches (deeper round, Jul 2026):** "BiomedCoOp CVPR 2025", "Biomed-DPT", "BiomedCCPL", "Medical Knowledge Intervention Prompt Tuning"

**Found (deeper round):**
- BiomedCoOp (CVPR 2025) — compares same methods on BiomedCLIP across 11 biomedical datasets, 9 modalities, 10 organs
- Biomed-DPT (2025) — dual modality prompt tuning for BiomedCLIP
- **BiomedCCPL (CVPR 2026)** — causal conditional prompt learning on BiomedCLIP, from HM Lab. Just published. Even more recent competition.
- **Medical Knowledge Intervention Prompt Tuning** — injects medical knowledge into prompt tuning for medical image classification. Conceptually close to your ontology embedding initialization idea. Need to read this paper specifically to confirm whether it occupies the same niche.

**Verdict (updated):** ⚠️ Needs sharpening, more urgent than before
**Why more crowded:** BiomedCCPL (CVPR 2026) is even more recent than BiomedCoOp. The ontology init idea may overlap with Medical Knowledge Intervention. The stronger differentiator is now: Gulf-endemic diseases (not in any of these benchmarks) + corpus-frequency analysis of PMC-15M (genuinely original).
**Required fix:** Read BiomedCCPL + Medical Knowledge Intervention Prompt Tuning before committing. Corpus-frequency analysis of PMC-15M is the strongest original move. Make that the headline.

### PP4 — Synthetic Gulf-Disease Image Generation via Diffusion LoRA
**Hypothesis:** Diffusion-based synthetic augmentation improves few-shot classification of Gulf-endemic diseases
**Searches:** "Stable diffusion LoRA synthetic chest X-ray augmentation few-shot classification", "diffusion synthetic data augmentation medical imaging"
**Found:**
- "Few-Shot Synthetic Data Generation with Diffusion Models for Downstream Vision Tasks" (arXiv 2605.11898, May 2026) — **EXACT same pipeline** (LoRA on 20-50 images → generate → classify → synthetic:real ratio sweep → tested on NIH ChestX-ray14 → rare-class recall improvement → diminishing returns at high ratios)
- "Evaluating and Improving the Effectiveness of Synthetic Chest X-Rays for Medical Image Analysis" (Nov 2024, updated 2025) — best practices for diffusion CXR augmentation
- "Synthetic-augmented adversarial training for robust chest X-ray classification" (Feb 2026)
- Multiple diffusion + LoRA for medical CXR papers (2025-2026)
**Verdict:** ❌ Killed as-is
**Why:** The core pipeline (LoRA adapters on 20-50 real images → generate synthetic → train classifier → measure improvement → sweep ratios) was published 2 months ago. Same method, same evaluation domain, same findings.
**Salvage options:**
1. Change the research question to bias/fairness: "Does synthetic augmentation amplify bias against rare Gulf-endemic conditions?"
2. Apply to a genuinely different domain (e.g., fundus photography for diabetic retinopathy in Gulf populations)
3. Use a different base generative model (e.g., medical-specific diffusion model instead of SD v1.5)

## Key Takeaway
The portfolio value is: PP2 (hook) → PP3 (lineage) → something generative (current work). PP1 is useful as a warm-up paper but doesn't connect to Elhoseiny. PP4 needs a new angle or replacement.
