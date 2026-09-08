# Project Evaluation Filters & Rating System — Academic Research Projects

A framework for evaluating whether a research project is worth pursuing and how it compares to alternatives. Originated from a VSRP-targeting student's self-defined criteria. Use this to rate candidate projects side-by-side before committing time.

## The 4 Go/No-Go Filters

Every project must pass ALL four before committing. These are binary — fail one, kill the project (or reframe until it passes).

### Filter 1 — Gradual Skill Building
> Does this project teach a transferable, marketable skill that starts from where the student actually is?

- Skill should open job market opportunities, not just work for one paper
- Must be gradual — not jumping into complex theory the student isn't ready for
- The skill should transfer to future projects, not be a one-trick

### Filter 2 — Novelty (65-70% own thinking, max 30-35% relying on existing work)
> Is the core question genuinely open, or was it already answered?

- Must pass litmus test: "can this be answered by thinking/logic alone?" If yes, it's not research
- Must require actual experiments
- If core idea has been published, either kill it or find a genuinely new angle
- Check: arXiv, Semantic Scholar, conference proceedings (last 2 years)

### Filter 3 — Identity Signal
> Does this project look like the work of the kind of researcher the student wants to become?

- Should feel authentic to the student's stated identity
- Should NOT make the student look like a clone/groupie of a specific professor (see pitfalls)
- Reader should think "this person thinks like a researcher" not "this person followed instructions"

### Filter 4 — Compute Reality
> Can this project be executed with the student's actual resources?

- Kaggle free tier: NVIDIA T4 16GB, 30 GPU hours/week, 9h max session
- Colab free: T4, 15-30h/week with cooldowns
- Colab Pro: $10/month, priority access
- Student cloud credits (AWS Educate, Azure for Students, GitHub Student Pack)
- NO: A100, multi-GPU, paid cloud beyond $10/month
- NO: full fine-tuning of 7B+ parameter models

## Multi-Criteria Rating System

After a project passes the 4 filters, rate it across these dimensions to compare against alternatives.

### Rating Dimensions

**1. Novelty / Scoop Risk (🟢 🟡 🔴)**
- 7-9/10: Genuinely unexplored. Less than 3 closely related papers.
- 5-6/10: General area exists but specific framing/dataset/angle is yours.
- 1-4/10: Already published or crowded. Kill or reframe.

**2. Difficulty Relative to Student's Current Level (🟢 🟡 🔴)**
- 3-4/10: Courses teach it → student applies immediately. 0h extra learning.
- 5-6/10: One new skill to build on existing foundation. 5-20h extra learning.
- 7-9/10: Requires 40-65h out-of-course learning in a new subfield.

Important: Always evaluate against CURRENT skills, not future planned ones.

**3. Compute Requirements (🟢 🟡 🔴)**
- 🟢: Fits Kaggle T4 free tier. 0-20 GPU hours.
- 🟡: Needs careful budgeting or $10 Colab Pro. 20-40 GPU hours.
- 🔴: Needs A100, multi-GPU, or >40h/week. Dead.

**4. Professor Match (for targeted applications)**
- 8-10: Directly extends their most recent work or fills a gap in their shipped tools.
- 5-7: Same broad area but not their active frontier.
- 2-4: Adjacent. Shows general skill but won't make them reply.

**5. Application Weight (VSRP / grad school)**
- 8-10: Strong talking point. Professors notice and ask about it.
- 5-7: Shows skill but generic. Most competitive applicants have this.
- 2-4: Proves you can finish. Won't make anyone reply.

**6. Who-Level (Who usually does this?)**
- 🟢 Undergrad: Standard transfer learning + evaluation. Final-year project level.
- 🟡 Master's: Systematic multi-method comparison, 200+ experiments. Ambitious for undergrad.
- 🔴 Master's/PhD: Requires research experience (evaluation design, multimodal systems, cross-lingual analysis).
- 🔴 PhD/Research Engineer: Full subfield specialty (generative AI, diffusion, federated learning).

### Rating Presentation Format

| Criteria | Rating | Evidence / Why |
|----------|--------|----------------|
| Novelty | 🟡 6/10 | Cross-dataset eval well-studied but MENA framing is yours |
| Difficulty | 🟢 3/10 | Standard transfer learning |
| Compute | 🟢 15-20h | Kaggle T4 |
| Prof Match | 🟡 2/10 | He doesn't work on this |
| App Weight | 🟡 4/10 | Shows you can finish |
| Who-Level | 🟢 Undergrad | Standard final-year level |

**Verdict:** ✅ / ⚠️ / ❌ with 1-sentence explanation.

## Pitfalls

- **Recommending sycophantic alignment projects.** Also search for the student's independent angle.
- **Assuming future skills are current skills.** Rate against what they know NOW.
- **Hiding the who-level assessment.** Be explicit about PhD vs undergrad level.
- **Single rating in isolation.** Always compare 3-6 candidates side by side.
- **Fabricating confidence without data.** No percentages without actual statistics.