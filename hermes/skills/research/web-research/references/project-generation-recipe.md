# Research Project Generation Recipe — Reusable Prompt Template

Use this when you need to generate research project ideas via an external agent (Claude, etc.). This template enforces filters BEFORE creativity, not after — the key difference between sessions that produced dead ideas (trendy methods, got scooped) and sessions that produced survivors (boring methods, understudied context).

## The Template

```
You are helping me design ONE new research project (a "PP" — a practice/portfolio paper)
for an academic application portfolio. Follow this process in order. Do not skip steps.
Do not just brainstorm and pick your favorite idea — filter hard and kill weak ideas explicitly.

MY PROFILE:
- Level: [e.g. "3rd year computer engineering undergrad, self-taught deep learning and
  medical imaging course stack ~50% complete"]
- Compute: [e.g. "Kaggle T4 free tier only, no Coloab Pro, no large-scale training"]
- Time budget: [e.g. "15h/day, want this done in under 150 hours total"]
- Artifacts I've already built: [list every trained model, dataset, and pipeline you
  already have — be specific]
- Skills I already have: [list — be specific, no vague "machine learning"]
- Target advisor / lab: [name, institution]
- My overarching research theme: [one sentence]

STEP 1 — Study the target's ENDURING identity, not their newest paper.
Search the web for their full publication history and official bio/lab page. Tell me
explicitly: what theme has stayed constant across their ENTIRE career (ideally 10+
years), versus what's just their newest direction? A recent single paper can age out
of relevance in 1-2 years. An enduring theme doesn't. Anchor primarily to the
enduring theme.

STEP 2 — Generate 3-5 candidates using this filter:
- Prefer OLD, well-documented, low-risk METHODS over currently-trendy ones. Trendy
  method categories attract fast-moving competition and get scooped or crowded quickly.
- Get novelty from an UNDERSTUDIED SPECIFIC CONTEXT, POPULATION, OR COMBINATION — not
  from inventing a new method.
- Maximize reuse of what I've already built. Ask explicitly: can this run mostly on
  artifacts I already have, with little or no new training?
- Flag (don't auto-reject, but flag clearly) any candidate needing a substantial new
  technical subfield I don't already know.

STEP 3 — Novelty check. MANDATORY. Do not skip.
For every surviving candidate, actually search the web for papers from the last 12
months doing the same core pipeline or answering the same core question. If something
already does 80%+ of what you're proposing, say so plainly. Either kill the idea or
tell me exactly what's left to differentiate it. Never claim novelty without having
actually searched.

STEP 4 — Compute and feasibility check. MANDATORY. Do not skip.
Estimate realistic (not optimistic) hours given my time budget. Confirm it fits my
stated compute. If it needs something I don't have, scale it down or drop it.

STEP 5 — Relationship-risk check (only if this touches the target's own named
model/dataset/tool).
Flag it explicitly. Tell me how to frame it constructively (extending their work,
never a takedown), and whether the field around that specific tool is already crowded —
crowdedness is a stronger reason to drop it than the relationship risk alone.

STEP 6 — Score every surviving candidate on these axes SEPARATELY. Do not let one
axis quietly inflate another:
- Novelty (1-10)
- Feasibility given my compute/time (1-10, 10 = easiest)
- Match to the target's ENDURING identity (1-10)
- Overall portfolio value (1-10 — can be high even with moderate novelty, if it shows
  real research maturity or safety/deployment thinking)

STEP 7 — Recommend one, with honest reasoning. If none of the candidates are genuinely
strong, say so and go back to Step 2 instead of forcing a recommendation.
```

## Key Differences From Failed Sessions

| Aspect | Failed session (PP2, PP4) | Successful session (PP5, PP6) |
|--------|--------------------------|-------------------------------|
| Method choice | Trendy (diffusion, VLM hallucination) | Boring, well-documented (Grad-CAM, MC-Dropout, conformal) |
| Novelty source | The method itself | The specific under-studied context/population |
| Scoop risk | High — many groups working on same thing | Low — 3+ year old methods, 0-2 papers on the context |
| Compute needs | Required new subfield learning (50+h) | Built on existing skills and artifacts |

## When to Use This

- User says "generate project ideas" or "bring new stuff nobody has done"
- User asks for PPA/PPB/PP-style project candidates
- User has a target advisor but wants their OWN identity, not to be a "mini duck following its mom"
- You need to verify if a project idea is novel or already done

## Pitfalls

1. **Do NOT skip Step 3.** The most common failure mode is claiming novelty without searching. If you skip the search, the project will likely be dead on arrival.
2. **Do NOT let Step 6's axes conflate.** A replication/audit has 5/10 novelty maximum, regardless of how valuable it seems. Score honestly.
3. **Do NOT force a recommendation.** If no candidates survive the filters, say so. Forcing a weak recommendation wastes the user's time.
4. **Trendy methods age fast.** If the method is <1 year old, assume it'll be crowded within 6 months. If it's 3+ years old and still underexplored in the target context, that's the sweet spot.
