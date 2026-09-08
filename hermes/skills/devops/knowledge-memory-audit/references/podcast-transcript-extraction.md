# Podcast/video-transcript → structured technique .md extraction

How to turn bug-bounty podcast/YouTube transcripts into structured, ingestion-ready
technique Markdown files for the knowledge tree. Validated live Aug 29, 2026 (17
transcripts → ~67 structured .md files staged in `~/bugagent/knowledge/recon-podcast/`).

## Why it's worth doing (and the value split)

- Writeups give WHAT worked (endpoint + payload + impact). Podcasts give the HOW/WHY —
  the speaker's reasoning chain ("saw X signal → checked Y → which led to Z"). That
  reasoning is the "sauce" a technique sheet needs, and it's not in writeups.
- The win is NOT "ingest the transcript" — it's EXTRACTING the specific technique +
  reasoning into structured form, the same discipline as the report extraction.

## The division of labor (validated)

- **GLM-5.3-Flash (hunter profile) engineers the EXTRACTION PROMPT** — one strict,
  reusable prompt that defines the output contract. Run via:
  `hermes -p hunter --safe-mode --ignore-rules -z "$(cat /tmp/glm_prompt_engineer_req.txt)"`
  (all flags BEFORE `-z`). GLM's brief: produce a prompt that forces structured .md
  files with exact section headings, extraction-over-summarization, verbatim commands
  + reasoning chains, `[explicit]/[inferred]/[generalizing]` confidence tags, and
  hard rules against fabrication / AI-slop / generic advice.
- **A separate LLM (Claude/ChatGPT) runs the prompt + transcript** and produces the
  .md files. The operator does this (paste prompt then transcript). Same prompt works
  on ChatGPT but may pad more — Claude respects the verbatim-extraction rules better.
- **The Hermes agent consumes the output**: stages the files, indexes them, folds them
  into the methodology/sheets layer.

The engineered prompt lives at `~/bugagent/prompts/podcast-to-md-extraction-prompt.md`
(in the bugagent repo so it's operator-mirrored). Output contract it enforces:
one .md per distinct technique, named `<phase>-<slug>.md`; a `00-meta-<episode>.md`
first file (source/speakers/date/total-techniques/file list); strict headings
(Source / Class tags / The Technique / Real examples / Indicators / Pitfalls /
Methodology fit / Confidence); rules: no fabrication, no AI slop, no generic advice,
verbatim where possible, [explicit]/[inferred] tags, self-contained files.

## Staging + indexing (the agent's part)

1. Operator returns the .md files (via a zip in the git repo, or pasted).
2. Extract to review, then stage into the knowledge tree under a dedicated subdir:
   `mkdir -p ~/bugagent/knowledge/recon-podcast/` (one dir per corpus source).
3. Run the incremental indexer so they become searchable:
   `~/memenv/bin/python ~/bugagent/scripts/index_corpus.py --incremental`
   (CPU re-embed is slow — minutes-to-hours; run it as a background job and confirm
   the chunk count GREW, don't wait on a foreground terminal timeout).
4. The recon-* files are the more valuable of the two forms for the agent (already
   playbook-shaped); the flat technique files fold into the L3 sheets layer.

## Pitfalls / quality notes (from the Aug 29 run)

- Some "transcripts" aren't transcripts — one file was just the extraction prompt
  itself. Check the INDEX file (`00-INDEX.md`) for what was skipped and why; don't
  re-run dead inputs.
- Tag drift: when a lot of content is process/mindset, `workflow/mindset` dominates
  and the class-tag list has no clean bucket for general content-discovery/fuzzing.
  Acceptable; normalize later with an alias map (same drift as the report extraction).
- Transcription garbles tool names ("Census and Showdown" = Censys/Shodan, "subj" =
  subjs). The prompt's `[inferred]` rule handles this honestly — do NOT silently
  "correct" a garbled name; flag it.
- Ingested podcast files are methodology/recon knowledge, distinct from the disclosed-
  report extraction (endpoints/payloads). Keep them in separate knowledge subdirs so
  the source grouping stays clean.
