---
name: hermes-model-governance
description: "Use when pinning Hermes models/providers within a budget."
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [hermes, models, providers, budget, nous, profiles, config]
    related_skills: [hermes-agent, hunter-mission]
---

## When to Use

Any task that configures which model/provider Hermes uses: setting a model per profile, switching providers, enforcing an allowlist/budget rule, or verifying a model actually works before relying on it. Covers the pattern proven on the bug-hunter Kali box (Aug 2026).

## Core Workflow

1. **Probe before trust.** Config saying `provider: nous` is not proof a model works. Send a 1-token chat completion against the provider API: HTTP 200 = usable; 404 "balance too low to use paid models" = account has no credits; 429 = rate-limited; 404 "model not found" = the id is an alias, not API-callable. Costs ~nothing. Full recipe: `references/nous-portal.md`.
2. **Pin per profile.** `hermes profile use <name>` then `hermes config set model.provider <p>` + `hermes config set model.default <model-id>` — writes to `~/.hermes/profiles/<name>/config.yaml`. Always restore `hermes profile use default` after. Verify with `hermes profile list`.
3. **Provider-switch hygiene.** A stale `model.base_url` survives a provider change and will send the new provider's model IDs to the old endpoint. After any `model.provider` change: `hermes config unset model.base_url`.
4. **Close the side-doors.** A budget allowlist is only as strong as its leaks: `hermes fallback list` must be empty (a fallback chain silently swaps models on failure); pin subagents via `hermes config set delegation.provider` + `delegation.model`; check `hermes moa list` — presets reference non-allowlist models (the sole preset cannot be deleted: "Cannot delete the only MoA preset"; keep MoA off).
5. **Verify replies, not error-absence.** `hermes chat -q` prints only a summary — the reply body is hidden. Capture raw output to a file and strip ANSI (`sed 's/\x1b\[[0-9;]*m//g'`) before grepping for the expected reply. Error request-dumps (`~/.hermes/sessions/request_dump_*.json`, or `profiles/<p>/sessions/`) are written ONLY on failures — absence of a dump is NOT proof of success; presence of a dump means read `.error.message` for the exact error.

## Pitfalls (all observed live)

- `~vendor/model-latest` entries in the model picker are picker aliases — the API returns "model not found" for them. Use the concrete id (`vendor/model`), not the alias.
- A completed `hermes chat -q` run that "Duration: 12s, Messages: 1" can still be a 404 — the summary format doesn't surface errors.
- Profile creation (`hermes profile create X`) copies the current skills tree — profiles created before a skills install miss the new skills.
- Interactive TUIs (`hermes model`) cannot be driven blind from a non-TTY session — prefer direct `config set` with model ids from the provider's live catalog API.

## References

- `references/nous-portal.md` — Nous Portal specifics: auth, API endpoints, catalog fetch, credit-probe curl, error signatures, the two-model pin table.
