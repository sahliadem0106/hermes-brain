# Hermes Brain

Portable copy of the Hermes agent setup: identity (SOUL), skills, memory, cron jobs, per-profile configuration. Designed to restore the same agent on a fresh machine.

**Keep this repo PRIVATE.** It contains personal identity and mission data.

## Contents

```
hermes/
  config.yaml        main agent config (settings only — no secrets)
  SOUL.md            agent persona
  skills/            all installed skills (14 MB)
  memories/          MEMORY.md + USER.md (agent memory)
  cron/jobs.json     scheduled jobs
  profiles/          per-profile config.yaml, SOUL.md, memories, plans
                     (hunter, hunter2, hunter-bulk)
scripts/restore.sh   one-shot restore to a new machine
.env.example         key names you must fill in (values never committed)
```

## What is deliberately NOT in this repo

| Excluded | Why |
|---|---|
| `.env` | API keys (DeepSeek, Browserbase). Recreate from `.env.example`. |
| `auth.json` | Nous Portal OAuth tokens. Re-authenticate with `hermes auth`. |
- `state.db`, `sessions/`, `logs/`, `pastes/` | Full conversation history — contains pasted cookies, OTPs, tokens. Never commit these. |
- `~/.hermes/.env`, `~/.hermes/auth.json`, profile `.env`/`auth.json` | API keys + OAuth tokens. Recreate from `.env.example` + `hermes auth`. |
| `~/bugagent/db/`, `knowledge/`, `evidence/`, `logs/`, `reports/` | 5+ GB of SQLite memory DBs and cloned reference repos. `scripts/fetch_knowledge.sh` re-downloads knowledge; DBs move via rsync/USB. |
| `~/bugagent` (raw) | Separate repo: `github.com/sahliadem0106/bugagent`. Clone it separately. |
| `~/.ssh` | Private keys. Set up GitHub SSH on each machine yourself. |
| Live recon tokens | `targets/**/evidence/current-access-token.txt`, `**/*session*.json`, `**/recon/cli_token_*.txt` — gitignored in bugagent, never pushed. |

## Restore on a new PC

```bash
# 1. Install Hermes (official installer)
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash

# 2. Clone this repo (private)
git clone git@github.com:sahliadem0106/hermes-brain.git ~/hermes-brain

# 3. Restore config, skills, memory, profiles
bash ~/hermes-brain/scripts/restore.sh

# 4. Create ~/.hermes/.env from the template and fill in real keys
cp ~/hermes-brain/.env.example ~/.hermes/.env
$EDITOR ~/.hermes/.env

# 5. Re-authenticate with the LLM provider (Nous Portal OAuth)
hermes auth

# 6. Pull the hunting machine
git clone git@github.com:sahliadem0106/bugagent.git ~/bugagent
```

Verify with `hermes doctor`.

## Notes

- Memory/skills are additive: restore.sh merges into an existing `~/.hermes` without deleting anything.
- The bugagent repo is synced separately (it already has its own git remote).
- Live session tokens from bug bounty recon (`missions/*/*token*.json`, `*session*.json`, recon `cli_*` files) are gitignored there and never pushed.
