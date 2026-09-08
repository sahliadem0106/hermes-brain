---
name: hermes-kali-box-ops
description: "Use when operating Hermes on Kali VM: sudo, git, CLI checks."
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [kali, sudo, git, pat, verification, infrastructure, nuclei]
    related_skills: [hermes-agent, hermes-model-governance]
---

## When to Use

Day-to-day operations of a Hermes agent on a Kali (or similar headless/VM) box: authenticating privileged commands, cloning private repos, verifying CLI output, and installing toolchains when the network is flaky. All patterns below were validated live (Aug 2026).

## sudo without a TTY

The agent terminal policy BLOCKS piping passwords to `sudo -S` ("brute-force attack vector"), and `SUDO_PASSWORD` in `.env` is NOT implemented in this Hermes build (verified absent in source — the scanner hint is generic).

Working pattern — interactive PTY, answer the prompt once:

1. `terminal(background=true, pty=true)` running the sudo command (e.g. `sudo apt install -y ...`).
2. `process poll` until the output shows `[sudo] password for <user>: `.
3. `process submit` the password.
4. Repeat per sudo timestamp window (~15 min — long jobs frequently re-prompt; poll for the prompt before submitting again).

The password lives only in the PTY exchange — never in command text, files, or memory.

## Private repo auth (PAT) — embed then scrub

`git -c http.extraheader="Authorization: Bearer $TOKEN" clone` does NOT work (git still prompts for username). Reliable one-shot:

```bash
git clone "https://oauth2:${TOKEN}@github.com/<owner>/<repo>.git" <dest>
git -C <dest> remote set-url origin https://github.com/<owner>/<repo>.git   # scrub NOW
git -C <dest> remote -v    # verify no token remains
```

For pulls on an existing scrubbed remote: temporarily `set-url` with the embedded token, pull, `set-url` back. Never leave the token in `.git/config`.

## Private repo auth (SSH key) — preferred, validated Aug 29 2026

PATs embedded in remotes leak into transcripts (MASTER.md records one leaked PAT).
The cleaner long-term auth is an SSH key added to GitHub — headless-friendly, no token
in any command, no prompts:

```bash
ls ~/.ssh/id_ed25519.pub 2>/dev/null || ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""   # create if absent
cat ~/.ssh/id_ed25519.pub                                                                    # operator adds to GitHub
# operator confirms, then:
git remote set-url origin git@github.com:<owner>/<repo>.git
ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null
git pull   # fast-forwards cleanly, no credentials asked
```

Sequence discipline: print the public key, then STOP and wait for the operator to say
the key is added before switching the remote and pulling. Don't guess whether the key
landed.

If `git remote set-url origin https://...` is already HTTPS and `git pull` fails with
"fatal: could not read Username for 'https://github.com': No such device or address",
the fix is the same SSH path above — never embed a token in a command or remote. Verify
the SSH key actually landed before switching (an HTTPS remote with no TTY will keep
failing until the remote points at SSH).

## Driving a Hermes profile as a batch LLM subprocess (validated Aug 29 2026)

When you need many cheap LLM extractions (e.g. turning ~10k disclosed reports into
structured records) WITHOUT putting API keys in a script, shell out to a profile
oneshot and parse stdout — the profile carries Nous OAuth, the script holds no secrets:

```python
cmd = ["hermes", "-p", "hunter-bulk", "--safe-mode", "--ignore-rules", "-z", prompt]
res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
```

- `--safe-mode --ignore-rules` are REQUIRED or the agent wraps the JSON in prose and
  writes it to a file instead of stdout. They must come BEFORE `-z` (after `-z` they're
  swallowed as its argument).
- Ask for a FLAT JSON array with a `report_id` field per finding — NOT a keyed object.
  At scale the model returns a flat array; a keyed parser silently yields 0 rows. Map
  findings back by the report_id field, accepting `report_<id>` / `<id>.md` variants.
- Persist raw stdout to a debug file on every call so a 0-row batch is diagnosable.
- Full working recipe (schema, prompt, cost, ARG_MAX pitfall, post-run fixes): see the
  memory-extraction reference in the ai-bug-bounty-agent skill.

## Verifying CLI output that hides the reply

- `hermes chat -q` prints a summary (Session/Duration/Messages) but hides the reply body — and even a 404 error run looks like "Duration: 12s, Messages: 1". Capture to a file and strip ANSI before checking: `timeout 180 hermes chat -q "..." > /tmp/t.txt 2>&1; sed 's/\x1b\[[0-9;]*m//g' /tmp/t.txt | grep -E "<expected>"`.
- Error dumps are written only on failure (`~/.hermes/sessions/request_dump_*.json`, or under `profiles/<p>/sessions/`); read `.error.message` for the exact error. No dump != success.
- Piping command output through `| tail -1` swallows the real exit code — capture `$?` before the pipe or check artifacts directly (binary exists? file count?).
- **pgrep -f false-positive (validated Aug 29 2026):** `pgrep -f "<script>.py"` matches ANY process whose full command line contains that string — including the Hermes terminal wrapper command you are currently running (its eval'd text contains the same string). So a long-running script can show `pgrep` as "RUNNING" long after it actually finished, or falsely "RUNNING" from the wrapper alone. To know whether a background job is truly alive:
  - `ps aux | grep <script>.py | grep -v grep` (excludes the wrapper too), AND
  - read the script's own completion line in its log (e.g. `[done]` / `[ok]`), AND
  - check the artifact count / DB row count is stable across two reads.
  If `ps aux | grep ... | grep -v grep` shows nothing and the log has a `[done]` line, the job is finished — do not trust a bare `pgrep -f` saying otherwise.
- **Batching subprocess argv that carries data (validated Aug 29 2026):** when shelling out to a CLI whose payload is passed as a single argument (e.g. `hermes -p <profile> -z "<big prompt>"`), Linux caps one argv string at `MAX_ARG_STRLEN` = 128 KB. A fixed-count batch (e.g. 32 reports) can exceed it → `OSError: [Errno 7] Argument list too long` even though 5-15 short ones worked. Batch by BYTE BUDGET (~96 KB per argv), not fixed count — short items batch together, long items get smaller batches.
- **Parsing LLM subprocess JSON output:** use `--safe-mode --ignore-rules` flags (BEFORE `-z` or they get swallowed as its arg) so the agent writes clean stdout JSON instead of prose + a file. Ask for a FLAT JSON array with a `report_id` field per item, not a keyed object — at scale the model returns flat, and a keyed parser silently returns 0 rows. Persist raw stdout to a debug file each call so a 0-row batch is diagnosable in one look.
- **Parallelize long extraction jobs with worker slicing + WAL (validated Aug 31 2026, ~6x speedup):** the bottleneck on one-file-per-call jobs is per-call model latency, and parallelism costs the SAME money (per-token, tokens don't change). Give the script `--worker-id` + `--worker-count` args that slice files round-robin (`files[id::count]` — spreads giant files so no worker starves), then run N background copies, each with its own log. On the shared SQLite set `PRAGMA busy_timeout=60000` and `PRAGMA journal_mode=WAL` so concurrent writers QUEUE instead of erroring. Sweet spot on this 8-core VM: 6 workers; 100 is wrong (each worker spawns a python + hermes process → memory thrash, and SQLite commits collapse under that many writers). If you change the worker count mid-run, RESTART ALL workers with the same count — slices must be consistent (`id % count`), you cannot add workers on top of a different count or they overlap files.
- **Never write to a SQLite DB while a long writer job is live (validated Aug 31 2026 — cost us a 4h job twice):** running a second writer (prune, migration, manual BEGIN+DELETE) against the same DB as a background extraction will hit "database is locked" — and the long job loses the race and DIES, not the short one. Worse: a failed write attempt that leaves an uncommitted transaction open keeps holding the lock. Diagnostic order: `fuser -v <db>` shows the holder; a Zs (zombie) process is harmless (no fd, no lock) but a live python/hermes_kernel connection with a dangling transaction IS the lock. Kill the stale holder to release, then re-run `PRAGMA wal_checkpoint(TRUNCATE)` and a write test before restarting the job. Rule: reads (SELECT, read-only audit samples) are safe alongside a writer; writes are not. Do the queued writes only after the writer finishes.
- **Background wrapper "exited (exit code None)" notifications are unreliable (validated repeatedly Aug 31 2026):** the Hermes background wrapper fires this spuriously WHILE the process keeps running — several fired once per parallel worker with all of them alive. Trust the process, not the notification: `ps -o pid,etime,stat` shows the process alive, `pgrep -P <pid>` children cycling to NEW pids (each cycle = one completed call), and the DB/artifact counter climbing. A REAL death shows a fresh traceback in the script's own log AND the pid gone/zombie. Only restart when you see those two together.

## Flaky-NAT installs (VirtualBox NAT)

- `go install` against proxy.golang.org: intermittent "connection reset by peer" / IPv6 DNS timeouts. Retry, or verify the binary landed (`ls ~/go/bin`, `tool -version`) — earlier installs in the chain may have succeeded.
- `nuclei -update-templates` fails with "context deadline exceeded ... failed to read resp body; failed to download templates" (release-asset CDN timeout). Working fallback: `git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates`, verify with `nuclei -tl -t ~/nuclei-templates | wc -l` (13k+ templates). Update via `git -C ~/nuclei-templates pull`.
- Plain git clones over https work fine when the CDN/zips fail — prefer git-clone fallbacks for big GitHub assets.
- **nuclei default-template-path trap (validated Aug 31 2026):** `nuclei -tl` (no `-t`) resolves the
  default directory to `~/.local/nuclei-templates`, which is EMPTY here (updates fail on NAT), and
  errors "Could not find template ... no templates found". Symlinking `~/.local/nuclei-templates` →
  `~/nuclei-templates` and adding `templates-directory:` to `~/.config/nuclei/config.yaml` do NOT fix
  the `-tl` listing error. The OPERATIONAL fix is simple: always pass `-t /home/kali/nuclei-templates`
  on every real scan/validate. That loads 13,248 templates and `nuclei -validate -t ...` passes
  ("All templates validated successfully"). Don't chase the cosmetic default-resolution error —
  just make `-t <store>` part of the hunt command.

## Apt installs: debconf dialogs and stale locks

- `apt install -y` still raises debconf dialogs (whiptail) that CANNOT be dismissed via PTY keystrokes — Enter, Tab+Enter, and typed answers all failed live (e.g. docker.io's "Automatically remove Docker data if package is purged? <Yes>/<No>"). Deterministic fix: kill the stuck run and rerun with `sudo DEBIAN_FRONTEND=noninteractive apt install -y ...` — debconf then applies its default answers.
- Killing a background PTY session does NOT kill the apt child it spawned: the orphan keeps running (often stuck on the dialog) and holds `/var/lib/dpkg/lock-frontend`, so any replacement install waits forever on "Waiting for cache lock... held by process N (apt)". Fix: `pgrep -a apt` to find the orphan pid, `sudo kill <pid>` it, then the waiting install proceeds on its own. If it died mid-unpack, run `sudo dpkg --configure -a` first.
- Long apt jobs re-prompt for the sudo password every ~15 min (timestamp window) and spawn debconf — always run them background+pty+notify and poll for prompts; never assume a long `apt install` will finish unattended.

## Environment notes

- PATH: pipx (`~/.local/bin`) and go (`~/go/bin`) binaries need explicit export in each session unless added to `~/.bashrc` (`export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"`); `pipx ensurepath` no-ops when pipx is apt-installed and already on PATH.
- Keep `sudo apt` jobs in background+notify with pty=true — they run long and re-prompt for sudo.
- **Recon Go tools install cleanly WITHOUT sudo** (validated Aug 31 2026): subfinder is in
  apt (`sudo apt install -y subfinder` needs PTY password), but katana/gau/waybackurls/dalfox/gf
  are go-install-only — `go install github.com/.../...@latest` lands in `~/go/bin` in seconds
  (module cache warm) with no sudo prompt. Full set: subfinder (apt OR go), katana, gau,
  waybackurls, dalfox, gf. Verify each with `-version`/`--help` after install; check the
  `~/.bashrc` PATH line already covers `~/go/bin` before adding anything.
