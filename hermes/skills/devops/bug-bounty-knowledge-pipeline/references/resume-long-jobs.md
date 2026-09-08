# Resuming long pipeline jobs after interruption (power cut / VM shutdown / crash)

Both long jobs are backgrounded Hermes processes that die with the VM. The DB and logs
survive; only the processes die. Recover with the exact invocations below. Both are
idempotent / resumable by design — a clean re-run continues where the log left off.

## Which job uses which model (verified from script PROFILE + profile configs)
| Job | Script | PROFILE | Model | Effort |
|---|---|---|---|---|
| L3 sheets | `scripts/synthesize_sheets.py` | `hunter` | z-ai/glm-5.3-flash | MEDIUM (operator rule) |
| Writeup re-extraction | `scripts/re_extract_writeups.py` | `hunter-bulk` | deepseek/deepseek-v4-flash-0731 | low (volume) |

Verify, don't assume: `grep PROFILE scripts/<script>.py` then
`grep -A2 '^model:' ~/.hermes/profiles/<profile>/config.yaml`.

## Before restarting
1. Start gate: `cd ~/bugagent && git pull` (fast-forward expected). If it fails, STOP.
2. Find where each job stopped: `tail -n 20 logs/re_extract_writeups.log` and
   `tail -n 20 logs/synthesize_sheets.log`. The last `[run]`/`[run N/M]` line is the resume point.

## Restart commands (append to the existing log, do not truncate)
```bash
# L3 sheets — RESUME-FREE: idempotent via sheets_meta (skips already-built classes).
# Just re-run the same command; it continues from the next class.
cd ~/bugagent && ~/memenv/bin/python scripts/synthesize_sheets.py \
  --source ajaysenr --min-records 3 >> logs/synthesize_sheets.log 2>&1

# Writeup re-extraction — MUST pass --start-idx = last completed file index,
# else it re-processes everything from 0. Log line "[run] 860/2397" => --start-idx 860.
cd ~/bugagent && ~/memenv/bin/python scripts/re_extract_writeups.py \
  --start-idx <N> >> logs/re_extract_writeups.log 2>&1
```
- synthesize_sheets.py: `--start-idx` does NOT exist; it skips by checking
  `sheets_meta` for an existing `sheet_id` (slugified class name).
- re_extract_writeups.py: has NO done-skip (old records are deliberately re-processed,
  per-file DELETE + INSERT to fix provenance). The ONLY resume mechanism is `--start-idx`.

## The "exited (exit code None)" false-alarm verification procedure
Hermes fires background-process "exited (exit code None)" notifications spuriously — often
WHILE the job is healthy (observed repeatedly, two sessions in a row). Never restart on the
notification alone. Confirm with:
```bash
ps -o pid,etime,stat,cmd -p <PID>          # job alive?
ps -eo pid,ppid,etime | awk '$2==<PID>'    # active hermes child (mid-LLM-call)?
tail -n 5 logs/<job>.log                   # recent [run]/[saved] lines
ls knowledge/sheets/*.md | wc -l           # sheet count climbing (L3)
sqlite3 db/memory.db "SELECT count(*) FROM reports_meta WHERE source='writeup';"
```
A job is genuinely working when it has a live hermes child even if no progress line has
printed since restart — re_extract only prints every 20 files and commits then.

## Slow-file expectation (do not panic)
re_extract is single-file mode by design (provenance fix). One huge writeup (e.g. a
multi-CVE Synology disclosure with full PoCs) can take 2-3+ min and trip the script's own
`[timeout]` recovery. Wait several minutes before judging a job stuck.

## After a job completes
Run the phase audit (GLM) to confirm quality held (provenance fixed for re-extraction,
sheets well-formed for L3). Audit-after-phase is the operator's standing requirement.
