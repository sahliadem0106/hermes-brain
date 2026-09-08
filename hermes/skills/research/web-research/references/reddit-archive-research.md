# Reddit Archive-API Research — Endpoint Catalog & Worked Recipe

Verified 2026-08-20 during the KAUST VSRP recon (700+ r/KAUST posts, ~55 threads deep-fetched).

## Why not the normal paths

| Path | Result (anonymous) |
|------|-------------------|
| `www.reddit.com/<path>.json` | HTML block page (189KB of reddit shell, zero JSON) |
| `old.reddit.com/r/X/comments/<id>/` | Redirects to `login/?reason=lor2` |
| `www.reddit.com` in the browser tool | `js_challenge` interstitial, snapshot shows only "File a ticket" |
| `r.jina.ai/https://www.reddit.com/...` | Cloudflare "Just a moment..." challenge |
| PullPush API | First ~6 calls OK, then **429 for the rest of the session** — 90s backoffs do NOT recover it |
| **Arctic Shift** | **Works reliably. Use this.** |

## Arctic Shift — endpoints

Base: `https://arctic-shift.photon-reddit.com/api/`

- Posts by ID (batch): `GET /posts/ids?ids=<id1>,<id2>,...` — up to ~30 ids; missing ids are silently absent from `data`
- Search posts: `GET /posts/search?subreddit=KAUST&title=VSRP&limit=100&sort=desc`
  - `title=` is case-insensitive substring; `subreddit=` narrows
  - Paginate backwards: `&before=<unix_ts>` = return posts OLDER than ts → set `before` to the last item's `created_utc` each page; stop when a page yields 0 new ids
  - NOTE: bare `title=VSRP` without subreddit/sort can 400 — keep `subreddit=` when possible
- Comments of a thread: `GET /comments/search?link_id=<post_id>&limit=100`
  - `link_id=` is the reliable param. `body=` / `q=` params returned **422 Unprocessable** in testing — avoid
  - Sorted by date; each item has `author`, `score`, `body`, `created_utc`, `permalink`
- Subreddits: `GET /subreddits/search?name=KAUST` — returned empty for the VSRP-specific names tested (r/KAUST_VSRP, r/kaustvsrp, r/KAUST_VS all have 0 posts) → confirms no dedicated subreddit exists

Fields: `created_utc` is unix time → `datetime.fromtimestamp(ts, datetime.UTC).strftime('%Y-%m-%d')`. Posts carry `title`, `selftext`, `author`, `score`, `permalink`.

## Workflow (proven)

1. **Check dedicated subreddits** (`subreddits/search`) — users often assume `r/<Topic>_<Thing>` exists; verify before telling them.
2. **Full-history sweep** of the main subreddit via `before=` pagination, saving each page. Count and report totals.
3. **Batch posts by ID** (`posts/ids`) for the interesting threads.
4. **Deep-fetch comments** for every relevant thread, one request per thread + 1–3s sleeps. Comments are where the intel lives (GPA numbers, acceptance timelines, PI email tactics).
5. **Save raw archives** to files (sweep1.txt / sweep2.txt...) and write a dated report `.md` that cites which archive each claim came from. Mark "verified" vs "anecdotal (N threads)" per claim.
6. **Run long fetches in the background** (`terminal(background=true, notify_on_complete=true)`) while doing other recon (official pages via curl, server directories, GitHub API) in parallel.

## Windows path pitfall (this host)

bash `/tmp` = `C:\Users\<user>\AppData\Local\Temp`, but `write_file` resolves `/tmp/x.py` as drive-relative `\tmp\x.py` — a DIFFERENT directory. Fix before writing scripts: `cd /tmp && pwd -W` (or `cygpath -w /tmp`), then `write_file` to that Windows path so the terminal and file tools agree. (Symptoms: script "not found" or data files missing when the script runs.)

## Worked example — KAUST VSRP (2026-08-20)

- ~700 posts across 8 paginated pages of r/KAUST history (2026-08 → 2025+)
- ~55 VSRP threads deep-fetched with complete comments (acceptance stories, desk-rejection cases, interview reports, waitlists, GPA questions)
- Findings that changed the user's decision picture:
  - Official floor 3.5/4.0 (KAUST internships page) but insider-reported **3.7 "hardline"**, "usually 3.8+", professors say "3.85–4.0" in high-demand majors
  - Documented exceptions: 80/100 GPA + 0 pubs admitted via PI calling admissions; 3.65 and 3.52 accepted on research experience; 2nd-year undergrad accepted
  - Process: `Admissions screen → PI verdict → Admissions final` — the screen happens FIRST, PI cannot override a definitive no
  - Alternative: non-VSRP visiting-student arrangement (PI-direct, no portal screen)
  - Tactics: email PI 4–6 months ahead, no "VSRP" in subject, follow up 10–15 days, Duolingo token free if no English score, 1 LOR, "wrong submission" cancel-and-resubmit trick
- Deliverables: `KAUST_VSRP_RECON.md` (v2) + raw archives (sweep1-3.txt, as_full.txt, gpa_threads.txt) kept in `%TEMP%\vsrp_recon\`
