# Reddit archive APIs — endpoint reference & worked example

Verified 2026-08-20 while sweeping r/KAUST (~700 posts, ~60 threads deep-fetched).

## Endpoint quick reference

| Need | Arctic Shift (primary) | PullPush (fallback) |
|---|---|---|
| Post metadata by ID | `/api/posts/ids?ids=id1,id2` | `/reddit/search/submission/?ids=id1,id2` |
| Comments for a post | `/api/comments/search?link_id=X&limit=100` | `/reddit/search/comment/?link_id=X&size=100` |
| Search posts | `/api/posts/search?subreddit=S&title=Q&limit=100&sort=desc` | `/reddit/search/submission/?subreddit=S&q=Q` |
| Subreddit exists? | `/api/posts/search?subreddit=S&limit=10` (empty data = no) | n/a |
| Paginate backwards | `&before=<created_utc of oldest on page>` (repeat) | `&before=` similar |

## Observed quirks (2026-08)

- Arctic Shift `comments/search?body=VSRP&subreddit=KAUST` → **422 Unprocessable**. `link_id` works; `body`/free-text comment search does not (use posts search + per-post comment fetch instead).
- Arctic Shift `posts/search?title=VSRP&sort=desc` + `before=` → **400 Bad Request** on some combos. Drop `sort` or the `before` when it 400s; pagination via `before` alone worked fine on `subreddit=KAUST&limit=100`.
- PullPush: 429 after ~4–6 requests per IP. Even 90s waits don't reset it mid-run. One thread's worth of calls can succeed before the throttle hits — use it first ONLY when you need 1–3 threads, otherwise Arctic Shift.
- Both need a browser-ish `User-Agent` header. `created_utc` is unix; convert with `datetime.fromtimestamp(ts, datetime.UTC)` (utcfromtimestamp is deprecated).
- Comments JSON: each item has `author`, `body`, `score`, `created_utc`, `permalink`. Deleted = author `[deleted]`, body `[removed]`.

## Direct-access failure modes (don't fight these)

- `curl www.reddit.com/...json` → HTML shell (~190KB, identical size for every URL = block page)
- `old.reddit.com` → 302 to `login/?reason=lor2`
- Browser on `www.reddit.com` → `js_challenge` interstitial, snapshot = just "File a ticket"
- `r.jina.ai/https://www.reddit.com/...` → Cloudflare "Just a moment..."
- Redlib/libreddit public instances → mostly dead/blocked (5KB pages)

## Worked example: full-subreddit sweep (KAUST VSRP recon)

1. Sweep: `GET /api/posts/search?subreddit=KAUST&limit=100&sort=desc` then repeat with `&before=<oldest ts>` → 700+ posts across 8 pages.
2. Grep titles for topic (`VSRP|intern|visiting|gpa`).
3. Deep fetch ~55 threads: `posts/ids?ids=...` (batch of 30) + per-ID `comments/search?link_id=` with 1–3s sleeps → full comment trees incl. insider accounts.
4. Official facts: `curl` the institution's own pages (admissions.kaust.edu.sa), strip tags via python `re.sub(r'<[^>]+>', ' ', ...)` + `html.unescape` → verbatim requirements (GPA floor, Duolingo token line, $1000 stipend).
5. Cross-check each claim across ≥2 threads (e.g., "Duolingo token for VSRP": official page + 2 accepted-student accounts).
6. Deliverables: raw `sweep*.txt` archives as receipts + distilled `*_RECON.md` report citing per-claim sources.

## Windows git-bash path trap (cost a round-trip)

- bash `/tmp` resolves to `C:\Users\<user>\AppData\Local\Temp` (`pwd -W` shows it).
- `write_file` with path `/tmp/x.py` resolves to `\tmp\x.py` (drive root) — NOT the same folder.
- Fix: run `pwd -W` once, then write all scripts with the absolute Windows temp path (`C:\Users\<user>\AppData\Local\Temp\...`) and run them from `cd /tmp/...`.
