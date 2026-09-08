---
name: reddit-archive-recon
description: Reddit blocked or need full thread/comment extraction.
---

# Reddit Archive Recon

Extract Reddit posts + full comment trees reliably when www.reddit.com is blocked, or when you need many threads' comments at scale (community intel, acceptance stories, sentiment mining, "go read the X subreddit" tasks).

## When direct Reddit access fails (all observed failure modes)
- `curl https://www.reddit.com/...json` → returns an HTML shell (block page), not JSON
- `old.reddit.com` → redirects to login (`?reason=lor2&dest=...`)
- `www.reddit.com` in a real browser → `js_challenge` interstitial; snapshot shows only "File a ticket"
- r.jina.ai reader → Cloudflare "Just a moment..." challenge
- Don't fight these. Go straight to the archive APIs below.

Content caveat: some subreddits aggressively mod-purge certain topics — e.g. r/NoFap and r/pornfree remove most tool/software-recommendation threads (selftext comes back `[removed]`, often 0 comments). For tool/resource research on sensitive self-help topics, lean on web_search + curated GitHub lists (e.g. `awesome-*` lists like wesinator/awesome-Adult-Content-Filtering) rather than archive comments. The archive is still great for *sentiment* sweeps (r/Tunisia nofap threads = 50-64 real comments) and for verifying a sub exists.

## Primary API: Arctic Shift (`arctic-shift.photon-reddit.com`)
- `GET /api/posts/ids?ids=id1,id2,...` — batch post metadata (title, selftext, author, score, created_utc, permalink)
- `GET /api/comments/search?link_id=<postid>&limit=100` — full comments for one post
- `GET /api/posts/search?subreddit=X&title=Y&limit=100&sort=desc` — search; paginate BACKWARD with `&before=<created_utc of oldest item>` (the `after` param does NOT work like expected)
- **Subreddit existence check**: `posts/search?subreddit=X&limit=10` — empty `data` = subreddit doesn't exist or has 0 posts (use this before assuming a named sub exists)
- Quirks: `body=` param on comments/search → HTTP 422 (use `link_id`); `title=` with `before=` → HTTP 400 on some combos (drop `sort`); always send a `User-Agent`; keep 1–3s sleeps; retry with ~5s backoff.
- **Pagination 422 trap (observed 2026)**: `posts/search?title=X` often succeeds on page 1 but the SECOND page (`&before=`) returns persistent 422, and some sub+keyword combos 422 on the very first request (intermittent — a retry sometimes succeeds). Do NOT retry 4× with long backoff (wastes ~50s per dead query). Fail fast (1 retry, 2s), record which queries failed, and refill them later in a separate pass with 3.5s sleeps — the API rate-limits (~429) with aggressive pacing, so interleave slow sleeps once you're mid-sweep. Write results incrementally (append per query) so partial data survives kills.
- Arabic keywords (UTF-8) work fine in `title=` (e.g. تحفيظ, حفظ, قرآن, ختم) — URL-encode them.

## Fallback: PullPush (`api.pullpush.io`)
- Same shapes: `/reddit/search/submission/?ids=...`, `/reddit/search/comment/?link_id=...&size=100`
- **Hard rate limit**: ~4–6 requests per IP, then persistent 429 even with long waits. Use only for a handful of threads with escalating backoff (6/12/25/45/90s) — expect mid-run failure. Arctic Shift is the workhorse.

## Workflow
1. **Sweep**: paginate `posts/search?subreddit=X` with `before=` (100/page) to list the sub's history; grep titles for the topic.
2. **Deep fetch**: batch relevant IDs via `posts/ids`, then per-ID `comments/search?link_id=` with sleeps. Write the fetcher to a file (see `scripts/fetch_reddit_threads.py`), run in background with notify, read the output file.
3. **Official sources first**: for institutional facts (requirements, deadlines, fees), curl the official site and strip tags (python `re` + `html.unescape`) — never trust third-party summaries. Cross-check every claim against ≥2 independent threads before reporting it as fact.
4. **Deliver**: raw archives on disk = the receipts (cite them) + a distilled report that per-claim cites sources. **Distinguish EXECUTED facts from PLANNED/rumored ones in the write-up** — see user pitfalls.

## Windows (git-bash) pitfalls
- bash `/tmp` = `C:\Users\<user>\AppData\Local\Temp`, but `write_file` resolves `/tmp/x` to `\tmp\x` (drive root) — a DIFFERENT folder. Check with `pwd -W` or `cygpath -w /tmp` first; write scripts via the absolute Windows temp path, then run from `cd /tmp/...`.
- Parse HTML/JSON with inline `python -c` or a script written to the correct path. Conda init warnings in git-bash are harmless noise.
- Community-discovery directories: disboard search URLs 404, top.gg returns bot listings not servers. If a community (e.g. a Discord server) doesn't surface anywhere, that's a legitimate finding ("no public Discord exists") — report it, don't force it.

## User-specific pitfalls (this user)
- **Record honesty is sacred**: never report PLANNED projects as done. His record: EXECUTED = PP1 only (TB cross-population). PP3/PP5/PP6 planned; PP2/PP4 killed. Inflating the count ("6 projects") has been corrected twice — hard rule: report EXECUTED vs PLANNED explicitly.
- **Deliverable shape**: he routes polished writing (emails, essays, letters) to Claude. Hermes delivers fact-briefs, verified data, checklists, source citations — not finished prose. When he says an email is needed, produce a fact-brief for Claude instead.
- **Plan variability**: never claim his plan is locked/figured out; targets and choices are changeable — present options and evidence, not settled truths.
- **Networking**: no PI name-dropping/tagging in outreach; low-pressure organic emails ("not applying to your group, just seeking advice") outperform application-style cold emails.
- **Faith framing when he's down**: remind him God can do whatever He wills (tawakkul, istikhara for choices); don't motivational-speak.

See `references/apis-and-examples.md` for endpoint details and a worked example.
