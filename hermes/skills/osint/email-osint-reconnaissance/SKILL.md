---
name: email-osint-reconnaissance
description: CLI tools for email OSINT when browser search is blocked.
version: 1.0
tags: [osint, email, reconnaissance, social-media]
---

# Email OSINT Reconnaissance

## When to Use
- User provides an email address and asks "who is this?" or "what is this linked to?"
- You need to find social media accounts, registrations, or identity info from an email

## ⚠️ Critical: Browser Search Limitation (2026+)

Google, Bing, and DuckDuckGo aggressively block automated browser queries (CAPTCHA, 403, empty result pages). **Do not start with browser-based search for OSINT.** The browser tools are unreliable for search engines. Always prefer CLI tools that hit APIs or databases directly.

If you must search the web, try terminal-based curl against text-focused search endpoints, or use dedicated OSINT websites manually via the browser (not general search).

## First Pass — Quick Checks

### 1. Holehe — Which sites is the email registered on?
```bash
holehe target@email.com
```
Checks 120+ services (Twitter, Instagram, Amazon, Spotify, Adobe, etc.) for email registration.
- **Install**: `pip install holehe`
- **Pitfall**: Can get rate-limited. Wait 30-60s between runs.
- **Output legend (read carefully)**:
  - `[+] Email used` — registered here (the high-value hits)
  - `[-] Email not used` — not found
  - `[x] Rate limit` — **could NOT check**. This is NOT a negative. A large batch of `[x]` means many sites were unverifiable; if a site matters, re-run after a pause or check it manually later. Don't conclude "not registered" from `[x]`.

### 2. Sherlock — Search the username across 400+ sites
```bash
sherlock username_part
```
- Use the part **before @** as the username
- **Pitfall**: If email has numbers (e.g. `bella.koukou34`), try with AND without numbers — the handle might differ from the email prefix
- Already installed at: `~/sherlock/sherlock`
- **Windows crash fix**: If sherlock dies instantly with `ModuleNotFoundError: No module named 'pandas._libs.pandas_parser'` or `pydantic_core`, it picked up the Hermes venv's broken packages via the leaked `PYTHONPATH`. Fix: `unset PYTHONPATH; sherlock <handle>` (do NOT re-source the venv in the same shell). Run in background with `--timeout 30` (takes several minutes; `tee` output to a file).
- A `name.name` dot-format handle most often points to a normal personal social presence (Instagram/Facebook/TikTok/Snapchat), not a technical/developer persona.

### 3. Gravatar — Profile picture leak
```bash
# Linux/Mac
curl -s "https://www.gravatar.com/avatar/$(echo -n 'email@example.com' | md5sum | cut -d' ' -f1)"

# Windows git-bash
curl -s "https://www.gravatar.com/avatar/$(printf 'email@example.com' | md5sum | cut -d' ' -f1)"
```
If a Gravatar exists, it reveals the profile pic and potentially linked accounts.

## Deep Recon

### 4. GHunt — Google account OSINT
```bash
pip install ghunt
ghunt login        # One-time auth (needs Google cookies)
ghunt email target@gmail.com
```
- Returns: profile name, profile photo, Google Maps reviews, YouTube channel, Calendar info
- **Pitfall**: Google blocks GHunt auth tokens quickly. May need fresh cookies.
- Only works for **@gmail.com** addresses

### 5. Epieos (Web-based)
Navigate manually to `https://epieos.com` and paste the email. Returns:
- Gravatar info, Google account profile, Google Maps reviews
- **Browser tool OK here** — Epieos is a dedicated OSINT site, not a general search engine

### 6. Have I Been Pwned
```bash
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/email@example.com"
```
Checks if the email appears in known data breaches.

## Full Workflow (Ordered)

```
1. holehe email          → discovers site registrations (2-5 min)
2. sherlock username     → discovers social accounts (5-10 min)
3. Gravatar check        → profile pic + hash lookup
4. Epieos (browser)      → Google account data
5. GHunt (if @gmail)     → deep Google data
6. HIBP                  → breach history
7. Manual follow-up      → dig into sites holehe/sherlock found
```

## Verify Sherlock Hits — HTTP 200 ≠ real account

Sherlock's `[+]` hits are a **candidate list, not confirmed accounts**. Many sites return HTTP 200 for ANY username. Always verify by checking the actual page content before reporting a hit as real.

- **Batch-verify via curl status code, then confirm by page `<title>`**:
```bash
# raw status first
curl -s -o /dev/null -w "%{http_code}" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "https://www.instagram.com/<handle>/"
# then confirm the account is real via page title/meta
curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "https://ko-fi.com/<handle>" | grep -oiE '<title>[^<]*</title>'
```
- A **real** account shows a meaningful title/meta containing the person's display name (e.g. `"Malek Magroun (@malek.magroun)"`, `"Buy Malek a Coffee"`). A false positive shows a generic site title, a JS "loading" shell, or nothing.
- **Known Sherlock false positives** (return 200 for any username — don't trust without a manual look): BugCrowd (redirects to a JS "hacker portal" loading page), Outgress, Velomania, BoardGameGeek, BabyRu, Blitz Tactics (though a real `<title>handle | Blitz Tactics</title>` indicates a genuine chess account), omg.lol.
- **Platform behaviors to expect**:
  - **Instagram** — curl hits a login wall; use the browser. A dead account titles the page *"Profile isn't available • Instagram"* = clean negative. Real = "Instagram" + @handle.
  - **X/Twitter** — redirects to `x.com/i/flow/login?...` = **inconclusive**, not a negative; don't count it either way.
  - **TikTok** — empty page via browser (bot wall); rely on sherlock + curl.
- The browser works on these profile pages (dedicated sites, not search engines).

## Real-Name / Identity Extraction (follow-up)

Holehe/Sherlock find *where* the person is; the highest-value next move is navigating **directly to a discovered profile** to surface their real identity. Many platforms expose the display name even when the handle is anonymized:
- **DailyMotion**: `https://www.dailymotion.com/user/<handle>` rendered the full real name ("Saadaoui Khaoula") in the page heading — a Tunisian name that also explained the "koukou" nickname (reduplication of "Khaoula").
- **BugCrowd, Vero, omg.lol, ko-fi**: open the profile URLs Sherlock returned — they often carry a bio, real name, location, or external links.
- Cross-reference the name against the email prefix / handle: nickname patterns (reduplication, suffix digits) can confirm the same person owns all accounts.
- These profile pages are dedicated sites, not general search engines, so the browser tool works on them (unlike Google/Bing/DDG).

## Pitfalls
- **Do NOT** rely on browser search (Google/Bing/DDG) — they will all CAPTCHA-block you
- Holehe and GHunt output is noisy — grep for "✅" or positive results
- Sherlock false positives: many sites return 200 for any username — see the "Verify Sherlock Hits" section above for the known false-positive list and the title-check verification method
- Sherlock `[+]` results are a candidate list; confirm each against the actual page before calling it a real account
- If the email was created recently, it may have zero footprint — that's also useful intel
- Try variations: full email as username, part before @, name split by dot
