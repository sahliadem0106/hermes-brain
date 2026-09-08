# JS SPA Reverse Engineering — Extracting Data from Bundles

When you can't use a browser (no CDP, no local Chrome) and need to understand a JavaScript Single-Page Application, the minified JS bundle itself contains everything — API endpoints, mock data, question text, field labels, and sometimes even answer keys. The HTML shell is empty (`<div id="root"></div>`), but the JS is a goldmine.

## When to Use

- Browser tools aren't available (no CDP endpoint, cloud browser blocked)
- You need to find API endpoints, data structures, or answer validation logic
- The app is a Vite/React/Next.js SPA with a predictable asset structure
- OSINT investigation dashboards, CTF web challenges, gamified training tools

## Core Technique

### Step 1: Fetch the HTML shell to find asset paths

```bash
curl -sL -m 10 "http://host:port/" 2>&1
```

Look for:
- `<script ... src="/assets/index-XXXXX.js">` — Vite/React bundle
- `<link ... href="/assets/index-XXXXX.css">` — stylesheet (reveals theme, fonts, component classes)
- `__NEXT_DATA__` — Next.js server-side data
- API proxy hints in the HTML

### Step 2: Check asset size to gauge complexity

```bash
curl -sL -m 10 "http://host:port/assets/index-XXXXX.js" | wc -c
```

- <50KB: simple app, likely readable
- 50-200KB: moderate, grep-able
- 200KB+: large app, need targeted grepping

### Step 3: Extract API endpoints

```bash
curl -sL -m 10 "http://host:port/assets/bundle.js" | grep -oP 'fetch\("/api/[^"]*"|"/api/[^"]*"'
```

Common patterns:
- `fetch("/api/check",{method:"POST"...})` — answer validation
- `fetch("/api/search?q="...)` — search endpoints
- `fetch("/api/data/")` — data fetching
- GraphQL: `"/graphql"` or `fetch("/api/graphql"...`

### Step 4: Extract UI strings (component names, field labels, question text)

```bash
# Find quoted strings that look like labels/titles
curl -sL bundle.js | grep -oP '"[A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+"|"[A-Z][a-z]+ [A-Z][a-z]+"' | sort -u

# Find question text specifically
curl -sL bundle.js | grep -oP '"Which[^"]*\?"' | sort -u
curl -sL bundle.js | grep -oP '"What[^"]*\?"' | sort -u
curl -sL bundle.js | grep -oP '"Who[^"]*\?"' | sort -u

# Find field labels
curl -sL bundle.js | grep -oP '"Registered Owner"|"Call Sign"|"Vessel Name"|"[A-Z][a-z]+ [A-Z][a-z]+"' | sort -u
```

### Step 5: Find data structures (mock data, hardcoded records)

```bash
# Look for data objects with IDs
curl -sL bundle.js | grep -oP '.{0,200}(IMO|imo|vessel|Vessel).{0,200}'

# Look for company/entity records
curl -sL bundle.js | grep -oP '.{0,200}(companyNumber|registeredOffice|directors).{0,200}'

# Extract broader context around key terms
curl -sL bundle.js | grep -oP '.{0,300}questionText.{0,300}'
```

The minified JS often contains **the entire dataset** embedded as React state initial values or module-level constants. Look for patterns like `{id:"...",name:"...",...}` chains.

### Step 6: Trace answer validation logic

```bash
# Find the submission/check logic
curl -sL bundle.js | grep -oP '.{0,150}fetch\("/api/check.{0,300}'

# Find answer mapping (question ID → answer key)
curl -sL bundle.js | grep -oP '.{0,200}answers.{0,200}'

# Find success/failure UI strings
curl -sL bundle.js | grep -oP '"CASE CLOSED"|"all_correct"|"Incorrect answers remain"'
```

### Step 7: Interact with discovered APIs directly

Once you've found the API structure, construct the request:

```bash
# POST with JSON
curl -sL -m 10 -X POST "http://host:port/api/check" \
  -H "Content-Type: application/json" \
  -d '{"answers":{"1":"answer one","2":"answer two"}}'

# GET with params
curl -sL "http://host:port/api/search?imo=9724418"
```

### Step 8: Check the CSS for theme/domain hints

```bash
curl -sL "http://host:port/assets/index-XXXXX.css"
```

Look for:
- Font imports (reveals aesthetic: monospace = terminal/tech, serif = vintage/official)
- Color palette (bronze/gold = maritime/official, neon = cyberpunk/CTF)
- Custom class names (`.tideglass-browser`, `.evidence-satchel` — reveals feature names)
- Background patterns (`desktop-bg` — reveals desktop-simulation UI)

## Real Example: Maritime OSINT Dashboard (July 2026)

**Target:** `http://154.57.164.68:31550/` — Vite+React+TS app

**Step 1 — HTML:** `<div id="root"></div>` + `<script src="/assets/index-D_2h5M9C.js">` (219KB)

**Step 3 — API:** Only one endpoint: `POST /api/check` with `{answers: {questionId: value, ...}}`

**Step 4 — UI:** 4 investigation tools (Tideglass Browser, Maritime Registry, P&I Directory, Submit Findings), 5 questions about vessel ownership

**Step 5 — Data:** Full dataset embedded in bundle — vessel ASHEN MERCY (IMO 9724418), 10 companies, P&I entry, charter fixture, all with IDs, addresses, directors, shareholders, parent relationships

**Step 7 — API interaction:** Submitted answers via curl POST, got `{"all_correct":false,"results":{"1":true,...}}` — iteratively fixed wrong answer (gilded_knife vs gilded_knight)

**Key lesson:** The JS bundle contained the ENTIRE scenario — vessel records, company registry, P&I data, charter fixtures, all 5 questions AND the answer structure. The API only validated. Everything needed to solve was grep-able from the bundle.

## Pitfalls

1. **Minified JS can mislead on string boundaries.** `grep -oP` regex with `.{0,N}` is approximate — verify names by finding them in multiple contexts.
2. **Variable names are mangled.** `Mr` might mean "questions array," `F` might mean "companies lookup." Trace by surrounding context, not variable names.
3. **Obfuscated keys differ from display names.** In the example, the charterer's key was `gilded_knife` but my first guess was "Gilded Knight Trading" — the actual display name was "Gilded Knife Commodities Ltd." Always cross-reference the key-to-name mapping.
4. **Don't skip the CSS.** It revealed the app was a noir-themed desktop simulation before I understood any JS — the bronze/gold palette and "IM Fell English" font signaled "maritime/official documents" immediately.
