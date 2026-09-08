---
name: hunter-l3-redos
description: "Use when hunting ReDoS on a target. Loads the L3 technique sheet: ReDoS (Regular expression Denial of Service) exploits catastrophic backtracking in regex engines that use backtracking implementations (Ruby, Python, JavaScript, PCRE)."
domain: cybersecurity
subdomain: web
tags:
- web
- redos
- hunting
- l3
version: '1.0'
---

# ReDoS — Technique Sheet

## Overview
ReDoS (Regular expression Denial of Service) exploits catastrophic backtracking in regex engines that use backtracking implementations (Ruby, Python, JavaScript, PCRE). When user-controlled input reaches a vulnerable regex — via a query parameter, HTTP header, file upload, request body field, or a parser fed attacker-controlled data — a crafted string sends the engine into polynomial or exponential matching time, pinning a CPU core and blocking the worker/event loop. It pays because it is often unauthenticated, needs no exploit primitive beyond a single request, and lands in libraries (Rack, Rails, Django, Ruby stdlib, Node modules) used by virtually every application. The class covers both "input hits a vulnerable app regex" and "user supplies the regex itself" (regex injection), plus memory/compiler-exhaustion variants in non-backtracking engines.

## Distinct sub-patterns

### 1. User-supplied value interpolated into a regex (regex injection → ReDoS)
- Endpoint shape: any endpoint where the parameter is used AS or INSIDE a regex.
  - `POST /graphql` with `search(q: "<attacker regex>", lang: "en")` (CS Money, id=1000567)
  - `GET /dags/{dag_id}/gantt?root=<attacker regex>` (Airflow, id=2068004)
  - Locale parameter in internationalized URLs: `?locale=<attacker regex>` (id=1746098, CVE-2022-41323)
  - RubyGems OIDC access policy / API key role: `string_matches` field takes a user-supplied regex (id=3542546)
- Payloads (verbatim):
  - GraphQL: `query a { search(q: "[a-zA-Z0-9]+\s?)+$|^([a-zA-Z0-9.'\w\W]+\s?)+$\", lang: "en") { ... } }`
  - Airflow gantt: `root=((((((.*)*)*)*)*)*)!`
  - Locale: `(a+)+$`
  - RubyGems: `^(a+)+$` evaluated against `refs/heads/aaaa...!`
- Root cause: parameter passed to `Regexp.new` / `re.match` / regex compilation with no sanitization, no timeout, no complexity validation (Ruby Regexp has no built-in timeout).
- Impact: GraphQL search went from instant to far-longer response; Airflow web request hung, denying service (CVE-2023-36543); RubyGems payload blocked a Puma worker — "a small burst of concurrent requests caused partial/full DoS of gem publishing".
- Exemplars: id=1000567, id=2068004, id=3542546, id=1746098.

### 2. HTTP header parsing ReDoS (the highest-yield sub-pattern)
These fire on almost any route — a single request to any endpoint with the poisoned header.
- Accept-family headers (Rack/Rails `Rack::Request::Helpers`):
  - Params: `Accept`, `Accept-Encoding`, `Accept-Language`, `Forwarded` (ids 2584376, 2446427, 2446433)
  - Payload verbatim (Accept-Encoding): `gzip;q=0.9, deflate;q=0.9, br;q=0.9,` repeated many times (id=2584376, CVE-2024-39316)
  - Impact: unauthenticated user causes excessive CPU; "a DoS vector affecting virtually all Rails applications" (CVE-2023-27539, id=2071556).
- `If-Modified-Since` (Rack::ConditionalGet): payload `"0 Feb 00 00 :00" + " " * 20000` → ~292s parse at 100k spaces, ~11.5s hang at 20k (id=1485501). Root cause: `Time.rfc2822` regex backtracking.
- `X-Forwarded-For` (ActionDispatch::RemoteIp): payload `"0.0.0.0/" + '1' * 50000 + '.'` → ~40s hang. Root cause: `mask!` regex `/\A(0|[1-9]+\d*)\z/` backtracks on a long digit prefix (id=1485717).
- `Content-Type` (Rack media type parser): "carefully crafted content type headers" → parser runs far longer than expected (id=2446437, CVE-2024-25126).
- `Range` header (Rack): payload verbatim `bytes=0-1,0-1,` repeated ~74 times ending in `0-` → parsing regex takes unexpected time (id=2012121, CVE-2022-44570). Note "body manipulation can bypass the request header size limit" was cited for the related Content-Disposition CVE (id=2012122).
- `Authorization: Digest` (Ruby WEBrick DigestAuth): payload `Authorization: Digest a="\b\b\b...` (~40 `\b`). Root cause: `split_param_value` regex `^\s*([\w\-\.\*\%\!]+)=\s*"((\\.|[^"])*)"\s*,?` backtracks. Impact: 100% CPU, 9+ seconds for a small string (id=661722).
- `User-Agent` (device-detector, GitLab): normal Chrome UA + appended runs of spaces/a's → DoS on the instance (id=1772063, CVE-2022-4131). Also Node `useragent` parser (id=320159) — long 'a' string.

### 3. Multipart / Content-Disposition parsing (Rack)
- Endpoint shape: `POST /` with multipart body.
- Payload verbatim (id=1489141): `Content-Disposition:G;\f="=;1=";\fD=";t*1*` — only 26 chars, exploiting exponential backtracking in `Rack::Multipart::RFC2183`.
- Root cause: exponential backtracking in the RFC2183 parsing regex; not mitigated by Ruby 3.2 memoization (id=2012125, CVE-2022-44572).
- Impact: ~22s CPU for a 26-char input on puma/unicorn (+nginx) stacks. Related: crafted Content-Disposition header ReDoS (id=2012122, CVE-2022-44571).

### 4. Body / form-field values hitting app validation regexes
- Money field: `POST /money`, param `money[amount]`, payload `"$" + ","*100000 + ".11!"`. Root cause: Money regex `(\D*[\d,]+\.\d{2}$)` O(n²) backtracking (CVE-2021-22880). Impact: ~40s; one more zero → essentially forever.
- Label color: `POST /:user/:project/labels/new`, param `label[color]`, payload `#0…(50000 times)c0ffee`. Root cause: `color_validator.rb` regex backtracks on long invalid colors. Impact: >90% CPU, GitLab inaccessible for all users (id=511381).
- Email validation (is-my-json-valid, Node): regex `/^\S+@\S+$/` (which is itself exploitable on long input despite looking simple — the anchored `\S+...\S+` overlap). 90K-char input → ~10s event-loop block (id=317548).
- Protobufjs: `option (my_option) = xxxx…!;` in a .proto file against regex `/^(?:\.?[a-zA-Z_][a-zA-Z_0-9]*)+$/` → DoS on parse (id=319576).
- sshpk: `` `ssh-rsa a${Array(200000).join(' ')}x\nx` `` against `/^([a-z0-9-]+)[ \t]+([a-zA-Z0-9+\/]+[=]*)([\n \t]+([^\n]+))?$/` → DoS parsing a ~200KB key (id=319593).
- Forward proxy path (forward.js): `http://${Array(81000).join('0')}` against `/http:\/\/[^/]*:?[0-9]*(\/.*)$/` → ~5s block per request (id=320586).
- Undici `Headers.set()/append()`: `"a" + "\t".repeat(50_000) + "\ta"` in a header value → ~3s (id=1784449).
- GraphQL/JSON-esque field validators generally: any anchored validation regex (`^...$`) with nested quantifiers over a user field is a candidate.

### 5. Content-rendering / text-processing ReDoS (stored-input variants)
Attacker stores crafted content; the regex fires when it renders or is processed — often for every viewer.
- GitLab wiki/markdown code view (Rouge syntax highlighter): payload `'Result size of ' + ' ' * 3456` triggers cubic-complexity lexers (factor, ghc_core, ceylon). Impact: ~60s of 100% CPU, 500/502 errors on render (id=1283484).
- Rails ActionText blockquote: rich-text content `"\t"*length + "a" + "\t"*length + "a"` → `to_plain_text` ~39.4s on Ruby 3.1.4 for 100k chars (regex `/\A(\s*)(.+?)(\s*)\Z/m`) (id=2389431).
- Django `Truncator.words(html=True)` / `truncatewords_html`: payload `'<' * 65535` → ~40s (id=2402193).
- Django `urlize()`: payload `'&' + ';:' * n` (~1M chars) → ~187s (id=2881639, CVE-2024-45230).
- Wappalyzer (page-fingerprinting): `<meta name="GENERATOR" content="IMPERIA 461979461979…66229:"/>` against a `([0-9.]{2,})+` regex → extension crashed in all tabs, CLI ran indefinitely (id=888030). Attacker-controlled third-party content poisoning the *client* is a notable variant.

### 6. Parser-level ReDoS in stdlib/framework internals (feed the parser attacker data)
- Ruby `Date.parse`: ~140 digits of '1' → full DoS on untrusted input; fix defaulted to 128-byte limit (id=1404789, CVE-2021-41817).
- Ruby `URI.parse`: `URI('https://example.com/dir/' + 'a'*n + '/##.jpg')` — two '#' chars trigger RFC3986 regex backtracking; time quintupled per input doubling (1.09s @50k → 122.7s @400k) (ids 1444501, 1944515; incomplete fix → CVE-2023-36617, id=2071561).
- `CGI::Cookie.parse`: crafted cookie string → super-linear time (id=3013913). `CGI::Util#escapeElement`: crafted input → high CPU (id=3023605).
- `String#underscore`/`titleize`/`tableize`/`foreign_key` (ActiveSupport): crafted string → CPU/memory exhaustion (id=2012131, CVE-2023-22796).
- GlobalID model-name parsing: crafted GlobalID URI → ReDoS; GlobalID is reached via ActiveJob and graphql-ruby with user input (id=2012135, CVE-2023-22799).
- Rails query-parameter filtering (Action Dispatch): crafted query params → filtering regex backtracks (id=2872502, CVE-2024-41128).
- Rails::Html `PermitScrubber.scrub_attribute`: SVG attributes trigger backtracking in the sanitizer (id=1804128, CVE-2022-23514).
- REXML XML parsing: (a) `<a xml:b="" b="">` + repeated `<D>` — a ~42KB file → 13 minutes of 100% CPU via namespace/attribute handling (id=2666849); (b) hex numeric character reference `&#x...;` with many digits → pathological CPU (id=2807139, CVE-2024-49761).
- Airflow unspecified regex endpoints: authenticated user hangs the current request (id=2064723).
- Mozilla bedrock: vulnerable regex in the `sideway/formula` dependency (id=1879546/1879548, CVE-2023-25166) — dependency-level ReDoS counts.

### 7. Async / background-job amplification
- GitLab webhook processing: webhook response containing an HTTP header line of `"a" + " " * 950000 + "b"` — `sub(/\s+\z/, '')` in net/http backtracks quadratically on long space runs with no trailing whitespace, and runs without timeout. Impact: Sidekiq web_hook job stuck at 100% CPU for over a year — CPU + memory exhaustion, and it bypassed the prior timeout fix (id=1531958). Key insight: a single attacker-triggered job can burn a worker indefinitely.

### 8. Compiler/complexity exhaustion in non-backtracking engines (Rust regex crate)
- Endpoint: any service where users supply regexes compiled by Rust `regex` (no backtracking, so classic ReDoS payloads fail — but memory/compile work is unbounded).
- Payload verbatim: `(?:){4294967295}` — repetitions of empty sub-expressions allocate zero bytes, bypassing memory-based mitigation; the compiler attempts 4,294,967,295 empty instances. Nested repetitions `(?:){64}{64}{64}{64}{64}{64}` = 64^6 instances → exponential compile CPU (id=1518036). Use this when the target language guarantees linear-time matching.

## Bypass / chain notes
- Bypass input-length limits via body, not headers: for the Rack Content-Disposition CVE, "body manipulation can bypass the request header size limit" (id=2012122). Multipart payloads can be tiny (26 chars, id=1489141) — exponential regexes don't need size.
- Bypass timeout fixes: GitLab had added timeouts to webhook handling; the space-run `sub(/\s+\z/)` payload ran inside net/http response parsing without timeout, re-enabling DoS a year later (id=1531958).
- Memoization mitigations don't help: the Rack RFC2183 boundary ReDoS was explicitly "not mitigated by Ruby 3.2 memoization" (id=2012125).
- Ruby-version-dependent behavior: several Rails payloads only fire on Ruby ≤3.1 (`/\A(\s*)(.+?)(\s*)\Z/m` in ActionText, Accept-header CVE-2024-26142) — check target Ruby version; Ruby 3.2+ regex timeout (Regexp.timeout) fixed some but not all (URI RFC2396_Parser still affected, id=2071561).
- Chained amplification: one poisoned header → every request that parses it (any route); one stored wiki/markdown/rich-text payload → CPU spike on every render/viewer (ids 1283484, 2389431); one webhook → permanent worker burn (id=1531958). Small concurrent bursts multiply single-request CPU into full outage (id=3542546).
- Client-side chain (id=888030): serve a crafted meta tag on any page the target extension scans — DoS lands in the victim's browser/extension, not your server.

## Gotchas / what NOT to do
- Do not assume a naive payload works against linear-time engines: Rust's regex crate is immune to `(a+)+$` — you need the empty-repetition compiler-exhaustion trick (id=1518036), or nothing.
- Anchored `^\S+@\S+$` still backtracks — "simple-looking" regexes with overlapping quantifiers over long input are valid targets; don't dismiss them.
- Long payloads aren't always needed: exponential regexes fire at 26 characters (id=1489141); quadratic ones need the length (100k–1M chars was common). Match payload size to the suspected complexity class.
- Requests that hang a worker may not return an error — measure timing server-side or via response latency deltas (e.g., instant 'AAA' query vs. regex-bomb query, id=1000567); a clean 200 with a 40s latency is still a finding.
- Trailing characters matter: quadratic patterns often need input that *almost* matches — e.g. trailing `!` or `.` to defeat a `$` anchor after a long near-match (`"$"+","*100000+".11!"`, `1'*50000 + '.'`, `a…x\nx`). A clean-matching string returns fast.
- Two '#' chars, not one, trigger the Ruby URI bug; specific *invalid* URL shapes trigger parser ReDoS, valid URLs don't (ids 1444501, 2071561).
- Authenticated low-effort DoS still counts (Airflow id=2064723) — don't skip logged-in surfaces.
- Don't leave a worker pinned for a year: demonstrate, measure, stop. The id=1531958 case got there by accident of the design, but in testing burst-and-release.

## Real-world impact examples
- Ruby Money field: `"$"+","*100000+".11!"` → ~40s CPU; CVE-2021-22880 (id=1023899).
- GitLab label color: >90% CPU, whole instance inaccessible (id=511381).
- Rack multipart: 26-char header → ~22s CPU per request (id=1489141).
- Ruby URI: 122.7s parse on a 400k-char URL (id=1444501).
- Django urlize: ~187s on ~1MB input (id=2881639).
- REXML: 42KB XML → 13 minutes at 100% CPU (id=2666849).
- GitLab webhook: single job stuck at 100% CPU for over a year (id=1531958).
- RubyGems: burst of crafted `string_matches` regexes → partial/full DoS of gem publishing (id=3542546).
- Wappalyzer extension: crashed in all browser tabs from one crafted meta tag (id=888030).