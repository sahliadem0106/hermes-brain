---
name: hunter-l3-redos-dos
description: "Use when hunting ReDoS (DoS) on a target. Loads the L3 technique sheet: ReDoS in this record set is not the classic \"evil regex in a route handler\" bug — it is algorithmic-complexity DoS triggered by feeding crafted content to a markdown/XML parser that already exists in the application."
domain: cybersecurity
subdomain: web
tags:
- web
- redos-dos
- hunting
- l3
version: '1.0'
---

# ReDoS (DoS) — Technique Sheet

## Overview

ReDoS in this record set is not the classic "evil regex in a route handler" bug — it is algorithmic-complexity DoS triggered by feeding crafted content to a markdown/XML parser that already exists in the application. The attacker's job is to find an entry point (preview endpoint, state-changing action like "move issue", XML ingest) that routes attacker text through a polynomial or super-linear parsing routine, then let a single request pin a CPU core for the full request timeout. All three verified bugs were found by the same reporter (ajaysenr), and all pay on any program with server-side markdown rendering or XML parsing where a single request can consume disproportionate CPU.

## Distinct sub-patterns

### 1. Polynomial regex on markdown during a state-changing action (issue move)

- Endpoint shape: `POST` issue move action (GitLab), with the malicious content pre-placed in the issue `description` field. The expensive parse fires server-side when the issue is moved (the rewriter re-scans the description to rewrite uploaded attachment references).
- Payload (verbatim, from record 1543584):
  ```python
  print('![l' * 100000 + '\n')
  ```
  i.e. 100,000 repetitions of the literal image-embed fragment `![l`, producing a ~300KB description full of unterminated markdown image syntax.
- Root cause: GitLab's `UploadsRewriter` scans the issue description with a polynomial-complexity regex (`MARKDOWN_PATTERN`). The repeated `![l` fragments force catastrophic backtracking across the whole string.
- Impact proven: One request burned a full CPU for 60 seconds (request timeout). Parallel requests exhaust multiple CPUs and can make the entire server unavailable.
- Exemplar report: 1543584 (GitLab).

### 2. Super-linear CPU in markdown cache/preview path

- Endpoint shape: `POST preview_markdown` (GitLab), parameter `text` — the live markdown preview endpoint. This is the most direct entry point because no state change is needed; you just submit the text.
- Payload (verbatim, from record 1543718):
  ```python
  print('![l' * int(1048576 / 3 - 1) + '\n')
  ```
  i.e. ~349,524 repetitions of `![l`, sized to land just under a 1MB limit (1048576 / 3 - 1 repetitions, each repetition being 3 characters). The payload was deliberately sized to the maximum the field accepts.
- Root cause: `cache_collection_render` in GitLab's markdown reference extractor exhibits super-linear CPU behavior on crafted descriptions — the caching layer re-processes the content in a way that scales worse than linearly with the number of reference-like tokens.
- Impact proven: Previewing the issue with the crafted description burned a full CPU for 60 seconds (request timeout); parallel requests can exhaust multiple CPUs and take the whole GitLab server down.
- Exemplar report: 1543718 (GitLab).

### 3. Quadratic XML parsing in REXML (CVE-2024-43398)

- Endpoint shape: `REXML::Document.new` — the Ruby stdlib XML parser. The attack surface is any application endpoint that parses attacker-supplied XML with a vulnerable REXML version (APIs accepting XML bodies, SAML endpoints, file uploads parsed as XML). In the record itself the param is "(none)" — the PoC targets the parser directly.
- Payload (verbatim, from record 3002543):
  ```python
  start = ""
  middle = "<a xml:b=\"\" b=\"\">" + "<D>" * 1
  end = ""
  print(start)
  COUNT = 2000
  for _ in range(COUNT):
  	print(middle)
  print(end)
  ```
  i.e. 2,000 repetitions of `<a xml:b="" b=""><D>` — deeply repeated elements carrying an attribute that reuses the `xml:` namespace prefix with an empty value plus a duplicate plain attribute `b=""`.
- Root cause: REXML (CVE-2024-43398) has poor performance parsing specially crafted XML — attribute/namespace handling on the crafted shape causes quadratic/uncontrolled resource consumption as element count grows.
- Impact proven: Parsing the crafted XML took a very long time with CPU at 100% on the vulnerable REXML version — denial of service. Note this is a dependency-level bug: the hunter demonstrated the parser flaw directly, and any app embedding the vulnerable version inherits it.
- Exemplar report: 3002543 (Internet Bug Bounty).

## Bypass / chain notes

- No multi-step chains appear in the records — all three are single-request DoS. But note the two entry-point strategies they represent:
  - Direct interactive entry (preview_markdown, `text` param) — fastest to test, no side effects.
  - Deferred entry (issue move) — the payload sits in the `description` field and only detonates when a *different* action re-processes the text through a second parser (`UploadsRewriter`). When a preview endpoint is hardened, look for other code paths that re-scan stored content (rewriters, exporters, notification rendering, migration/import).
- Size tuning against input limits: the markdown payload was sized as `int(1048576 / 3 - 1)` to stay just inside an apparent 1MB cap — find the field's max size and fill it, since complexity bugs scale with input length.
- Fragment choice matters: `![l` (unterminated markdown image syntax) is what stresses the reference-extraction regex. Repetition count (100,000 vs ~349,524) is tuned per endpoint — the preview path tolerated a larger payload than the move path needed.
- For XML: the specific shape `<a xml:b="" b="">` (namespace-prefixed attribute with empty value alongside a duplicate attribute name) is the trigger for CVE-2024-43398; simple repetition of well-formed elements alone did not fire it. `COUNT = 2000` was sufficient — quadratic bugs need far less data than polynomial regex bugs.

## Gotchas / what NOT to do

- Do not report "slow page" — the proven impact bar here is CPU saturation with timing: a full core pinned for the entire 60-second request timeout, and a parallelization argument (N parallel requests → N cores → server unavailable). Reproduce with timing evidence and demonstrate parallel impact.
- Don't assume only the obvious endpoint parses your input. Both GitLab bugs used the same payload class but different parser paths (`preview_markdown`'s cache_collection_render vs the move action's UploadsRewriter) — test every path that touches the stored content.
- Don't ship unbounded payloads blindly — the working payload was engineered to fit under a size limit (1MB) while maximizing repetition count. An oversized payload that gets rejected proves nothing.
- Don't test on production infrastructure with heavy parallelism before confirming the single-request effect and coordinating with the program — this class takes servers down, and all three records are for programs (GitLab, Internet Bug Bounty) with explicit DoS scope.
- For dependency-level findings (REXML), the record targets the parser directly with no app parameter — verify the target application actually runs the vulnerable version and that attacker XML reaches it before claiming app-level impact.
- Note for reproducibility: the markdown payloads are Python `print` expressions generating the string, not raw request bodies — generate the string, then place it in `description` / `text`.

## Real-world impact examples

- GitLab (1543584): a single issue-move request with a ~300KB `![l`-flood description burned a full CPU for 60 seconds, the entire request timeout; parallelized, it exhausts CPUs and can make the whole server unavailable.
- GitLab (1543718): the same class of payload via `preview_markdown` (`text` param, ~1MB) pinned a full CPU for 60 seconds per request; parallel requests can take the GitLab instance down.
- Internet Bug Bounty (3002543): 2,000 crafted XML elements caused the vulnerable REXML to parse at 100% CPU for a very long time — a CVE-credited (CVE-2024-43398) denial of service in the Ruby standard library, inherited by every application embedding it.