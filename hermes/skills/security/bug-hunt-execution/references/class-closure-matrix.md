# Class-Closure Sub-Surface Matrix (template)

Use before declaring any ladder class DEAD. Copy, fill every row, and only mark the class DEAD when every row has a result. If any row is UNTESTED, the class status is PARTIAL — even if every tested row was negative.

## Generic rows to consider per class
| Row | What it proves | Example payload/probe |
|---|---|---|
| READ cross-tenant | object can be read by non-owner | swap wid/id in URL with 2nd account session |
| WRITE cross-tenant | object can be mutated by non-owner | same swap on state-changing POST |
| DELETE cross-tenant | object can be destroyed by non-owner | same swap on delete endpoint |
| Unauth strip | endpoint works with NO session | drop cookies/token entirely |
| Empty/nil id | server falls back to 'latest/default' object | empty path segment, empty token param |
| Encoded/mutated id | obfuscation is not authz | base64/unhex/UUID variants, trailing whitespace |
| Side-channel on rejection | failed cross-tenant call leaks info (email, PII) | trigger the mutation, check notification/email |
| State-dependent | permission change leaves stale access | download/export after role revocation |
| Feature-gate vs authz | feature-flag denial ≠ authorization denial | same endpoint from feature-disabled vs unauthorized user |
| Alternate code path | second door has weaker checks | import/template, batch/CSV, legacy endpoint, personal vs root config |
| Parser/500 hunt | unhandled exception or stack leak | malformed-but-valid input per format; wrong types; extra keys |
| Race | check-then-act on limit/state | N concurrent requests at a redemption/seat/view boundary |

## Class-specific examples (from live sessions)

### File-upload/import (class 6)
- UI create name validation vs API create vs import-template name validation (import may reuse same regex — or not)
- OVERWRITE existing project/config via import (create-only vs merge) — the strongest alternative to 'weaker validation'
- Secret names via the template secrets-block path (may differ from POST endpoint)
- Environment NAME chars (validated separately from slug)
- Description / extra fields (parser handling; extra keys rejected?)
- Parser error classes: empty input, broken YAML/JSON, null collections, deep nesting, non-object secrets → look for 500s and stack traces (js-yaml/zod fingerprints in messages = INFO only, not a finding)

### SSRF (class 8)
- Input validation gap at create (does it accept internal IPs?) — NOT the finding by itself
- Delivery reality (external callback hit from prod IP/UA)
- Egress proxy behavior on internal targets (407 = mitigated; try redirect chains + internal hostnames to bypass domain-based proxies)
- Response-body exposure (blind vs full)

### XSS (class 9)
For each attacker-controlled string, test ALL of: input validation, storage, log/report rendering, SSR hydration embedding, React/DOM sink. A string stored raw with HTML but rendered only as React text or inside <textarea value> is NOT XSS.

## Output format
File per class in mission dir: status line (DEAD/PARTIAL/OPEN), table of rows with payload + result, evidence filenames, cleanup list, and the honest gap list. Commit before moving on.
