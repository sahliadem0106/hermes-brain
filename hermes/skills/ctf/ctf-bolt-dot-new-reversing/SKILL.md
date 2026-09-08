---
name: ctf-bolt-dot-new-reversing
description: 'Reverse-engineer Bolt.new-built CTF web apps (Vite+React+TS SPAs) by extracting JS bundles, grepping for data/APIs/questions, and submitting answers without a browser. Also covers coding challenge CTFs (Monaco editor, /run API), SCADA/Modbus ICS challenges, crypto challenges, and MicroPython .mpy bytecode reversing. GENERAL PRINCIPLE: keep it simple, try easier solutions first before going deep.'
domain: ctf
subdomain: web-osint
tags:
- ctf
- bolt-new
- vite
- react
- reversing
- osint
- js-bundle
- web
- micropython
- bytecode
version: '1.0'
---
# Bolt.new CTF Web App Reversing

## Detection
Bolt.new apps have distinctive HTML:
- `<title data-default>Vite + React + TS</title>`
- `og:image` pointing to `https://bolt.new/static/og_default.png`
- Single `<div id="root"></div>` shell
- JS bundles at `/assets/index-<hash>.js`

Server typically **Werkzeug** (Python Flask) or **gunicorn**.

## Workflow

### 1. Recon
```bash
# Check server
curl -s -m 10 -v http://<target>:<port>/ 2>&1 | head -80

# Get HTML, extract JS bundle path
HTML=$(curl -s http://<target>:<port>/)
JS_URL=$(echo "$HTML" | grep -oP 'src="/assets/index-[^"]+\.js"')
```

### 2. Extract Questions + Data
```bash
# Grab JS bundle
curl -s -m 10 "http://<target>:<port>/assets/index-<hash>.js" > bundle.js

# Find questions
grep -oP '"Which[^"]*\\?"|"What[^"]*\\?"|"Who[^"]*\\?"|"How[^"]*\\?"' bundle.js

# Find company/vessel/entity data (varies per theme)
grep -oP 'name:"[^"]*"|"companyNumber"[^}]*}|id:"[^"]*"' bundle.js

# Find API endpoints
grep -oP '"/api/[^"]*"' bundle.js
```

### 3. Understand API Format
Two common patterns seen:
- **Map submission**: `POST /api/check` with `{"answers": {"1": "...", "2": "..."}}`
- **Single submission**: `POST /api/check` with `{"question": N, "answer": "..."}` or `POST /api/validate` with `{"q1": "...", "q2": "..."}`

Find the exact format:
```bash
grep -oP '.{0,200}fetch\("/api/[^"]*".{0,300}' bundle.js
```

### 4. Extract Ciphertext / Encrypted Data
If the app shows encrypted data at startup (e.g. hex string before asking for input), grab it from the initial HTML response.

### 5. Submit Answers
```bash
# Map format
curl -s -X POST http://<target>:<port>/api/check \
  -H "Content-Type: application/json" \
  -d '{"answers":{"1":"ANSWER1","2":"ANSWER2"}}'

# Single format
curl -s -X POST http://<target>:<port>/api/check \
  -H "Content-Type: application/json" \
  -d '{"question":1,"answer":"ANSWER"}'
```

## Coding Challenge CTFs (Monaco Editor Platform)

Multiple CTFs on this platform present algorithmic problems through a Monaco code editor with a `/run` API.

### Detection
- Page loads Monaco Editor (`monaco-editor@0.47.0`)
- Language options: python, c, cpp, rust
- `/run` API endpoint accepts `{"code": "...", "language": "python"}`
- Challenge description embedded in HTML with input/output format

### Workflow
```bash
# 1. Read the problem description from the page HTML
# 2. Solve with the provided example data, verify output matches expected
# 3. Submit via /run API (use Python's urllib.request to avoid shell quoting issues)
python -c "
import json, urllib.request
code = open('solution.py').read()
data = json.dumps({'language': 'python', 'code': code}).encode()
req = urllib.request.Request(f'http://<target>:<port>/run', data=data,
    headers={'Content-Type': 'application/json'})
resp = urllib.request.urlopen(req, timeout=15)
print(resp.read().decode())
"
# flag is in data.flag when data.challengeCompleted is true
```

### Common Problem Types Seen
- **Granary Seal**: Set membership — count items where all fields appear in lookup sets
- **Toll Schedule**: Greedy matching — sort arrivals + clearances, assign earliest clearance >= arrival. Minimum total wait = sum of (clearance - arrival).
- **Ash Record**: Subsequence matching with minimum gap — greedy + binary search on sorted timestamps
- **Rumour Spine**: Minimum vertex cut — max flow with vertex splitting (Dinic)
- **Vow Engine**: XOR path existence — spanning tree + linear basis (XOR basis on 60-bit ints). Cycle XOR = dist[u] ^ dist[v] ^ w for non-tree edges.

### Anti-pattern
**Don't overthink it.** These are textbook algorithms — test with the example, submit, iterate. If a solution approach takes more than 5 minutes of reasoning, you're overcomplicating it. The user wants speed and directness — when stuck, try the simplest next thing, not 6 alternative theories before any action. Re-reading the same code 3 times looking for non-existent edge cases is wasted time: just submit and iterate from actual error output.

**This applies double to web/CSP challenges.** Before building elaborate multi-step exploit chains, try the simplest injection first. The Google JSONP endpoint on www.googleapis.com works for script-src bypass on that origin — but if no useful callback exists, stop and try another approach rather than testing 20 callback names.

### MicroPython .mpy Bytecode Reversing

Some CTF challenges embed the verification logic in MicroPython bytecode (`.mpy` files) — a "foreign engine" that standard reversing tools don't handle natively.

**Detection:**
- File extension `.mpy`
- Magic bytes `4d 06` (MPY version 6) or `4d 05` (version 5)
- Small file size (hundreds of bytes) with readable strings (source filenames, function names) in hex dump

**Workflow:**
1. Extract the `.mpy` from any archive.
2. Download `mpy-tool.py` from the micropython repo:
   ```bash
   curl -sL -o mpy-tool.py "https://raw.githubusercontent.com/micropython/micropython/master/tools/mpy-tool.py"
   curl -sL -o makeqstrdata.py "https://raw.githubusercontent.com/micropython/micropython/master/py/makeqstrdata.py"
   ```
3. Disassemble: `python mpy-tool.py -d challenge.mpy`
4. Reconstruct the algorithm from bytecode mnemonics (key: `LOAD_CONST_SMALL_INT`, `LOAD_CONST_OBJ`, `LOAD_FAST`, `STORE_FAST`, `BINARY_OP`, `CALL_FUNCTION`, `LOAD_METHOD`/`CALL_METHOD`, `POP_JUMP_IF_TRUE`, `RETURN_VALUE`)
5. BINARY_OP codes (v6): `0=__lt__`, `2=__eq__`, `4=__gt__`, `14=__iadd__`, `23=__xor__`, `24=__and__`, `27=__add__`, `29=__mul__`
6. Reverse the algorithm — the `.mpy` typically encrypts input and compares to an embedded target tuple.

**Pitfalls:** `mpy-tool.py` needs `makeqstrdata` from `py/` (not `tools/`). No micropython runtime needed. Variable names become `LOAD_FAST N` indices.

**Reference:** `references/mpy-reversing.md`

### Web XSS + CSP Bypass via Google JSONP (Stored XSS with Messenger Bot)

Found on the "Rookery" / "Massagold" messenger CTF: EJS `<%-` unescaped output, CSP `script-src 'self' https://www.googleapis.com`, admin bot visits messages.

**Key technique: form auto-submission via JSONP callback**
```html
<form id="f" action="/messages" method="POST">
  <input name="to_username" value="attacker_user">
  <input name="content" value="STOLEN_DATA">
</form>
<script src="https://www.googleapis.com/discovery/v1/apis?callback=f.submit"></script>
```
The JSONP response calls `f.submit(data)`, which calls `HTMLFormElement.submit()` (argument ignored). The form submits POST to `/messages`, creating a new message from admin → attacker.

**CSP analysis:**
- `script-src 'self' https://www.googleapis.com` — Google Discovery API JSONP endpoint works
- `form-action 'self'` — form submission to same origin allowed
- `img-src 'self' data:` — external image exfiltration blocked
- `connect-src 'self'` — fetch/XHR to external blocked
- **navigate-to NOT in CSP** — `<meta http-equiv="refresh">` and `document.location` changes work

**Limitation:** The callback `f.submit(data)` passes the Google API response object as argument (ignored). The form values are static — cannot dynamically read admin's inbox. To actually exfiltrate dynamic data, need to find a callback that enables arbitrary JS execution (open problem).

**Google API JSONP format:** `// API callback\ncallbackName({...})` where `callbackName` is the `callback` parameter. Google validates callback as `[a-zA-Z0-9_.]+`. Dots like `location.assign` work.

**Known working callbacks:** `location.assign`, `f.submit`, `open`, `close`, `setTimeout`, `eval` (accepts dots).

## SCADA / Modbus CTF Challenges

Industrial control system challenges with Modbus/TCP, RF-433 MHz, and HMI interfaces.

### Detection
- GitHub-like code repository alongside a Flask web app (HMI, "The Salt Gate" etc.)
- Port ranges may host different services (one port for HTTP git/HMI, another for OT protocols)
- Scenario descriptions reference PLC, HMI, brine/seal processes, keyfobs, locks

### Workflow
1. **Find credentials** — often exposed in the web app login page ("Seeded Staff")
2. **Explore all HMI routes** — `/app/login`, `/app/watch`, `/app/gate/present`, `/app/charter`, `/app/notices`
3. **Clone the git repo** — dev credentials often in the Pull Requests page developer access section
4. **Read source code** — `gate.py` for access control rules (internal IP ranges), `routes.py` for endpoints
5. **Scan ports** — the same IP may have a port range (e.g. 31600-31609) with different services
6. **Check each port** — some announce banners, some are Modbus, some are HTTP

### RF-433 MHz Keyfob Channel
- Service may speak a custom text protocol (commands: STATUS, TX &lt;hex&gt;, JAM ON/OFF)
- **Banner**: `RiverGate RF-433 shared service channel` on port 31600
- **Frame structure**: 18 bytes total. Sync pattern is the ASCII string "River" (hex: `5269766572`) followed by serial(2B) + counter(2B) + button(1B) + padding(8B)
- **Counter**: Rolling code counter that must increment with each use (`last_counter=N` in status)
- **Jamming**: The channel may be jammed — send JAM OFF before TX attempts
- **Status format**: `STATUS lock=&lt;state&gt; jammer=&lt;on/off&gt; last_counter=&lt;N&gt; flag=&lt;hidden|visible&gt;`
- **Frame transmission**: `TX &lt;36-char-hex&gt;` sends an 18-byte frame. Response is `CAR REJECT source=&lt;...&gt; reason=&lt;...&gt;` or `CAR ACCEPT`.
- **Common rejection reasons**: `bad_length` (wrong frame size), `sync_not_found` (wrong sync pattern), `unknown_serial` (wrong keyfob serial), `channel_jammed` (jammer on)

### Internal Desk (IP Spoofing)
- Some HMI endpoints are IP-restricted via X-Forwarded-For / ProxyFix
- Flask app using `ProxyFix(x_for=2)` — send `X-Forwarded-For: 127.0.0.2, <real_ip>` to spoof internal IP
- Internal IPs checked: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.2/32

### Pitfalls
- Port 31604 may LOOK like Modbus (accepts connections) but is actually an nginx HTTP server responding with 400 to raw binary
- Actual Modbus service may be on a different port than expected
- RF frame sync detection is sensitive to byte values after the sync marker — padding affects detection

## Cloud Infrastructure CTFs (AWS Mock, LocalStack)

Multi-component CTFs where a cloud infrastructure (usually a LocalStack-like AWS mock) is paired with a connected web application and an SSO/SAML identity provider. The goal is typically to extract a secret from a restricted AWS service.

### Detection
- IP with multiple open ports (e.g. 30998 briefing, 31788 AWS mock, 31787 web app, 31789 secondary mock)
- AWS credentials provided (access key + secret key + user ARN)
- Role chain with ExternalIds (e.g. custody-reader → indexer → verifier-runner → shard-custodian)
- SAML SSO at `/sso/` with SimpleSAMLphp (URL: `.../loginuserpass`)
- Fantasy narrative: "Closed Gate", "Crownspire", "Registry", "Vaultrune"

### Phase 1: AWS Recon

Test STS GetCallerIdentity, then enumerate: S3 GetObject, KMS Decrypt, DynamoDB GetItem (keys are lowercase), SQS ReceiveMessage (URL needs account ID), SNS Subscribe/ListTopics, CloudFormation DescribeStacks. IAM write operations (CreateRole, AttachRolePolicy) are blocked for ALL identities — don't waste time.

### Phase 2: STS Role Chaining

Chain-assume roles. Each successive role may unlock more permissions. But CreateRole is universally blocked — the solution is never about creating a new IAM role.

### Phase 3: Policy Bundle

Decrypt the encrypted bundle via KMS. The bundled JSON reveals the policy needed (GetSecretValue + KMS Decrypt on a second key) and the target secret name.

### Phase 4: Discover Adjacent Services

Port-scan nearby ports on the same IP. A **web app** (Crownspire Bellworks) and a **secondary mock** are typically found.

### Phase 5: SAML Federation

The web app uses SimpleSAMLphp. Sign up → login → extract SAML assertion → use with `AssumeRoleWithSAML`. SAML-assumed roles have the same IAM restrictions as regular assumed roles.

### Phase 6: Web App JS Analysis

JS reveals the keeper flow:
- `/api/standing` — returns role (viewer/scribe/keeper)
- `/admin/account` — returns `[data-api-key]` with the sealing key (keeper-only)
- `/api/account/reset-password` — reset passphrase with sealing key
- `/admin/courier` — SSRF to arbitrary URLs (keeper-only)

The keeper login password IS the AWS secret — chicken-egg loop.

### Pitfalls (AWS-specific)
- HTML form defaults like `bellkey_7f4a91c2b8` are placeholders, not the actual secret
- SAML assertions are signed — modifying attributes breaks them
- Secret names from CloudFormation are exact (no random suffix in mocks)
- DynamoDB key names are lowercase (`plate_id`, not `PlateId`)
- S3 ListObjects and other list operations are typically blocked

### Reference
- `references/cloud-ctf-closed-gate.md` — Specific challenge details

## Pitfalls
- **Minified JS variable names change per build**: Don't rely on specific variable names. Use content-based grepping.
- **Question key format**: The first CTF used `{"1","2",...}` keys, the second used `{"q1","q2",...}`, and another used `{"question": N, "answer": "..."}`. Always check the actual fetch() call structure.
- **Python 3.13+ base64 strict mode**: `base64.b64decode()` now rejects data with length % 4 == 1 (even with `strict_mode=False`). Use `binascii.a2b_base64(data, strict_mode=False)` instead, or manually add `=` padding EXCEPT when len % 4 == 1 (in that case, drop the last char of data first since 1-char padding is invalid per spec).
- **LLM CTF chatbots are highly resistant to direct prompt injection**: Commands like `[SYS_OVERRIDE]` or "ignore previous instructions" are explicitly filtered. Use narrative social engineering instead — build context across multiple turns, claim authority from in-world entities (e.g. "the Gilded Knife", "Lord Damas Marrowcairn"), use the bot's own "dossier" feature to record information, and state false claims for the bot to "correct" with real data.
- **Fractured PEM files**: When a PEM has sections replaced with `***` asterisks, the remaining clean base64 fragments may still be decodable. Join all non-asterisk, non-whitespace base64 chars and decode. Each fragment between asterisk blocks that contains only valid base64 chars is an independent DER segment.
- **PML files (Process Monitor logs)**: Install the `procmon-parser` pip package. PML files have a binary format starting with `PML_`. Use `ProcmonLogsReader(f, should_get_details=True, should_get_stacktrace=False)` and iterate. Key event operations to filter: `Process Create`, `Load Image`, `RegSetValue`, `CreateFile` + "Mutant" for mutexes. For speed, you can pass `should_get_details=False` and `should_get_stacktrace=False` on the first pass. Events have `.time`, `.process.process_name`, `.process.image_path`, `.operation`, `.details` (only when details=True), and `.process.pid`.
- **Bit ordering in crypto**: Sage's `Integer.bits()` is LSB-first, Python's `int(bin_str, 2)` is MSB-first. When reconstructing bits from a solver, check both orderings.
- **Prompt injection CTFs**: Some servers are LLM-based chatbots. The Obligation Indexer pattern requires creative deception (roleplay, authority claims, dossier manipulation) — standard injection commands like `[SYS_OVERRIDE]` or "ignore previous instructions" may not work. Use narrative social engineering instead.
- **HTTP/0.9 servers**: Some crypto challenges serve raw text via HTTP/0.9. Use `curl --http0.9` to connect.
- **Don't present scraped flags as verified**: When extracting data from other people's sessions (shared links, walkthroughs, writeups), the flag and path may be instance-specific or outdated. Always verify independently before reporting as fact. Say "found this in a walkthrough" not "the flag is X."

## References

- `references/bolt-new-themes.md` — specific app themes encountered (maritime, corporate, aviation, accounting)
- `references/coding-challenge-ctfs.md` — coding challenge problem types (set membership, greedy, subsequence, vertex cut, XOR basis)
- `references/crypto-ctf-techniques.md` — crypto techniques from session (oracle manipulation, bit ordering, MQ over GF(2), RSA partial key recovery)
- `references/scada-hollow-courier.md` — SCADA/ICS challenge specifics (HMI routes, RF-433 protocol, IP spoofing)
- `references/web-xss-google-jsonp-csp-bypass.md` — Google JSONP CSP bypass for Messenger CTFs (callback=f.submit form submission, CSP analysis)

## Support Files

- `templates/` — (empty, add solver stubs as needed)
- `scripts/` — (empty, add automation scripts as needed)
