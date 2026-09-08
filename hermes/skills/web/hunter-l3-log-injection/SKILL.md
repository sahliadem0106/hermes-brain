---
name: hunter-l3-log-injection
description: "Use when hunting Log Injection on a target. Loads the L3 technique sheet: Log Injection covers attacks where attacker-controlled data flows unsanitized into server, daemon, or proxy logs — either to execute terminal escape sequences, forge log lines that analysts/SIEMs trus"
domain: cybersecurity
subdomain: web
tags:
- web
- log-injection
- hunting
- l3
version: '1.0'
---

# Log Injection — Technique Sheet

## Overview
Log Injection covers attacks where attacker-controlled data flows unsanitized into server, daemon, or proxy logs — either to execute terminal escape sequences, forge log lines that analysts/SIEMs trust, or corrupt log structure so entries are silently dropped. It pays when targets have logging pipelines that feed incident response, alerting, or human terminals, and when trusted request metadata (usernames, custom parameters, auth headers) is written verbatim into log output. Severity is typically low-to-medium on its own but rises sharply when forged lines can defeat forensic analysis or when log entries can be erased entirely. All three exemplar records here came from the same reporter (ajaysenr) across Ruby, Monero, and HackerOne programs.

## Distinct sub-patterns

### 1. Terminal escape sequence injection via unsanitized Basic Auth username
- **Endpoint shape / parameter:** Any server exposing HTTP Basic Auth — `GET /` with the `Authorization: Basic base64(user:pass)` header. The injectable field is the **username** portion, which the server extracts and echoes into its log line.
- **Payload that actually fired (verbatim):**
  ```
  ]2;BOOM!
  ```
  (embedded in the username field of the Basic Auth credentials; the report annotates it as `ESCAPE SEQUENCE HERE->]2;BOOM!<-SEE WINDOW TITLE`)
- **Root cause:** WEBrick's BasicAuth handler logs the supplied username without sanitizing or escaping it. The payload begins with the ANSI escape `ESC ]2;` (Operating System Command, set window title) so the terminal rendering the log line executes it and rewrites its own window title.
- **Impact proven:** The server's terminal window title changed to `BOOM!` — direct, observable proof that the injected escape sequence executed in the log output. ESC sequences can set titles, move the cursor, or clear output, so this class can obscure attacker activity in a live console.
- **Exemplar:** id=223363 (Ruby program, CVE-2017-10784)

### 2. Forged log lines via newline injection in a logged request field (JSON-RPC `params.note`)
- **Endpoint shape / parameter:** ZMQ JSON-RPC daemon endpoint at `tcp://host:18082` (wallet RPC). The injectable field is `params.note` — a free-form string inside the JSON-RPC request body that the daemon logs before validating request semantics.
- **Payload that actually fired (verbatim):**
  ```json
  {"jsonrpc":"2.0","id":1,"method":"get_info","params":{"note":"ATTACKER_MARKER_BEGIN\nFORGED_LOG_LINE: authentication succeeded for admin\nATTACKER_MARKER_END"}}
  ```
- **Root cause:** The ZMQ RPC path logs raw untrusted request content (`MDEBUG` log level) **before** semantic validation of the request. Embedded `\n` control characters in the JSON string value are therefore written verbatim into the log file, splitting the single log record into multiple lines that look like independent log entries.
- **Impact proven:** Verified that attacker-supplied newline/control characters in the request body appear in daemon logs. This enables log forging — injecting lines like `authentication succeeded for admin` — with persistence of attacker-controlled text that SIEM and analysts ingest as trusted events.
- **Exemplar:** id=3621606 (Monero program)

### 3. Log entry destruction via delimiter column corruption (Authorization header → nginx `$remote_user`)
- **Endpoint shape / parameter:** `POST /graphql?secret=1`. The injectable field is the `Authorization` header, whose value is parsed by nginx as Basic Auth into `$remote_user`, then written into an access-log format without quoting.
- **Payload that actually fired (verbatim):**
  ```
  A:B
  ```
  — sent as the Authorization header, i.e. an extra whitespace/space delimiter inside the header value (a corrupted auth header with an added space column).
- **Root cause:** nginx's `$remote_user` (derived from the Authorization header) is written **unquoted** into the log format string. An injected whitespace character adds an extra delimiter column to the log line, so the parsed record has one more column than the schema expects.
- **Impact proven:** A request with a corrupted Authorization header caused the corresponding log entry to be **completely discarded from the ingested Events source**. This undermines incident-response and debugging conclusions — an attacker can erase their own (or any single request's) log trail.
- **Exemplar:** id=447488 (HackerOne program)

## Bypass / chain notes
- No WAF/filter-bypass chains were present in these records; the common theme is that **no sanitization existed at all** at the logging sink. Payload design therefore follows the sink's format directly:
  - For terminal sinks: lead the payload with `ESC ]2;` (OSC title set) since the username/auth fields are echoed raw.
  - For line-oriented log files: inject `\n` inside JSON string values — JSON escaping (`\\n` becomes a literal newline after JSON parsing) means the value that reaches the logger contains real control characters even though the request is valid JSON.
  - For structured/parsed log ingestion (regex or delimiter-based): a single extra unquoted column (space) is enough; you don't need full line injection — **destructive corruption is as impactful as forging**.
- Multi-step chains observed:
  - id=3621606: connect to ZMQ RPC → send `get_info` with newline-laden `note` → raw request logged verbatim, forged lines injected into logs.
  - id=447488: send Authorization with an extra space delimiter → nginx logs an extra unquoted column → log ingestion discards the whole entry.
- Note that id=3621606's logging happened **before** semantic validation — meaning even invalid/rejected requests still hit the log sink. That ordering widens the attack surface: any request that merely reaches the daemon, not just accepted ones, can inject.

## Gotchas / what NOT to do
- Don't assume the log sink is a file only. id=223363's sink was a live terminal — the proof was the window title change. Craft payloads for the actual rendering surface.
- Don't forget JSON decoding semantics: `\n` inside a JSON string is transformed to a real newline by the parser. The forged line works because the daemon logs the *decoded* value. A payload that survives as literal backslash-n text proves nothing.
- Don't overlook negative-space payloads: id=447488 used no escape sequences at all — just a whitespace in the Authorization header. Sometimes the strongest injection is one extra column, not a new line.
- Don't test on log sinks you can't observe. All three reports succeeded because the reporters could verify the effect (window title, log contents via the daemon, ingestion diff in Events source). Without an observable sink you have no impact demonstration.
- Don't claim RCE or code execution from escape sequences unless you can demonstrate it — the proven impact here was title change, log forging, and log entry destruction only.
- Payload not stated caveat: none of the three records provided a full raw HTTP request byte-for-byte beyond what's quoted above — reconstruct surrounding framing (Basic Auth base64 encoding, HTTP headers) when reproducing.

## Real-world impact examples
1. **Terminal window hijack (id=223363, Ruby/WEBrick, CVE-2017-10784):** `]2;BOOM!` injected in a Basic Auth username changed the server terminal's window title to `BOOM!` — proving raw escape-sequence execution in the operator's console, a vector for hiding attacker activity from a live administrator.
2. **Forged authentication log lines (id=3621606, Monero wallet RPC):** The verbatim payload above planted `FORGED_LOG_LINE: authentication succeeded for admin` into daemon logs, attacker-controlled text that SIEM pipelines would ingest as trusted events — a direct path to defeating forensic analysis and fabricating evidence of successful authentication.
3. **Silent log entry erasure (id=447488, HackerOne nginx):** A single extra space in the `Authorization: A:B` header caused the corresponding log entry to be wholly discarded from the ingested Events source — the attacker can request-by-request remove their footprint from the log pipeline, undermining incident-response and debugging conclusions.