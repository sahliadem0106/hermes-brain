---
name: hunter-l3-insecure-deserialization
description: "Use when hunting Insecure Deserialization on a target. Loads the L3 technique sheet: Insecure deserialization is the class of bugs where application code turns attacker-controlled data (JSON, YAML, pickle, PHP serialized strings, XCom records) back into live objects or executable structures without validation."
domain: cybersecurity
subdomain: web
tags:
- web
- insecure-deserialization
- hunting
- l3
version: '1.0'
---

# Insecure Deserialization — Technique Sheet

## Overview
Insecure deserialization is the class of bugs where application code turns attacker-controlled data (JSON, YAML, pickle, PHP serialized strings, XCom records) back into live objects or executable structures without validation. Unlike most injection classes, the payload is often a structured "object graph" rather than a string, and impact ranges from object instantiation (a strong foothold) through full pre-auth RCE. It pays especially well when you can find the deserialization sink behind a low-visibility parameter (a query-args blob, a notification context, an XML-RPC field), and it chains beautifully — several of the highest-impact findings here were deserialization escalated from a second bug (SQLi, DAG-author access).

## Distinct sub-patterns

### 1. Unsafe pickle deserialization of user-reachable stored data (Python)
- Endpoint shape: any endpoint that renders data whose "context" is stored server-side and later unpickled. Concrete exemplar: `GET /notifications` (`render_notifications`), where the notification context blob is unpickled.
- Payload that actually fired (verbatim, hex-encoded pickle):
  `\x80027d710028580400000061736432710158030000006c6f6c71025801000000627103580500000033303030307104580100000063710563706f7369780a73797374656d0a7106580c000000736c656570203530303030307107857108527109752e`
  (a pickle stream whose opcodes build a `posix.system` call with the argument `sleep 5000000`)
- Root cause: notification context is deserialized with unsafe `pickle`, which executes arbitrary Python object construction — `pickle` is a code-execution format, not a data format.
- Impact proven: crafted pickle executed `sleep 5000000`, hanging the server — a demonstrated RCE primitive.
- Exemplar: id=361341 (Liberapay).
- Note the escalation shape: this was reached via a chain — SQL injection into the notifications context → poisoned pickle stored → server unpickles it on render. If you find SQLi into a table whose columns are later unpickled, immediately test pickle payloads in the injected data.

### 2. Unsafe `yaml.load()` in Python code (PyYAML)
- Endpoint shape: any code path calling `yaml.load()` (not `yaml.safe_load()`) on user-supplied YAML. Exemplar: `yaml.load()` in `testing/vcr.py` (Liberapay), parameter = the YAML document itself.
- Payload that actually fired (verbatim):
  `!!python/object/apply:os.system ["id"]`
- Root cause: `yaml.load()` without a safe Loader can construct arbitrary Python objects from the YAML document via `!!python/object/apply:` tags — direct arbitrary function invocation.
- Impact proven: confirmed arbitrary Python object construction (RCE potential). Caveat from the record: the sink was in testing/VCR code, not exploited on the live site — still accepted/valid but scope-limited.
- Exemplar: id=2467232 (Liberapay).
- Hunt tip: grep-adjacent behavior — look for YAML upload/import features, config editors, test-infrastructure endpoints exposed in production.

### 3. YAML typed-tag deserialization bridging into PHP `unserialize()` (the `!php/object` tag)
- Endpoint shape: PHP `yaml_parse()` / `yaml_parse_url()` on any YAML input. No specific endpoint in the record — the sink is the function itself.
- Payload that actually fired (verbatim):
  `yaml_parse('x: !php/object O:1:"A":0:{}')`
- Root cause: the `!php/object` YAML tag invokes PHP `unserialize()` on the tagged value, permitting instantiation of arbitrary PHP classes; destructor (`__destruct`) methods fire on teardown.
- Impact proven: destructor of class `A` invoked, confirming arbitrary class instantiation enabling code execution.
- Exemplar: id=73257 (Internet Bug Bounty).
- Key insight: YAML parsers with typed tags are deserialization sinks even when the language is "safe" — the tag smuggles a serialized-object payload inside an innocuous scalar.

### 4. PHP object injection via `unserialize()` on a request parameter (XML-RPC)
- Endpoint shape: `POST /www/delivery/adxmlrpc.php` calling the XML-RPC method `openads.spc`; parameter = `what`.
- Payload: (crafted serialized payload to the `what` param — exact bytes not stated in the record; a minimal PHP serialized object looks like `O:<len>:"<Class>":0:{}` — same grammar as the exemplar in sub-pattern 5).
- Root cause: the XML-RPC script calls `unserialize()` on the attacker-controlled `what` parameter with no validation.
- Impact proven: PHP object injection / serialization-related attacks; the reporter notes these flaws were "possibly already used to gain access to Revive Adserver instances and deliver malware to third-party sites" — i.e., real-world exploitation observed, not just theory.
- Exemplar: id=512076 (Revive Adserver).
- Hunt tip: XML-RPC endpoints are under-audited deserialization surfaces; any `unserialize()` of an XML-RPC parameter is pre-auth by nature.

### 5. PHP object injection via serialized object smuggled through "query args" (pre-auth, WordPress-style)
- Endpoint shape: `job_manager_ajax_get_listings` (wrapping `get_job_listings`); parameter = the query args passed to the AJAX handler.
- Payload that actually fired (verbatim):
  `O:8:"stdClass":1:{s:4:"test";s:5:"hello";}`
- Root cause: `get_job_listings` unserializes user-supplied input and additionally stores the serialized WP_Query result in a transient without safe handling — a double exposure: the unserialize sink itself, plus a persistence layer that re-serializes attacker-tainted data.
- Impact proven: pre-auth unserialization of user-supplied input; with a suitable gadget chain or a vulnerable PHP version this spans "multiple vulnerabilities from XSS to RCE."
- Exemplar: id=308489 (Automattic).
- Hunt tip: this is the classic POP-chain shape. The `stdClass` payload is a safe proof-of-concept (harmless class) — use it to prove the sink is reachable pre-auth, then enumerate available gadget chains in the codebase for escalation.

### 6. Deserialization of trusted-worker data bypassing a safety flag (Apache Airflow XCom)
- Endpoint shape: not a single endpoint — the XCom datastore plus any consumer: a victim task that deserializes XCom data, or the web `xcomEntries` endpoint where an authenticated web user triggers deserialization.
- Payload: (none stated — the record describes the poisoning technique, not literal bytes).
- Root cause: poisoned XCom data bypasses the `enable_xcom_pickling=False` protection; deserialization of that poisoned data still occurs, so the flag-as-defense fails.
- Impact proven: RCE scenarios described and accepted (CVE-2023-50943).
- Exemplar: id=2334460 (Internet Bug Bounty).
- Chain (verbatim from record): attacker task poisons XCom data → bypass `enable_xcom_pickling=False` protection → victim task or authenticated web user deserializes poisoned data.
- Key insight: a config flag disabling pickling is not a fix if poisoned data can still enter the store through another path. Attack the trust boundary between tenants/roles (DAG author vs. worker vs. web user), not just the flag.

### 7. Unsafe JSON deserialization in a library consumer (Ruby/Kredis)
- Endpoint shape: (none — library-level). Any app passing untrusted input to Kredis, which JSON-deserializes it into typed structures.
- Payload: (none stated).
- Root cause: Kredis JSON deserialization trusted untrusted data, allowing deserialization of unexpected objects (CVE-2023-27531; fixed in 1.3.0.1).
- Impact proven: crafted JSON processed by Kredis results in deserialization of unexpected objects in the system.
- Exemplar: id=2071554 (Internet Bug Bounty).
- Key insight: even "JSON" is in scope — when a library maps JSON onto typed native objects (Ruby symbols/objects), attacker-shaped JSON can instantiate structures the developer never intended. Audit library boundaries, not just first-party code.

## Bypass / chain notes
- Config-flag bypass: `enable_xcom_pickling=False` was defeated by poisoning data upstream of the flag (id=2334460). Lesson: deserialization defenses applied at one consumption point are bypassed if attacker data reaches the same sink via a different writer.
- Second-order delivery via SQLi: SQL injection used to plant a pickle payload into a stored context that the app later unpickles (id=361341). Pattern: injection → storage → deserialization sink. If you can write to any column that feeds `pickle.loads`/`unserialize`/`yaml.load`, you own the sink regardless of where the parameter appears.
- Trust-role chains: DAG author (not anonymous attacker) poisons data; victim is a worker task or authenticated web user. Report these as privilege-escalation chains — "low-privilege role A to RCE on role B" is the accepted framing.
- Tag smuggling across languages: `!php/object` inside YAML converts a YAML parser call into a PHP `unserialize()` call (id=73257); `!!python/object/apply:` converts YAML parse into Python function invocation (id=2467232). Typed tags are the universal bridge.
- Persistence layer exposure: `get_job_listings` both unserializes input directly AND writes the serialized WP_Query result to a transient (id=308489) — cached serialized attacker data can extend the blast radius to other code paths that read the transient.

## Gotchas / what NOT to do
- Don't stop at "it's in test code": the Liberapay `yaml.load()` in `testing/vcr.py` was a valid finding but explicitly not exploited on the live site. Report scope honestly — confirm whether the sink is reachable in production before claiming RCE.
- Don't assume JSON is safe: Kredis JSON deserialization was a CVE. "We only parse JSON" is not a defense.
- Don't treat a disabled-flag as a fix: the XCom pickling flag was bypassable. Verify the full data-flow into the sink, including other writers.
- Use harmless proof-of-concept classes first: the accepted PHP PoC was `O:8:"stdClass":1:{...}` — a benign stdclass, not a dangerous gadget. Prove reachability, then discuss gadget-chain potential rather than detonating destructive payloads.
- Destructive payloads prove impact but break things: the pickle `sleep 5000000` hung the server. A short sleep (e.g. 5–10s) demonstrates execution with far less damage; time-based proof is the standard.
- Scope-limitation honesty matters: the Revive Adserver record notes impact "possibly already used" by attackers — hedged language for observed-in-the-wild exploitation is acceptable; unverified certainty is not.

## Real-world impact examples
- RCE primitive via pickle: crafted notification-context pickle executed `sleep 5000000`, hanging the Liberapay server (id=361341) — escalated from SQL injection.
- Arbitrary Python object construction: `!!python/object/apply:os.system ["id"]` confirmed against `yaml.load()` (id=2467232).
- Arbitrary PHP class instantiation: `!php/object` tag in YAML triggered a destructor, confirming code-execution potential (id=73257).
- Pre-auth PHP object injection: serialized object accepted through the job-listings AJAX query args, with XSS-to-RCE potential given a gadget chain (id=308489); and via the `what` param of `openads.spc`, with real-world instance compromise and malware delivery to third-party sites suspected (id=512076).
- RCE in Airflow: poisoned XCom data deserialized by victim task or via `xcomEntries` despite `enable_xcom_pickling=False` (CVE-2023-50943, id=2334460).
- Library-level object deserialization: crafted JSON against Kredis deserializing unexpected objects (CVE-2023-27531, id=2071554).