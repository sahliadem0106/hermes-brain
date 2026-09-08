---
name: hunter-l3-type-confusion
description: "Use when hunting Type Confusion on a target. Loads the L3 technique sheet: Type confusion is a memory-corruption or logic-flaw class where a value of one type is treated as another — a tagged union dereferenced with a bogus tag, an object stored without type validation, or a"
domain: cybersecurity
subdomain: web
tags:
- web
- type-confusion
- hunting
- l3
version: '1.0'
---

# Type Confusion — Technique Sheet

## Overview
Type confusion is a memory-corruption or logic-flaw class where a value of one type is treated as another — a tagged union dereferenced with a bogus tag, an object stored without type validation, or a class looked up by name and swapped for a different type. In web-facing bug bounty it appears two ways: (1) C-level type confusion in interpreters/parsers (Python C extensions, PHP extensions, WDDX, libsass, mruby) that yields crashes and potentially RCE, and (2) application-level "type confusion" where a permission or type check is missing so an object of the wrong kind is accepted (GraphQL gid handling, unsafe params iteration). The memory-corruption variants pay in lower-level programs (Internet Bug Bounty); the app-level variants pay in mass-market web apps (GitLab, Rails) and are far easier to weaponize.

## Distinct sub-patterns

### 1. Unvalidated exception/type restore → wrong-typed object stored (Python C internals)
- Endpoint shape: CPython internal APIs, not a network endpoint. `Modules/_asynciomodule.c` `FutureIter_throw()`.
- Payload: not stated (POCs named `POC2`; attack is calling `throw` with attacker-supplied `type`/`val`/`tb` args).
- Root cause: `FutureIter_throw()` passes unchecked `type`, `val`, `tb` arguments straight to `PyErr_Restore()`, which stores them as the current exception without validating that `type` is actually an exception type. Later consumption by `PyErr_Fetch()` assumes a valid exception object → type confusion.
- Impact: Segmentation fault (crash) demonstrated via POCs; POC2 shows attacker-controlled `tp_repr` function-pointer overwrite — arbitrary code execution plausible but not fully proven.
- Exemplars: id=182169.

### 2. Type confusion in attribute setters (pyexpat xmlparse_setattro)
- Endpoint shape: Python `pyexpat` extension — `xmlparse_setattro` (attribute assignment on the parser object).
- Payload: not stated.
- Root cause: type confusion in the setattr path lets one object type be treated as another during attribute assignment.
- Impact: memory-corruption-class bug in CPython's XML parser (bugs.python.org issue 25019); resolved.
- Exemplars: id=104000.

### 3. Type confusion in JSON encoder (EIP control)
- Endpoint shape: Python `json` module encoder objects.
- Param: json encoder objects (attacker-supplied custom encoder hooks).
- Payload: not stated (PoC named `eip.py`).
- Root cause: a type confusion during JSON encoding lets an attacker corrupt the object graph and gain control of EIP — the encoder calls back into attacker-controlled object types without validating the C-level contract.
- Impact: demonstrated EIP control via `eip.py`; arbitrary code execution potential.
- Exemplars: id=112855.

### 4. Type confusion in PHP extension option/serialization paths
Two related sub-cases in PHP's C layer:
- `SoapClient::serialize_function_call()`: type confusion during SOAP function-call serialization → RCE (PHP bug 70388, CVE-2015-6836). Exemplar: id=104010.
- `curl_setopt_array()`: mishandles the types of option values — passing wrong-typed values through the array → type confusion (bug 70163). Exemplar: id=104015.
- Payloads: not stated for either.
- Root cause (shared): PHP C functions that consume option/argument arrays or user objects trust the incoming zval types and reinterpret them as expected internal types.
- Impact: RCE proven for the SOAP case; memory-corruption class for curl_setopt_array.

### 5. Deserialization-driven type confusion (PHP WDDX)
- Endpoint shape: PHP `wddx` deserialization — crafted WDDX XML packet fed to a deserializing application.
- Payload: not stated (crafted WDDX packet).
- Root cause: deserializing a crafted WDDX packet causes a type confusion — the deserializer constructs values whose C types don't match what downstream code expects.
- Impact: type confusion in WDDX packet deserialization (PHP bug #71335).
- Exemplars: id=114339.

### 6. Exception-class redefinition by name (mruby / shopify-scripts)
- Endpoint shape: mruby script sandbox (mruby-engine). Class/exception names resolved by string lookup at runtime.
- Payload (verbatim):
  ```
  NotImplementedError = String
  Module.constants # mrb_raise(mrb, E_NOTIMP_ERROR, "Module.constants not implemented");
  ```
- Root cause: `E_*_ERROR` exception types are looked up by name and never validated as exception types. Redefining one as a non-exception (`String`) means `mrb_exc_set` treats a wrong-typed object as an exception, corrupting memory.
- Impact: native crash in mruby-engine; reporter states memory corruption and arbitrary-code-execution potential (RCE not demonstrated).
- Exemplars: id=185041.

### 7. Class-redefinition via name lookup at use site (mruby Decimal)
- Endpoint shape: mruby script sandbox (mruby-engine).
- Payload (verbatim):
  ```
  olddecimal = Decimal.new(1)
  Decimal = Hash
  a = -olddecimal
  puts a
  ```
- Root cause: `wrap_decimal` looks up the `Decimal` class by name at runtime; redefining `Decimal` as `Hash` makes a numeric operation act on a wrong-typed object, corrupting memory.
- Impact: native crash in mruby-engine; memory corruption / ACE potential indicated (exploit not provided).
- Exemplars: id=185051.

### 8. Tagged-union tag corruption (LibSass parser state)
- Endpoint shape: `libsass` parser; crash reached via a malformed `.swf`-style input file processed by `sassc` (PoC named `PoC.swf`).
- Payload: not stated in detail — PoC file `PoC.swf` (crashes sassc in libsass).
- Root cause: a tagged union in the `Sass::ParserState` copy constructor was misinterpreted, dereferencing an invalid tag value (`$0x8`, a bogus tag).
- Impact: sassc crashed mid-run by dereferencing the bogus tag — memory-unsafe dispatch on wrong type.
- Exemplars: id=66724.

### 9. Missing type check on a polymorphic identifier (GitLab GraphQL gid)
- Endpoint shape: `POST /-/graphql-explorer` — `deleteAnnotation` mutation.
- Param: `id` (GraphQL global ID / gid).
- Payload (verbatim):
  ```
  mutation { deleteAnnotation(input: {id: "gid://Gitlab/Project/<project-id>"}) { clientMutationId } }
  ```
- Root cause: `deleteAnnotation`'s `find_object` lacked a type check, so a Project gid passed the annotation permission check (Developer role is sufficient for annotations), allowing deletion of arbitrary objects of the wrong type.
- Impact: A Developer deleted a project and its repository that they were not authorized to delete — the project disappeared entirely.
- Exemplars: id=292797 (wait — that's the Rails one; the GitLab record is id=960244).

Correction: exemplar is id=960244 (GitLab).

### 10. Iteration returning wrong-typed/unpermitted object (Rails Strong Parameters)
- Endpoint shape: any Rails controller iterating `ActionController::Parameters` — e.g. `params.each {}`.
- Payload (verbatim, response observed):
  ```
  params.each {}
  => {"city"=>"Nijmegen", "country"=>"Netherlands", "language"=>"Dutch"}
  ```
- Root cause: `.each` on `ActionController::Parameters` returns an unsafe (unpermitted) hash of all params, unlike `to_h`, which enforces strong-parameters permitting. Code that iterates instead of converting via `to_h` operates on a differently-trusted object than intended — the "wrong type" here is the unpermitted variant.
- Impact: attacker sends extra parameters (e.g. `is_admin:true`) that bypass authorization checks when a controller iterates params with `.each`.
- Exemplars: id=292797 (Ruby on Rails program).

## Bypass / chain notes
- Name-lookup redefinition chain (mruby): the exploit is entirely a two-step chain — (1) rebind the well-known constant to a benign-but-wrong type (`NotImplementedError = String`, `Decimal = Hash`), (2) trigger the code path that looks the name up and assumes the type. No filter evasion needed; the bypass is that runtime name lookup is treated as a type guarantee.
- Unchecked-argument chain (CPython): attacker-controlled `throw(type, val, tb)` → `PyErr_Restore` stores non-exception `type` → `PyErr_Fetch` later consumes it under a valid-exception assumption → function-pointer confusion (`tp_repr`) → potential ACE. The permission boundary bypassed is Python's own exception-object invariant, not an auth check.
- GraphQL gid chain (GitLab, 4 steps as recorded): (1) Add target user as Developer (lowest privileged paid role in many orgs); (2) Execute `deleteAnnotation` mutation with a Project gid; (3) permission check passes because it only validates the annotation-level role requirement; (4) Project and repository are deleted. The missing type check means any gid type could be substituted — the same shape likely generalizes to other mutations with polymorphic `id` inputs.
- Strong-params bypass chain: attacker appends an extra key to a normal form POST (`is_admin=true`); server-side `.each`-based iteration hands the whole unpermitted hash to downstream logic that trusts it. Defense (`to_h` with `permit`) is skipped precisely because `.each` works — no error, no warning.
- No input-filter bypasses (WAF, encoding) appear in these records; the "bypasses" here are all invariant/assumption bypasses.

## Gotchas / what NOT to do
- Don't stop at the crash. For the interpreter-level bugs (mruby, pyexpat, WDDX, LibSass, curl_setopt_array), reporters showed a segfault and asserted RCE; only the PHP SOAP one had RCE accepted (CVE-2015-6836). A clean crash PoC is a valid report, but if you claim RCE, show the mechanism (function-pointer overwrite, controlled address) — and label unproven steps as unproven, as id=182169 did ("may lead to arbitrary code execution (not fully proven)").
- Don't look for type confusion only in exotic parsers. The GitLab finding (id=960244) needed nothing but the GraphQL explorer and a Developer account — check every mutation whose input is a gid/ID for a missing type check on `find_object`.
- Don't assume `.each` vs `to_h` matters only stylistically. `params.each` silently returns unpermitted data; testing is as simple as adding one extra param (`is_admin=true`) to a normal request and observing whether it lands in downstream state.
- Don't test name-redefinition bugs (mruby/shopify-scripts) on shared production engines — these corrupt native memory and crash the engine process; run them in your own sandbox instance.
- Don't expect a documented payload format for the C-level bugs; several records state "payload not stated" and instead shipped a PoC file or script (`eip.py`, `PoC.swf`, POC2). Reproduce from the PoC artifact, not from a payload string.
- Don't confuse this class with plain NULL-deref crashes: LibSass's crash was specifically a bogus tagged-union tag (`$0x8`) — the report's value is showing the misinterpreted type, not just the signal.

## Real-world impact examples
- RCE in PHP core: type confusion in `SoapClient::serialize_function_call()` during SOAP function-call serialization led to remote code execution, resolved as CVE-2015-6836 (id=104010).
- EIP control in Python: `eip.py` PoC demonstrated instruction-pointer control via JSON-encoder type confusion — a direct path to arbitrary code execution (id=112855).
- Attacker-controlled function pointer: POC2 for the asyncio `FutureIter_throw()` bug showed `tp_repr` overwritten with attacker-controlled data (id=182169).
- Full project deletion as a Developer: on GitLab, a low-privileged Developer used `deleteAnnotation` with a Project gid to delete a project and its repository they were not authorized to delete — permanent data loss through a one-line missing type check (id=960244).
- Authorization bypass in Rails: extra `is_admin:true` parameters flow through `params.each` past strong-parameters enforcement (id=292797).
- Sandbox escapes in mruby-engine: two independent constant-redefinition PoCs (`NotImplementedError = String`, `Decimal = Hash`) caused native crashes in the hosted engine, indicating memory corruption and claimed ACE potential (ids 185041, 185051).