---
name: hunter-l3-memory-corruption-crash
description: "Use when hunting Memory Corruption (Crash) on a target. Loads the L3 technique sheet: This class targets memory-unsafety in native interpreters/sandboxes exposed to attacker-controlled scripts — here, mruby-based sandboxing (Shopify Scripts, via the `shopify-scripts` program)."
domain: cybersecurity
subdomain: web
tags:
- web
- memory-corruption-crash
- hunting
- l3
version: '1.0'
---

# Memory Corruption (Crash) — Technique Sheet

## Overview
This class targets memory-unsafety in native interpreters/sandboxes exposed to attacker-controlled scripts — here, mruby-based sandboxing (Shopify Scripts, via the `shopify-scripts` program). When the sandbox host embeds an interpreter written in C (mruby), any segfault in the interpreter is a full denial-of-service of the sandbox service, and often signals deeper type-confusion or GC bugs that can escalate beyond DoS. These bugs pay in programs that accept arbitrary script input (scripting endpoints, plugin engines, template sandboxes) and rate the crash as valid security impact.

All four records here come from one hunter (ajaysenr) against the same target surface (mruby / mruby_engine), so the meta-lesson is: pick a single C-interpreter sandbox and fuzz/audit it systematically for crash primitives — four distinct crash classes fell out of the same surface.

## Distinct sub-patterns

### 1. Argument-count boundary condition in codegen (off-by-one at CALL_MAXARGS)
- Endpoint shape: mruby source fed to the compiler/codegen — specifically a method call with exactly 127 positional arguments (the CALL_MAXARGS boundary). No HTTP parameter; the "endpoint" is `mruby` / `mruby_engine` accepting a script.
- Payload that actually fired (verbatim): a method invocation with 127 comma-separated fixnum arguments:
  ```
  x 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  ```
  (i.e., 21 args per line × 6 lines, plus 1 on the last line = 127 args to `x`)
- Root cause: In `gen_values` (codegen), when the argument count hits exactly CALL_MAXARGS (127), the loop exits *before* creating the argument array. Downstream code then treats a fixnum as an array and dereferences a null/invalid pointer. Classic boundary-condition type confusion: 126 args is fine, 128 args is fine (array path taken), 127 is the poisoned value.
- Impact: Segmentation fault demonstrated in both `mruby` and `mruby_engine`, and reproducible in the parent MRI (Ruby) as well.
- Exemplar report IDs: 182484.
- Hunter note: Always probe exact boundary constants in interpreter internals — CALL_MAXARGS=127 here. Payload is trivial: `f <127 args>`.

### 2. Unvalidated value cast in string mutation path (mrb_str_concat / mrb_str_modify)
- Endpoint shape: mruby script exercising string concatenation with pathological syntax — heredocs, empty-string literals, and `Proc#call` via shorthand `qqq.(...)`.
- Payload that actually fired (verbatim):
  ```ruby
  def n
  if $0
  end
  ""if 00end
  qqq=Proc.new{|*x|x.join}
  qqq.("",<<000,"",
  000
  "")
  qqq.("","#{<<000}",
  000
  "")
  0[<<0000,
  #{<<0000}
  0000
  0000
  0]
  ```
- Root cause: `mrb_str_concat` casts a `mrb_value` to `RString*` without validating the value's type tag, passing an invalid pointer into `mrb_str_modify`/`check_frozen`, which dereferences it. This is raw type confusion: a non-string value reaches a string-mutation C function and is treated as an `RString*`.
- Impact: Segmentation fault (invalid memory access at address 0x1) in the mruby sandbox — denial of service of the sandbox service.
- Exemplar report IDs: 183231.
- Hunter note: The payload is deliberately syntactically mangled (weird heredoc placement, `#{...}` interpolation inside call args, trailing junk) — likely reaching an edge in the parser/parser-to-AST path that produces a malformed value. Don't assume you need clean Ruby; broken syntax that still compiles is often where interpreter invariants break.

### 3. GC marking of an invalid object-table pointer (mark_tbl / mrb_gc_mark_iv)
- Endpoint shape: mruby script that nests `Array.new` constructors with blocks, instance-variable table churn, and pathological expressions (`%` empty literals, `Array.dup.new`, range args).
- Payload that actually fired (verbatim):
  ```ruby
  t0me=%
  Array.new(9){t0me.empty?s=Array.new(9){%{}*0
  s=Array.dup.new(23)
  Array(0)}
  Array(0..6)}
  ```
- Root cause: An invalid object table pointer (`t=0x17`) is passed to `mark_tbl` during GC marking and dereferenced in `mrb_gc_mark_iv`. GC paths are a rich crash surface: anything that corrupts or desynchronizes object/iv tables gets dereferenced later during a collection.
- Impact: Segmentation fault (invalid memory access at 0x17) in mruby — denial of service of the sandbox service.
- Exemplar report IDs: 183239.
- Hunter note: Small addresses (0x1, 0x17) in the crash output are the tell — you're dereferencing a small integer masquerading as a pointer (fixnum-as-pointer confusion). Trigger allocation/GC pressure via nested `Array.new(size){...}` blocks plus parser oddities.

### 4. Aliasing Object#send over initialize (C-function call-path confusion)
- Endpoint shape: mruby script using `alias_method` to rebind `Object#send` as `initialize`, then instantiating and calling `send` on the new object.
- Payload that actually fired (verbatim):
  ```ruby
  def foo
  end

  class X
    alias_method :initialize, :send
  end

  X.new.send(:foo)
  ```
- Root cause: Aliasing `Object#send` over `initialize` makes `Class#new` (a C function) call `send` with arbitrary arguments. Invoking a Ruby method through `Object#send` under this C-driven path segfaults the mruby VM. The bug lives in the interaction between a C-level entry point (`Class#new`) and a Ruby-level method dispatch (`send`) that was never expected to be invoked from that path with that receiver state.
- Impact: Segmentation fault of the mruby VM.
- Exemplar report IDs: 183425.
- Hunter note: This is a 6-line payload — extremely cheap to test in any mruby-based sandbox. Aliasing core methods over `initialize` is a reusable template: try `alias_method :initialize, :<dangerous_builtin>` for `send`, `instance_eval`, `instance_variable_get`, etc.

## Bypass / chain notes
- No multi-step chains appear in these records — all four are single-script crash primitives (`chain: (none)` in every record). Do not invent chain patterns beyond that; the standalone-DoS impact was sufficient for each report.
- Cross-realm amplification seen in one record: the CALL_MAXARGS bug (182484) reproduced in mruby, mruby_engine, *and* the parent MRI — demonstrating the bug is in shared upstream codegen, which raises severity and report credibility.
- Crash-address fingerprinting as a validation habit across records: 0x1 (183231) and 0x17 (183239) both indicate small-integer/invalid-pointer dereference rather than a wild pointer — a strong signal in triage that you have a real type-confusion, worth reporting even before escalation analysis.

## Gotchas / what NOT to do
- Don't assume the crash must come from a "big" payload. Record 183425's segfault is 6 lines of Ruby; record 182484 is one method call with 127 zeros. Minimal, precisely-targeted payloads at known boundary constants beat blind blob-fuzzing.
- Don't ignore syntactically invalid-looking scripts. 183231 and 183239 both use mangled heredocs, `if`-modifier-after-end constructs, and `%`-literals glued to identifiers — the parser accepting near-garbage is exactly where internal invariants break.
- Don't stop at one crash. All four records are from the same hunter against the same program — after finding crash #1, enumerate other interpreter subsystems (codegen arg handling, string ops, GC marking, method dispatch/aliasing) and keep reporting distinct root causes as separate findings.
- Don't report crashes without identifying the root cause. Each record here names the exact C function (`gen_values`, `mrb_str_modify`, `mark_tbl`/`mrb_gc_mark_iv`, `Class#new`→`send`) — that's what makes these credible security reports rather than flaky fuzz noise.
- Don't conflate "crashes locally" with "accepted impact" — but note that in this program (shopify-scripts), sandbox DoS was accepted impact for each record.

## Real-world impact examples (concrete, from records)
- 182484: Segfault via a single 127-argument method call, reproduced in mruby, mruby_engine, and the parent MRI — a boundary bug in shared codegen (`gen_values` at CALL_MAXARGS).
- 183231: Segfault at invalid address 0x1 through `mrb_str_concat` → `mrb_str_modify`/`check_frozen` on a non-string `mrb_value` — DoS of the Shopify Scripts sandbox service.
- 183239: Segfault at invalid address 0x17 during GC marking (`mark_tbl` / `mrb_gc_mark_iv` dereferencing `t=0x17`) — DoS of the sandbox service.
- 183425: Segfault of the mruby VM from a 6-line `alias_method :initialize, :send` script — arbitrary-argument C-function-to-Ruby-dispatch confusion.

Every technique above is drawn strictly from these four verified records; payloads are preserved verbatim where stated, and no record omitted payload data.