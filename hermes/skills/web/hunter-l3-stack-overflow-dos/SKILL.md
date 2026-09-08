---
name: hunter-l3-stack-overflow-dos
description: "Use when hunting Stack Overflow (DoS) on a target. Loads the L3 technique sheet: This class is recursive-descent / recursive-algorithm stack exhaustion: a parser (or recursive fill routine) recurses once per element of attacker-controlled nesting depth with no depth limit, so a sm"
domain: cybersecurity
subdomain: web
tags:
- web
- stack-overflow-dos
- hunting
- l3
version: '1.0'
---

# Stack Overflow (DoS) — Technique Sheet

## Overview

This class is recursive-descent / recursive-algorithm stack exhaustion: a parser (or recursive fill routine) recurses once per element of attacker-controlled nesting depth with no depth limit, so a small input (hundreds to a few thousand nested tokens) blows the fixed-size call stack and crashes the process. It pays when the recursive code runs in a shared or long-lived service — a daemon (monerod), an image-processing library (PHP GD) reachable through app file-upload pipelines, or a compiler/parser exposed via CLI or CI — because a single few-hundred-byte payload takes down the whole process rather than one request.

## Distinct sub-patterns

### 1. Deeply nested brackets `[[[[...` against a JSON/RPC parser (daemon crash)

- Endpoint shape: the daemon's JSON-RPC endpoint — e.g. `monerod` JSON-RPC (POST body is parsed by the node's built-in JSON parser). Parameter: the top-level JSON body itself.
- Payload (verbatim): `[[[[[[[[...` (unterminated run of `[` characters — the recorded payload is an open-bracket repetition ending mid-stream; the report chain did not require well-formed JSON). Root pattern: a long run of `[` optionally closed by a matching run of `]` at the end (record shows ~190 open brackets followed by ~80 close brackets in the writeup payload).
- Root cause: the JSON parser does not check object/array tree depth while parsing nested structures — each `[` adds a C-level stack frame.
- Impact: stack overflow / crash of `monerod` (full daemon DoS); reporter noted potential for arbitrary code execution from uncontrolled stack overwrite.
- Exemplar: id=390499 [ajaysenr] (Monero).

### 2. Deeply nested brackets `[[[[...` against a CSS/SCSS bracket-list parser

- Endpoint shape: parser CLI fed stdin — `sassc -s` (LibSass). Parameter: none (stdin SCSS source).
- Payload (verbatim): `@H#{[[[[[[...` — i.e. a selector/interpolation prefix `@H#{` followed by a long unbroken run of `[` (hundreds of `[` in the report).
- Root cause: the parser recurses `parse_value -> parse_bracket_list -> parse_factor -> parse_operators -> parse_expression` for every nested `[` with no recursion-depth limit, so each bracket costs a full call cycle across five functions — stack runs out fast.
- Impact: ASan confirms stack-overflow during parse; `sassc` aborts (process DoS).
- Exemplar: id=221260 [ajaysenr] (LibSass).

### 3. Deeply nested parentheses `((((...` in a value/expression parser

- Endpoint shape: same parser CLI, stdin compile — `sassc` with SCSS on stdin. Parameter: the SCSS source text.
- Payload (verbatim): `/**/0{i:((((((((...` — a comment, a token, a map key context (`{i:`), then a long run of `(` with no closing parens (the recorded payload is unterminated; closing is unnecessary — the crash happens while descending).
- Root cause: deeply nested parenthesized expressions cause unbounded recursion in `parse_map`/`parse_factor` chain — every `(` recurses into factor/expression parsing again with no depth cap.
- Impact: ASan reports stack-overflow in parser recursion; `sassc` aborted (crash).
- Exemplar: id=221292 [ajaysenr] (LibSass).

### 4. Invalid color argument triggering unbounded recursion in a graphics primitive (library DoS)

- Endpoint shape: `imagefilltoborder()` from PHP's GD extension on a **truecolor** image. Parameter: `color`.
- Payload (verbatim): `-2` — a color value outside the valid range.
- Root cause: the invalid color makes `gdImageFillToBorder` fail its termination conditions; the flood fill recurses on neighbors via y+1/y-1 (and equivalents) and never terminates on truecolor images, so calls nest until the stack is exhausted.
- Impact: stack exhaustion → process crash; fixed in PHP 5.6.28.
- Chain (verbatim from record): (1) call `imagefilltoborder` on a truecolor image with an invalid color, (2) recursive y+1/y-1 calls never terminate, (3) process stack overflow.
- Exemplar: id=190863 [ajaysenr] (Internet Bug Bounty / PHP).

## Bypass / chain notes

- Termination is not required: in all three parser cases the payload is **unterminated** (unclosed `[`/`(`). The crash occurs during the descending recursion, so don't waste time balancing delimiters — but the Monero record shows closing brackets also work (open run + shorter close run).
- Depth threshold is small: the recorded payloads are on the order of a few hundred nesting characters. If a first attempt doesn't crash, scale depth up (e.g. 1k–100k chars) rather than changing the technique.
- Trigger context matters: for the parser cases the nesting must sit in a spot the recursion actually descends into — e.g. `@H#{` prefix (interpolation/bracket-list context) or `/**/0{i:` (map-value context). Bare `((((` outside a value position may be rejected lexically; wrap it as in the recorded payloads.
- The GD pattern is a **library-level bug chained via app features**: any web app that processes user-uploaded images with PHP GD (thumbnails, avatars) is a delivery vector — the "endpoint" there is the app's upload/processing route, with the crafted image (truecolor + fill using color `-2`) as the payload.
- Parser DoS in a CLI tool chains into CI/CD or dev pipelines: repos with `.scss` assets compiled at build time are attack surface for the LibSass patterns (a malicious style file in a PR = builder DoS).

## Gotchas / what NOT to do

- Don't assume input validation helps the target: none of these payloads are "malformed" in a way the target rejects pre-recursion — they're lexically fine; the bug is missing depth checks, not missing syntax checks.
- Don't test recursion-depth crashes without a memory sanitizer available if you need to demonstrate *severity*: the LibSass records relied on ASan stack-overflow reports as evidence. A plain segfault is still valid, but ASan output makes root cause and crash site unambiguous.
- Don't conflate this class with allocation-based DoS: the payloads here are tiny (hundreds of bytes). If your payload is megabytes, you're probably testing the wrong sub-pattern.
- For the GD case, the image must be **truecolor** — the recursion non-termination is specific to truecolor images; a palette image with the same invalid color is not the recorded bug.
- Note the recursion path differs per parser (LibSass: five-function cycle; GD: self-recursive fill) — but the reportable root cause is the same generic shape: "no recursion-depth limit on attacker-controlled nesting".
- The Monero reporter flagged potential RCE from the stack overflow; treat that as a severity argument in the report, not as a demonstrated impact — the proven impact was daemon crash.

## Real-world impact examples

- Monero (id=390499): a payload of nested `[` characters sent to `monerod`'s JSON-RPC caused a stack overflow and crash of the node daemon — full network-node DoS from a few hundred bytes, with reporter-noted RCE potential.
- PHP GD (id=190863, Internet Bug Bounty): `imagefilltoborder()` with color `-2` on a truecolor image caused unbounded recursive `gdImageFillToBorder` calls and stack exhaustion — crash in the PHP core imaging extension, patched in PHP 5.6.28. Any PHP application exposing GD-based image processing to users inherits the crash.
- LibSass (id=221260, id=221292): two distinct input shapes — nested `[[[[...` (bracket lists) and nested `((((...` (parenthesized expressions) — both caused ASan-confirmed stack overflows and `sassc` abort via the parser's unlimited recursion (`parse_value → parse_bracket_list → parse_factor → parse_operators → parse_expression`, and `parse_map`/`parse_factor` respectively). Two separate reports to the same parser from the same researcher, because each recursive grammar production is its own independent bug.