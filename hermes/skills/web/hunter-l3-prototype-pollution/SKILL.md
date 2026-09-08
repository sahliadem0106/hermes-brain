---
name: hunter-l3-prototype-pollution
description: "Use when hunting Prototype Pollution on a target. Loads the L3 technique sheet: Prototype pollution is the injection of arbitrary properties onto `Object.prototype` (or another object's prototype) by abusing recursive merge/deep-copy, path-setter, or config-parsing routines that "
domain: cybersecurity
subdomain: web
tags:
- web
- prototype-pollution
- hunting
- l3
version: '1.0'
---

# Prototype Pollution — Technique Sheet

## Overview
Prototype pollution is the injection of arbitrary properties onto `Object.prototype` (or another object's prototype) by abusing recursive merge/deep-copy, path-setter, or config-parsing routines that fail to guard the `__proto__` and `constructor.prototype` keys. Once polluted, every object in the process inherits the injected property — flipping application option flags, corrupting defaults, overwriting `toString`/`valueOf`, or reaching gadget functions that turn the pollution into XSS or RCE. It pays in Node.js third-party module programs (where proof-of-concept property injection on a known-vulnerable library is the accepted bar) and in real web apps wherever attacker-controlled JSON reaches a merge sink (e.g. Mermaid directives in GitLab issue descriptions).

## Distinct sub-patterns

### 1. Deep-merge/deep-extend sink via `__proto__` key (the canonical pattern)
- Endpoint shape: any function or API that passes attacker JSON to a recursive merge — `merge({}, input)`, `extend(true, {}, input)`, `deepExtend({}, input)`, or HTTP endpoints like `POST /api/v1/data` whose body is merged server-side.
- Payload (verbatim, recurring across many reports):
  `{"__proto__": {"polluted":"yes"}}` / `{"__proto__": {"isAdmin": true}}` / `{"__proto__": {"abc": "Injected value through dataset"}}`
  JS form: `merge({}, JSON.parse('{"__proto__":{"oops":"It works !"}}'))`
- Root cause: the merge routine recursively assigns source properties onto the target without blocking `__proto__`, so assignment writes through the live prototype reference onto `Object.prototype`.
- Impact proven: `{}.polluted`, `{}.oops`, `{}.isAdmin`, or `{}.devMode` returns the injected value on every object (e.g. `console.log({}.isAdmin) // true`); at minimum guaranteed DoS by overwriting `toString`/`valueOf`, RCE/property injection application-dependent.
- Exemplars: 310446 (deap), 310706 (merge-object), 310707 (assign-deep), 310708 (merge-deep), 381185 (extend), 381194 (merge.recursive), 430831 (node.extend), 438274 (smart-extend), 439098 (mergify), 439107 (lutils-merge), 439120 (upmerge), 878339 (extend-merge), 454365 (jQuery `$.extend` deep), 864701 family.

### 2. `constructor.prototype` as the pollution vector (filter-evasion form)
- Endpoint shape: same merge sinks, but payload uses `constructor` instead of `__proto__` — critical when the sink blacklists `__proto__` only.
- Payload (verbatim): `{"constructor": {"prototype": {"isAdmin": true}}}` and `{ "constructor": { "prototype": { "polluted": true } } }`
- Root cause: `obj.constructor` resolves to `Object`, so `obj.constructor.prototype` is `Object.prototype` — recursive copy descends through it just like `__proto__`. In i18next (968355), `deepExtend` explicitly blacklisted `__proto__` but NOT `constructor`, so this payload defeated the existing fix.
- Impact proven: `isAdmin=true` injected onto `Object.prototype` (`console.log({}.isAdmin) // true`); in i18next the proof printed "Object is polluted" — DoS/XSS/RCE potential.
- Exemplars: 380873 (lodash merge/mergeWith/defaultsDeep), 380878 (defaults-deep), 430291 (just-extend), 968355 (i18next.addResourceBundle).

### 3. Path-based setters writing through dotted paths
- Endpoint shape: libraries that accept a *string path* to set a value: `set(obj, path, val)`, `mpath.set(path, val, obj)`, `ts-dot-prop set()`, `property-expr setter()`, lodash `set`/`setWith`/`zipObjectDeep`.
- Payloads (verbatim):
  - `mpath.set('__proto__.x', ['hilarious', 'fruity'], obj);` (310860 → id 390860)
  - `tsDot.set(obj, '__proto__.isAdmin', true);` (980599)
  - `expr.setter('constructor.prototype.isAdmin')(obj,true)` (910206)
  - `lod.setWith({}, "__proto__[test]", "123")` and `lod.set({}, "__proto__[test2]", "456")` (864701 — note bracket-notation path form)
  - `_.zipObjectDeep(['__proto__.z'],[123])` (712065)
- Root cause: path parsers split the string into keys (`__proto__`, `.x`, bracket `[test]`, or `constructor.prototype`) and resolve each segment on the object without validating that intermediate keys are own properties or that the path terminates before the prototype chain.
- Impact proven: `obj.isAdmin` changed `undefined → true`; `test`/`test2` present on `Object.prototype`; global `z === 123`; "guaranteed server crash/DoS and potentially RCE".
- Exemplars: 390860, 910206, 980599, 864701, 712065.

### 4. Config/directive JSON parsed and merged by an embedded renderer (app-level)
- Endpoint shape: `POST /{namespace}/{project}/issues` (GitLab) — Mermaid diagram syntax in the issue description carries an `init` directive whose JSON is merged into the renderer config.
- Payload (verbatim): `%%{init: { '__proto__': {'polluted': 'asdf'}} }%%`
- Root cause: the Mermaid directive JSON object is merged into the config without sanitization; `'__proto__'` overwrote `Object.prototype` for every new object in the renderer.
- Impact proven: the issue page on gitlab.com (and a local instance) broke — users could not comment or edit comments (real, user-visible DoS on production).
- Exemplar: 1106238.

### 5. Inheritance-of-key writes in module APIs (implicit sink, no merge function)
- Endpoint shape: event-handler / module APIs that write object keys from caller-controlled identifiers — `noble.onServicesDiscover(peripheralUuid, serviceUuids)`, Chart.js merge helper `helpers.core.js _merger` (dataset/options).
- Payload (verbatim): `try { noble.onServicesDiscover("__proto__", "x"); } catch(e) {}` — Chart.js: `{"__proto__": {"abc": "Injected value through dataset"}}` passed as dataset.
- Root cause: module writes keys onto objects (or recursively merges dataset properties) without validating they are own properties or blocking prototype keys. In noble, the attacker-controlled `peripheralUuid` is used as a key; strong evidence values are controllable remotely over Bluetooth.
- Impact proven: arbitrary properties on `Object.prototype`; Chart.js pollution "for some applications leads to XSS".
- Exemplars: 390857 (noble), 776371 (Chart.js).

### 6. Client-side pollution via jQuery `$.extend`
- Endpoint shape: pages/app code paths that deep-extend option objects with a named `__proto__` property.
- Payload (verbatim): `{"__proto__": {"devMode": true}}`
- Root cause: deep `$.extend` merges the named `__proto__` property onto `Object.prototype`.
- Impact proven: `{}.devMode === true`, changing default values for option functions across the application (logic tampering in the browser).
- Exemplar: 454365.

## Bypass / chain notes
- `__proto__` filtered? Use `constructor.prototype` — verified against i18next's `deepExtend`, which blacklisted only `__proto__` (968355). The same dual-payload habit applies everywhere: test `{"__proto__":{...}}` and `{"constructor":{"prototype":{...}}}` against every merge sink.
- Path-notation variants: dotted (`__proto__.isAdmin`), bracket (`__proto__[test]`), and multi-key (`_.zipObjectDeep(['__proto__.z'],[123])`) forms all fire against path setters — switch notation when one is normalized/escaped.
- The pollution itself is step one; the records show impact is realized by (a) overwriting `toString`/`valueOf` → guaranteed DoS, (b) flipping option/flag defaults (`devMode`, `isAdmin`) → logic change/auth bypass, (c) chaining polluted properties into an app's render/template gadget → XSS (776371, Chart.js), (d) RCE "in some cases" depending on downstream gadget libraries.
- In the GitLab case, the "endpoint" was a content field (issue description) — the sink was client/server code parsing embedded directive JSON. When testing an app, look for any field whose value gets fed into a parser that merges config (Mermaid, charting libs, i18n bundles).

## Gotchas / what NOT to do
- Don't report pollution in isolation without demonstrating where the property lands: the accepted proof pattern in these reports is a before/after check — `console.log(a.oops)` before, call sink, `console.log(a.oops)` after showing the inherited value.
- Don't assume one fixed payload covers all sinks: `deepCopy`/`deepExtend` (1001218), `deap.merge` (310446), `extend.deep()` (438274), `json8-merge-patch.apply()` (980649 — payload `'{ "__proto__": { "isAdmin": true }}'`), and `ts-dot-prop.set()` each needed their own invocation shape.
- Don't test only `__proto__` — the `constructor.prototype` bypass was the difference between filtered and accepted in the i18next case.
- Don't stop at "could theoretically lead to RCE": reports that showed concrete injection (property visible on all objects, app page breakage in GitLab) are the strong ones; DoS claims via `toString`/`valueOf` overwrite should be stated as the guaranteed minimum.
- Don't overlook non-HTTP surfaces: the class covers library-level (no endpoint), Bluetooth-driven (noble), and user-content-driven (Mermaid) sinks.
- Avoid relying on `Object.prototype` being writable in frozen/hardened runtimes — these records are all unhardened Node/browser contexts; the technique sheet's payload assumes standard objects.

## Real-world impact examples
- GitLab production DoS (1106238): a single Mermaid directive in an issue description broke commenting/editing on gitlab.com issue pages — pollution propagated through the shared renderer config for every new object.
- Property injection on every object (380873, 381185, 430831, etc.): `console.log({}.isAdmin) // true` after one merge call — authentication/authorization flags and feature toggles (`devMode`) become attacker-settable.
- Guaranteed DoS primitive (310446 et al.): overwriting inherited `toString`/`valueOf` crashes server code that calls them on plain objects; lodash `zipObjectDeep` report (712065) characterized it as "guaranteed server crash".
- XSS chain potential (776371): Chart.js dataset pollution put attacker strings on `Object.prototype` where applications consuming them as template/config values rendered them — XSS in some apps.
- Cross-cutting library coverage: the same `{"__proto__":{"polluted":"yes"}}`-style payload was proven against ~15 distinct npm packages (firebase/util, deap, merge-object, assign-deep, merge-deep, extend, merge, just-extend, node.extend, smart-extend, mergify, lutils-merge, upmerge, extend-merge, json8-merge-patch), showing the vulnerability is a shared root-cause pattern (unguarded recursive assignment), not a per-package quirk.