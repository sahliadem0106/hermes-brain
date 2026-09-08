---
name: hunter-l3-homograph-attack
description: "Use when hunting Homograph Attack on a target. Loads the L3 technique sheet: Homograph (IDN spoofing) attacks abuse Unicode characters that render identically to ASCII — most famously Cyrillic 'а' (U+0430) inside a Latin word like \"ebay\" — to register or display lookalike domains (ebаy.com → xn--eby-7cd.com)."
domain: cybersecurity
subdomain: web
tags:
- web
- homograph-attack
- hunting
- l3
version: '1.0'
---

# Homograph Attack — Technique Sheet

## Overview

Homograph (IDN spoofing) attacks abuse Unicode characters that render identically to ASCII — most famously Cyrillic 'а' (U+0430) inside a Latin word like "ebay" — to register or display lookalike domains (ebаy.com → xn--eby-7cd.com). The bugs that pay are almost never in the registration itself; they are in *rendering and filtering layers*: a platform that displays IDNs in Unicode instead of punycode, a homograph filter with an incomplete character blocklist, or a URL handler that skips validation for certain syntax shapes ('@' userinfo, scheme-less URLs). These are consistently low-severity-to-medium phishing-enabler findings, but they recur against the same targets because fixes are repeatedly incomplete — making "bypass of a prior homograph fix" a reliable re-submission pattern.

## Distinct sub-patterns

### Sub-pattern 1: Incomplete homograph filter — one missed Unicode variant

- Endpoint shape: Any input field where the target already implemented a homograph/Unicode filter — typically domain/username/profile filters (record 268981, Legal Robot; no specific endpoint — "domain filter").
- Payload that fired: Verbatim payload not stated; the root cause was that the filter blocked most homographs but missed one homograph of a Latin 'l' character (e.g. an alternate Unicode codepoint rendering as 'l' that the blocklist didn't cover).
- Root-cause pattern: Homograph filters are character blocklists. Any blocklist built by enumerating "obvious" confusables (Cyrillic а, о, е, etc.) will miss less common homoglyphs of letters like 'l' (uppercase I, digit 1 lookalikes, alternate Latin lookalikes from other scripts). One gap = full bypass.
- Impact proven: Confirmed a lookalike-domain spoofing path remained open after the vendor's prior fix — a bypass of the existing mitigation, which is exactly what pushes severity up on re-reports.
- Exemplar: 268981 (Legal Robot).

### Sub-pattern 2: URL with '@' userinfo — validation and punycode display skipped

- Endpoint shape: Browser homepage / "custom homepage URL" setting in Brave (record 268984).
- Payload that fired (verbatim): homepage URL containing `@ebаy.com/` — i.e. an IDN hostname with a Cyrillic 'а', prefixed with `@` (userinfo delimiter).
- Root-cause pattern: The `@` in a URL denotes userinfo (`user@host`). When the user-supplied homepage URL contains `@`, the homograph validation is not applied properly — and punycode is not displayed to the user. The `@`-containing URL redirects to the punycode lookalike domain `http://xn--eby-7cd.com/`, while the visible representation stays the deceptive Unicode form.
- Impact proven: Bypassed Brave's homograph filter end-to-end: user-visible Unicode name, actual navigation to the spoofed punycode domain.
- Exemplar: 268984 (Brave Software).

### Sub-pattern 3: External-link warning pages render IDNs in Unicode, not punycode

- Endpoint shape: Any interstitial/warning page shown before navigating to an external link. Verified on HackerOne's bug-report link warning page (records 29491, 58612).
- Param: URL (in a report body / external-link warning).
- Payloads that fired (verbatim):
  - `http://ebаy.com/` (record 29491)
  - `http:ebаy.com` (record 58612 — scheme-less variant, see below)
- Root-cause pattern: The warning page's purpose is to show the user exactly where they're going. When the destination is an IDN, the page renders it in Unicode (ebаy.com) rather than punycode (xn--eby-7cd.com), so the interstitial itself becomes part of the deception — it "warns" the user with a string that looks identical to the real domain.
- Impact proven: A homograph URL renders in Unicode on the warning page, enabling phishing of HackerOne users via report links. Record 58612 confirmed the same behavior persisted after HackerOne shipped a homograph fix — the second report was explicitly a bypass of the prior fix. No data accessed in either case; impact is phishing enablement.
- Exemplars: 29491, 58612 (HackerOne).

### Sub-pattern 4: Scheme-less URL variant to evade the fix

- Endpoint shape: Same external-link warning page, but dropping the `//` after the scheme.
- Payload that fired (verbatim): `http:ebаy.com`
- Root-cause pattern: If the renderer/linkifier treats `http://` URLs through a punycode-conversion path but accepts other syntactically valid-but-odd URL forms (`http:` without `//`) through a different code path that skips conversion, a one-character change in URL syntax reintroduces the bug after the "obvious" fix. Browsers normalize `http:ebаy.com` as an external navigation, so the link still works.
- Impact proven: Working homograph URL rendered in Unicode on the warning page post-fix; phishing enablement confirmed.
- Exemplar: 58612 (HackerOne).

### Sub-pattern 5: URL shortener redirect warning skips punycode/IDN URLs entirely

- Endpoint shape: t.co shortener's redirect/malicious-URL warning page (record 37108, X/Twitter).
- Param: URL.
- Payload that fired: punycode/IDN URL (verbatim punycode string not stated in the record; the tested destination was the same class of lookalike domain).
- Root-cause pattern: t.co warns on known-malicious URLs and shows a redirect interstitial for outbound links, but the warning logic has no punycode/IDN branch — punycode URLs pass through with no redirection warning at all.
- Impact proven: No URL redirection warning is shown for punycode/IDN URLs. Demonstrated scenario: credential-phishing page on a spoofed IDN domain targeting admins. No account compromise was demonstrated — the finding is the missing warning, not a takeover.
- Exemplar: 37108 (X / xAI).

## Bypass / chain notes

- **Re-test after every fix.** Three of the five records are direct or implicit bypasses of a prior homograph fix (268981: one missed glyph; 58612: `http:` scheme-less variant surviving the fix). When a target ships a homograph mitigation, immediately re-test with: (a) every confusable glyph, not just Cyrillic а; (b) URL syntax variants (`@` userinfo, scheme-less `http:`); (c) every *rendering surface* — report bodies, warning interstitials, notification emails, browser chrome.
- **URL-syntax mutations to try against any homograph filter:**
  - `@` userinfo: `http://anything@ebаy.com/` (validated display vs. actual host diverge — fired in 268984).
  - Scheme-less: `http:ebаy.com` (fired in 58612 to survive a fix that presumably handled `http://`).
- **Chaining observed:** none of the records chain the homograph into a second bug (no chains listed). The standard claimed-but-unproven chain is homograph → attacker-controlled lookalike site → credential capture (37108 claims the scenario; no account compromise shown).
- **Rendering-surface enumeration:** the same underlying bug (Unicode display of IDNs) had to be reported separately for bug-report bodies and the external-link warning page (29491 vs. 58612). Each surface that echoes user URLs — reports, interstitials, emails, chat — is a separate finding.

## Gotchas / what NOT to do

- **Registering the lookalike domain is usually required and is itself a cost/OPSEC decision** — all five records rely on a live, resolvable punycode domain (xn--eby-7cd.com). Payload "delivery" is the target's own UI rendering your URL; you don't need to host content to prove the rendering bug, but a plausible phishing scenario strengthens severity.
- **Don't overstate impact.** In these records the honest ceiling was "phishing enablement" — records explicitly note "no account compromise demonstrated" (37108) and "no data accessed" (58612). Claiming takeover without demonstrating it weakens the report.
- **A filter fix that handles one URL form is not a fix.** If you verify `http://ebаy.com` is now punycoded, immediately try `http:ebаy.com`, `@`-prefixed forms, and uppercase/mixed-case Unicode before concluding the class is closed.
- **Don't only test Cyrillic 'а'.** Record 268981 shows the paying gap was a homograph of Latin 'l'. Sweep the full confusables set per character of the target brand (l/I/1, o/о/0, e/е, a/а, c/с, p/р, x/х, s/ѕ…).
- **Severity expectations:** these land as low-to-medium (phishing/spoofing enabler). The leverage is that they're cheap to test, and *repeat* findings against the same program as fixes leak — 2 of 5 records here are by the same hunter (ajaysenr) hitting the same bug class across 4+ programs.

## Real-world impact examples

- **Brave browser (268984):** a homepage URL set to `@ebаy.com/` bypassed the homograph filter and redirected to `http://xn--eby-7cd.com/` while punycode was never shown — a real user-facing spoof inside the browser itself.
- **HackerOne (29491, 58612):** a link in a bug report pointing at `http://ebаy.com/` rendered as Unicode on the external-link warning page, so the security interstitial itself displayed the spoofed domain. After the first fix, `http:ebаy.com` still rendered in Unicode — the fix was bypassed with a scheme-less variant.
- **X / t.co (37108):** punycode URLs received no redirect warning from t.co, enabling an admin-targeted credential-phishing scenario with a spoofed domain (no compromise demonstrated).
- **Legal Robot (268981):** the deployed homograph filter missed a single homograph of Latin 'l', leaving an open lookalike-domain spoofing path — a bypass of their existing mitigation found by testing beyond the obvious glyphs.