---
name: hunter-l3-tabnabbing
description: "Use when hunting Tabnabbing on a target. Loads the L3 technique sheet: Tabnabbing is a reverse-tabnabbing bug class where a target application opens attacker-controlled links in a new tab without `rel=\"noopener\"` (or `rel=\"noreferrer\"`)."
domain: cybersecurity
subdomain: web
tags:
- web
- tabnabbing
- hunting
- l3
version: '1.0'
---

# Tabnabbing — Technique Sheet

## Overview
Tabnabbing is a reverse-tabnabbing bug class where a target application opens attacker-controlled links in a new tab without `rel="noopener"` (or `rel="noreferrer"`). The newly opened attacker page retains a live DOM reference to the originating tab via `window.opener` and can silently redirect, replace, or phish against the original session's tab. It pays on any feature that renders user- or external-supplied URLs as clickable links — profile fields, work samples, rich-text content, and "external link" openers — and is trivially demonstrable with a one-line payload.

## Distinct sub-patterns

### 1. Centralized "external link opener" redirect
- **Endpoint shape / parameter:** The target routes all outbound external links through a dedicated opener on its main domain (here: `hackerone.com` external link opener). The parameter is the external link URL itself — any user-controllable outbound link, e.g. a profile or report field containing `https://awasthi7.github.io/`.
- **Payload that fired (verbatim):** `https://awasthi7.github.io/` — a plain attacker-controlled page; no JS was even needed in this record to prove the tab was replaceable once opened without `noopener`.
- **Root cause:** External links are opened in a new tab without `rel=noopener`, so the opened page keeps `window.opener` access and can replace or control the original `hackerone.com` tab.
- **Impact proven:** Tabnabbing demonstrated — opening the crafted external link in a new tab replaced the `hackerone.com` tab with another site (Google), enabling phishing against a tab the victim believes is the trusted domain.
- **Exemplar:** id=1159398 (HackerOne)
- **Chain observed:** Attacker page opened in new tab → page replaces the originating hackerone.com tab, enabling phishing.

### 2. User-supplied profile/website URL field
- **Endpoint shape / parameter:** A user-editable website URL field on the target's profile/work-sample surface (here: Mavenlink work sample website URL). The attacker controls the full URL value, which the app renders as an anchor opening in a new tab.
- **Payload that fired (verbatim):** `window.opener.location.replace('http://daniel-tomescu.com/hackerone/scampage.php');`
- **Root cause:** Links open in a new tab without `rel=noopener`, so the destination page can access `window.opener` and silently redirect the originating tab. Note the payload is placed on the attacker's page (the URL the user clicks through to), not injected into the target site.
- **Impact proven:** Clicking the crafted work-sample link silently redirected the original Mavenlink tab to an attacker phishing page without user awareness — demonstrated end to end.
- **Exemplar:** id=220737 (Mavenlink)
- **Chain:** none stated.

### 3. External links inside app content views (parent-redirect variant)
- **Endpoint shape / parameter:** External links rendered inside an authenticated app view, here `infogram.com/app/{project}` — the project editor/view page containing an external link. No dedicated parameter; the link is embedded in the project content.
- **Payload that fired (verbatim):** `window.opener.parent.location.replace('http://attacker.com');`
- **Root cause:** External links open in new tabs without `rel=noopener/noreferrer`, so `window.opener` is live and can redirect the parent tab. This record adds `.parent` — useful when the originator is (or may be) inside a frame hierarchy, walking up to the top-level browsing context.
- **Impact proven:** Opening the link in a new tab replaced the original infogram tab with an attacker-controlled URL.
- **Exemplar:** id=280500 (Infogram)
- **Chain:** none stated.

## Bypass / chain notes
- **No filter bypass needed in these records** — all three fired against plain external links with no `noopener`. The "bypass" is simply that none of the three targets emitted `rel="noopener"` on any tested anchor.
- **The payload lives off-target.** In 2 of 3 records the JavaScript (`window.opener.location.replace(...)`) is hosted on the attacker's own page (GitHub Pages, personal domain). Nothing needs to be injected into the target — you only need to get a victim to click a link whose destination you control. This makes the technique robust against target-side input filtering entirely.
- **`window.opener.location.replace()` vs `location.href=`:** the records use `.replace()`, which removes the phishing redirect from the victim's back-button history — the original tab's history entry is replaced, so the victim can't easily go "back" to the legitimate page. Preserve this in your PoC.
- **Frame-aware escalation:** the Infogram record uses `window.opener.parent.location.replace(...)` — if the originating context is framed, `.parent` reaches the top-level tab. Include the `.parent` variant in your payload when the entry point might be embedded.
- **Chain shape:** attacker page opened in new tab → silently replace originating tab with phishing page → victim returns to what looks like the trusted site and enters credentials. The demonstrated chain (id=1159398) framed this as phishing enablement on the trusted domain.

## Gotchas / what NOT to do
- **Don't inject the payload into the target.** The anchor on the target only needs to point at your controlled page; the JS executes from your page. Injecting into the target is a different (and unnecessary) bug class.
- **Don't forget the demo tab-swap proof.** All three records prove impact by actually replacing the originating tab (Google in id=1159398, a scampage in id=220737, attacker.com in id=280500). A report claiming theoretical `window.opener` access without demonstrating the silent redirect is weaker.
- **Don't test only with `alert(opener)`.** The proven impact in every record is a silent `.location.replace()` of the origin tab — demonstrate that exact behavior.
- **Don't overlook `noreferrer`.** The Infogram record cites the missing `rel=noopener/noreferrer` pair; dropping `noreferrer` also leaks the referrer, so mention both in the root cause where applicable.
- **Mind the hosting surface.** Two of three attackers hosted payloads on plausible-looking pages (GitHub Pages profile, a personal domain path `.../hackerone/scampage.php`). A raw IP or suspicious host weakens the realism of the demonstrated phishing chain.

## Real-world impact examples
- **HackerOne (id=1159398):** Opening a crafted external link in a new tab replaced the original `hackerone.com` tab with an attacker-chosen site (Google), proving a victim can be silently phished on what they believe is the HackerOne domain.
- **Mavenlink (id=220737):** Clicking an attacker-crafted work-sample website link silently redirected the original Mavenlink tab to `http://daniel-tomescu.com/hackerone/scampage.php` — an explicit phishing page — with no user awareness.
- **Infogram (id=280500):** Opening an external link from `infogram.com/app/{project}` replaced the original infogram tab with `http://attacker.com` via `window.opener.parent.location.replace()`, demonstrating full control of the parent browsing context.