---
name: hunter-l3-reverse-tabnabbing
description: "Use when hunting Reverse Tabnabbing on a target. Loads the L3 technique sheet: Reverse tabnabbing is a phishing-enabling client-side flaw where a page renders user-controlled links with `target=\"_blank\"` but without `rel=\"noopener noreferrer\"`."
domain: cybersecurity
subdomain: web
tags:
- web
- reverse-tabnabbing
- hunting
- l3
version: '1.0'
---

# Reverse Tabnabbing — Technique Sheet

## Overview

Reverse tabnabbing is a phishing-enabling client-side flaw where a page renders user-controlled links with `target="_blank"` but without `rel="noopener noreferrer"`. The opened child page retains access to `window.opener`, letting an attacker silently rewrite the original tab's location to a lookalike phishing page while the user's attention is on the new tab. It pays on any platform that renders user-supplied URLs — profiles, editor comments, report attachments, document wiki-links — especially authenticated, high-trust sessions where a cloned login page is credible.

## Distinct sub-patterns

### 1. User profile link fields rendered without `noopener` (target=_blank)

- Endpoint shape: any profile "website"/"link" field rendered as an anchor on the site, e.g. `GET /statement` on Gratipay showing the user's profile link.
- Payload that fired (verbatim): `<a href="http://google.com">http://google.com</a>` — the profile owner sets their link URL and anchor text; the victim clicks it from the profile.
- Root cause: user-supplied profile links are rendered in a new tab with no `rel=noopener`/`noreferrer`, so the attacker-controlled page keeps a live `window.opener` reference.
- Impact proven: profile owner can point victims at a referral/malicious link whose opened tab switches the original tab to a phishing page mimicking the site (tabnabbing).
- Exemplar: 109161 (Gratipay).

### 2. User links inside rich app content (editor descriptions) — opener takeover cross-origin

- Endpoint shape: links embedded in user content inside a stateful web application, e.g. `https://www.mapbox.com/editor/?id={id}` where `{id}` is a project/description containing a user-authored `<a href>` link.
- Payload that fired (verbatim): `http://chasemiller.me/hax/mapbox_test.html` — attacker-hosted page that grabs `window.opener` and rewrites it.
- Root cause: user-generated links opened with `target="_blank"` and no `rel=noopener`, leaving `window.opener` controllable cross-origin by the child document.
- Impact proven: attacker took control of the Mapbox editor tab's `window.opener` object cross-origin and replaced the legitimate mapbox.com session tab with a phishing login page — i.e., hijacking a tab that was mid-workflow in a real editor.
- Exemplar: 165136 (Mapbox).

### 3. `rel=noreferrer` alone (missing `noopener`) on outbound links

- Endpoint shape: any outbound/external link rendered by the platform, e.g. external links inside HackerOne reports; the relevant parameter is the `rel` attribute value.
- Payload: not stated (the demonstration was behavioral — the opened page accessed the opener).
- Root cause: `rel=noreferrer` does NOT imply `noopener` on the affected browsers/configurations at the time; developers add `noreferrer` believing it closes the vector, but the child can still reach `window.opener`. (Key nuance: on some older browsers noreferrer-only still leaks the opener; the report explicitly demonstrated it.)
- Impact proven: external report links could access and replace the opener page — reverse tabnabbing demonstrated against a security-audience surface.
- Exemplar: 284143 (HackerOne).

### 4. Wiki/markup link syntax that slips past the sanitizer's rel injection

- Endpoint shape: document/comment markup links, Phabricator-style: `[[ URL | label ]]`. The parser applies `rel=noreferrer` to well-formed URLs — but URL parsing quirks defeat it.
- Payload that fired (verbatim): `[[ /\jackluru02.000webhostapp.com/tabnabbing.html | click_me ]]`
- Root cause: the backslash-prefixed path (`/\jackluru02...`) is treated by the markup engine as a relative/internal link, so the `rel=noreferrer` protection is not applied — but browsers normalize `/\host` into `//host`, making it a protocol-relative external URL. The child page therefore has full `window.opener` access.
- Impact proven: bypassed `rel=noreferrer`; the malicious child page's `window.opener.location` was changed to an attacker-controlled page, enabling malicious activity against any user who viewed the document/comment and clicked the link.
- Exemplar: 284143 (HackerOne, same researcher family) and 306414 (Phabricator).

### 5. Platform-wide `target="_blank"` anchor templates lacking both rel values

- Endpoint shape: any site page (Liberapay — liberapay.com pages generally) that emits `target="_blank"` anchors from templates.
- Payload: not stated — the finding is a code/DOM audit: locate any rendered `<a target="_blank">` missing `rel`.
- Root cause: template-level omission — links with `target="_blank"` lack `rel="noopener noreferrer"`, so any opened window can modify `window.opener.location`.
- Impact proven: an opened window can silently replace the parent tab URL, enabling phishing credential capture against logged-in users.
- Exemplar: 361054 (Liberapay).

## Bypass / chain notes

- The only bypass recorded is the Phabricator markup trick: prefix the host with `/\` (`[[ /\attacker.com/page.html | label ]]`) so the sanitizer classifies the link as internal/relative and skips `rel` injection, while the browser normalizes it to a protocol-relative external URL. Test this against any wiki/markup link syntax (Phabricator `[[...]]`, MediaWiki `[...]`, Markdown renderers) where `rel=noreferrer` is auto-added to absolute URLs only.
- Practical exploitation sequence common to all five: (1) host a page that runs `window.opener.location = 'https://phish-clone.example/login';` (optionally after a delay or `onblur` so the change is invisible), (2) plant the link where the target user base clicks it (profile, project description, report, comment), (3) victim clicks, attacker page loads in the new tab, (4) original tab navigates to the phishing clone of the logged-in session.
- No multi-step technical chains (e.g. combined with XSS or CSRF) appear in the records — the impact stands alone as phishing, but it lands against users who are already authenticated, which is what makes the cloned login page convincing.

## Gotchas / what NOT to do

- Do not assume `rel=noreferrer` is sufficient. The HackerOne record (284143) is precisely a demonstration that noreferrer-only outbound links were still exploitable — test for `noopener` independently.
- Do not only test obvious "website" fields. Mapbox's firing point was a link inside project/editor description content; Liberapay's was any template-emitted `target="_blank"` anchor. Enumerate every renderer of user content.
- Do not submit as "attacker can change location" alone — the accepted reports framed it as phishing credential capture against an authenticated session tab (cloned login page of the target site), which is what elevated severity.
- Don't claim self-XSS-style damage beyond location rewriting: none of the records showed script execution in the opener's origin. The proven primitive is `window.opener.location` control, not DOM access.
- Avoid obvious placeholder payloads (`google.com` alone) as the whole test — Gratipay's accepted payload used it, but the stronger records (Mapbox, Phabricator) hosted an actual opener-hijacking page and demonstrated the end-state phishing tab.

## Real-world impact examples

- Mapbox (165136): a user-supplied link inside the editor (`https://www.mapbox.com/editor/?id={id}`) let the attacker's page (`http://chasemiller.me/hax/mapbox_test.html`) seize `window.opener` of a live mapbox.com editor tab cross-origin and swap it for a phishing login page — a mid-session tab in a complex, trust-heavy application.
- Phabricator (306414): the `/\` markup-link bypass defeated the deployed `rel=noreferrer` defense entirely; any viewer clicking `[[ /\jackluru02.000webhostapp.com/tabnabbing.html | click_me ]]` in a document/comment had their parent window silently navigated to attacker-controlled content.
- HackerOne (284143): outbound links on reports — a core security-professional surface — allowed the opened page to access and replace the opener, showing the class survives even on security-focused platforms when `noreferrer` is mistaken for a complete fix.
- Liberapay (361054): a site-wide template audit showed `target="_blank"` links missing `rel="noopener noreferrer"`, meaning any opened window could silently rewrite the parent tab URL for credential phishing.
- Gratipay (109161): a plain profile link (`<a href="http://google.com">http://google.com</a>`) opened without noopener was enough for a profile owner to run tabnabbing phishing against anyone viewing their profile.