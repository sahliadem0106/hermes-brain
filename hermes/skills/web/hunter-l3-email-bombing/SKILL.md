---
name: hunter-l3-email-bombing
description: "Use when hunting Email Bombing on a target. Loads the L3 technique sheet: Email bombing is the abuse of any application function that triggers an outbound email to an attacker-controlled or victim-specified address, when that function lacks rate limiting."
domain: cybersecurity
subdomain: web
tags:
- web
- email-bombing
- hunting
- l3
version: '1.0'
---

# Email Bombing — Technique Sheet

## Overview
Email bombing is the abuse of any application function that triggers an outbound email to an attacker-controlled or victim-specified address, when that function lacks rate limiting. It pays on programs that accept functionality reports: the primitive is trivial to demonstrate, the impact is a denial-of-service on the victim's mailbox, and it frequently chains into mail-related admin functions. The three records here all share one root cause — an email-sending endpoint (verification, password reset, or mail-server test) with no throttle and either no authentication on the target address or the ability to set the target arbitrarily.

## Distinct sub-patterns

### 1. Unthrottled email-verification endpoint with attacker-set arbitrary address
- Endpoint shape: `POST /settings/user/{username}/page/email/` (Phabricator-style settings/email-verification flow)
- Parameters: `verify` (in query string, e.g. `?verify=14295`), `__csrf__` (CSRF token obtained as the victim/attacker session allows), plus form bookkeeping fields `__form__` and `__dialog__`
- Payload (verbatim, from id=221948 — an auto-submitting CSRF-style form):
```
<form id="myform" action="https://admin.phacility.com/settings/user/toma/page/email/?verify=14295" method="POST" target="_blank">
<input type="text" name="__csrf__" value="B@f3wyama2759fcd6f915746da">
<input type="text" name="__form__" value="1">
<input type="text" name="__dialog__" value="1">
<inpu
```
  (truncated in the record; the form is completed with remaining hidden inputs and an auto-submit script that resubmits it in a loop)
- Root cause: the email-verification endpoint is not rate-limited, and because the address is set at registration and never verified, an unverified user can point it at ANY arbitrary email address. Each submission of the form triggers another verification email to that address.
- Impact: repeatedly auto-submitting the verification form bombs an arbitrary victim's mailbox with verification emails. Because the address is unverified at registration, any third party's mailbox can be targeted — not just the attacker's own account.
- Exemplars: id=221948 (Phabricator / admin.phacility.com)

### 2. Unthrottled lost-password / reset-email endpoint
- Endpoint shape: `POST /{username}/lostpassword/email` (Nextcloud instance path containing the username)
- Parameters: `user`
- Payload: not stated in the record (the attack was a replay of the lost-password XHR request)
- Root cause: the lost-password email API has no rate limiting, so reset emails can be triggered an unlimited number of times for a chosen user.
- Impact: replaying the lost-password XHR repeatedly flooded the target admin's mailbox with password-reset emails — email bombing of any (demo) instance's default admin. Note the target is any valid username on the instance, so the victim does not need to be the attacker.
- Exemplars: id=222080 (Nextcloud)

### 3. Unthrottled admin mail-test function with attacker-chosen recipient
- Endpoint shape: `POST /{instance}/settings/admin/mailtest`
- Parameters: none stated (recipient address chosen via the admin mail-test UI; the record does not give the body field name — payload not stated)
- Root cause: the email-server test API sends a test email to an attacker-chosen target address and has no rate limiting.
- Impact: replaying the mailtest XHR sends unlimited test emails to an arbitrary target email address — a bombing primitive exposed by a purely administrative feature.
- Exemplars: id=222660 (Nextcloud)

## Bypass / chain notes
- CSRF-style auto-submit: in id=221948 the request was wrapped in an HTML `<form>` targeting the real endpoint with `__csrf__` populated, plus `__form__=1` and `__dialog__=1` hidden fields, and an auto-submit script to fire it repeatedly. This pattern works even where the handler checks for a valid session token but does not bind it to the request origin — the token is fetched once, then replayed N times.
- Query-string verification token: the `?verify=14295` parameter rides along on the POST; the record shows the verification trigger is what fires the email, so enumerate the verify token once and loop the POST.
- No multi-step chains appear in these records (all three list `chain: (none)`). The escalation is purely repetition: one legitimate request captured in a proxy, replayed at volume.

## Gotchas / what NOT to do
- Do NOT actually flood a mailbox at scale in a report environment — demonstrate the loop conceptually or with a small number of sends; the records demonstrate unlimited sends, not unlimited sends performed.
- Do NOT assume the victim must be your own account. All three records hinge on targeting a third party (an arbitrary address in id=221948 and id=222660; an instance admin in id=222080). That third-party targeting is what elevates this from self-DoS to a reportable weakness.
- Do NOT test only the "obvious" reset endpoint. The mailtest/admin mail-check function (id=222660) is a frequently overlooked email-sending primitive — check admin settings pages for any "send test email" feature.
- Check whether the email-sending feature is reachable pre-authentication or by low-privileged users: the Phabricator case (id=221948) works from an unverified registration state, which is a much stronger claim than an authenticated admin-only throttle failure.
- When the endpoint is a POST behind CSRF protection, confirm whether the token is per-session rather than per-request — a session-scoped token can be harvested once and reused across the loop.

## Real-world impact examples
- id=221948 (Phabricator): an auto-submitting form bombing an arbitrary victim's mailbox with verification emails; any person's mailbox could be targeted because the address is set and never verified at registration.
- id=222080 (Nextcloud): a demo instance's default admin mailbox flooded with password-reset emails from repeated lost-password XHR replays.
- id=222660 (Nextcloud): unlimited test emails to an arbitrary target email address via the admin mailtest XHR.