---
name: hunter-l3-sms-spam
description: "Use when hunting SMS Spam on a target. Loads the L3 technique sheet: SMS Spam is a vulnerability class where an attacker abuses a target application's SMS-sending features (verification texts/calls, notification SMS, \"send SMS\" tools) to flood an arbitrary phone number with messages."
domain: cybersecurity
subdomain: web
tags:
- web
- sms-spam
- hunting
- l3
version: '1.0'
---

# SMS Spam — Technique Sheet

## Overview
SMS Spam is a vulnerability class where an attacker abuses a target application's SMS-sending features (verification texts/calls, notification SMS, "send SMS" tools) to flood an arbitrary phone number with messages. It pays because every unwanted SMS costs the company money (per-message carrier fees, aggregator overages), can exhaust SMS delivery infrastructure, and constitutes harassment of arbitrary third parties who never consented to receive messages. The three verified records here are all from the same reporter and share a common thread: **SMS send primitives with no verification of ownership, no rate limiting, or input validation flaws that map many inputs to one victim number.**

## Distinct sub-patterns

### Sub-pattern 1: Unauthenticated/unrestricted "Send SMS" feature (Uber partner dashboard)
- Endpoint shape: `GET /dashboard/documents/` — the partner documents area exposes a "Send SMS" action tied to phone number entry during registration.
- Parameter: `phone`
- Payload: (none stated in record — triggered via the registration + Send SMS UI flow)
- Root cause: The partner documents "Send SMS" feature sends an SMS to **any phone number** with **no verification** that the sender owns the number, and **no daily limit** on sends.
- How it fired: Use a victim's phone number as your own during partner registration, then trigger the Send SMS feature — Uber sends an SMS to that number.
- Impact proven: Demonstrated ability to spam any phone number with Uber-branded SMS at will.
- Exemplars: id=127918 (Uber)

### Sub-pattern 2: Digit-count truncation in phone validation (Uber Android rider sign-up)
- Endpoint shape: Android Rider sign-up phone verification flow.
- Parameter: `phone number`
- Payload (verbatim): `12345678901` — an 11-digit input; 12-digit variants also accepted.
- Root cause: Phone validation accepts 11/12-digit inputs that are **truncated to 10 digits**. Many distinct 11/12-digit inputs (differing prefixes/suffixes) collapse to the same 10-digit target, and each accepted input counts as a "new" number — so per-number rate limits or duplicate-checks never fire.
- Impact proven: Spammed a phone number with verification calls AND texts by cycling 11/12-digit variants that all truncate to the same victim number.
- Exemplars: id=177551 (Uber)

### Sub-pattern 3: Unthrottled SMS resend endpoint with attacker-controlled resend count (Unikrn)
- Endpoint shape: `POST /apiv2/user/verifytelephone`
- Parameter: `resend`
- Payload (verbatim): `{"session_id":"lcso6bc6vv2jcf7ebukdfgrfm3s38v6a","resend":1}`
- Root cause: The resend endpoint accepts arbitrary resend count values **without rate limiting**. Additionally, the account-edit flow **re-triggers sends**, providing a second, independent send primitive. The session_id parameter scopes sends to whatever number is bound to that session — which the attacker controls (victim's number entered as their own).
- Impact proven: Exhausted the SMS delivery system and spammed a target number with **hundreds** of verification SMS (delivery cadence observed at 1 SMS per 2 minutes), directly increasing the SMS service cost line item.
- Exemplars: id=263010 (Unikrn)

## Bypass / chain notes
- **Validation-bypass rate-limit evasion (id=177551):** classic bypass pattern — when throttling or deduplication keys on the *input* rather than the *normalized destination*, inflating the digit count of the victim's number (e.g., prepending/inserting digits that get truncated) defeats the guard entirely. The victim number stays the same; the "unique input" changes every request.
- **Dual send primitives (id=263010):** the resend endpoint and the account-edit flow are two independent triggers for the same SMS system. If one gets throttled, the other may not — always enumerate every code path that causes an outbound SMS.
- **Registration as session bootstrap:** in id=127918 and id=263010, the attacker first enters the victim's number as *their own* during registration/onboarding to obtain a valid session bound to the victim's number, then abuses the send/resend primitives within that session. This avoids needing to verify ownership — the flows that would normally gate sending (verification) are exactly the flows being abused.

## Gotchas / what NOT to do
- Do not actually flood a real person's phone with hundreds of messages when demonstrating. In id=263010 the impact claim included "hundreds of SMS (1 per 2 minutes)" — a sustained, measurable demonstration. Modern triage prefers: send a small, bounded burst (e.g., 3-5 sends via the bypassed path), screenshot timestamps, and extrapolate cost impact. Keep the victim number under your own control (your second SIM / VoIP number) whenever possible.
- Do not test with random third-party numbers — the target number should be one you control or one explicitly sanctioned by the program.
- Don't report a single resend button as spam on its own — the finding is only interesting when you can show the throttle is absent or bypassable (arbitrary `resend` values, no 429, no cooldown, or truncation-based bypass).
- Normalize the phone number before concluding rate limits exist: a working throttle on `+11234567890` may be bypassable via `11234567890` (11-digit) — test the truncation variant, not just the plain number.
- Don't confuse cost-impact claims with guessed figures: anchor to observed delivery rates (e.g., 1 SMS per 2 minutes) and the program's own SMS volumes; state the cost multiplier, not a fabricated dollar total.

## Real-world impact examples
- Uber (id=127918): any phone number could be spammed with Uber SMS via the partner documents Send SMS feature — no ownership verification, no daily limit.
- Uber (id=177551): one victim number received repeated verification **calls and texts** from an infinite family of distinct 11/12-digit inputs (`12345678901` et al.), all truncating to the same 10-digit destination.
- Unikrn (id=263010): hundreds of verification SMS delivered to a single target at ~1 per 2 minutes, exhausting the SMS delivery system and measurably inflating the company's SMS service cost.