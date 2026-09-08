---
name: hunter-l3-2fa-bypass-broken-access-control
description: "Use when hunting 2FA Bypass / Broken Access Control on a target. Loads the L3 technique sheet: This class covers platform-level gaps where a \"2FA required\" policy is enforced at one entry point (e.g., original report submission to a program) but not enforced at adjacent entry points into the sa"
domain: cybersecurity
subdomain: web
tags:
- web
- 2fa-bypass-broken-access-control
- hunting
- l3
version: '1.0'
---

# 2FA Bypass / Broken Access Control — Technique Sheet

## Overview

This class covers platform-level gaps where a "2FA required" policy is enforced at one entry point (e.g., original report submission to a program) but not enforced at adjacent entry points into the same restricted context — report transfer, collaborator invites. It pays on bug-bounty platforms themselves (HackerOne in these records) and on any product with tiered-security programs/workspaces where sensitive vulnerability data is exposed to 2FA-exempt participants. The proven impact in these records is not account takeover: it is defeat of a security-gating control that exists specifically to limit exposure of sensitive vulnerability data, which platforms treat as a legitimate security report.

## Distinct sub-patterns

### Sub-pattern 1: Report transfer without 2FA validation on the reporter

- Endpoint shape / parameter: HackerOne report transfer flow — moving an existing report into a 2FA-required program. No query/body parameter involved; the control point is the transfer action itself (`(none)` in records). Template: `transfer report {report_id} → program {program_id}` where `program.settings.require_2fa = true`.
- Payload: not stated — this is a workflow/state transition, not an injection. The "payload" is the state of the actor: a reporter account with 2FA not enabled.
- Root-cause pattern: the transfer path validates that the target program requires 2FA, but does not re-validate that the *reporter* satisfies the program's 2FA policy. The check exists only on the original submission path, so the transfer is a second, unguarded entrance into the same restricted context. Classic "policy enforced at one ingress, missing at a parallel ingress."
- Impact proven: reproduced that a report submitted by a non-2FA user can be transferred into a program that requires 2FA for submissions, bypassing the 2FA gating (record 2569993, ajaysenr, HackerOne).
- Exemplar report IDs: 2569993.

### Sub-pattern 2: Collaborator invite without 2FA enforcement

- Endpoint shape / parameter: HackerOne report collaboration invite — inviting a user as a collaborator on a report that belongs to (or targets) a 2FA-required program. Template: `invite collaborator {user_id/email} → report {report_id}` where `report.program.require_2fa = true`. Parameter: the invitee identity (email/username); records list param as `(none)` beyond the invite flow itself.
- Payload: not stated — the operative condition is again the actor state: invitee account has 2FA not enabled at both invite time and accept time.
- Root-cause pattern: the 2FA requirement is not enforced on collaborators invited to a report. The program's 2FA policy gates direct report submission but the collaboration-invite path never checks the invitee's 2FA status — neither when the invitation is sent nor (critically) when it is accepted. Two records (2571981, 2575079) demonstrate the same flaw independently, meaning the accept step is where access actually materializes: an invitee who sets up no 2FA can still accept and gain report access.
- Impact proven: reproduced that a collaborator without 2FA can be invited and accept, gaining access to a report (with its sensitive vulnerability data) submitted to a 2FA-requiring program (2571981); and independently, that a collaborator without 2FA can be invited and can accept, accessing a report on a 2FA-requiring program (2575079).
- Exemplar report IDs: 2571981, 2575079.

## Bypass / chain notes

No multi-step chains were recorded in these records (`chain: (none)` across all three). The only "bypass" mechanics present are:

- Alternative-ingress bypass: whenever a protected resource has multiple entrance paths (submission, transfer, invite, disclosure, merge), test each path for the policy independently. The 2FA check lived on submission only; transfer and invite were open doors.
- Accept-side gap: for invite-style flows, enforcement must exist at accept time, not just invite time. Both collaborator records show the non-2FA user gets actual access after accepting — the full lifecycle is unguarded.

## Gotchas / what NOT to do

- Don't frame this as "I bypassed 2FA on my own account" (i.e., don't present it as authentication bypass / ATO). All three records are scoped as policy-gating bypasses exposing sensitive vulnerability data to non-2FA participants. Wrong framing risks N/A.
- Don't test this against arbitrary user accounts — every record here uses the researcher's own non-2FA account as the invitee/reporter. Stay inside your own test accounts.
- Don't assume the submission-path check is broken; it wasn't. The bug is the *absence* of the check on parallel paths. Report the specific unenforced path.
- These are platform-workflow bugs, not injection — there is no payload to spray. If you're hunting with a payload list, this class isn't where those apply; the artifact is a reproduction walkthrough.
- Don't conflate the two sub-patterns: transfer (2569993) moves an existing report in; invite (2571981/2575079) brings a person in. They are separate code paths and separate reports.

## Real-world impact examples

- 2569993: A report authored by a researcher without 2FA was transferred into a program that mandates 2FA for submissions — the program's security gating was defeated, with the report now residing in the restricted context.
- 2571981: A collaborator without 2FA was invited to a report on a 2FA-requiring program, accepted, and obtained access to the report including its sensitive vulnerability data — a non-2FA party now holds disclosure-sensitive information the program explicitly gated behind 2FA.
- 2575079: Independently reproduced the same collaborator-invite gap: non-2FA user invited, accepted, accessed the report on the 2FA-requiring program — demonstrating this is not a one-off misconfiguration but a systematic gap in the invite path.

Hunting heuristic derived from these records: pick any program with `require_2fa`, then enumerate every path that grants a principal read access to the program's reports — submit, transfer, invite/collaborate, and any equivalent flows — and test each with a deliberately non-2FA account you control.