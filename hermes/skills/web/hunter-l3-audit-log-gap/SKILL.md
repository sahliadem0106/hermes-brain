---
name: hunter-l3-audit-log-gap
description: "Use when hunting Audit Log Gap on a target. Loads the L3 technique sheet: Audit Log Gap findings occur when a security-relevant state change in an application (sharing, authentication, account security) succeeds but is never written to the admin-facing audit log."
domain: cybersecurity
subdomain: web
tags:
- web
- audit-log-gap
- hunting
- l3
version: '1.0'
---

# Audit Log Gap — Technique Sheet

## Overview
Audit Log Gap findings occur when a security-relevant state change in an application (sharing, authentication, account security) succeeds but is never written to the admin-facing audit log. The bug is not exploitable behavior in the traditional sense — it is a forensic/integrity failure: an attacker or negligent user can perform sensitive actions invisibly, so incident response and compliance trails are incomplete. These pay in programs with explicit security/compliance scope (file collaboration platforms, identity providers, enterprise SaaS) where audit completeness is a stated requirement, and are typically accepted as low/informational severity — but they are fast, repeatable, and frequently missed because hunters focus on injection/broken-access-control classes.

## Distinct sub-patterns

### 1. Share expiration unset not audited
- Endpoint shape: Share management flow — Nextcloud share link/API where an expiration date is first set on a share, then removed. Parameter-space equivalent: `PUT /ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}` with `expireDate` set, then again with `expireDate` cleared/empty. No specific parameter was implicated in the record — the trigger is the *unset* operation, not the set.
- Payload: none — no injection payload. The "action" is the UI/API operation of unsetting an existing share expiration date.
- Root cause: The audit/logging layer (Nextcloud's `admin_audit` app) emits events for share creation and modification of attributes like expiration set, but the transition "expiration date removed" is not emitted as an auditable event. The action succeeds in the data layer while the audit subscriber simply has no corresponding log entry type.
- Impact proven: The audit log lacks the unset-expiration event entirely, leaving an incomplete trail of share changes. Security implication: a share that was deliberately time-boxed can be silently made permanent with no forensic record.
- Exemplar: id=1200810 [ajaysenr], Nextcloud.

### 2. Federated share accept/decline not audited
- Endpoint shape: Federated (server-to-server) sharing flow — the local user accepting or declining a share received from another Nextcloud instance. API shape: `POST /ocs/v2.php/apps/files_sharing/api/v1/remote_shares/{share_id}` (accept) / `DELETE` (decline). Record does not specify exact route — trigger is the accept/decline action in the federated shares UI.
- Payload: none — action-based, no payload.
- Root cause: The federated sharing app's accept/decline handlers do not invoke the audit logger. Cross-instance sharing events are a blind spot in the audit subscriber configuration.
- Impact proven: Audit log is missing federated share accept/decline events, leaving an incomplete trail. Implication: an external-instance share that grants data access can be accepted with no local audit evidence of who/when.
- Exemplar: id=1200815 [ajaysenr], Nextcloud.

### 3. 2FA enable/disable not audited
- Endpoint shape: Account security settings flow — user (or admin) enabling or disabling two-factor authentication for an account. Settings UI: Settings → Security; API shape corresponds to the 2FA provider enrollment/unenrollment endpoints.
- Payload: none — the trigger is toggling 2FA state.
- Root cause: The 2FA provider enable/disable code paths do not write audit events. Notably this is an *account security* change, the category most universally expected to be audited.
- Impact proven: No audit trail for account security changes (2FA enable/disable). Implication: an attacker with session access can disable a victim's 2FA (or an insider can disable their own after setting up) with zero log footprint.
- Exemplar: id=1200989 [ajaysenr], Nextcloud.

### 4. Auth token lifecycle not audited
- Endpoint shape: App passwords / auth token management — creation, revocation, and scope change of API tokens/app passwords (Settings → Security → Devices & sessions; corresponding REST endpoints under the provisioning/security API).
- Payload: none — trigger is create/revoke/scope-change operations on tokens.
- Root cause: Token lifecycle operations (create, revoke, scope modification) are absent from the audit event stream. Scope change is the most dangerous variant: a token's permissions can be widened without any record.
- Impact proven: No audit trail for auth token lifecycle events, hindering incident tracking. Implication: persistent backdoor access via an unlogged token, or silent privilege escalation via scope change, cannot be detected forensically.
- Exemplar: id=1200992 [ajaysenr], Nextcloud.

## Bypass / chain notes
- No chains were recorded in these findings — all four are standalone audit-completeness gaps.
- Implicit chain potential (not demonstrated in the records, do not report as proven): combining unlogged 2FA disable (sub-pattern 3) with unlogged token creation (sub-pattern 4) yields a persistence path with no audit evidence — worth mentioning in the report narrative as *why it matters*, not as an executed exploit.

## Gotchas / what NOT to do
- Verify against the actual audit log output (Nextcloud's `admin_audit` log file / logging config) — confirm the event is genuinely absent, not merely rendered elsewhere in the UI or in the standard `nextcloud.log`. Check both logs before claiming a gap.
- Do not assume the absence of a UI log view equals an audit log gap; distinguish application logs from the security audit log.
- Compare against the vendor's own audit documentation / event list: the strongest report shows "event X is documented as auditable (or is security-relevant) but produces no audit entry."
- These are single-vendor patterns observed in Nextcloud; do not generalize the exact event names to other platforms — hunt the *category* (share mutations, federated sharing, 2FA, token lifecycle) in whatever audit framework the target documents.
- Payload fields are empty by design in this class; don't fabricate request bodies. Describe the exact UI/API operation performed and the expected-vs-observed audit entries.
- Expect low severity. Framing matters: tie the gap to incident-response and compliance impact (e.g., "attacker with temporary access can hide persistence"), not just "logging is missing."

## Real-world impact examples
- id=1200810: Unsetting a share expiration date left no audit entry — a time-limited external share could be silently made permanent without a trace in the admin audit log.
- id=1200815: Federated share accept/decline events were absent from the audit log, so cross-instance data-access grants had no local forensic record.
- id=1200989: Enabling or disabling 2FA produced no audit entry — account security posture could be weakened with no trail.
- id=1200992: Auth token create/revoke/scope-change events were unlogged — persistent access tokens could be minted or widened invisibly, undermining incident tracking.

All four were reported by the same researcher (ajaysenr) against the same program, sharing one method: enumerate the platform's security-sensitive state transitions against its documented audit event list, exercise each transition, and diff the audit log for missing entries.