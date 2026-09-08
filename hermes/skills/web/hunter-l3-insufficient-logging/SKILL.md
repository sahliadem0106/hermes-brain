---
name: hunter-l3-insufficient-logging
description: "Use when hunting Insufficient Logging on a target. Loads the L3 technique sheet: This class covers AWS API endpoints that either (a) fail to emit CloudTrail audit events at all, or (b) emit CloudTrail events with sanitized/incorrect source metadata (UserAgent and network info reported as \"AWS Internal\")."
domain: cybersecurity
subdomain: web
tags:
- web
- insufficient-logging
- hunting
- l3
version: '1.0'
---

# Insufficient Logging — Technique Sheet

## Overview
This class covers AWS API endpoints that either (a) fail to emit CloudTrail audit events at all, or (b) emit CloudTrail events with sanitized/incorrect source metadata (UserAgent and network info reported as "AWS Internal"). Both variants still enforce normal IAM authorization, so an adversary with valid credentials can enumerate permissions or invoke operations while leaving either zero forensic trace or a misleading one. Every record here is from AWS's Vulnerability Disclosure Program (plus one Nintendo-hosted AWS Health finding), so the technique is AWS-specific — but the root-cause pattern (endpoint variants with degraded logging parity) generalizes to any provider with regional/FIPS/non-prod endpoint surfaces.

## Distinct sub-patterns

### Sub-pattern 1: Non-production endpoints — no CloudTrail logging at all
The dominant pattern (11 of 14 records). AWS services expose alternative API endpoint URLs (non-production endpoints reachable via `--endpoint-url` in the CLI). These endpoints perform full, normal IAM permission checks but never write audit events to CloudTrail.

- **Endpoint shape:** standard AWS CLI invocation with an alternate endpoint:
  - `aws bedrock list-imported-models --endpoint-url {non-prod}` (id=2951803)
  - `aws devicefarm get-account-settings --region us-west-2 --endpoint-url {non-prod}` (id=2999116) — verbatim payload in the record: `aws devicefarm get-account-settings --region us-west-2 --endpoint-url` (URL redacted/not stated)
  - `aws route53domains list-domains --endpoint-url {non-prod}` (id=3092085)
  - `aws cloudwatch list-dashboards` with non-production `--endpoint-url` (id=3775702)
  - `aws s3tables list-table-buckets` with non-production `--endpoint-url` (id=3780277)
  - Service-specific CLI subcommands also used directly against non-prod endpoints: `docdb-elastic list-cluster-snapshots` (id=3009411), `datazone list-domains` (id=3014785), `elasticache describe-users` (id=3021451), `neptune-graph list-graphs` (id=3068422)
- **Payload:** the CLI command itself; only the Device Farm record states one verbatim (above). For the rest, "payload not stated" — but the technique is identical: call any read-only/List* operation against the non-prod endpoint URL.
- **Root cause:** endpoint parity gap — the non-production endpoint shares the authorization plane (IAM checks run normally) but not the logging plane (no CloudTrail event is emitted). The logging pipeline is wired only to production endpoints.
- **Impact proven:** silent IAM permission enumeration. With compromised credentials, an attacker calls List*/Describe*/Get* operations and reads success vs. AccessDenied to map exactly which actions the identity can perform — generating zero CloudTrail events. Confirmed scale across records:
  - bedrock: 5 non-prod endpoints (`ListImportedModels`, `ListModelImportJobs`) (id=2951803)
  - neptune-graph: 7 endpoints (+1 limited to `neptune-graph:ListGraphSnapshots`) (id=3068422)
  - AWS Health (Nintendo program): 11 non-prod endpoints via `aws health describe-entity-aggregates` (id=3042475)
  - s3tables: **23 endpoints** for `list-table-buckets` with admin vs. no-perm responses differing and "zero matching CloudTrail events observed for either principal" (id=3780277)
  - cloudwatch: 4 endpoints for `list-dashboards`, same admin-vs-noperm differential, zero events for either principal (id=3775702)
  - Single-endpoint confirmations: datazone (x2, ids 2981210, 3014785), devicefarm (2999116), docdb-elastic (3009411), elasticache (3021451), route53domains (3092085)
- **Exemplar reports:** id=3780277 (largest surface, cleanest proof methodology), id=2951803.

### Sub-pattern 2: FIPS endpoints — CloudTrail logs misattribute to "AWS Internal"
A second, distinct flaw: FIPS (Federal Information Processing Standards) endpoint variants *do* log to CloudTrail, but the logged `UserAgent` and source IP/network information are reported as **"AWS Internal"** instead of the caller's real values.

- **Endpoint shape:** FIPS endpoint variants of standard service operations:
  - `POST comprehendmedical` via FIPS endpoints (id=2979238) — e.g. Comprehend Medical's `comprehendmedical-fips` regional endpoints; the record gives the service but not a full URL ("payload not stated")
  - `aws kendra-ranking list-rescore-execution-plans` via 4 FIPS endpoints (id=3044471)
  - `aws pinpoint-sms-voice-v2 describe-pools` via 5 FIPS endpoints (id=3072841)
- **Payload:** "payload not stated" in all three records — standard read-only API calls through the FIPS endpoint.
- **Root cause:** the FIPS endpoint front-door is classified as AWS-internal infrastructure, so the logging layer stamps the event's UserIdentity/network metadata as "AWS Internal" rather than propagating the caller's user-agent, source IP, and OS information.
- **Impact proven:** attribution evasion. The adversary performs API calls while CloudTrail events hide their source IP, user-agent, and OS information — destroying the primary forensic signals defenders use to scope a credential-compromise investigation. The events exist (so action-based alerting still fires), but every event looks like it came from inside AWS.
- **Exemplar reports:** id=2979238, id=3072841.

### Sub-pattern 3: Non-production endpoints on AWS Health (cross-program confirmation)
- **Endpoint shape:** `aws health describe-entity-aggregates` against 11 non-production Health endpoints.
- **Payload:** "payload not stated".
- **Root cause:** same as sub-pattern 1 — IAM enforced, CloudTrail silent.
- **Impact proven:** permission enumeration across the AWS Health service with no CloudTrail logs.
- **Exemplar report:** id=3042475 (Nintendo program — worth noting this class was accepted and rewarded outside the AWS VDP itself, on a program whose scope merely included AWS infrastructure).

## Bypass / chain notes
- **Permission-enumeration chain (stated explicitly in ids 3009411, 3014785, 3021451):**
  1. Obtain compromised IAM credentials (e.g. leaked key, phishing, SSRF-extracted role creds).
  2. Call the service's non-production endpoint with a read-only operation.
  3. Read success/failure to enumerate permissions — with no CloudTrail record.
  This is the canonical kill chain for sub-pattern 1: the logging gap is most valuable immediately post-compromise, when the attacker wants to map the identity's capabilities before touching anything a defender could alert on.
- **Admin-vs-noperm differential as proof:** ids 3775702 and 3780277 validated the flaw by issuing the same call from an admin principal and a principal with no permissions, confirming the responses differ (authorization is live) while CloudTrail shows zero events for either principal. This differential method is the cleanest way to prove both halves of the bug (IAM enforced + logging absent) in one test.
- **Why silent enumeration matters in chains:** a full CloudTrail-visible `List*` sweep is itself a detection signal (GuardDuty/UnusualBehaviors, event-volume alerting). Routing the sweep through non-prod endpoints lets the attacker complete reconnaissance before their first logged action.

## Gotchas / what NOT to do
- **Use read-only operations.** Every confirmed finding used List*/Describe*/Get* calls (`list-imported-models`, `list-domains`, `describe-users`, `describe-pools`, `list-table-buckets`, `get-account-settings`, `describe-entity-aggregates`, `list-graphs`, `list-cluster-snapshots`, `list-dashboards`, `list-rescore-execution-plans`). Never mutate state on shared AWS infrastructure.
- **Don't confuse the two sub-patterns when reporting.** Non-prod endpoints = zero events (missing logging). FIPS endpoints = events present but metadata wrong ("AWS Internal"). The root cause, affected service list, and fix differ — mixing them weakens the report.
- **Verify the negative with both principals.** id=3780277/3775702 explicitly checked CloudTrail for *both* the admin and no-perm principal. A single-principal check risks the event being attributed elsewhere or delayed.
- **Don't assume all services are affected.** The gap is per-service, per-endpoint: records confirmed specific counts (4, 5, 7, 11, 23 endpoints) and even found one neptune-graph endpoint limited to a single action (`ListGraphSnapshots`). Enumerate the endpoint surface per service rather than assuming coverage.
- **FIPS attribution findings hinge on the event existing.** If the FIPS call produced *no* CloudTrail event at all, that's sub-pattern 1, not metadata misattribution — check what the log actually contains before claiming "AWS Internal" stamping.
- **This is AWS-infrastructure specific in these records.** All 14 findings are AWS endpoints (one via the Nintendo program). Nothing in the records supports the same claim against other clouds without independent verification.

## Real-world impact examples
- **23 silent endpoints on one service (id=3780277):** confirmed `s3tables list-table-buckets` across 23 non-production endpoints where admin vs. no-permission responses differ — i.e., real authorization decisions observable — with zero matching CloudTrail events for either principal. A compromised identity can map its full s3tables capability set invisibly.
- **Full recon chain across 11 Health endpoints (id=3042475):** enumerated permissions of compromised IAM credentials for AWS Health via 11 non-production endpoints, no CloudTrail logs generated — accepted and rewarded through the Nintendo program.
- **Multi-service coverage (id=2951803):** `bedrock:ListImportedModels` and `bedrock:ListModelImportJobs` enumerated across 5 non-prod endpoints, no CloudTrail logs — demonstrating the gap spans newer AI services too.
- **Attribution wipeout (id=2979238):** FIPS Comprehend Medical calls produce CloudTrail events reading "AWS Internal" for user-agent and network info — an investigator reviewing logs during an incident sees no source IP, no user-agent, no OS fingerprint, even though the calls are logged.
- **Bulk metadata suppression (ids 3044471, 3072841):** 4 Kendra Ranking FIPS endpoints and 5 Pinpoint SMS/Voice v2 FIPS endpoints all misattribute caller metadata, showing the FIPS variant of the flaw is systematic across the endpoint fleet, not a one-off.