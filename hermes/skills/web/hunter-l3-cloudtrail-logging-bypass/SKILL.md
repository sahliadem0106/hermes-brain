---
name: hunter-l3-cloudtrail-logging-bypass
description: "Use when hunting CloudTrail Logging Bypass on a target. Loads the L3 technique sheet: This class covers AWS API endpoints that accept standard IAM credentials but do not emit CloudTrail logs."
domain: cybersecurity
subdomain: web
tags:
- web
- cloudtrail-logging-bypass
- hunting
- l3
version: '1.0'
---

# CloudTrail Logging Bypass — Technique Sheet

## Overview
This class covers AWS API endpoints that accept standard IAM credentials but do not emit CloudTrail logs. AWS maintains many non-production (dual-stack, beta, internal, or regional-fallback) endpoints per service; calls against these endpoints execute real service APIs without generating a CloudTrail event. It pays when you hold (or assume) compromised IAM credentials and want to enumerate permissions, resource state, or service access without tripping CloudTrail-based detection — CloudTrail is the primary audit source for most AWS detection stacks, so any "unlogged callable endpoint" is a silent recon primitive.

All four records in this class were reported by the same researcher (ajaysenr) to the AWS Vulnerability Disclosure Program, and all follow the same core pattern; the differences are per-service (which service, how many unlogged endpoints, which list API).

## Distinct sub-patterns

### Sub-pattern 1: Unlogged non-production SSM endpoints — silent IAM permission enumeration
- Endpoint shape / parameter: `POST /ssm` against non-production SSM endpoints. The controllable parameters are the `--endpoint-url` and `--region` flags of the AWS CLI — you do NOT change the API call itself, only which endpoint fronts it.
- Payload that actually fired (verbatim):
  ```
  aws ssm describe-instance-properties --region us-west-2 --endpoint-url ██████
  ```
  (the endpoint URL is redacted in the disclosed record; the technique is the `--endpoint-url` override)
- Root-cause pattern: 18 non-production SSM endpoints are callable with standard IAM credentials and do not log to CloudTrail. The data-plane/auth path accepts normal SigV4-signed IAM requests, but the logging/auditing path is only wired up on the production endpoints.
- Impact proven: An adversary with compromised IAM credentials can silently enumerate their own permissions (and validate SSM access) without generating any CloudTrail logs — no `ssm:DescribeInstanceProperties` event ever appears for defenders to alert on.
- Exemplar report: id=2926361 [ajaysenr], AWS VDP.

### Sub-pattern 2: Unlogged non-production Forecast endpoints
- Endpoint shape / parameter: `aws forecast list-datasets` executed against non-production Forecast endpoints (via the same `--endpoint-url` override pattern; specific parameter not stated in the record).
- Payload: payload not stated.
- Root-cause pattern: Four non-production Amazon Forecast API endpoints accept standard IAM credentials but do not emit CloudTrail logs.
- Impact proven: An adversary can enumerate IAM permissions of compromised credentials for the Forecast service without any CloudTrail logging — e.g., confirming `forecast:ListDatasets` is granted before ever touching the production endpoint.
- Exemplar report: id=3022516 [ajaysenr], AWS VDP.

### Sub-pattern 3: Unlogged non-production Global Accelerator endpoints
- Endpoint shape / parameter: `aws globalaccelerator list-accelerators` executed against non-production Global Accelerator endpoints (via the same endpoint-override pattern; specific parameter not stated in the record).
- Payload: payload not stated.
- Root-cause pattern: Eight non-production AWS Global Accelerator API endpoints accept standard IAM credentials but do not emit CloudTrail logs.
- Impact proven: Silent permission enumeration for the `globalaccelerator` service — an attacker can validate `globalaccelerator:ListAccelerators` (and by extension the credential's GA access) with zero CloudTrail evidence.
- Exemplar report: id=3031512 [ajaysenr], AWS VDP.

### Sub-pattern 4: Unlogged non-production Glue endpoints
- Endpoint shape / parameter: `aws glue list-jobs` executed against non-production Glue endpoints (via the same endpoint-override pattern; specific parameter not stated in the record).
- Payload: payload not stated.
- Root-cause pattern: Twelve non-production AWS Glue API endpoints accept standard IAM credentials but do not emit CloudTrail logs.
- Impact proven: Silent permission enumeration for the `glue` service — `glue:ListJobs` (and potentially resource-visible data such as job names) can be queried with no audit trail.
- Exemplar report: id=3029552 [ajaysenr], AWS VDP.

Note on the shared shape: all four sub-patterns are one technique instantiated per service — swap the service command (list-style, read-only API) and the `--endpoint-url` to a non-production endpoint for that service. The common template is:

```
aws <service> <read-only-list-api> --region <region> --endpoint-url <non-prod endpoint for that service>
```

## Bypass / chain notes
- The bypass itself is the endpoint override: standard SigV4 signing with the victim's IAM credentials still authenticates against non-production endpoints, so nothing exotic (no tampered signatures, no policy tricks) is required. Only `--endpoint-url` (and matching `--region`) changes.
- Chains: none of the records demonstrate a multi-step chain. The proven usage is single-step: compromised credentials → unlogged enumeration call. The records frame impact as reconnaissance/enumeration of compromised credentials, not data exfiltration.
- Read-only `list`/`describe` APIs were the demonstrated calls (`describe-instance-properties`, `list-datasets`, `list-accelerators`, `list-jobs`), which keeps the action indistinguishable from benign use even if some other telemetry existed.
- Discovery-side note (inferred from the reports' framing, not an explicit chain): a tester finds these endpoints by identifying alternate/non-production endpoints per service, then verifying (a) the call succeeds with standard IAM creds and (b) no CloudTrail event appears.

## Gotchas / what NOT to do
- Do not assume a lack of CloudTrail logs means lack of other monitoring — the proven impact here is limited to CloudTrail invisibility; the reports do not claim bypass of other telemetry.
- Do not assume ALL endpoints of a service are unlogged — production endpoints log normally. The class is specifically about the non-production endpoint sets (18 SSM, 12 Glue, 8 Global Accelerator, 4 Forecast endpoints per the records).
- Do not assume unlogged endpoints grant unauthorized access — IAM authorization still applies on these endpoints. If the credential lacks the permission, the call fails like it would on production. This is a logging gap, not an authz bypass.
- These are AWS first-party service endpoints reported to the AWS VDP — the same technique does not automatically translate to a finding on a customer's bug bounty scope; customer-side hunter reports should target the customer's own unlogged surfaces, not AWS's service endpoints.
- Write/destructive operations were not demonstrated in these records; do not claim unlogged write impact without proof.

## Real-world impact examples
- id=2926361 (AWS VDP): 18 non-production SSM endpoints callable with standard IAM credentials; demonstrated with `aws ssm describe-instance-properties --region us-west-2 --endpoint-url ██████`. An adversary holding compromised IAM credentials can silently enumerate their SSM permissions with no CloudTrail logs generated.
- id=3029552 (AWS VDP): 12 non-production Glue endpoints; silent `glue` permission enumeration of compromised credentials.
- id=3031512 (AWS VDP): 8 non-production Global Accelerator endpoints; silent `globalaccelerator` permission enumeration of compromised credentials.
- id=3022516 (AWS VDP): 4 non-production Forecast endpoints; silent `forecast` permission enumeration of compromised credentials.

In every case the accepted-and-paid impact was the same: CloudTrail-blind IAM permission enumeration for a specific AWS service via that service's non-production endpoints.