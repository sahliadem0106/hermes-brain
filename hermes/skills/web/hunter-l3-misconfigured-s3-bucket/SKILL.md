---
name: hunter-l3-misconfigured-s3-bucket
description: "Use when hunting Misconfigured S3 Bucket on a target. Loads the L3 technique sheet: Misconfigured S3 buckets are AWS storage assets exposed to unauthenticated users via public ACLs, bucket policies, or listing permissions."
domain: cybersecurity
subdomain: web
tags:
- web
- misconfigured-s3-bucket
- hunting
- l3
version: '1.0'
---

# Misconfigured S3 Bucket — Technique Sheet

## Overview
Misconfigured S3 buckets are AWS storage assets exposed to unauthenticated users via public ACLs, bucket policies, or listing permissions. The bug is almost never in application code — it is a cloud configuration mistake, which means scanners and recon tooling miss it unless you explicitly enumerate bucket names and probe them. It pays when buckets belong to a target organization (not third-party/CDN infrastructure the company deliberately made public), and especially when listing is enabled, since you can enumerate everything and prove real data exposure rather than a mere 403-vs-200 difference.

## Distinct sub-patterns

### Sub-pattern 1: Publicly listable + readable bucket via virtual-hosted endpoint
- **Endpoint shape / parameter:** `GET https://{bucket}.s3.amazonaws.com/` (virtual-hosted style, no authentication, no path parameter — the root listing itself is the finding).
- **Payload that actually fired:** payload not stated — the attack was a plain unauthenticated GET to the bucket root, which returned an XML `ListBucketResult` instead of `AccessDenied`.
- **Root-cause pattern:** The bucket's permission configuration allowed public list/read access (anonymous principals granted `s3:ListBucket` and `s3:GetObject`) with no authentication requirement. No signed request, no policy condition restricting by IP/referrer/AWS principal.
- **Impact proven:** Listed and downloaded bucket contents — binaries, repodata, manuals, documents, media — entirely without authentication. Full read of CI/CD artifacts (GoCD build output), which can leak internal code and credentials.
- **Exemplar reports:** id=1654145 [ajaysenr] (GoCD), id=94502 [ajaysenr] (Shopify).

### Sub-pattern 2: Public-read ACL on buckets that were not intended to be public
- **Endpoint shape / parameter:** `s3://{bucket-name}` — probe the bucket as an S3 resource (e.g. via `aws s3 ls s3://bucket --no-sign-request` or anonymous HTTP equivalents). In the Mapbox case: `s3://mapbox-js` plus a second Mapbox-owned bucket, both carrying `public-read` ACLs.
- **Payload that actually fired:** payload not stated — confirmation was an ACL/permission check showing `public-read` on buckets owned by the target.
- **Root-cause pattern:** Bucket ACL (not just policy) set to `public-read`. Critically, one bucket (the JS distribution) was public *by design*, but a second bucket carried the same public ACL unintentionally. The tell: comparing ACLs across buckets owned by the same org to find one that deviates from intended exposure.
- **Impact proven:** Confirmed public-read ACL on two Mapbox-owned S3 buckets; the unintended bucket exposed data to unauthenticated read. Bucket was subsequently switched to private — company accepted and remediated, confirming it was in scope.
- **Exemplar reports:** id=222724 [ajaysenr] (Mapbox).

### Sub-pattern 3: World-readable with listing enabled, plus world-writable variant
- **Endpoint shape / parameter:** S3 buckets probed for anonymous access; testing both read/list and write permissions against Shopify-owned buckets.
- **Payload that actually fired:** payload not stated — the check was an anonymous permission test against each bucket (list attempt, read attempt, write attempt).
- **Root-cause pattern:** Buckets left world-readable with file listing enabled; one bucket additionally world-writable. The combination of listing + world-writability is the most dangerous configuration in this class: an attacker can enumerate contents AND replace objects.
- **Impact proven:** Two Shopify-owned buckets world-readable with listing enabled (potentially containing sensitive data), one world-writable. Remediation: bucket options changed to disable listing — again accepted and fixed by the program.
- **Exemplar reports:** id=94502 [ajaysenr] (Shopify).

## Bypass / chain notes
- No multi-step chains or filter bypasses appear in the records. The core "technique" is discovery and confirmation:
  - Distinguish by-design public buckets (CDN/JS distribution, e.g. `mapbox-js`) from unintended ones — the reportable bug is the *unintended* exposure, not the intentional public asset.
  - Compare ACLs across multiple buckets owned by the same organization; a shared/misapplied ACL configuration is how one public bucket signals that its siblings may be public too (exactly what happened at Mapbox: finding `mapbox-js` public led to checking other Mapbox buckets, one of which was unintentionally public).
  - Test the full permission matrix, not just read: anonymous ListBucket (GET on root), anonymous GetObject, and anonymous PutObject (write). Shopify's finding included a world-writable bucket — read-only probing would have missed a third of that impact.

## Gotchas / what NOT to do
- Do NOT report buckets that are public by design (public asset distribution like `mapbox-js`). Verify the bucket is owned by the target and that the exposure contradicts intent; in the Mapbox case the by-design bucket was only context, the finding was the *other* bucket.
- Do NOT modify or delete anything in world-writable buckets — write access is proven by permission checks, never by actually uploading destructive or persistent content. The Shopify report proves impact via configuration state, not by planting files.
- Do NOT assume a bucket is safe because the web app doesn't link to it — none of these buckets required any endpoint discovery from the application; they were found by bucket-name enumeration and direct probing.
- Do NOT stop at "can I read one object." Listing enabled is what upgrades the finding from a single leaked file to full enumeration of binaries, documents, repodata — describe what the listing actually exposes in your report.
- Do NOT skip confirming ownership — all three reports succeeded because the buckets were verifiably company-owned (GoCD, Mapbox, Shopify). Randomly public third-party buckets are out of scope.

## Real-world impact examples
- **GoCD (id=1654145):** Unauthenticated listing and download of the GoCD S3 bucket's full contents — binaries, repodata, manuals, documents, and media — with zero authentication. A CI/CD artifact store readable by anyone.
- **Mapbox (id=222724):** Two Mapbox-owned buckets confirmed with public-read ACLs; one (not public by design) exposed its data to unauthenticated read until the company switched it to private.
- **Shopify (id=94502):** Two Shopify buckets world-readable with file listing enabled (potentially containing sensitive data), and one world-writable — anonymous users could enumerate contents and write objects. Fixed by disabling listing on the buckets.