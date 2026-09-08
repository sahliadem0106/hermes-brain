---
name: hunter-l3-s3-bucket-takeover
description: "Use when hunting S3 Bucket Takeover on a target. Loads the L3 technique sheet: S3 bucket takeover occurs when code, documentation, or infrastructure references an S3 bucket (or a hostname backed by one) that has not been registered by the owning organization."
domain: cybersecurity
subdomain: web
tags:
- web
- s3-bucket-takeover
- hunting
- l3
version: '1.0'
---

# S3 Bucket Takeover — Technique Sheet

## Overview
S3 bucket takeover occurs when code, documentation, or infrastructure references an S3 bucket (or a hostname backed by one) that has not been registered by the owning organization. Because S3 bucket names are globally unique and first-come-first-served, any third party can create the unclaimed bucket in their own AWS account and fully control the content served from it. It pays when the dangling reference is used to serve executable or security-sensitive content — JavaScript files, browser extensions, apt/installer binaries — because claiming the bucket enables arbitrary content injection into a trusted origin. All three records here come from one hunter (ajaysenr), all found via the same core method: extract every S3 hostname referenced in a target's code/docs/repos, then check whether the bucket resolves and whether it is claimable.

## Distinct sub-patterns

### 1. Unclaimed S3 bucket referenced in product JavaScript / repo files
- Endpoint shape: any S3 hostname found in JS sources, e.g. `https://<bucket-name>.s3.amazonaws.com` (regional forms like `https://s3-us-west-2.amazonaws.com/<bucket>/` count too).
- Payload that actually fired: none needed to identify the bug — the proof was serving a POC page: `http://brave-extensions.s3.amazonaws.com/index.html` returned attacker-controlled content, demonstrating the bucket was attacker-owned.
- Root-cause pattern: Brave's code (3 `.js` files in their public repos) referenced `brave-extensions.s3.amazonaws.com`, but the bucket was not registered by Brave. Anyone could create a bucket named `brave-extensions` and serve content at that exact URL the code trusts.
- Impact proven: an attacker could upload files matching the filenames used in Brave's code (e.g. `redirect.html`) and steal cookies of victims who load them — content injection into a URL Brave's own JS fetches.
- Exemplar report: id=1316650 (Brave Software).

### 2. Unclaimed S3 bucket backing software install/distribution channels
- Endpoint shape: regional path-style URL used in install docs, e.g. `GET https://s3-us-west-2.amazonaws.com/brave-apt/` — the bucket referenced by Brave's official Linux (apt) install instructions.
- Payload that actually fired: `https://s3-us-west-2.amazonaws.com/brave-apt/proof.txt` — attacker created the bucket `brave-apt` in a new AWS account and uploaded `proof.txt`, retrievable at the original URL.
- Root-cause pattern: the bucket referenced by the official install instructions was unclaimed; a new AWS account could register the globally-unique name and serve whatever it wants at the URL users are told to trust.
- Impact proven: attacker controls the source that serves the Brave browser install to Linux users — arbitrary/malicious binary distribution (supply-chain compromise).
- Exemplar report: id=1791558 (Brave Software).

### 3. Unclaimed S3 bucket behind an acquired/product endpoint (vendor surface)
- Endpoint shape: an S3 bucket behind a product/acquired-company endpoint (Apptio, acquired by IBM); the record identifies `bucket_name` as the relevant parameter on the apptio endpoint.
- Payload: N/A / not stated.
- Root-cause pattern: the S3 bucket behind the apptio endpoint was unclaimed, allowing registration and control by an attacker — same dangling-reference class, discovered through an acquisition's legacy infrastructure rather than the parent's primary repos.
- Impact proven: S3 bucket takeover on the apptio endpoint was confirmed and remediated by IBM (accepted and fixed).
- Exemplar report: id=2498255 (IBM).

## Bypass / chain notes
- The universal "chain" in these records is a 4-step discovery workflow, not a filter bypass (record 1316650 lists it explicitly):
  1. Grep the target's public repos / JS bundles / docs for S3 hostnames (`s3.amazonaws.com`, `s3-<region>.amazonaws.com`, `*.s3.*.amazonaws.com`).
  2. Collect the bucket names and check each: does the URL resolve? (NXDOMAIN or "NoSuchBucket" XML error = dangling reference = claimable).
  3. Create an S3 bucket with that exact name in your own AWS account (must be in the region the URL expects — record 1791558 used the `us-west-2` regional path-style form).
  4. Upload proof content at the exact path the reference expects and retrieve it via the original URL.
- Match the reference style: path-style URLs (`s3-us-west-2.amazonaws.com/<bucket>/`) require the bucket in the URL's stated region; virtual-hosted style (`<bucket>.s3.amazonaws.com`) maps to us-east-1 by default. Getting this wrong means your proof won't resolve at the original URL.
- Name your proof files after the files the code actually references (record 1316650: `redirect.html`; use `index.html` for a root POC) — this demonstrates real impact rather than just "I made a bucket".
- Acquisition surfaces are a fertile hunting ground (IBM/Apptio): legacy product endpoints often outlive their infrastructure and their buckets get deprovisioned while references remain.

## Gotchas / what NOT to do
- Don't report a bucket that already resolves with an "AccessDenied" error — that means the bucket exists and is owned (just private). Only "NoSuchBucket" / unresolvable references are claimable.
- Don't serve actual malicious content in your POC; a benign `proof.txt` (record 1791558) or a harmless `index.html` (record 1316650) is sufficient and keeps you within program rules.
- Don't stop at "bucket is claimable" as the impact statement — tie it to what the URL is *used for* (cookies via referenced files, install binaries). Impact contextualization is what made the Brave reports land.
- Don't forget to release/delete the bucket after demonstrating takeover — squatting on a name you've proven is both unethical and often a program-rule violation.
- Region matters: creating the bucket in the wrong region means the original URL won't serve your content and your proof fails.
- Don't limit the search to the main product repos — docs (install instructions led to record 1791558) and acquired-company code (record 2498255) were the sources in these records.

## Real-world impact examples
- Brave (id=1316650): claiming `brave-extensions.s3.amazonaws.com` lets an attacker upload `redirect.html` and other files the browser's JS fetches, stealing victim cookies — from a bucket no one owned.
- Brave (id=1791558): claiming `brave-apt` gave control of the URL in Brave's official Linux install instructions — an attacker could serve malicious browser binaries to every user following the docs (supply-chain attack).
- IBM (id=2498255): confirmed takeover of the unclaimed S3 bucket behind the Apptio endpoint; IBM accepted and remediated it.