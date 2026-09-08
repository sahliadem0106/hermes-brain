---
name: hunter-l3-algorithmic-bias-improper-input-validation
description: "Use when hunting Algorithmic Bias (Improper Input Validation) on a target. Loads the L3 technique sheet: This class covers bugs where a platform's ML-driven content transformation (here, Twitter's saliency-based image auto-cropping) systematically misrepresents, excludes, or economically harms subjects in user media."
domain: cybersecurity
subdomain: web
tags:
- web
- algorithmic-bias-improper-input-validation
- hunting
- l3
version: '1.0'
---

# Algorithmic Bias (Improper Input Validation) — Technique Sheet

## Overview
This class covers bugs where a platform's ML-driven content transformation (here, Twitter's saliency-based image auto-cropping) systematically misrepresents, excludes, or economically harms subjects in user media. Unlike classic injection or access-control bugs, "payloads" are ordinary image compositions — the trigger is the semantic content of the input, not a crafted string. It pays when the platform's algorithm produces demonstrable, reproducible harm: cropped-out business information (economic damage) or consistent demographic/color-based exclusion, which these dedicated bug-bounty programs (e.g., Twitter Algorithmic Bias) accept as in-scope findings.

## Distinct sub-patterns

### Sub-pattern 1: Saliency crop excludes business-critical text (economic harm)
- Endpoint shape / parameter: Not a traditional endpoint. Target: Twitter's image-cropping saliency algorithm as applied to timeline/ad image previews. Input: a small-business ad graphic containing text with a website URL.
- Payload: Payload not stated (no crafted string; the "payload" is a real ad image where the URL text competes visually with other subjects — here, a dog).
- Root-cause pattern: The saliency model scores visual regions by its notion of "interesting" content (faces, animals, high-contrast subjects) and prioritizes them over textual/informational regions. A dog outranked the text containing the URL, and the automatic crop cut out the beginning of the website URL — the purchase-critical information.
- Impact proven: Beginning of the website URL cropped out of the ad graphic, reducing customers/profits — concrete economic harm to a small business.
- Exemplar: id=1290872 [ajaysenr], Twitter Algorithmic Bias.

### Sub-pattern 2: Color/luminance bias within a single image (under-representation of darker subjects)
- Endpoint shape / parameter: Same target — saliency-based auto-crop on a multi-subject photo. Input: a photo containing two dogs of different colors (one lighter, one darker).
- Payload: Payload not stated.
- Root-cause pattern: The saliency model centered on the lighter-colored dog and cut off the darker-colored dog in the frame, indicating the model's scoring is influenced by subject color/luminance, not just subject type.
- Impact proven: The darker dog was cut off and barely shown — reproducible under-representation bias against darker-colored subjects.
- Exemplar: id=1294062 [ajaysenr], Twitter Algorithmic Bias.

### Sub-pattern 3: Subject-type + color bias across subjects (animal favored over person)
- Endpoint shape / parameter: Same target — auto-crop on a photo containing both a person and an animal. Input: a photo with an African American woman and a golden retriever.
- Payload: Payload not stated.
- Root-cause pattern: The saliency algorithm favored the golden retriever over the African American woman, identifying the dog as the crucial focus. The woman's head was cropped off entirely — intersection of subject-type bias (animal over human) and color-based under-representation.
- Impact proven: The African American woman's head was cropped out entirely from the visible preview frame.
- Exemplar: id=1294242 [ajaysenr], Twitter Algorithmic Bias.

## Bypass / chain notes
- No chains were present in the records (all three marked chain: none). Findings in this class are single-stage: the crop itself is the full proof.
- Practical reproduction note implied by the records: side-by-side comparisons in one frame are the strongest test vector — two subjects differing in exactly one attribute (color of the same animal type; human vs. animal) isolate the bias and make the cropping behavior unambiguous in screenshots. Do not extrapolate bypass techniques beyond this; none are documented here.

## Gotchas / what NOT to do
- Do not expect traditional endpoints, parameters, or injectable payloads — all three records show param "(none)" and payload "(none)". A typical injection methodology doesn't apply.
- Do not report a single ambiguous crop as bias. All accepted records here used comparative compositions where the discriminated subject was clearly cut off or excluded while a comparable subject was centered — that contrast is the evidence.
- Do not overclaim impact: the economic-harm finding (id=1290872) was framed as reduced customers/profits from a cropped URL, not fabricated revenue figures. Keep impact claims tied to what the crop visibly destroyed.
- Salience bias findings depend on the platform running a dedicated algorithmic-bias program; the same behavior may be out of scope or informational elsewhere. Confirm program scope before submitting.

## Real-world impact examples
- id=1290872: A small-business ad graphic had the beginning of its website URL cropped out of preview by the saliency model (which focused on a dog), directly reducing potential customers and profits — economic harm from an algorithmic crop.
- id=1294062: In a two-dog photo, the darker-colored dog was cut off and barely shown while the lighter dog was centered — demonstrated color-based under-representation.
- id=1294242: The saliency algorithm chose a golden retriever over an African American woman as the image's focus, cropping her head out entirely — a striking, publicly demonstrable case of color-based under-representation bias with reputational impact for the platform.