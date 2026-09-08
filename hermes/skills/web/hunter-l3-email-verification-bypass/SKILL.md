---
name: hunter-l3-email-verification-bypass
description: "Use when hunting Email Verification Bypass on a target. Loads the L3 technique sheet: Email verification bypass is the class of bugs where an attacker causes a system to treat an email address as verified — or otherwise complete registration/login — without ever proving control of that inbox."
domain: cybersecurity
subdomain: web
tags:
- web
- email-verification-bypass
- hunting
- l3
version: '1.0'
---

# Email Verification Bypass — Technique Sheet

## Overview

Email verification bypass is the class of bugs where an attacker causes a system to treat an email address as verified — or otherwise complete registration/login — without ever proving control of that inbox. It pays well because verified-email-as-identity is load-bearing everywhere: OAuth "Sign in with X" flows, parental/guardian controls, SCIM/SAML enterprise provisioning, domain-restricted accounts, and any place a third party trusts `email` as a unique identifier. Impact ranges from account impersonation on third-party apps to full signup-as-victim on the target platform itself.

## Distinct sub-patterns

### 1. Inviter-side invite-key disclosure (invite link readable by inviter)

- Endpoint shape: `GET /rest/v1.1/sites/{num}/invites?http_envelope=1&status=all&number=100` (WordPress.com/Tumblr invites API)
- Param: `invite_key`
- Payload: none — a plain authenticated GET as the inviter returns the `invite_key` and invite link for each invite.
- Root cause: The invites API exposes the invite_key and full invite link to the inviter, not just the invitee. Anyone with an account can enumerate invites and complete signup on behalf of the invitee's email address without touching their inbox.
- Impact: Demonstrated (video POC) creation of a WordPress.com/Tumblr account on behalf of another person's email address, fully bypassing email verification.
- Exemplars: 1040047 (Automattic)

### 2. Client-side verification flag flip (trust the response, not the server)

- Endpoint shape: `POST /userEmailReg` (GSA registration flow)
- Param: the `success` field in the verification response body
- Payload: intercept the response and modify `"success":false` to `"success":true`
- Root cause: Email verification state is derived from a client-side response value rather than server-side validation of the verification code. The client trusts the flag the server sent and proceeds to the next registration step regardless.
- Impact: Flipping the flag allowed continuing registration and completing the flow with an unverified email.
- Exemplars: 1181253 (U.S. General Services Administration)

### 3. Email change without re-verification

- Endpoint shape: `POST` change-email in account settings (mtn.com)
- Param: `email`
- Payload: not stated — standard change-email request with a new, unowned address.
- Root cause: Changing the account email does not trigger re-verification of the new address. The account (and any email-verified status it carries) transfers to an address the attacker does not own.
- Impact: Account email set to an arbitrary unowned address with no verification challenge; effectively lets an attacker create/verify an account under someone else's email.
- Exemplars: 1182016 (MTN Group)

### 4. Verification-token reuse after email switch (deferred-verify race)

- Endpoint shape: `POST https://www.khanacademy.org/settings/account` (account email change)
- Param: `email`
- Payload: not stated — the bug is flow logic, not a payload.
- Root cause: An email verification token issued for a temporary/attacker email remains valid and is later applied to verify a different (victim) email after the account email is switched back. The verification is bound to the token, not to the address at verify time.
- Impact: Tied `info@khanacademy.org` as a verified parent/guardian account to the attacker's child account without owning that email — a full verification bypass plus a trust-relationship injection.
- Chain:
  1. Sign up as a learner with age below 13, set victim email as parent's email
  2. Change account email to an attacker-controlled temporary email
  3. Receive/complete verification for the temporary email (chain truncated in records)
  4. Switch the account email back to the victim address; the prior verification still applies
- Exemplars: 1636552 (Khan Academy)

### 5. Forgot-password as a pre-verification login path

- Endpoint shape: `POST /password-reset/token` (reached via sign-in forgot-password)
- Param: `token`
- Payload: not stated.
- Root cause: The forgot-password flow issues a working password-reset token and allows setting a new password and logging in before email verification is completed. Verification is treated as a parallel, non-blocking requirement.
- Impact: Logged into a freshly registered account without ever clicking the email verification link — registration completes with an unverified email.
- Exemplars: 265749 (Legal Robot)

### 6. SCIM provisioning auto-marks emails verified

- Endpoint shape: `POST /api/scim/v2/groups/{group}/Users` (GitLab)
- Param: `emails.value`, `userName`, `externalId`
- Payload (verbatim, truncated in record):
```json
{"externalId":"REPLACE_ME","active":null,"userName":"anyusernamewilldo","emails":[{"primary":true,"type":"work","value":"ANYGITLABEMAIL@gitlab.com"}],"name":{"formatted":"Test User","familyName":"User","givenName":"Test3"},"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"meta":{"resourceTyp...
```
- Root cause: SCIM provisioning marks a user's email as verified without sending any verification email. A group owner with a SCIM token can create users carrying arbitrary `@gitlab.com` emails, pre-marked verified.
- Impact: Created a user with email `ngalog@gitlab.com` marked verified, then logged in via SAML SSO — bypassing email verification to access services that gate on the `@gitlab.com` domain.
- Chain:
  1. Upgrade group to gold plan
  2. Set up SAML SSO and create a SCIM token
  3. POST SCIM user with arbitrary `@gitlab.com` email
  4. Login via `/groups/{group}/...` (SAML SSO)
- Exemplars: 565883 (GitLab)

### 7. Onboarding-response replay (replay a signup response to verify arbitrary email)

- Endpoint shape: `POST /1.1/onboarding/task.json` (Twitter/X signup flow)
- Param: `email`
- Payload: Replay of the captured onboarding/task.json signup response via Fiddler Autoresponder.
- Root cause: The signup flow reuses an earlier onboarding response to verify an arbitrary unused email without owning that inbox — the client's flow state can be satisfied by a stale recorded response.
- Impact: Verified any unused email address on a Twitter account without inbox access; enables OAuth login/impersonation on third-party apps that trust the email from "Sign in with Twitter".
- Chain:
  1. Capture the onboarding/task.json signup response in Fiddler
  2. Add a Fiddler Autoresponder rule replaying that response
  3. Log into the attacker's own Twitter account (chain truncated in records) and walk the email-verification step with the replayed response
- Exemplars: 574962 (X / xAI)

### 8. Federated login creates accounts outside the verification pipeline

- Endpoint shape: `POST /users/sign_in` (GitLab's Salesforce login integration)
- Param: none explicitly singled out
- Payload: not stated.
- Root cause: The Salesforce login integration lets an admin create a user with an arbitrary email; signing in through Salesforce bypasses GitLab's email verification and the domain whitelist/blacklist entirely.
- Impact: Attacker created and signed in as an account with an arbitrary email domain, bypassing both email domain restriction and email verification on gitlab.com.
- Chain:
  1. Login via Salesforce (arbitrary email)
  2. Sign in to GitLab with Salesforce
  3. Account created with unverified arbitrary email domain
- Exemplars: 617896 (GitLab)

## Bypass / chain notes

- Enterprise provisioning as a verification side door: GitLab twice (565883, 617896) shows that SCIM/SAML/Salesforce paths provision emails as verified outside the normal email-verification pipeline. Whenever a target offers SSO/SCIM/group provisioning, test whether provisioned emails land marked-verified, and whether that unlocks domain-gated resources (`@gitlab.com` checks).
- Verification logic lives in the client: in 1181253 the fix surface was a response field (`success`), so a proxy flip was enough. Always check whether the "verify" step's decision is made server-side or merely reflected client-side.
- Token/flow-state confusion: two patterns exploit state not being bound to the current address — a token issued for address A verifies address B (1636552), and a recorded signup response satisfies verification for a different address (574962). Capture-then-replay with an intercepting proxy (Fiddler Autoresponder) and email-switch-then-verify-then-switch-back are the two concrete chains.
- Secondary flows that skip verification: forgot-password (26549-like: 265749) completed login pre-verification; invites (1040047) handed the completing party the invite secret. Any parallel flow that grants account access (password reset, invite acceptance, SSO JIT provisioning) is a candidate bypass of the primary verification gate.
- Multi-step chains matter for severity: the Khan Academy bug needed the under-13 learner flow to even request a parent email (1636552); GitLab SCIM needed gold plan + SAML setup (565883). Don't stop at "the endpoint rejects me" — look for the flow that lets you plant the victim email first.

## Gotchas / what NOT to do

- Don't test with emails you don't own on third parties without care: several of these bugs involve verifying addresses belonging to others (`info@khanacademy.org`, `ngalog@gitlab.com`). Prefer clearly reserved/unused addresses on the target's own domain where the report did, and document rather than persist access.
- Don't assume the verification endpoint itself is the bug. In most of these records the verification endpoint was fine; the bug was in invites, account settings, password reset, SCIM, or client-side state.
- Don't ignore age-gated/parent-child flows — the under-13 learner path was the enabler at Khan Academy.
- Don't test response-flipping only on the final response; the flipped flag in 1181253 was in a mid-flow verification response (`/userEmailReg`), not the signup response.
- Don't report "email not verified" without proving impact: the accepted impacts here were impersonation via OAuth trust (574962), domain-gated access (565883), guardian-tie on a child account (1636552), and account creation on someone else's email (1040047, 1182016). Bare "I could set an unverified email" is the weak version of this class.
- SCIM payloads must be well-formed SCIM 2.0 (`schemas`, `emails[].primary/type`, `userName`, `externalId`) — a malformed body just 400s; the bug is the server's verify-marking, not malformed input.

## Real-world impact examples

- 574962 (X/xAI): Verified any unused email on a Twitter account with no inbox access, then used the trusted email for OAuth login/impersonation on third-party apps.
- 565883 (GitLab): `ngalog@gitlab.com` created via SCIM and marked verified; SAML SSO login granted access to services gated on the `@gitlab.com` domain.
- 1636552 (Khan Academy): Attacker's child account got `info@khanacademy.org` attached as a verified parent/guardian — identity forgery inside a trust relationship.
- 1040047 (Automattic): Account created on behalf of a third party's email via the exposed invite link (video POC).
- 617896 (GitLab): Account with arbitrary email domain created via Salesforce login, evading both domain whitelist/blacklist and verification.
- 1181253 (GSA) / 265749 (Legal Robot) / 1182016 (MTN): Registration and login completed with emails never verified — the baseline version of this class, still accepted as valid findings.