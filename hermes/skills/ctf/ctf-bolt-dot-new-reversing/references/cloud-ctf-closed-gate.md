# Closed Gate / Crownspire Bellworks CTF

Full session notes from the "Closed Gate" HTB-style infrastructure CTF.

## Infrastructure

| Service | Port | Server |
|---------|------|--------|
| Briefing page | 30998 | SaltCrownBriefing/1.0 Python/3.12.13 |
| AWS Mock (primary) | 31788 | LocalStack-like, SigV4 auth |
| Crownspire Bellworks | 31787 | nginx + Python (Werkzeug?) + Varnish cache |
| AWS Mock (secondary) | 31789 | Apache/2.4.41 (Ubuntu) — different creds |
| PhantomKernel (unrelated) | 30997 | Apache/2.4.67 (Debian) |
| Retro Arcade (unrelated) | 31790 | Werkzeug/3.1.8 Python/3.12.13 |

## Starting Credentials

- User: `registry-outer-clerk`
- Access Key: `AKIAJT9AOLQRPTOT7VLH`
- Secret Key: `sKdNezEer2jhknuxINXv0vfjZjvv02CsNdpiCMFh`
- Account: `728491650384`

## AWS Role Chain

| Step | Role | ExternalId |
|------|------|------------|
| 1 | registry-custody-reader | registry-job-custody-4e8c |
| 2 | registry-indexer | registry-indexer-relay-4e8c |
| 3 | registry-verifier-runner | registry-verifier-bind-4e8c |
| 4 | shard-custodian | registry-custodian-seal-4e8c |

## Assumable No-ExtId Roles

All of these are assumable from outer-clerk or shard-custodian, but none can CreateRole or GetSecretValue:
AdministratorAccess, admin, Admin, ShardReader, shard-reader, ShardReaderRole, registry-shard-reader, plus ~35+ more discovered via brute-force guessing.

## DynamoDB

Table: `registry-plate-index`, key name: `plate_id` (lowercase)

PLATE-4E8C is the only ACTIVE plate. Others are ARCHIVED, SEIZED, REVOKED, DRAFT, CLOSED, or VOID.

## CloudFormation Outputs

Stack: `registry-shard-stack-live`
- `ShardSecretName = registry/shard/live-shard-4e8c`
- `ShardKmsKeyId = 6a47af8e-06a4-4a14-a2f9-9325f302678d`

## Decrypted Policy Bundle

```json
{
  "managed_policy_arn": "arn:aws:iam::728491650384:policy/ShardReaderPolicy",
  "policy_document": {
    "Statement": [
      {"Sid": "CallerIdentity", "Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
      {"Sid": "ReadLiveShardSecret", "Effect": "Allow",
       "Action": "secretsmanager:GetSecretValue",
       "Resource": "arn:aws:secretsmanager:us-east-1:728491650384:secret:registry/shard/live-shard-4e8c-*"},
      {"Sid": "DecryptLiveShard", "Effect": "Allow",
       "Action": "kms:Decrypt",
       "Resource": "arn:aws:kms:us-east-1:728491650384:key/6a47af8e-06a4-4a14-a2f9-9325f302678d"}
    ]
  }
}
```

## Web App API Endpoints (Crownspire Bellworks)

### Public
- `GET /` — Homepage
- `GET /health` — Not found (404)
- `GET /login` — SAML login form (redirects to SSO)
- `GET /signup` — Registration form
- `GET /admin` — Keeper sign-in form (POST /admin/login)
- `GET /notices` — Public notices
- `GET /scripts/bellworks.js?v=bw5` — Client JS (key source of API endpoints!)
- `GET /design/signal.css`, `/styles/tower.css` — Styles
- `GET /favicon.svg` — Favicon

### Authenticated (viewer role)
- `GET /registry` — Dashboard with forms
- `GET /api/standing` — Returns role: `{"authed":true,"role":"viewer","label":"Viewer",...}`
- `GET /notices` — Public notices
- `GET /admin/account` — 403 "Sealed" (keeper-only)
- `GET /admin/courier` — 403 "Sealed" (keeper-only)
- `GET /appeals` — 403 "Sealed" (keeper-only)

### Keeper-only
- `POST /admin/courier` — SSRF dispatch. Accepts JSON `{"address":"url","headers":{},"body":""}`. POSTs to arbitrary URLs server-side.
- `POST /api/account/reset-password` — Reset passphrase. Accepts `{"api_key":"<key>","new_password":"<pw>"}`. Sealing key from `[data-api-key]` on `/admin/account`.
- `POST /admin/login` — Login with username + password. Successful auth returns 302 with session cookie setting role to "keeper".
- `GET /admin/account` — Returns page with `<... data-api-key="<real_key>">` attribute.
- `GET /admin/courier` — Courier dispatch UI.
- `GET /appeals` — Route filings page.

### SAML
- `GET /sso/saml2/idp/metadata.php` — IdP metadata XML
- `POST /sso/module.php/core/loginuserpass` — SAML login endpoint
- `POST /saml/acs` — SAML assertion consumer service
- `GET /sso/module.php/saml/idp/singleSignOnService` — SSO redirect
- `GET /sso/admin` — 403 Forbidden (SimpleSAMLphp admin interface blocked)

## Keeper API Key Flow (from JS analysis)

```javascript
// When role === "keeper":
fetch("/admin/account", { credentials: "same-origin" })
  .then(r => r.ok ? r.text() : Promise.reject(r.status))
  .then(html => {
    const key = new DOMParser().parseFromString(html, "text/html")
      .querySelector("[data-api-key]")?.getAttribute("data-api-key") || "";
    // key is the REAL sealing key
  });

// Form submit:
fetch("/api/account/reset-password", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ api_key: realKey, new_password: newPassphrase })
});
// On success: "Passphrase reset with the sealing key."
// On failure: "Reset refused." or "Unknown sealing key."
```

The default HTML value `bellkey_7f4a91c2b8` is a placeholder hint, NOT the real sealing key. The real key is stored on the server and only returned to keeper sessions via `[data-api-key]`.
