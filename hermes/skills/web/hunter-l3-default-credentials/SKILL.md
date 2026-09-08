---
name: hunter-l3-default-credentials
description: "Use when hunting Default Credentials on a target. Loads the L3 technique sheet: This class covers internet-facing admin panels, consoles, appliances, and internal tooling that still authenticate with factory-default, vendor-default, or trivially-guessable credentials (username-as-password, `changeme`, `guest`)."
domain: cybersecurity
subdomain: web
tags:
- web
- default-credentials
- hunting
- l3
version: '1.0'
---

# Default Credentials — Technique Sheet

## Overview
This class covers internet-facing admin panels, consoles, appliances, and internal tooling that still authenticate with factory-default, vendor-default, or trivially-guessable credentials (username-as-password, `changeme`, `guest`). It pays reliably because almost every organization runs at least one exposed management plane — Tomcat, Splunk, Jenkins, RabbitMQ, Rundeck, SAP, Django, Spring Boot, DVRs, and internal dashboards — and deployment pipelines routinely skip "change the default password." Proven impacts in this class range from full site administration and queue-dumping to device-control RCE, all from a single successful login with zero exploitation sophistication.

## Distinct sub-patterns

### 1. admin/admin on bespoke / third-party admin panels
- Endpoint shape: `POST /login`, `POST /owncloud6/login`, `POST /kinetic/app/`, `POST https://<host>/geoportal/` with form params `username`, `password`.
- Payload that fired (verbatim): `admin/admin` (records 107849, 1297480, 1839012, 1938693, 204052); also `username=admin&password=admin`.
- Root cause: admin account provisioned with the vendor's shipped default pair and no forced password change; in several cases the same pair worked across multiple instances of the product.
- Impact proven: full admin control of ownCloud instance (107849); full control of MTN broadband-maps site (1297480); DoD portal access incl. emails, links, data (1839012); Kinetic Core System Console admin exposing server logs, DB users with emails/names, system activity (1938693); file upload on nutty.ubnt.com (204052).
- Exemplars: 107849 (ownCloud), 1938693 (DoD /kinetic).

### 2. Username-as-password on named accounts
- Endpoint shape: `POST https://<host>/Marathon/Default.aspx` with `username=rick&password=rick`.
- Payload that fired (verbatim): `username=rick&password=rick` (1168104).
- Root cause: weak/no password policy lets an administrator account's password equal its username — a variant of "default" worth testing even when no vendor default exists.
- Impact proven: login to the `rick` account with administrator access; ability to edit, create, and update users.
- Exemplar: 1168104 (GSA mysmartplans).

### 3. Vendor-default creds on Java/ops consoles
- Endpoint shapes and verbatim pairs that fired:
  - `GET /manager/html` — Apache Tomcat: `tomcat:tomcat` (1267174).
  - `GET https://apt.ec2.shopify.com:8089` — Splunk management console: `admin/changeme` (158118).
  - Rundeck at `https://34.120.209.175/user/login` — `admin/admin` (1415241).
  - RabbitMQ management console on staging `*.dev.unikrn.space` — `guest:guest` (753602).
  - Nexus Repository Manager at `nexus.imgur.com` — user: `anonymous`, pass: `anonymous` (435457).
- Root cause: ops tooling deployed quickly and exposed publicly; default service accounts never rotated. Nexus is a special case: the *anonymous account enabled by default* is itself the finding when combined with no access restriction.
- Impact proven: Tomcat manager admin access (1267174); Splunk console login (158118); Rundeck login whose resulting 500 error disclosed version, physical path, and class name (1415241); RabbitMQ console access with ability to view/dump queues containing confidential SSO and API details and add/modify/delete queues (753602); Nexus access to all repositories enabling dependency proxying, component deletion, and application analysis (435457).
- Exemplars: 158118 (Splunk), 753602 (RabbitMQ), 435457 (Nexus).

### 4. Product-specific defaults on appliances/enterprise software
- Endpoint shapes and pairs:
  - Adobe Experience Manager: `GET /repository` then `GET /lc` on a .mil host, using default AEM credentials (payload not stated) (710813).
  - SAP webgui: internet-exposed SAP server with default TMSADM credentials still enabled (payload not stated) (195163).
  - Spring Boot Admin dashboard on `*.8x8.com` left exposed with default credentials configured (payload not stated) (1417635).
  - Cisco TelePresence SX80 exposed with default admin credentials (payload not stated) (684070).
  - Kinetic Core System Console 2.1.0-SNAPSHOT (see #1) (1938693).
  - Jenkins protected only by weak/default credentials (payload not stated) (2954547).
- Root cause: enterprise appliances ship with documented service/default accounts (TMSADM for SAP transport management, AEM's default admin, Cisco device admin) that are rarely disabled on internet-facing deployments.
- Impact proven: AEM admin-panel access on a .mil host (710813); SAP webgui login exposing default-installation test data and internal server names via web pages (195163); program-confirmed exposed Spring Boot Admin instance (1417635); full SX80 device control (see chain in Bypass/Chain notes) (684070); IBM Jenkins access, remediated after disclosure (2954547).
- Exemplars: 195163 (SAP), 684070 (Cisco).

### 5. Default "user"-tier accounts on device panels and file managers
- Endpoint shapes and verbatim pairs:
  - DVR web client login: `user / user` (398797).
  - Tiny File Manager login: `user/12345` (1747146).
- Root cause: low-tier default accounts (`user`, non-admin) ship enabled; hunters often only test `admin`, but the `user`-tier defaults are frequently left intact and still grant harmful capability.
- Impact proven: browsing live DVR camera feeds (398797); Tiny File Manager access with modify, upload, and delete privileges (1747146).
- Exemplars: 398797, 1747146.

### 6. Weak/generic creds on internal dashboards and Django admin
- Endpoint shapes and payloads:
  - `POST /api-auth/login/` (Django): verbatim `csrfmiddlewaretoken=Gt5IRFhlh8BekC11btkUdo8doBniN2pJ&next=%2F&username=admin&password=research&submit=Log+in` (128114).
  - Analytical dashboard: redacted weak/generic credential pair `█████:██████` (692116).
- Root cause: internal/admin tooling with guessable themed passwords (`admin/research`) and no rate limiting or lockout on the login endpoint — enabling both guessing and brute force.
- Impact proven: Django admin panel + REST API access including adding new users and groups via the API (128114); access to internal analytical data (692116).
- Exemplars: 128114, 692116.

## Bypass / chain notes
- **Device-control → RCE chain (684070, DoD):** Access exposed Cisco TelePresence SX80 → login with default admin credentials → full device control → add startup scripts = RCE; noted as usable as a silent backdoor. Default credentials on appliances are often a step to code execution, not just data access.
- **Console-access chain (1938693):** Browse to `/kinetic/app/` → login `admin/admin` → full admin console access → server logs, DB users, emails, names, system activity.
- **Multi-instance reuse (107849):** the `admin/admin` pair worked on one instance while other instances used different passwords — test every exposed instance of a product independently.
- **Auth-flow specifics:** the Django case (128114) required fetching and replaying the `csrfmiddlewaretoken` in the login POST — expect CSRF tokens on Django/ASP.NET-style login forms before credential testing.
- **Anonymous-enabled as "default credential":** 435457 shows that merely having the default `anonymous/anonymous` account enabled on Nexus, with no access restriction, qualifies — check whether anonymous/DEPRECATED-style guest access is on before hunting for pairs.

## Gotchas / what NOT to do
- **Don't stop at `admin/admin`.** The set that actually fired here includes `tomcat:tomcat`, `admin/changeme`, `guest:guest`, `user/user`, `user/12345`, `username=username` (rick/rick), and `admin/research`. Cover vendor defaults per product and username-as-password variants.
- **Don't ignore non-admin tiers.** `user/user` on a DVR and `user/12345` on Tiny File Manager both produced real impact (camera feeds; file upload/delete).
- **Don't assume staging is out of scope** — 753602 fired on `*.dev.unikrn.space`, a staging RabbitMQ.
- **Don't dismiss "nothing sensitive" outcomes prematurely but report honestly:** 1417635 (8x8 Spring Boot Admin) was confirmed by the program but contained nothing sensitive; 204052 (Ubiquiti) was closed Informative because the system doesn't differentiate authenticated users. Impact framing matters — pair the login with what the session can actually do (dump queues, add users, upload files, delete components).
- **Watch for info-leak bonus:** a post-login 500 error on Rundeck (1415241) disclosed version, physical path, and class name — capture error responses even when the login partially fails.
- **Payload gaps are common:** several records (AEM, SAP, Spring Boot Admin, Cisco, Jenkins) state "default credentials" without the literal pair — consult the product's documented defaults rather than assuming admin/admin.
- **Program-scoping caution:** one DoD record (192074) involves credential reset/theft via a misconfigured user-account application rather than a default pair — related but distinct; don't conflate weak reset flows with this class in reports.

## Real-world impact examples
- **RCE via appliance:** Cisco TelePresence SX80 default creds → startup-script addition → remote code execution / silent backdoor (684070).
- **Confidential data exfil via message queues:** RabbitMQ `guest:guest` on Unikrn staging → dumped queues containing confidential SSO and API details, plus queue add/modify/delete (753602).
- **Full supply-chain surface:** Imgur Nexus `anonymous/anonymous` → access to all repositories, dependency proxying/collection, component deletion, application analysis (435457).
- **PII/enterprise metadata:** Kinetic console `admin/admin` on DoD → server logs, database users with emails and names, system activity (1938693).
- **Physical security:** Starbucks DVR `user/user` → live browsing of camera feeds (398797).
- **Account creation via API:** Snapchat Django admin `admin/research` → new users and groups added via REST API on `*.sc-corp.net` host (128114).
- **Full site takeover:** ownCloud `admin/admin` (107849); MTN broadband maps full site control (1297480); DoD geoportal `admin/gptadmin` → post deletion and website editing (2262365).