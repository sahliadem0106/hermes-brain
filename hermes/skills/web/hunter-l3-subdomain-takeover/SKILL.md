---
name: hunter-l3-subdomain-takeover
description: "Use when hunting Subdomain Takeover on a target. Loads the L3 technique sheet: Subdomain takeover occurs when a DNS record (CNAME, A, NS, or delegation) points to an external resource that has been deprovisioned, expired, or never claimed — but which an attacker can register on the third-party platform."
domain: cybersecurity
subdomain: web
tags:
- web
- subdomain-takeover
- hunting
- l3
version: '1.0'
---

# Subdomain Takeover — Technique Sheet

## Overview
Subdomain takeover occurs when a DNS record (CNAME, A, NS, or delegation) points to an external resource that has been deprovisioned, expired, or never claimed — but which an attacker can register on the third-party platform. Once claimed, the attacker serves arbitrary content under the victim's trusted domain, giving them phishing, cookie theft (including httpOnly cookies from the parent domain in some cases), valid TLS certificate issuance, and CORS/CSP bypass. It consistently pays well when you can *prove* control: serve a marker page or claim the resource in your own account.

## Distinct sub-patterns

### 1. Dangling AWS S3 bucket
- **Shape:** `CNAME sub.victim.com -> bucket-name.s3.amazonaws.com` (or `s3-website-region`)
- **Fingerprint / payload:** Response `NoSuchBucket` from the S3 endpoint. Then register a bucket with the exact name in the same region and enable static website hosting. Verbatim markers used: `<!-- taken over by hackerone.com/ian ... -->` (Affirm, id=1297689), "S3 takeover POC" content (Khan Academy, id=1777077).
- **Root cause:** Bucket deleted or never registered; DNS record left in place.
- **Impact proven:** Served arbitrary content on the victim subdomain, TLS cert issuance, potential OAuth/cookie abuse (Affirm 1297689); cookie theft, phishing, CSP/CORS bypass (1777077); fake login page harvesting credentials (Bime 121461).
- **Exemplars:** 109699 (assets.goubiquiti.com), 1102537 (musical.ly), 1329792 (DoD), 1297689 (Affirm), 1777077 (Khan Academy), 1406335 (images.crossinstall.com).

### 2. Terminated / replaced AWS EC2 instance (A record to re-claimable IP)
- **Shape:** `A record sub.victim.com -> x.x.x.x` (former EC2 public IP), or CNAME to `ec2-...compute-1.amazonaws.com` public DNS.
- **Payload:** Launch a new EC2 instance and repeatedly request the same released elastic IP until assigned; serve a marker: `<!-- hackerone.com/ian -->` (1180697, 1182864).
- **Root cause:** EC2 public DNS used as CNAME instead of an Elastic IP (1294492); instance terminated/replaced but A record never removed (1101877, 1108125, 1280167).
- **Impact proven:** Served arbitrary content on v.zego.com, fr1.vpn.zomans.com, turn.shopify.com (PoC at `/0xd0m7`), and a DoD subdomain; obtained valid TLS certs for the domains; on turn.shopify.com: phishing, stored XSS, DoS, SSH sniffing, malware distribution. In one case the IP was already claimed by a third party — SSL data showed foreign cert `CN *.test.tugo.com` (max1.liveplan.com, 1294492).
- **Exemplars:** 1180697, 1182864, 1295497, 1296366, 1101877, 1108125, 1294492, 1280167.

### 3. Deallocated AWS ELB
- **Shape:** `CNAME sub.victim.com -> <name>-<id>.<region>.elb.amazonaws.com`
- **Fingerprint:** `NXDomain` on the alias; the ELB name can be re-created in the same region to reclaim the DNS name (Rocket.Chat, id=1390782: `a0e7eaaaa82f611e9b1cc0e9ccd15f3e-557536140.us-west-2.elb.amazonaws.com`, us-west-2).
- **Impact proven:** Takeover demonstrated, enabling phishing.
- **Exemplar:** 1390782.

### 4. Dangling CloudFront distribution
- **Shape:** `CNAME sub.victim.com -> dxxxx.cloudfront.net` (or a bare Fastly/Akamai-style CDN CNAME)
- **Root cause:** Distribution deleted; the CNAME alias is still set on the victim's side, so you claim it as a custom origin/domain on your own distribution.
- **Impact proven:** Served attacker content at `http://rider.uber.com/login-poc` (Uber, 175070, HTTP and HTTPS); partners.ubnt.com served `http://partners.ubnt.com/login` with httpOnly-cookie theft and valid SSL cert issuance (145224); fastly.sc-cdn.net takeover at `/takeover.html` (Snapchat, 154425).
- **Exemplars:** 175070, 145224, 154425.

### 5. Unclaimed SaaS hosting platforms (the long tail)
Each platform has a characteristic "unclaimed" fingerprint page. Register the subdomain/username on the platform with no ownership verification:

- **Heroku:** CNAME to `*.herokuapp.com` returning `No such app`. Takeover demonstrated at alpha.readfu.com serving attacker content (1073114).
- **GitHub Pages:** CNAME to `<user>.github.io`. Claimed the GitHub account and hosted a PoC at https://new.rubyonrails.org (1429148).
- **Tumblr:** CNAME to `domains.tumblr.com` (66.6.42.22). engineering.zomato.com (113869) and Paragon Initiative subdomain (180393) — claimable by anyone.
- **Wix:** CNAME chain to `*.wixdns.net` returning 404 on unclaimed sites. Claimed 4 subdomains across Uber properties (1116545); www.cyberlynx.lu (1256389); sifchain.finance showed the Wix claim-your-site error (1183296 — requires a premium Wix account to execute).
- **Shoplo:** alongside Wix in Uber takeover (1116545).
- **Zendesk / Freshdesk / FreshDesk-hosted:** CNAME to `<name>.zendesk.com`; page says "No help desk configured... you can claim it". support.urbandictionary.com (103432), support.invisionpower.com (1646554), fddkim.zomato.com via Freshdesk 0-day (1130376), expired FreshDesk subscription at service.kiwi.ki (118514).
- **Uservoice:** inactive account CNAME, register the username — feedback.screenhero.com (142096).
- **DYN:** host never claimed on DYN — web.mopub.com (119220).
- **Modulus:** dangling CNAME; claimed wildcard `*.legalrobot.com`, served `<!--FRANS ROSEN-->` marker at api.legalrobot.com (148770).
- **Google (ghs.google.com):** abandoned CNAME, claim via Google Apps registration — moderator.ubnt.com (181665).
- **Instapage:** CNAME to Instapage, served own HTML on www.hacker.one (159156).
- **Piwik Cloud:** signed up and added the domain — gratipay.piwik.pro (111078).
- **Shopify instance:** unclaimed Shopify subdomain, set up PoC storefront (Mars, 1851886).
- **Kajabi:** course.oberlo.com (1690951).
- **Vercel:** CNAME `cname.vercel-dns.com` with no claiming project — proxies.sifchain.finance, condition confirmed only, not taken over (1487793).
- **Squarespace:** claimed 8ybhy85kld9zp9xf84x6.imgur.com via custom-domain binding to reporter's account (1527405).
- **Medium:** DNS points to Medium custom-domain servers but host unclaimed — badootech.badoo.com (1034023; blocked only because Medium paused custom domains).
- **Odoo:** CNAME to `exness-stg.odoo.com`, no longer controlled (1540252).
- **Tilda.cc (NS-level delegation):** entire domain ozoncorporate.ru delegated and unused (1160381).
- **Azure Cloud App:** unregistered endpoint `araz-sp.centralus.cloudapp.azure.com` — hosted `<!-- poc by deleite -->` (1341133); second Azure endpoint takeover with PoC at an obscure URL (1457928).
- **Reddit (platform-specific):** unclaimed `*.reddit.com` subdomains resolve to a community page; created community named `webcovid19` and controlled the subdomain (1591085).

### 6. Expired / purchasable redirect & domain targets
- **Expired redirect target:** windsor.shopify.com auto-redirected to aislingofwindsor.com, which expired; purchased via domain drop, then fully controlled content under the shopify.com subdomain. Chain: enumerate via crt.sh → find redirect to expired domain → buy it (150374).
- **CNAME to purchasable domain:** rb.readfu.com pointed to hqn.ro, bought for 9 EUR (1073114).
- **CNAME to an unregistered TLD:** dig returns NXDOMAIN with the CNAME visible in the answer; register the TLD domain and create the matching subdomain (Affirm, 1312365).
- **Expired hosted service:** tool.mopub.com pointed to expired `hosted-by.myinternetservices.com` (101104).
- **Expired hosting provider:** status.hosting24.com (1570551/1570591) — cookie theft and content control.

### 7. Unclaimed IP / foreign-certificate indicator
- **Shape:** A record resolving to an IP outside the victim's control. vpn.inverselink.com resolved to 54.202.130.246 serving a *Workday* TLS cert — evidence the IP was released and re-claimed (1112679). TLS fingerprinting (checking the cert CN served by the dangling IP) is itself a valid finding technique (1294492).

### 8. Bare NS-zone takeover
- **Shape:** NS records for a subdomain delegated to a zone claimable in a DNS provider account. us-east4.37signals.com pointed to an unclaimed NS zone; attacker claimed the zone, then created arbitrary records beneath it (nagli.us-east4.37signals.com/takeover.html), enabling parent-domain cookie-based account takeover, stored XSS, phishing (1342422). NS takeover is the most powerful variant — you control everything below the delegated name.

### 9. Application-level claim without DNS control (no dangling DNS needed)
- **Trailing-dot domain bypass (canonical):** Shopify's wholesale "add domain" check doesn't normalize the RFC 1034 absolute form; adding `shop.inti.io.` (trailing dot) passes the "already in use" check, then you register that domain and serve a fake shop at `https://shop.inti.io./accounts/sign_in` (1086108).
- **Platform bind without ownership check:** POST `/v3/publish/connect-domain-hostinger` with `{"domain":"test.zyrosite.com","siteId":"{yourSiteId}"}` lets any account bind arbitrary `*.zyrosite.com` subdomains to its own site, no verification (1767771).
- **Reddit community-name claim** (see #5).

## Bypass / chain notes
- **Recon chains:** enumerate subdomains via crt.sh (150374); reverse CNAME lookups to find wholesale/customer domains (1086108); `dig`/`nslookup` to capture the CNAME chain (1256389 shows a full Wix chain: www118.wixdns.net -> balancer.wixdns.net -> ...); watch for NXDOMAIN-with-CNAME-in-answer as the cleanest takeover signal (1312365, 1390782).
- **Multi-step:** find DNS entry → claim the resource on the platform (signup/registration) → enable hosting / bind domain → serve marker HTML → (optionally) obtain TLS cert to prove HTTPS control.
- **TLS-cert issuance is the impact multiplier:** confirmed on EC2-IP takeovers (1180697, 1182864, 1295497), S3 (1406335), CloudFront (145224), and enables convincing phishing.
- **Parent-domain cookies:** NS-zone and same-domain hosting claims enabled account takeover via parent-domain cookies (1342422) and httpOnly cookie theft (145224).
- **Verification-assist quirks:** services often don't verify domain ownership before binding (Medium, Squarespace, Hostinger/Zyro, Uservoice, Zendesk) — that's the root cause across most SaaS patterns.

## Gotchas / what NOT to do
- **Don't report unconfirmed claimability alone when a claim is trivially possible** — the strongest reports actually register and serve a marker (`<!-- hackerone.com/ian -->`, `<!--FRANS ROSEN-->`, `/takeover.html`). But some programs accepted confirm-only reports with fingerprint evidence (1183296, 1487793, 1034023) when execution required paid accounts — state the blocker explicitly.
- **Wildcard gotchas:** a claimed wildcard on the platform can cover many subdomains at once (148770 took `*.legalrobot.com` in one claim).
- **EC2 re-claiming is lottery-style:** you must repeatedly request released IPs; don't fabricate success if you never got the IP.
- **Wix requires a premium account** to execute the takeover (1183296); Vercel similar nuance — check the platform's plan requirements before promising impact.
- **Check whether the bucket/asset holds user data** — programs will triage lower if it does; musical.ly's bucket held none per program confirmation (1102537).
- **Trailing-dot domains:** target browsers/apps treat `shop.inti.io.` as the same site, but many ownership checks don't normalize it — always test the absolute form against in-use-domain checks, not just DNS.
- **Fastly/Akamai/CloudFront reclaim rules differ per CDN** (region, account, plan constraints) — verify you can actually re-provision the exact name (154425, 1390782).

## Real-world impact examples
- **turn.shopify.com** (1295497): attacker re-registered the released EC2 IP, served `http://turn.shopify.com/0xd0m7`, and could issue a valid SSL cert for shopify.com — phishing, stored XSS, DoS, SSH sniffing, malware distribution.
- **us-east4.37signals.com** (1342422): claimed the NS zone, hosted `nagli.us-east4.37signals.com/takeover.html`, enabling account takeover via parent-domain cookies plus stored XSS.
- **a2.bime.io** (121461): registered the unclaimed S3 bucket and served a fake BIME login page to harvest victim credentials on a trusted domain.
- **Uber properties** (1116545, 175070): 4 subdomains taken over via Wix/Shoplo claims; rider.uber.com fully taken over on HTTP and HTTPS via CloudFront.
- **www.hacker.one** (159156): official HackerOne domain serving attacker HTML — ideal fake-login positioning.
- **Shopify trailing dot** (1086108): attacker-controlled fake wholesale shop login at `https://shop.inti.io./accounts/sign_in` for PII capture.
- **max1.liveplan.com** (1294492): dangling subdomain already serving a foreign certificate (`CN *.test.tugo.com`) — proof that these get claimed in the wild by third parties before a researcher arrives.
- **TLD-level** (1312365, 1160381): an unregistered TLD behind an Affirm CNAME, and a whole corporate domain (ozoncorporate.ru) delegated to Tilda.cc — takeover isn't limited to subdomains.