---
name: hunter-l3-man-in-the-middle
description: "Use when hunting Man-in-the-Middle on a target. Loads the L3 technique sheet: MitM bounty findings are about proving an attacker positioned on the network path (or controlling an intermediate layer — proxy, DNS, router advertisement, TLS session) can read or modify traffic that the victim believes is protected."
domain: cybersecurity
subdomain: web
tags:
- web
- man-in-the-middle
- hunting
- l3
version: '1.0'
---

# Man-in-the-Middle — Technique Sheet

## Overview
MitM bounty findings are about proving an attacker positioned on the network path (or controlling an intermediate layer — proxy, DNS, router advertisement, TLS session) can read or modify traffic that the victim believes is protected. Pure "this subdomain has no HTTPS" reports pay poorly or get N/A'd; the ones that pay are those where a *specific* trust mechanism (TLS session resumption, HSTS, certificate CN validation, DNSSEC, credential exchange, IP ownership in a cluster) is broken so interception requires no user-side certificate warning, or where the interception escapes an intended security boundary (container → host, cluster-internal → external). When hunting, target the trust-establishment machinery itself, not just "HTTP exists".

## Distinct sub-patterns

### 1. TLS session resumption confusion across proxy/destination contexts
- Endpoint shape: any client using an HTTPS (TLS-in-TLS) proxy — e.g. `curl --proxy-cacert proxy_ca.pem --proxy-header 'Mitm: 1' -x 'https://localhost:12346' 'https://haxx.se'`. Root code path: libcurl's `Curl_ssl_addsessionid` session cache.
- Payload that fired (verbatim): `curl --proxy-cacert proxy_ca.pem --proxy-header 'Mitm: 1' -x 'https://localhost:12346' 'https://haxx.se'`
- Root cause: TLS 1.3 session tickets are delivered *post*-handshake, so `CONNECT_PROXY_SSL()` mislabels the connection context — the proxy's session ticket gets stored under the destination's context and later offered to the destination.
- Impact: a malicious HTTPS proxy holding its own session-ticket key could complete a *resumed* TLS handshake with the destination — full MitM with no certificate error (limited to environments already trusting the proxy CA).
- Exemplar: id=1129529 (curl).

### 2. Plaintext HTTP on a security-relevant service
- Endpoint shape: `http://lists.parrotsec.org` — mailing lists / announcement services reachable only over plaintext HTTP.
- Payload: not stated (passive interception; no request payload needed).
- Root cause: the service is simply served unencrypted; a network-positioned attacker can intercept and modify list traffic (including injected content into security announcements).
- Impact: interception/modification of mailing-list traffic for a security-focused distribution.
- Exemplar: id=238344 (Parrot Sec).

### 3. Incomplete certificate validation — CA checked, Common Name not
- Endpoint shape: client polling a fixed TLS endpoint over HTTPS — here, Burp's Collaborator server polling connection.
- Payload: not stated (validation flaw observed in the client, not triggered by a crafted request).
- Root cause: the client validated the certificate's CA chain but *not* the Common Name — a valid cert issued for any other domain was accepted.
- Impact: a MITM presents a valid-for-someone-else cert and intercepts the polling connection, reading the Collaborator records (which contain out-of-band interaction data for in-progress pentests).
- Exemplar: id=337680 (PortSwigger).
- Note for hunters: hostname-vs-CA asymmetry is a recurring bug class in thick clients. Test whether an unrelated valid cert (e.g. for a domain you own) is accepted by the tool's TLS client.

### 4. HSTS bypass in endpoint-protection / TLS interception software
- Endpoint shape: HTTPS browsing while Kaspersky Web protection (local TLS interception proxy) is active; tested against HSTS-protected sites including google.com.
- Payload: not stated (certificate-override dialog path, not a wire payload).
- Root cause: Kaspersky Internet Security ignores the Strict-Transport-Security header, so the browser permits a certificate override on HSTS sites where it must be forbidden.
- Impact: MitM on HSTS sites (google.com included) by getting the user past the otherwise-unbypassable cert warning.
- Exemplar: id=461780 (Kaspersky).
- Generalization: any local security/parental-control/DLP agent that terminates TLS is worth testing against HSTS sites and pinned apps.

### 5. TLS certificate scope mismatch on an adjacent/auxiliary domain
- Endpoint shape: `GET https://www.urbandictionary.net` — a sibling/marketing domain not covered by the site's certificate.
- Payload: not stated (browser certificate warning observed).
- Root cause: the domain is not covered by the SSL certificate in use, so the connection is unprotected; users clicking through the warning expose the traffic.
- Impact: data sent/received on urbandictionary.net could be stolen, read, or modified by a MITM.
- Exemplar: id=504507 (Urban Dictionary).
- Hunter angle: enumerate subdomains and satellite domains (.net/.org/CDN hosts) of your target and check each one's cert SANs — mismatched or absent coverage on a live, linked-from-the-main-site host is the finding.

### 6. Missing DNSSEC on a domain serving downloadable binaries
- Endpoint shape: DNS for `download.nextcloud.com` (a host users fetch software from).
- Payload: N/A — the "payload" is the *absence* of DNSSEC records on nextcloud.com (verified via DNS lookups).
- Root cause: the domain has no DNSSEC enabled, so DNS responses are not cryptographically authenticated; a network attacker can spoof resolution of the content host.
- Impact: DNS spoofing / content substitution for users downloading Nextcloud — i.e., binary replacement MitM.
- Exemplar: id=509390 (Nextcloud).
- Caveat: this class is frequently judged informational by triagers; it lands best when the domain serves executables/installers that victims execute.

### 7. Credential-reusable SMTP exchange interceptable by a proxy
- Endpoint shape: UniFi Controller → configured SMTP server outbound connection.
- Payload: not stated (attacker runs an "evil SMTP proxy" between controller and real server).
- Root cause: the controller sends SMTP credentials in a form an interposing SMTP proxy can capture (CVE-2019-5456).
- Impact: the malicious proxy records the controller's SMTP credentials and reuses them — persistent account compromise, not just one-time interception.
- Exemplar: id=519582 (Ubiquiti).
- Hunter angle: any self-hosted appliance's outbound mail/webhook/notification integrations — point the integration at a server you control and observe whether credentials can be harvested by anything on-path.

### 8. Unvalidated loadBalancerIP / externalIP assignment in Kubernetes (cluster-level MitM)
- Endpoint shape: `PATCH /api/v1/namespaces/{namespace}/services/{name}/status`, parameter `status.loadBalancer.ingress.ip`.
- Payload that fired (verbatim): `{"status":{"loadBalancer":{"ingress":[{"ip":"1.1.1.1"}]}}}`
- Root cause: kube-proxy honors `loadBalancerIP`/`externalIPs` without validating that they don't collide with other clusters' IPs, pod IPs, ClusterIPs, or loopback (CVE-2020-8554). Any user who can patch Service status (default for many roles) claims arbitrary IPs.
- Impact: proven MitM of traffic destined to external IPs, ClusterIPs, pod IPs, and 127.0.0.1 within the cluster.
- Exemplar: id=764986 (Kubernetes).

### 9. Rogue IPv6 router advertisements from a compromised container to the host
- Endpoint shape: the container's veth interface on the host; requires a root shell in a container with `CAP_NET_RAW`.
- Payload that fired: a smoltcp-based POC sending rogue IPv6 router advertisements, with a dummy HTTP server listening on all IPv6 addresses on the attacker side.
- Root cause: host has `accept_ra=1` with IPv6 forwarding disabled — in that configuration the host accepts router advertisements from any link-local peer, including a pod. A root-in-container attacker with CAP_NET_RAW injects rogue RAs and becomes the default router for the host's IPv6.
- Impact: reproduced on GKE and Kubespray clusters — attacker MitM'd part of the host's IPv6 traffic; chained with host RCE (CVE-2019-3462) to escalate to the host (CVE also assigned).
- Exemplar: id=819717 (Kubernetes).
- Chain (as recorded): gain CAP_NET_RAW as root inside a container → send rogue IPv6 RAs to the host (`accept_ra=1`, `forwarding=0`) → redirect host IPv6 traffic (chain truncated in records).

## Bypass / chain notes
- Resumption-as-bypass (id=1129529): TLS 1.3's post-handshake ticket delivery was itself the bypass vector — session tickets crossed security contexts (proxy vs destination), turning a legitimately-trusted proxy cert into a no-warning full MitM of the destination.
- Cert-valid-but-wrong-host bypass (id=337680): no need to break crypto — reuse a genuinely valid cert for any other domain when the client only checks the CA.
- HSTS bypass via local interception agents (id=461780): the security product that's supposed to *add* protection becomes the mechanism that strips it.
- Multi-step infra chains (id=819717): container compromise → rogue RAs → host traffic interception → combine with an unrelated host RCE (CVE-2019-3462) for full host escalation. MitM findings gain severity when framed as a chain step rather than a standalone.
- Credential capture → persistence (id=519456/519582): interception is the *first* step; the reported impact is credential reuse, which survives after the attacker leaves the network path.

## Gotchas / what NOT to do
- Plain "no HTTPS / no cert on subdomain" is weak alone (id=504507, id=509390 style findings are the low end of this class). Add specificity: what traffic flows there, what a MITM gains, whether users are funneled to the host.
- Missing DNSSEC is often triaged informational — pair it with binary/software distribution to make impact concrete.
- "Limited to environments trusting a proxy CA" caveats matter: id=1129529's impact explicitly scoped the attack; accurate scoping is why the curl report was credible rather than dismissed as theoretical.
- Don't claim you can break TLS where you actually rely on a user clicking through a warning (id=461780's finding was precisely that the product *made* the click possible on HSTS sites — the report hinged on that distinction).
- Kubernetes id=764986 requires the ability to PATCH Service status — verify the permission your target's RBAC actually grants before claiming exploitability.
- Container-RA attacks need root in the container plus CAP_NET_RAW; without CAP_NET_RAW the raw sockets don't exist.
- Record gaps: several records (337680, 461780, 504507, 519582) state no verbatim payload — the finding was demonstrated by client/agent behavior or proxy positioning, not a single request. Don't fabricate payloads where the original demonstration was environmental.

## Real-world impact examples
- CVE-2020-8554 (id=764986): a one-line JSON patch (`{"status":{"loadBalancer":{"ingress":[{"ip":"1.1.1.1"}]}}}`) let a cluster user intercept traffic to external IPs, ClusterIPs, pod IPs, and 127.0.0.1.
- CVE-2019-5456 (id=519582): SMTP proxy positioned between a UniFi Controller and its mail server captured reusable SMTP credentials.
- CVE-2019-3462 chain (id=819717): rogue IPv6 router advertisements from a pod MitM'd host IPv6 traffic on GKE/Kubespray and chained with host RCE for host takeover.
- id=1129529: a malicious HTTPS proxy with its own ticket key resumed TLS to haxx.se with zero certificate errors.
- id=337680: Burp Collaborator polling intercepted by a MITM, exposing pentesters' out-of-band interaction records.