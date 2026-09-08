# Outbound-Webhook SSRF Recipe (proven on Doppler dashboard, Sep 2026)

Class of target: SaaS with an 'outbound webhook on secret/config change' feature (Team/paid plan usually).
Goal: determine whether webhook URLs are attacker-controlled, delivered from production infra, and whether internal/metadata hosts are reachable. End each stage with a verdict; do NOT submit on a single anomaly.

## Stage 0 — map the webhook model
- Create endpoint shape: POST /workplace/<wid>/projects/<proj>/webhooks/add (or /webhooks/<id|add>).
- CRITICAL gotcha: created webhooks have `enabledConfigs: []` unless the create payload binds them. Bind key is `enableConfigs` (not `selectedConfigs`, not `configs`); values are config NAMES (e.g. `dev`) — passing the internal config UUID slug returns 'Config ... not found' even though the UUID is what list-APIs return. This is a classic payload-shape mismatch; find it by reading the UI chunk that builds the submit payload (search `enableConfigs`, `transformSubmitData`), not by guessing.
- A webhook that is not bound to any config NEVER fires. Verify binding in the list response before triggering.

## Stage 1 — validation mapping (input layer)
Probe creation with, each as a distinct test:
- https://127.0.0.1:443/h (loopback)
- https://[::1]:443/ (v6 loopback)
- https://169.254.169.254/latest/meta-data/ (cloud metadata)
- https://metadata.google.internal/... (metadata hostname)
- https://internal.doppler.com/ style (own-domain hostnames often have a dedicated blocklist message)
- http://... (protocol allowlist test — many accept https: only)
Expected outcomes: (a) all 200 → NO URL validation (lead); (b) 400 with 'must start with https://' → protocol rule only (redirect test becomes interesting); (c) hostname blocklist messages reveal what they think about.

## Stage 2 — does delivery actually happen? (callback capture)
- Create a public request bin: POST https://webhook.site/token → {uuid}; poll https://webhook.site/token/<uuid>/requests?sorting=newest.
- Add a webhook bound to a real config, URL = https://webhook.site/<uuid>. Trigger a real change on that config (set/update a secret). Poll 60-90s.
- Positive = request arrives showing source IP + UA (e.g. GCP IP, UA 'Doppler Bot') → production delivery of attacker-chosen URLs is REAL.
- Common miss: webhook fires only on actual secret-value change of the bound config; repeat the trigger if first fires nothing, and verify the event landed in the webhook event-log page (usually /webhooks/logs) which lists per-attempt status codes.

## Stage 3 — internal reachability (status-code oracle)
- Repoint the bound webhook to 169.254.169.254 / metadata hostname / loopback, trigger again.
- The webhook LOGS page reveals per-attempt HTTP status for each delivery attempt (200 vs 407 vs 0). 200 from 169.254.169.254 = metadata reachable (high signal). 407 = egress proxy requiring auth.
- Do NOT conflate: if the external callback succeeded but every internal target 407s, the 'SSRF' is mitigated by an egress proxy. Then try (a) redirect chains (httpbin.org/redirect-to?url=http://internal) to test if the worker follows redirects past the proxy, (b) internal-only hostnames that a domain-based proxy allowlist would let through. One anomalous 200 among many 407s is NOT proof — it may be a proxy-generated response.

## Stage 4 — data exfil question
- Does the event log or any response surface include the RESPONSE BODY of the internal fetch? (Usually only responseCode is stored.) If body is not exposed → blind SSRF only; frame impact as internal/status oracle, not metadata credential theft.

## Stage 5 — cleanup (mandatory)
- Delete every test webhook (verify 200), remove callback tokens if possible. Trigger artifacts (test secrets) null/remove. This is responsible testing and keeps the account submittable later.

## Submission bar (operator rule)
- Never submit: egress-proxy-407-mitigated SSRF, WAF-bypass-only, or a single anomalous 200 without reproducible delivery evidence. Log as DEAD-WEAK with the anomaly noted for future re-test.
