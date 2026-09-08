# Nous Portal — operational detail (validated Aug 28, 2026 on the bug-hunter Kali box)

## Auth

- `hermes auth add nous` — OAuth device-code flow. Re-running finds existing creds at `~/.hermes/shared/nous_auth.json` and offers import ("Import these credentials? [Y/n]").
- The file holds `access_token`, `refresh_token`, `inference_base_url`, `portal_base_url`. Never echo the token.

## API endpoints

- Inference base: `https://inference-api.nousresearch.com/v1` (from `jq -r '.inference_base_url' ~/.hermes/shared/nous_auth.json`).
- Catalog: `GET $IB/models` with `Authorization: Bearer $TOKEN` → `.data[].id` (hundreds of ids, `vendor/name` form).
- No per-model detail endpoint at `$IB/models/<id>` (404).

## Credit probe (verify a model before relying on it)

```bash
IB=$(jq -r '.inference_base_url' ~/.hermes/shared/nous_auth.json)
TOKEN=$(jq -r '.access_token' ~/.hermes/shared/nous_auth.json)
curl -s -m 25 -o /tmp/probe.json -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$IB/chat/completions" \
  -d '{"model":"<model-id>","messages":[{"role":"user","content":"hi"}],"max_tokens":1}'
unset TOKEN
```

| HTTP | Meaning |
|---|---|
| 200 | usable (free or paid-with-credits) |
| 404 "requires available credits... balance is too low" | paid model, account balance $0 |
| 404 "model ... not found" | id is a picker alias, not API-callable |
| 429 | exists but rate-limited |

Zero-credit fallback: model ids with a `:free` suffix (e.g. `stepfun/step-3.7-flash:free`, `upstage/solar-pro4:free`, `tencent/hy3:free`, `poolside/laguna-s-2.1:free`) return 200 with a $0 balance — the catalog lists them alongside paid ids. Useful as a temporary pin for a budget-constrained account until credits land; `~vendor/latest`-style aliases are NOT API-callable, so probe the concrete id.

## Error signatures in Hermes runs

A failed model call writes a request dump (`~/.hermes/sessions/request_dump_*.json` or `~/.hermes/profiles/<p>/sessions/request_dump_*.json`) with top-level keys `error`, `reason`, `request`. Read `.error.message` for the provider's exact words (e.g. the "balance too low" 404). Successful runs write no dump.

## Config pinning commands

```bash
hermes profile use hunter && hermes config set model.provider nous \
  && hermes config set model.default <id> && hermes profile use default
hermes config unset model.base_url   # after ANY provider switch
hermes config set delegation.provider nous
hermes config set delegation.model deepseek/deepseek-v4-flash
hermes fallback list                 # must be empty
hermes moa list                      # presets are a leak; sole preset undeletable
```

## Current pin table (bug-hunter box, Aug 2026)

| Profile | model.default | Role |
|---|---|---|
| default | deepseek/deepseek-v4-flash | general; this is what new sessions start on |
| hunter | z-ai/glm-5.3-flash | brain ($0.06/$0.20) |
| hunter-bulk | deepseek/deepseek-v4-flash | volume ($0.02/$0.08) |

Prices confirmed on the portal model pages: GLM-5.3-Flash $0.06/$0.20 (20% portal-exclusive discount may apply); DS V4 Flash Latest $0.02/$0.08; pinned 0731 snapshot is pricier at $0.07/$0.14. Portal fees are non-refundable per ToS — stage top-ups (small first) to validate before committing.
