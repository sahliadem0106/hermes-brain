# Nous Portal provider setup without the TUI (verified 2026-08)

`hermes model` is an interactive picker (can't be scripted, hard to drive blind in a PTY).
The working non-interactive path, verified end-to-end:

## 1. Auth

```bash
hermes auth add nous        # OAuth device flow
```
- If `~/.hermes/shared/nous_auth.json` already exists, the flow asks "Import these credentials?" — answer Y to rehydrate (validates and reuses the session).
- Credential file shape: `access_token`, `refresh_token`, `inference_base_url`, `portal_base_url`, `expires_at`. Read fields with jq; never echo the token.

## 2. Configure profiles (per-profile model)

```bash
hermes profile use hunter        # makes hunter the active config target
hermes config set model.provider nous
hermes config set model.default z-ai/glm-5.3-flash    # writes profiles/hunter/config.yaml
hermes profile use hunter-bulk   # repeat for the second profile
hermes config set model.provider nous
hermes config set model.default deepseek/deepseek-v4-flash-0731
hermes profile use default       # ALWAYS restore; leaving a sticky profile changes future sessions
```
Config keys are `model.provider` and `model.default` (NOT `model.model`). `hermes profile list` shows per-profile model after the set.

## 3. Live catalog (no picker needed)

```bash
IB=$(jq -r '.inference_base_url' ~/.hermes/shared/nous_auth.json)
TOKEN=$(jq -r '.access_token' ~/.hermes/shared/nous_auth.json)
curl -s -H "Authorization: Bearer $TOKEN" "$IB/models" | jq -r '.data[].id'   # 343 models on Nous Portal
```
- Model IDs are `vendor/name` (e.g. `z-ai/glm-5.3-flash`, `deepseek/deepseek-v4-flash-0731`, `anthropic/claude-fable-5`).
- `~vendor/name-latest` entries exist in the picker as aliases but are NOT API-callable ("model not found" on direct use) — resolve them to a concrete `vendor/name` id first.

## 4. Zero-balance semantics (paid vs free) — READ THE DUMP, NOT THE SUMMARY

- Paid model + empty account → HTTP 404: `Model 'X' requires available credits. Your account balance is too low to use paid models — add credits at https://portal.nousresearch.com or pick a free model.`
- `hermes chat -q` prints only Session/Duration/Messages on failure too; the 404 lives in `<profile>/sessions/request_dump_*.json` under `.error.message` / `.reason` (reason `non_retryable_client_error`).
- Free-tier models confirmed HTTP 200 with a $0 account (2026-08): `tencent/hy3:free`, `upstage/solar-pro4:free`, `stepfun/step-3.7-flash:free`, `poolside/laguna-s-2.1:free`. `meituan/longcat-2.0:free` exists but was 429 (rate-limited) at probe time.
- Probe any model cheaply with `scripts/probe_model.sh <model-id>` (1-token completion, prints HTTP code + message).

## 5. Successful run signature

A clean `hermes chat -q` writes NO request dump (dumps are failure artifacts). Absence of a new dump + non-trivial Duration + 0 tool calls is consistent with success; the API probe (200) is the strongest proof.
