#!/usr/bin/env bash
# probe_model.sh — 1-token chat-completion probe against the logged-in Nous Portal session.
# Answers "does this model actually work for me right now?" (200) vs paid/blocked (404/429) vs bogus (404 not found).
# Usage: ./probe_model.sh <model-id> [more-model-ids...]
set -u
AUTH="$HOME/.hermes/shared/nous_auth.json"
[ -f "$AUTH" ] || { echo "no Nous credentials at $AUTH — run 'hermes auth add nous' first"; exit 2; }
IB=$(jq -r '.inference_base_url' "$AUTH")
TOKEN=$(jq -r '.access_token' "$AUTH")

probe() {
  local m="$1"
  curl -s -m 25 -o /tmp/probe_model.json -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    "$IB/chat/completions" \
    -d "{\"model\":\"$m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"max_tokens\":1}"
}

for m in "$@"; do
  code=$(probe "$m")
  msg=$(jq -r '.error.message // "ok"' /tmp/probe_model.json 2>/dev/null | head -c 130)
  echo "$m -> HTTP $code | $msg"
done
