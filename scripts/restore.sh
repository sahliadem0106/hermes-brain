#!/usr/bin/env bash
# Restore Hermes brain (config, skills, memory, cron, profiles) into $HERMES_HOME.
# Additive — backs up existing files, never deletes anything.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"

echo "==> Restoring Hermes brain into $HERMES_HOME"
mkdir -p "$HERMES_HOME"
TS="$(date +%Y%m%d-%H%M%S)"

backup() { # $1 = rel path being overwritten
  local dest="$HERMES_HOME/$1"
  if [ -e "$dest" ] && [ ! -L "$dest" ]; then
    mkdir -p "$HERMES_HOME/.restore-backup-$TS"
    cp -a "$dest" "$HERMES_HOME/.restore-backup-$TS/$(basename "$1")" 2>/dev/null || true
    echo "   backed up existing: $1"
  fi
}

copy_into() { # $1 = src rel path, $2 = dest rel path
  local s="$SRC/$1" d="$HERMES_HOME/$2"
  [ -e "$s" ] || return 0
  mkdir -p "$(dirname "$d")"
  if [ -d "$s" ]; then
    backup "$2"
    mkdir -p "$d"
    cp -a "$s/." "$d/"
  else
    backup "$2"
    cp -a "$s" "$d"
  fi
  echo "   restored: $2"
}

echo "-- config & persona"
copy_into hermes/config.yaml config.yaml
copy_into hermes/SOUL.md SOUL.md
copy_into hermes/memories memories
copy_into hermes/cron/jobs.json cron/jobs.json

echo "-- skills (merge)"
mkdir -p "$HERMES_HOME/skills"
cp -a "$SRC/hermes/skills/." "$HERMES_HOME/skills/"
echo "   restored: skills/"

echo "-- profiles"
for p in "$SRC"/hermes/profiles/*/; do
  [ -d "$p" ] || continue
  name="$(basename "$p")"
  copy_into "hermes/profiles/$name/config.yaml" "profiles/$name/config.yaml"
  copy_into "hermes/profiles/$name/SOUL.md" "profiles/$name/SOUL.md"
  copy_into "hermes/profiles/$name/memories" "profiles/$name/memories"
  copy_into "hermes/profiles/$name/plans" "profiles/$name/plans"
  copy_into "hermes/profiles/$name/cron/jobs.json" "profiles/$name/cron/jobs.json"
done

echo "-- .env template (only if missing)"
if [ ! -f "$HERMES_HOME/.env" ]; then
  cp "$SRC/.env.example" "$HERMES_HOME/.env"
  chmod 600 "$HERMES_HOME/.env"
  echo "   created .env — FILL IN REAL KEYS"
else
  echo "   .env exists — left untouched"
fi

echo
echo "Done. Next:"
echo "  1. Edit $HERMES_HOME/.env with real API keys"
echo "  2. Run: hermes auth   (Nous Portal login)"
echo "  3. Run: hermes doctor (verify)"
