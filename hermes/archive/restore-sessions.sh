#!/usr/bin/env bash
# Restore encrypted session history (chat transcripts + state.db + history + pastes).
# Usage: bash restore-sessions.sh            (uses SESSIONS-KEY.txt in this dir)
#        bash restore-sessions.sh /path/to/key  (explicit key path)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY="${1:-$DIR/SESSIONS-KEY.txt}"
[ -f "$KEY" ] || { echo "ERROR: key not found at $KEY"; exit 1; }
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
cd "$DIR"
cat sessions-part-* > sessions-all.tar.gz.gpg
gpg --batch --yes --decrypt --passphrase-file "$KEY" -o sessions-all.tar.gz sessions-all.tar.gz.gpg
tar xzf sessions-all.tar.gz -C "$HERMES_HOME"
echo "Restored sessions + state.db + history + pastes into $HERMES_HOME"
echo "Verify: ls -lah $HERMES_HOME/sessions/ | head; ls -lah $HERMES_HOME/state.db"
