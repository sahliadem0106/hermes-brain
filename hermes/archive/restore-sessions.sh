#!/usr/bin/env bash
# Restore encrypted session history (chat transcripts + state.db + history + pastes).
# Usage: bash restore-sessions.sh /path/to/SESSIONS-KEY.txt
# The key file is NOT in the repo — you saved it from the source machine
# (e.g. ~/hermes-brain-SESSIONS-KEY.txt). Keep it in your password manager.
set -euo pipefail
KEY="${1:?usage: restore-sessions.sh /path/to/SESSIONS-KEY.txt}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
cd "$DIR"
cat sessions-part-* > sessions-all.tar.gz.gpg
gpg --batch --yes --decrypt --passphrase-file "$KEY" -o sessions-all.tar.gz sessions-all.tar.gz.gpg
tar xzf sessions-all.tar.gz -C "$HERMES_HOME"
echo "Restored sessions + state.db + history + pastes into $HERMES_HOME"
echo "Verify: ls -lah $HERMES_HOME/sessions/ | head; ls -lah $HERMES_HOME/state.db"
