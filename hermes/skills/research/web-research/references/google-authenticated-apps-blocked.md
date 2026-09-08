# Google-Authenticated Web Apps — CDP Bypass Guide

## Problem

Google's `accounts.google.com` uses browser fingerprinting + device trust signals to detect automated/remote cloud browsers (Browserbase, etc.), producing:

> **"Couldn't sign you in. This browser or app may not be secure."**

This is NOT a CAPTCHA — retrying, changing proxies, or switching User-Agents does nothing. The browser itself is flagged.

## Solution: Local CDP (Chrome DevTools Protocol) Connection

Configure Hermes to use the **user's local Chrome/Edge** instead of the cloud browser. The user's local browser has a genuine profile with trusted Google sessions.

### Step-by-step setup

#### 1. Enable the browser toolset

```bash
hermes tools enable browser
```

If `platform_toolsets.cli` exists in config.yaml, the `toolsets:` key is ignored — use `hermes tools enable` to write into the right key.

#### 2. Configure CDP URL

```bash
hermes config set browser.cdp_url http://localhost:9222
```

This goes under the `browser:` section in `~/.hermes/config.yaml`. The value is **HTTP** (not ws://) — the tool internally resolves to the WebSocket endpoint via `/json/version`.

#### 3. Launch local browser with remote debugging

**Windows (Chrome):**
```cmd
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="%LOCALAPPDATA%\Google\Chrome\User Data\CDP_Profile" --no-first-run --no-default-browser-check
```

**Windows (Edge):**
```cmd
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --remote-debugging-port=9222 --user-data-dir="%LOCALAPPDATA%\Microsoft\Edge\User Data\CDP_Profile" --no-first-run --no-default-browser-check
```

**macOS (Chrome):**
```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --remote-debugging-port=9222 --no-first-run --no-default-browser-check
```

**Linux (Chrome):**
```bash
google-chrome --remote-debugging-port=9222 --no-first-run --no-default-browser-check
```

**Flags explained:**

| Flag | Purpose |
|------|---------|
| `--remote-debugging-port=9222` | Opens CDP on port 9222 — Hermes connects here |
| `--user-data-dir=<path>` | REQUIRED on Windows — avoids Chromium single-instance lock (see Trap 3 below) |
| `--no-first-run` | Suppresses the welcome wizard on fresh profile |
| `--no-default-browser-check` | Suppresses "set as default browser" prompt |

#### 4. Verify the connection

```bash
curl -s http://localhost:9222/json/version
```

Should return JSON with a `webSocketDebuggerUrl` field.

#### 5. Restart / reset Hermes

Run `/reset` in the session so the browser tool picks up the new CDP config. Then `browser_navigate` will use the local browser.

### Windows-specific pitfalls (from GitHub issue #53822)

#### Trap 1: `platform_toolsets.cli` overrides `toolsets`

If `platform_toolsets.cli` exists in config.yaml, the `toolsets:` key is completely ignored. Fix:

```bash
hermes tools enable browser   # writes into platform_toolsets.cli
```

#### Trap 2: Edge not recognized as Chromium

The `_chromium_installed()` check in `browser_tool.py` looks for `chrome`, `chromium`, or `google-chrome` in PATH — `msedge.exe` is not one of them. Fix: set env var:

```bash
export AGENT_BROWSER_EXECUTABLE_PATH="/path/to/msedge.exe"
```

#### Trap 3: Chromium single-instance lock (critical!)

**Symptom:** You launch with `--remote-debugging-port=9222`, the process appears briefly, but `curl http://localhost:9222/json/version` returns "connection refused."

**Root cause:** Chromium enforces a single-instance-per-user-data-directory policy. If any Chrome/Edge process is already running (even a background crashpad handler), the new process forwards its args to the existing instance and exits immediately. The existing instance never had `--remote-debugging-port`, so CDP never opens.

**Fix:** Always pass `--user-data-dir=<unique_path>` — this gives the CDP instance its own profile directory, bypassing the instance lock.

**Verification:**
```cmd
netstat -ano | findstr 9222   # should show LISTENING
```

#### Trap 4: CDP format

Use `http://localhost:9222` (HTTP), NOT `ws://localhost:9222`. The tool resolves to the WebSocket endpoint internally.

#### Trap 5: `__pycache__` persistence

After editing `browser_tool.py` (or any Python file), clear cached bytecode:

```bash
find /path/to/hermes -type d -name __pycache__ -exec rm -rf {} +
```

#### Trap 6: Multiple Hermes installs

If `hermes` runs old code after fixes, check if a second pip install's `hermes.exe` precedes the production venv in PATH.

### Tradeoffs

| Aspect | CDP approach | Cloud browser (Browserbase) |
|--------|-------------|---------------------------|
| Google sign-in | ✅ Works (user's real browser) | ❌ Blocked |
| Setup effort | Requires launching browser with flags | Zero setup |
| Cookie persistence | Fresh sandbox profile (`--user-data-dir`) | Ephemeral, no persistence |
| Multi-profile isolation | Each CDP instance = one profile | Each session = fresh browser |
| Resource usage | Consumes local memory/CPU | Remote, no local load |

To use the **user's default profile** (with all existing cookies/sessions), omit `--user-data-dir` on macOS/Linux. On Windows this triggers the single-instance lock — instead, launch Chrome via the existing running instance's command line or close all other Chrome processes first.

### Camofox alternative

For persistent cookies across restarts without CDP, use Camofox with `managed_persistence: true`:

```yaml
browser:
  camofox:
    managed_persistence: true
```

This keeps cookies and login state across Hermes restarts, building up a trusted profile over time. However, it may still trigger Google's initial sign-in block on first use.
