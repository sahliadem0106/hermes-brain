# CDP Session-Capture Cookbook — patterns proven in real hunts

Condensed from Privy (wallet SDK auth) and Blend Labs (mortgage app) missions, Sep 2026.
NOTE: a narrower skill `browser-cdp-hunting` exists with the CDP attach class and launch commands;
this file holds session-level patterns learned AFTER it was written. Consider merging if that
skill is ever curator-adopted (`hermes curator adopt browser-cdp-hunting`).

## 1. React SPA form automation (the hard part)

React controlled inputs ignore naive `.value = x`. Working pattern, in order of preference:

1. **Native setter + events** (works most of the time):
```js
const s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
s.call(el, val);
el.dispatchEvent(new Event('input', {bubbles:true}));
el.dispatchEvent(new Event('change', {bubbles:true}));
el.dispatchEvent(new Event('blur', {bubbles:true}));  // validation often fires on blur
```
2. **`Input.insertText`** (trusted event, works when setter fails): focus the field via JS, then
   one `Input.insertText` per char at ~100ms. Clear via native setter first, re-focus, then type —
   watch for garbage accumulating in the field.
3. **Real mouse** for dropdowns/autocomplete (Google Places `.pac-item` never picks via JS click):
   `getBoundingClientRect()` on the suggestion → `Input.dispatchMouseEvent` mouseMoved →
   mousePressed → mouseReleased.

Pitfalls seen:
- Pages hide duplicate decoy inputs (autofill traps like `fakeusernameremembered`).
  `filter(i=>i.name==='password')` may return 2+ — target the LAST, verify by re-reading values.
- aria-invalid can be stale after programmatic set — check React fiber state instead: find the
  `__reactFiber$` key, walk `.return` for memoizedProps carrying `.value`/`.error`.
- Google Places validation rejects typed text until a dropdown suggestion is actually picked.
- Multi-step wizards: click through by matching button innerText against a whitelist
  (Continue/Next/NO/Skip...), re-reading `location.href` each step. Check URLs, not body text,
  for 'reached X' decisions (body keywords match too early and end the loop prematurely).

## 2. File download capture

Download clicks show nothing in the page's Network log (browser handles it). Options:
```js
c.send("Browser.setDownloadBehavior", behavior="allowAndName",
       downloadPath="/mission/dir/downloads", eventsEnabled=True)
```
GUID filenames + magic bytes (`%PDF`) identify the file. But the reliable way to get the download
URL: read the anchor href from the DOM (`row outerHTML` / `a.href`) — e.g.
`/api/loans/{id}/documents/{docId}/download`. Then replay with Python under both sessions for the
cross-tenant test.

**Warning:** never re-click download rows repeatedly — the operator sees files piling up in their
Downloads folder (happened in the Blend session). Read the href, then use Python.

## 3. Faye/Bayeux websocket channels (realtime authz testing)

Pattern: client POSTs `/api/users/faye-auth {subscription: channel}` → JWT `webToken` with claims
{userId, subscription, deployment, iat, exp} → subscribe on wss://faye.../faye.

Test matrix:
1. Mint token as session A for A's OWN channel (control) and B's channel (the test).
2. Decode both JWTs — check `userId` vs `subscription` claims (mismatch = authz gap at issuance).
3. Subscribe with the foreign token. If accepted, run the mismatch control (token for chan X,
   subscribe chan Y) — proves the server checks token↔channel binding, isolating the flaw to
   the issuance endpoint.
4. Listen (websocket AND long-polling) for events while the foreign user actively uses the app.
   **0 events = impact unproven** — the authz gap alone reports Low/informational at best.
   Don't report unproven-impact authz gaps; park them with the unblock condition.

Faye protocol: JSON-array messages; handshake → subscribe (`ext.webToken`) → connect cycles.
Long-polling variant POSTs to the same /faye endpoint (use ~30s timeouts, loop, catch ReadTimeout).

## 4. JWT session handling quirks

- localStorage tokens are often JSON-quoted: `json.loads()` before use.
- Cookie vs bearer: some apps validate ONLY the cookie and ignore the bearer entirely (garbage
  bearer + valid cookie = 200 in-browser; the same call from Python 401s). Verify which layer
  actually authenticates before concluding from 401s — test in the browser context via
  `fetch(url, {credentials:'include'})`.
- Re-login in the same browser profile can invalidate an earlier captured session (rotation).
  Keep per-account session files; re-login via the public login endpoint to refresh.
- Cookie re-injection into a CDP browser: `Network.setCookie` (domain/path/secure,
  httpOnly=True for auth cookies). `Network.getCookies` reads them back — HttpOnly included.
- Console/dashboard apps may gate their UI client-side while the cookie works fine for direct
  API calls from Python. Don't fight the SPA hydration; drive the API directly.

## 5. Mission-dir layout convention

```
missions/<target>/
  ATTACK-SURFACE.md        # living ledger: assets, per-class results, open leads
  cdp.py                   # CDP driver class (copy from browser-cdp-hunting skill, adjust port)
  session{,2}.json         # per-account session blobs (sid, xsrf, object ids)
  cookies.json             # raw cookie jars for Python replay
  downloads/               # captured downloads
  walk_*.py, *_probe.py    # one-shot probe scripts, kept for reproducibility
```

## 6. Background listener watch-dogging

Long-running listeners (websocket/long-poll) run as background `terminal` processes with their own
timeouts. Print progress lines (`flush=True`) and poll them. Hermes 'exit code None' notifications
can be false alarms — check process state before restarting.
