# HMAC Authentication

This document explains HMAC request signing in Jared for securing both webhook and REST API communications.

## Overview

Jared supports HMAC-SHA256 request signing in two directions:

| Direction                          | Use Case                     | Configuration       |
| ---------------------------------- | ---------------------------- | ------------------- |
| **Outbound** (Jared → Your Server) | Webhook notifications        | `webhooks[].secret` |
| **Inbound** (Your Server → Jared)  | REST API `/message` endpoint | `webServer.secret`  |

Both use the same signature format for consistency.

## How It Works

```
┌─────────────┐                                    ┌─────────────┐
│ Your Server │  ◄──── Webhooks (signed) ────      │    Jared    │
│  (Django)   │  ──── /message (signed) ────►      │    (Mac)    │
└─────────────┘                                    └─────────────┘
```

When a `secret` is configured, requests include three HTTP headers:

| Header        | Description                           | Example                                |
| ------------- | ------------------------------------- | -------------------------------------- |
| `X-Timestamp` | Unix timestamp (seconds since epoch)  | `1703652650`                           |
| `X-Nonce`     | Unique UUID to prevent replay attacks | `550e8400-e29b-41d4-a716-446655440000` |
| `X-Signature` | HMAC-SHA256 signature as hex string   | `a1b2c3d4e5f6...`                      |

### Signature Computation

```
signature = HMAC-SHA256(secret, timestamp + \0 + nonce + \0 + request_body)
```

> **Why NUL delimiters?** Without delimiters, different (timestamp, nonce, body) combinations could produce identical concatenated strings, creating a security vulnerability.

---

## Configuration

```json
{
	"webhooks": [
		{
			"url": "https://your-server.com/webhook/",
			"secret": "webhook-secret-here"
		}
	],
	"webServer": {
		"port": 3001,
		"secret": "rest-api-secret-here"
	}
}
```

> **Note:** Secrets are optional. Without a secret, requests are unsigned/unverified.

---

## Outbound: Webhook Signing (Jared → Your Server)

When webhooks have a `secret`, Jared signs outbound requests so your server can verify authenticity.

### Jared Side (Swift)

The signing happens in [`WebHookManager.swift`](../Jared/WebHookManager.swift):

```swift
import CryptoKit

private func addSignatureHeaders(to request: inout URLRequest, body: Data, secret: String) {
    let timestamp = String(Int(Date().timeIntervalSince1970))
    let nonce = UUID().uuidString

    // Build payload with NUL delimiters
    var payload = Data()
    payload.append(contentsOf: timestamp.utf8)
    payload.append(0)
    payload.append(contentsOf: nonce.utf8)
    payload.append(0)
    payload.append(body)

    let secretKey = SymmetricKey(data: Data(secret.utf8))
    let mac = HMAC<SHA256>.authenticationCode(for: payload, using: secretKey)
    let signatureHex = mac.map { String(format: "%02x", $0) }.joined()

    request.setValue(timestamp, forHTTPHeaderField: "X-Timestamp")
    request.setValue(nonce, forHTTPHeaderField: "X-Nonce")
    request.setValue(signatureHex, forHTTPHeaderField: "X-Signature")
}
```

### Verifying in Django/Python

```python
import hmac
import hashlib
import time
from django.core.cache import cache

def verify_jared_signature(request, secret: str, max_age_seconds: int = 60) -> bool:
    timestamp = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    signature = request.headers.get("X-Signature")

    if not timestamp or not nonce or not signature:
        return False

    # Timestamp freshness
    try:
        request_time = int(timestamp)
    except ValueError:
        return False

    now = int(time.time())
    if abs(now - request_time) > max_age_seconds:
        return False

    # Nonce replay protection
    if not cache.add(f"jared_nonce:{nonce}", 1, timeout=max_age_seconds):
        return False

    # Verify signature
    body = request.body
    payload = timestamp.encode() + b"\0" + nonce.encode() + b"\0" + body
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    return hmac.compare_digest(signature, expected)
```

---

## Inbound: REST API Verification (Your Server → Jared)

When `webServer.secret` is configured, Jared verifies signatures on `/message` requests.

### Jared Side (Swift)

Verification happens in [`JaredWebServer.swift`](../Jared/JaredWebServer.swift):

```swift
private func verifySignature(request: HTTPRequest, secret: String, maxAgeSeconds: Int = 60) -> Bool {
    guard let timestamp = request.headers["X-Timestamp"],
          let nonce = request.headers["X-Nonce"],
          let signature = request.headers["X-Signature"] else {
        return false
    }

    // Check timestamp freshness
    guard let requestTime = Int(timestamp) else { return false }
    let now = Int(Date().timeIntervalSince1970)
    if abs(now - requestTime) > maxAgeSeconds { return false }

    // Build expected signature
    var payload = Data()
    payload.append(contentsOf: timestamp.utf8)
    payload.append(0)
    payload.append(contentsOf: nonce.utf8)
    payload.append(0)
    payload.append(request.body)

    let secretKey = SymmetricKey(data: Data(secret.utf8))
    let mac = HMAC<SHA256>.authenticationCode(for: payload, using: secretKey)
    let expected = mac.map { String(format: "%02x", $0) }.joined()

    // Timing-safe comparison
    return signature == expected  // (actual impl uses XOR comparison)
}
```

### Signing in Django/Python

```python
import hmac
import hashlib
import time
import uuid
import json
import requests

def send_message_to_jared(jared_url: str, secret: str, body: dict):
    body_bytes = json.dumps(body).encode('utf-8')
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())

    payload = timestamp.encode() + b'\0' + nonce.encode() + b'\0' + body_bytes
    signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    headers = {
        'Content-Type': 'application/json',
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Signature': signature
    }

    return requests.post(f"{jared_url}/message", data=body_bytes, headers=headers)
```

---

## Security Best Practices

1. **Keep secrets secure** — Use environment variables, not hardcoded strings
2. **Use HTTPS** — Encrypt traffic to prevent MITM attacks
3. **Track nonces** — Store used nonces in Redis/Memcached (shared across workers)
4. **60-second window** — Requests outside this window are rejected

## Files

| File                                                    | Purpose                  |
| ------------------------------------------------------- | ------------------------ |
| [`Webhook.swift`](../Jared/Webhook.swift)               | Webhook `secret` field   |
| [`WebHookManager.swift`](../Jared/WebHookManager.swift) | Outbound signing         |
| [`Configuration.swift`](../Jared/Configuration.swift)   | WebServer `secret` field |
| [`JaredWebServer.swift`](../Jared/JaredWebServer.swift) | Inbound verification     |
