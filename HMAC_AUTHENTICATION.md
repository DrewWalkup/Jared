# HMAC Webhook Authentication

This document explains how HMAC request signing works in Jared for securing webhook communications.

## Overview

When Jared sends webhook requests to your server, it can optionally sign each request using HMAC-SHA256. This allows your server to verify that requests genuinely came from Jared, preventing spoofed requests from attackers.

## How It Works

```
┌─────────┐                              ┌─────────────┐
│  Jared  │  ──── POST /webhook ────►    │ Your Server │
│  (Mac)  │  + X-Timestamp               │  (Django)   │
│         │  + X-Nonce                   │             │
│         │  + X-Signature               │             │
└─────────┘                              └─────────────┘
```

When a webhook has a `secret` configured, Jared adds three HTTP headers to every request:

| Header        | Description                           | Example                                |
| ------------- | ------------------------------------- | -------------------------------------- |
| `X-Timestamp` | Unix timestamp (seconds since epoch)  | `1703652650`                           |
| `X-Nonce`     | Unique UUID to prevent replay attacks | `550e8400-e29b-41d4-a716-446655440000` |
| `X-Signature` | HMAC-SHA256 signature as hex string   | `a1b2c3d4e5f6...`                      |

### Signature Computation

The signature is computed by concatenating the timestamp, nonce, and request body **with NUL byte delimiters**, then applying HMAC-SHA256:

```
signature = HMAC-SHA256(secret, timestamp + \0 + nonce + \0 + request_body)
```

> **Why NUL delimiters?** Without delimiters, different (timestamp, nonce, body) combinations could produce identical concatenated strings, creating a security vulnerability.

## Configuration

Add a `secret` to any webhook in your `config.json`:

```json
{
	"webhooks": [
		{
			"url": "https://your-server.com/api/webhook/",
			"secret": "your-shared-secret-here"
		}
	]
}
```

> **Note:** Keep this secret secure! It should match a secret stored on your receiving server.

## Code Walkthrough

### Jared Side (Swift)

The signing happens in [`WebHookManager.swift`](Jared/WebHookManager.swift):

```swift
import CryptoKit

private func addSignatureHeaders(to request: inout URLRequest, body: Data, secret: String) {
    let timestamp = String(Int(Date().timeIntervalSince1970))
    let nonce = UUID().uuidString

    // Build payload with NUL delimiters (prevents ambiguous concatenation)
    var payload = Data()
    payload.append(contentsOf: timestamp.utf8)
    payload.append(0) // NUL delimiter
    payload.append(contentsOf: nonce.utf8)
    payload.append(0) // NUL delimiter
    payload.append(body)  // Raw bytes, no string conversion

    // Compute HMAC-SHA256
    let secretKey = SymmetricKey(data: Data(secret.utf8))
    let mac = HMAC<SHA256>.authenticationCode(for: payload, using: secretKey)
    let signatureHex = mac.map { String(format: "%02x", $0) }.joined()

    // Use setValue (not addValue) to avoid duplicate headers
    request.setValue(timestamp, forHTTPHeaderField: "X-Timestamp")
    request.setValue(nonce, forHTTPHeaderField: "X-Nonce")
    request.setValue(signatureHex, forHTTPHeaderField: "X-Signature")
}
```

### Server Side (Python/Django)

Your server should verify signatures like this:

```python
import hmac
import hashlib
import time
from django.core.cache import cache

def verify_jared_signature(request, secret: str, max_age_seconds: int = 60) -> bool:
    """
    Verify that a webhook request came from Jared.

    Args:
        request: The Django request object
        secret: The shared secret (must match Jared's config)
        max_age_seconds: Maximum age of request (prevents replay attacks)

    Returns:
        True if signature is valid, False otherwise
    """
    timestamp = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    signature = request.headers.get("X-Signature")

    if not timestamp or not nonce or not signature:
        return False

    # 1) Timestamp freshness
    try:
        request_time = int(timestamp)
    except ValueError:
        return False

    now = int(time.time())
    if request_time > now + max_age_seconds:
        return False  # too far in the future
    if now - request_time > max_age_seconds:
        return False  # too old

    # 2) Nonce replay protection
    nonce_key = f"jared_nonce:{nonce}"
    if not cache.add(nonce_key, 1, timeout=max_age_seconds):
        return False  # nonce already used

    # 3) Compute expected signature with NUL delimiters (raw bytes)
    body = request.body  # bytes exactly as received
    payload = timestamp.encode("utf-8") + b"\0" + nonce.encode("utf-8") + b"\0" + body

    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected)
```

Usage in a Django view:

```python
from django.http import JsonResponse

JARED_WEBHOOK_SECRET = "your-shared-secret-here"  # Store in settings/env

def webhook_endpoint(request):
    if not verify_jared_signature(request, JARED_WEBHOOK_SECRET):
        return JsonResponse({"error": "Invalid signature"}, status=401)

    # Process the verified webhook...
    data = json.loads(request.body)
    # ...
```

## Security Best Practices

1. **Keep secrets secure** - Never commit secrets to git. Use environment variables or a secrets manager.

2. **Reject old requests** - The timestamp check (default: 60 seconds) prevents attackers from replaying captured requests.

3. **Track nonces** - The nonce cache prevents replay attacks within the time window.

4. **Use HTTPS** - Always use HTTPS for webhooks to prevent man-in-the-middle attacks.

## Backward Compatibility

The `secret` field is **optional**. Webhooks without a secret will work exactly as before—no HMAC headers will be added. This allows gradual migration.

## Files Changed

| File                                                                   | Purpose                                  |
| ---------------------------------------------------------------------- | ---------------------------------------- |
| [`Webhook.swift`](Jared/Webhook.swift)                                 | Added `secret: String?` field to model   |
| [`WebHookManager.swift`](Jared/WebHookManager.swift)                   | Added HMAC signing logic using CryptoKit |
| [`Documentation/webhooks.md`](Documentation/webhooks.md)               | Added HMAC section to docs               |
| [`Documentation/config-sample.json`](Documentation/config-sample.json) | Added secret field examples              |

## Questions?

See the full [webhook documentation](Documentation/webhooks.md) for more details on the webhook API.
