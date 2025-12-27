# Webhooks

Jared provides a webhook API which allows you to be notified of messages being sent/received. You can reply inline to the webhook requests to respond, or make separate requests to the [REST API](restapi.md). You can use a site like https://webhook.site/ to debug and view webhook content.

## Configuration

To add webhooks, add their URLs to `config.json`'s `webhooks` key. You can define two types of webhooks:

1. Route webhook  
   This is a webhook that is only called for messages that match specific routes defined. For more information, see the [routes documentation](routes.md).
2. Global webhook  
   This is a webhook that is called for every single message sent or received.

```
  "webhooks": [
    {
      "url": "http://webhook.route.com",
      "secret": "your-shared-secret",
      "routes": [
        {
          "name": "/hello",
          "description": "a test route",
          "parameterSyntax": "/hello",
          "comparisons": {
            "startsWith": ["/hello"]
          }
        }
      ]
    },
    {
      "url": "https://webhook.all.requests",
      "secret": "another-shared-secret"
    }
  ],
```

In that example, the first webhook will only be called if a message starts with `/hello`. The second webhook will be called for every message.

## HMAC Authentication

For production deployments, you should configure HMAC request signing to verify that webhook requests actually originate from Jared. When a `secret` is configured for a webhook, Jared will add the following headers to every request:

| Header        | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| `X-Timestamp` | Unix timestamp (seconds since epoch) when the request was made |
| `X-Nonce`     | Unique UUID for this request (for replay attack prevention)    |
| `X-Signature` | HMAC-SHA256 signature as a hex string                          |

The signature is computed as:

```
HMAC-SHA256(secret, timestamp + \0 + nonce + \0 + request_body)
```

> **Note:** The payload uses NUL (`\0`) byte delimiters between fields to prevent ambiguous concatenation attacks.

### Verifying Signatures (Python/Django Example)

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
    # cache.add returns False if key already exists
    nonce_key = f"jared_nonce:{nonce}"
    if not cache.add(nonce_key, 1, timeout=max_age_seconds):
        return False

    # 3) Compute expected signature over raw bytes with NUL delimiters
    body = request.body  # bytes exactly as received
    payload = timestamp.encode("utf-8") + b"\0" + nonce.encode("utf-8") + b"\0" + body

    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected)
```

## Webhook Requests

When a webhook is triggered, The body of the POST request is in the following format.

_outgoing message_

```
{
  "body": {
    "message": "Jared is an amazing app"
  },
  "sendStyle": "regular",
  "attachments": [],
  "recipient": {
    "handle": "+14256667777",
    "givenName": "Zeke",
    "isMe": true
  },
  "sender": {
    "handle": "taylor@swift.com",
    "givenName": "Taylor",
    "isMe": false
  },
  "date": "2019-02-03T22:05:05.000Z",
  "guid": "EA123B39-7A45-40D9-BF04-A748B3148695"
}
```

_incoming message_

```
{
  "body": {
    "message": "thank u next"
  },
  "sendStyle": "regular",
  "attachments": [],
  "recipient": {
    "handle": "ariana@grande.com",
    "givenName": "Ariana",
    "isMe": false
  },
  "sender": {
    "handle": "zeke@swift.com",
    "givenName": "Zeke",
    "isMe": true
  },
  "date": "2019-02-03T22:05:05.000Z",
  "guid": "EA123B39-7A45-40D9-BF04-A748B3148614"
}
```

_outgoing message with an attachment_

```
{
  "sender": {
    "handle": "me@me.com",
    "isMe": true
  },
  "sendStyle": "regular",
  "date": "2020-08-22T19:10:34.000Z",
  "attachments": [
    {
      "mimeType": "image/png",
      "id": 25491,
      "fileName": "1989 [Deluxe Edition].png",
      "isSticker": false,
      "filePath": "~/Library/Messages/Attachments/ae/14/F253C657-1B34-48E5-9010-28DA45C27904/1989 [Deluxe Edition].png"
    }
  ],
  "recipient": {
    "handle": "friend@icloud.com",
    "isMe": false
  },
  "body": {
    "message": "\ufffcHey check out this great image!"
  },
  "guid": "441F4CA4-22C3-44DC-9E2A-6A43C44D61F2"
}
```

_outgoing group message_

```
{
  "sender": {
    "handle": "+14256667777",
    "isMe": true
  },
  "sendStyle": "regular",
  "date": "2020-08-22T19:06:58.000Z",
  "attachments": [],
  "recipient": {
    "name": "Testing Room",
    "handle": "iMessage;+;chat123456789999111888",
    "participants": [
      {
        "handle": "handle@icloud.com",
        "isMe": false
      },
      {
        "handle": "handle2@gmail.com",
        "isMe": false
      }
    ]
  },
  "body": {
    "message": "Don't take the money"
  },
  "guid": "441F4CA4-22C3-44DC-9E2A-6A23C44D61F1"
}
```

_incoming group message_

```
{
  "sender": {
    "handle": "handle@icloud.com",
    "givenName": "Jared",
    "isMe": false
  },
  "sendStyle": "regular",
  "date": "2020-08-22T19:59:13.000Z",
  "attachments": [],
  "recipient": {
    "name": "Testing Room",
    "handle": "iMessage;+;chat123456789999111888",
    "participants": [
      {
        "handle": "friend@icloud.com",
        "givenName": "Betty",
        "isMe": false
      },
      {
        "handle": "handle2@gmail.com",
        "isMe": false
      }
    ]
  },
  "body": {
    "message": "We can talk it so good"
  },
  "guid": "760B85F7-122D-42A5-ACE0-44F44150BF04"
}
```

## Webhook Responses

When called, Jared will wait for 10 seconds for a response from the webhook endpoint. If a response is received in time, Jared will then respond to the triggering message with the content of the webhook response. The response must have a `200` HTTP status code, and be in the following format:

```
{
  "success": true,
  "body": {
    "message": "We're on each other's team"
  }
}
```

In the case that the server is unable to process the request, you may return back an error response instead. Jared will log this for debugging purposes.

```
{
  "success": false,
  "error": "Too many concurrent requests"
}
```

## Sending other messages

If you wish to send multiple messages, cannot fit inside the 10 second timeout, or have other non-synchronous use cases, your server can make a request to send a message at any time using Jared's [REST API](restapi.md).
