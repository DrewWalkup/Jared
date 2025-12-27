# REST API

If enabled, Jared exposes a webserver on the port `3000` by default. You can configure this port in the `~/Library/Application Support/Jared/config.json` file under the `webServer.port` property.

## `POST /message` Endpoint

Send iMessage messages to any Person or Group. You will receive a `200 OK` status code if Jared successfully parses the request, and passed it on to the handler. Otherwise, you will receive a `400 Bad Request` exception.

> NOTE: Messages will not be send if Jared does not show **🟢 Enabled** in the UI.

```
{
  "body": {
    "message": "Jared is an amazing app"
  },
  "recipient": {
    "handle": "handle@email.com",
  }
}
```

You can also send group messages by using the Group Chat's GUID. The GUID can by either:

1. Inspecting [webhook](webhooks.md) content.
2. Using the /barf command
3. Inspecting the chat database located at `~/Library/Messages/chat.db` using a SQLite database viewer.

```
{
  "body": {
    "message": "This is a group chat message."
  },
  "recipient": {
    "handle": "iMessage;+;chat100000000000",
  }
}
```

You may also specify attachments (such as images) to send. Simply specify file paths in the attachments array of the request body. Note that the file path specified must be accessible by the user that Jared is running under.

```
{
  ...
  "attachments": [
    {
      "filePath": "~/Pictures/funnyimage.jpeg"
    }
  ],
  "recipient": {
    "handle": "handle@email.com"
  }
}
```

## HMAC Authentication

For production deployments, you can configure HMAC request signing so Jared only accepts requests from authorized clients.

### Configuration

Add a `secret` to your `config.json` webServer configuration:

```json
{
	"webServer": {
		"port": 3001,
		"secret": "your-shared-secret-here"
	}
}
```

### Signing Requests

When a secret is configured, all requests to `/message` must include these headers:

| Header        | Description                          |
| ------------- | ------------------------------------ |
| `X-Timestamp` | Unix timestamp (seconds since epoch) |
| `X-Nonce`     | Unique UUID for this request         |
| `X-Signature` | HMAC-SHA256 signature as hex string  |

The signature is computed as:

```
HMAC-SHA256(secret, timestamp + \0 + nonce + \0 + request_body)
```

> **Note:** The payload uses NUL (`\0`) byte delimiters between fields.

### Python Example

```python
import hmac
import hashlib
import time
import uuid
import requests

def send_message_to_jared(url: str, secret: str, body: dict):
    body_bytes = json.dumps(body).encode('utf-8')
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())

    # Build signature payload with NUL delimiters
    payload = timestamp.encode('utf-8') + b'\0' + nonce.encode('utf-8') + b'\0' + body_bytes

    signature = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()

    headers = {
        'Content-Type': 'application/json',
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Signature': signature
    }

    return requests.post(url, data=body_bytes, headers=headers)
```
