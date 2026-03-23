# OmniMail — Next-Generation Transport-Agnostic Messaging Protocol

```
╔══════════════════════════════════════════════════════════════╗
║          OmniMail v1.0 · Hypermodern Messaging Stack          ║
║  SMTP · Matrix · Webhooks · E2E Encryption · Lightning ⚡     ║
╚══════════════════════════════════════════════════════════════╝
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        OmniMailSDK                          │
│                (high-level Python interface)                 │
└────────────┬────────────┬───────────────┬───────────────────┘
             │            │               │
      ┌──────▼──────┐  ┌──▼──────────┐  ┌▼──────────────────┐
      │   Router    │  │  Crypto     │  │  MessageQueue     │
      │  (fallback) │  │  Layer      │  │  (retry + DLQ)    │
      └──────┬──────┘  └─────────────┘  └───────────────────┘
             │
   ┌─────────┼──────────────────────────────┐
   │         │                              │
┌──▼────┐ ┌──▼────────┐ ┌────────────┐ ┌───▼──────┐
│ SMTP  │ │  Matrix   │ │  Webhook   │ │  Memory  │
│Adapter│ │  Adapter  │ │  Adapter   │ │  Adapter │
└───────┘ └───────────┘ └────────────┘ └──────────┘
```

## Quick Start

```bash
pip install -r requirements.txt
python examples/demo.py          # runs all demos
uvicorn omnimail.api.server:create_app --factory --reload  # starts API
```

## Project Structure

```
omnimail/
├── __init__.py             # Public API exports
├── core/
│   ├── message.py          # OmniMessage schema (transport envelope)
│   └── router.py           # Intelligent router with fallback
├── adapters/
│   ├── base.py             # Abstract BaseAdapter
│   ├── smtp_adapter.py     # SMTP/IMAP transport
│   ├── matrix_adapter.py   # Matrix homeserver transport
│   ├── webhook_adapter.py  # HTTP webhook transport
│   └── memory_adapter.py   # In-memory (testing/demo)
├── crypto/
│   └── encryption.py       # X25519 + ChaCha20 + Ed25519
├── queue/
│   └── message_queue.py    # Retry queue with dead-letter
├── payments/
│   └── lightning.py        # Lightning Network integration
├── client/
│   └── sdk.py              # High-level Python SDK
├── api/
│   └── server.py           # FastAPI REST + WebSocket server
└── frontend/
    └── index.html          # Hypermodern web client
```

## SDK Usage

```python
import asyncio
from omnimail import OmniMailSDK, SMTPAdapter, MatrixAdapter, Priority

async def main():
    sdk = OmniMailSDK()

    # Register transports
    sdk.register_adapter("smtp", SMTPAdapter(
        smtp_host="smtp.gmail.com",
        username="you@gmail.com",
        password="app-password",
    ))
    sdk.register_adapter("matrix", MatrixAdapter(
        homeserver="https://matrix.org",
        access_token="your_token",
        default_room="!room:matrix.org",
    ))

    await sdk.start()

    # Send a plain message (router picks best adapter)
    msg_id = await sdk.send(
        sender="alice@gmail.com",
        to=["bob@example.com"],
        subject="Hello from OmniMail",
        body="Transport-agnostic messaging!",
    )

    # Send encrypted + signed
    sdk.generate_identity()
    sdk.register_peer_key("bob@example.com", bob_public_key)

    await sdk.send(
        sender="alice@gmail.com",
        to=["bob@example.com"],
        subject="Secret",
        body="Only Bob can read this",
        encrypt=True,
        sign=True,
    )

    # Send with Lightning payment (priority fast-lane)
    await sdk.send(
        sender="merchant@shop.com",
        to=["customer@example.com"],
        subject="Priority order update",
        body="Your order shipped!",
        lightning_msats=1000,   # 1 sat
        priority=Priority.HIGH,
    )

    # Fetch inbox from all adapters
    messages = await sdk.fetch_inbox()
    for msg in messages:
        print(msg.sender, msg.subject)

    await sdk.stop()

asyncio.run(main())
```

## REST API

| Method | Endpoint                        | Description                     |
|--------|---------------------------------|---------------------------------|
| POST   | `/messages/send`                | Queue a message                 |
| GET    | `/messages/inbox`               | List inbox                      |
| GET    | `/messages/inbox/fetch`         | Poll adapters for new messages  |
| GET    | `/messages/{id}`                | Get single message              |
| POST   | `/messages/{id}/reply`          | Reply to message                |
| GET    | `/adapters`                     | List registered adapters        |
| POST   | `/adapters/{id}/health`         | Adapter health check            |
| GET    | `/queue/stats`                  | Queue metrics                   |
| GET    | `/queue/dead-letter`            | Dead-letter queue               |
| POST   | `/queue/{id}/requeue`           | Re-attempt failed message       |
| POST   | `/keys/generate`                | Generate identity key pair      |
| POST   | `/keys/peer`                    | Register peer's public key      |
| POST   | `/lightning/invoice`            | Create Lightning invoice        |
| POST   | `/lightning/verify/{hash}`      | Verify payment                  |
| WS     | `/ws`                           | Real-time message stream        |

## OmniMessage Packet Format

```json
{
  "id":           "uuid-v4",
  "thread_id":    "uuid-v4 | null",
  "sender":       "alice@example.com",
  "recipients":   ["bob@example.com"],
  "subject":      "Hello",
  "body":         "Message body or ciphertext",
  "message_type": "plaintext | html | encrypted | signed | multipart",
  "timestamp":    1704067200.0,
  "ttl":          86400,
  "priority":     "low | normal | high",
  "delivery_mode":"unicast | multicast | broadcast",
  "encryption_algo": "x25519-xchacha20poly1305-ed25519",
  "sender_public_key": "base64-encoded-public-key",
  "signature":    "base64-encoded-ed25519-signature",
  "lightning": {
    "invoice":      "lnbc...",
    "amount_msats": 1000,
    "payment_hash": "hex-hash",
    "paid":         false
  },
  "preferred_adapters": ["smtp", "matrix"],
  "routing_history": [
    {"adapter": "smtp", "timestamp": 1704067200, "status": "failed", "note": "timeout"},
    {"adapter": "matrix", "timestamp": 1704067201, "status": "sent", "note": "OK"}
  ],
  "headers": {},
  "fingerprint": "sha256-hex"
}
```

## Adding a Custom Adapter

```python
from omnimail.adapters.base import BaseAdapter
from omnimail.core.message import OmniMessage
from typing import List

class XMPPAdapter(BaseAdapter):
    adapter_id      = "xmpp"
    priority_weight = 70

    async def send(self, message: OmniMessage) -> None:
        # Convert OmniMessage to XMPP stanza and deliver
        ...

    async def receive(self) -> List[OmniMessage]:
        # Poll XMPP server and return new messages
        ...

# Register it
sdk.register_adapter("xmpp", XMPPAdapter())
```

## License

MIT
