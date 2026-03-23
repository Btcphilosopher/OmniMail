"""
omnimail.adapters.webhook_adapter
───────────────────────────────────
HTTP webhook transport adapter for OmniMail.

Delivers messages as signed JSON POST requests to a configurable
endpoint.  Optionally verifies HMAC-SHA256 signatures on incoming
webhook payloads (acts as a receiver endpoint).

Useful for integration with Slack incoming webhooks, Discord, custom
backends, and any service that accepts HTTP callbacks.

Requires: pip install aiohttp
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from typing import Callable, Dict, List, Optional

try:
    import aiohttp
    _AIOHTTP = True
except ImportError:
    _AIOHTTP = False

from omnimail.adapters.base import BaseAdapter
from omnimail.core.message import OmniMessage

log = logging.getLogger(__name__)

# Type alias for an incoming message callback
MessageCallback = Callable[[OmniMessage], None]


class WebhookAdapter(BaseAdapter):
    """
    HTTP webhook transport adapter.

    Outbound: POSTs OmniMessage JSON to *endpoint_url*, optionally
    signed with an HMAC-SHA256 header.

    Inbound: maintains an internal queue that external code (e.g. a
    FastAPI route) can push incoming webhook payloads into via
    ``push_incoming()``.

    Parameters
    ----------
    endpoint_url : URL to POST outbound messages to
    secret       : HMAC-SHA256 signing secret (optional)
    timeout      : HTTP request timeout in seconds
    max_retries  : number of HTTP retries on failure
    """

    adapter_id      = "webhook"
    priority_weight = 40

    SIGNATURE_HEADER = "X-OmniMail-Signature"

    def __init__(
        self,
        endpoint_url: str,
        secret:       str = "",
        timeout:      int = 10,
        max_retries:  int = 3,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.secret       = secret
        self.timeout      = timeout
        self.max_retries  = max_retries
        self._incoming:   List[OmniMessage] = []
        self._session:    Optional[object]  = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        if _AIOHTTP:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )

    async def disconnect(self) -> None:
        if self._session:
            await self._session.close()  # type: ignore[union-attr]

    # ── Signing ───────────────────────────────────────────────────────────────

    def _sign(self, body: bytes) -> str:
        """Return HMAC-SHA256 hex digest of *body*."""
        return hmac.new(
            self.secret.encode(), body, hashlib.sha256
        ).hexdigest()

    def verify_signature(self, body: bytes, signature: str) -> bool:
        """Return True if *signature* matches the expected HMAC."""
        if not self.secret:
            return True
        expected = self._sign(body)
        return hmac.compare_digest(expected, signature)

    # ── Send ──────────────────────────────────────────────────────────────────

    async def send(self, message: OmniMessage) -> None:
        if not _AIOHTTP:
            raise RuntimeError("aiohttp is required for WebhookAdapter")

        body    = message.to_json().encode()
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.secret:
            headers[self.SIGNATURE_HEADER] = self._sign(body)

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                async with self._session.post(  # type: ignore[union-attr]
                    self.endpoint_url, data=body, headers=headers
                ) as resp:
                    if resp.status < 300:
                        log.info(
                            "WebhookAdapter: sent %s → %s [%d]",
                            message.id[:8], self.endpoint_url, resp.status,
                        )
                        return
                    text = await resp.text()
                    raise RuntimeError(f"HTTP {resp.status}: {text[:200]}")
            except Exception as exc:
                last_exc = exc
                log.warning(
                    "WebhookAdapter: attempt %d/%d failed: %s",
                    attempt, self.max_retries, exc,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)  # exponential back-off

        raise RuntimeError(
            f"WebhookAdapter: all {self.max_retries} attempts failed"
        ) from last_exc

    # ── Receive ───────────────────────────────────────────────────────────────

    def push_incoming(self, payload: bytes, signature: str = "") -> OmniMessage:
        """
        Called by external code (e.g. a web framework route handler) when an
        inbound webhook arrives.

        Verifies the signature, deserialises the payload, and enqueues it for
        the next ``receive()`` call.
        """
        if self.secret and not self.verify_signature(payload, signature):
            raise ValueError("Webhook signature verification failed")

        message = OmniMessage.from_dict(json.loads(payload))
        self._incoming.append(message)
        log.info("WebhookAdapter: queued inbound message %s", message.id[:8])
        return message

    async def receive(self) -> List[OmniMessage]:
        """Drain the inbound queue and return pending messages."""
        msgs, self._incoming = self._incoming[:], []
        return msgs

    def can_deliver_to(self, address: str) -> bool:
        # Webhooks can deliver to anything; the endpoint decides
        return True
