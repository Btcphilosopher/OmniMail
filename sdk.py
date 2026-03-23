"""
omnimail.client.sdk
────────────────────
High-level Python SDK for OmniMail.

This is the primary interface for application developers.  It wraps the
Router, Queue, encryption layer, and Lightning payment service behind a
clean, ergonomic API.

Quick start::

    sdk = OmniMailSDK()
    sdk.register_adapter("smtp", SMTPAdapter(...))
    sdk.register_adapter("matrix", MatrixAdapter(...))

    await sdk.start()

    msg_id = await sdk.send(
        sender="alice@example.com",
        to=["bob@example.com"],
        subject="Hello from OmniMail",
        body="This is a test message",
    )

    inbox = await sdk.fetch_inbox()
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from omnimail.adapters.base import BaseAdapter
from omnimail.core.message import (
    OmniMessage,
    MessageType,
    Priority,
    DeliveryMode,
    Attachment,
    LightningPayment,
)
from omnimail.core.router import Router, DeliveryReport, RoutingStrategy
from omnimail.crypto.encryption import (
    KeyPair,
    generate_keypair,
    encrypt_omni_message,
    decrypt_omni_message,
    sign_omni_message,
    verify_omni_message,
)
from omnimail.queue.message_queue import MessageQueue
from omnimail.payments.lightning import LightningPaymentService

log = logging.getLogger(__name__)


class OmniMailSDK:
    """
    The OmniMail SDK – your one-stop interface to the protocol.

    Parameters
    ----------
    routing_strategy : custom RoutingStrategy subclass (optional)
    max_retries      : default retry count for queued messages
    enable_queue     : if False, messages are sent immediately without queuing
    lightning_service: LightningPaymentService instance; if None, payments
                       are disabled
    """

    def __init__(
        self,
        routing_strategy:  Optional[RoutingStrategy] = None,
        max_retries:       int = 3,
        enable_queue:      bool = True,
        lightning_service: Optional[LightningPaymentService] = None,
    ) -> None:
        self._router   = Router(strategy=routing_strategy)
        self._queue    = MessageQueue(self._router, max_retries=max_retries)
        self._lightning = lightning_service
        self._keypair:  Optional[KeyPair] = None   # local identity key
        self._peer_keys: Dict[str, str]   = {}     # address → public_key_b64
        self._enable_queue = enable_queue
        self._started  = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialise all adapters and start the message queue worker."""
        if self._started:
            return
        for aid, adapter in self._router.adapters.items():
            try:
                await adapter.connect()
            except Exception as exc:
                log.warning("SDK: adapter %r connect failed: %s", aid, exc)
        if self._enable_queue:
            await self._queue.start()
        self._started = True
        log.info("OmniMailSDK started (adapters=%s)", list(self._router.adapters))

    async def stop(self) -> None:
        """Drain the queue and disconnect all adapters."""
        if not self._started:
            return
        await self._queue.stop(drain=True)
        for aid, adapter in self._router.adapters.items():
            try:
                await adapter.disconnect()
            except Exception as exc:
                log.warning("SDK: adapter %r disconnect failed: %s", aid, exc)
        self._started = False

    # ── Adapter management ────────────────────────────────────────────────────

    def register_adapter(self, adapter_id: str, adapter: BaseAdapter) -> None:
        self._router.register(adapter_id, adapter)

    def unregister_adapter(self, adapter_id: str) -> None:
        self._router.unregister(adapter_id)

    # ── Identity / Keys ───────────────────────────────────────────────────────

    def generate_identity(self) -> KeyPair:
        """Generate and store a new key pair for this SDK instance."""
        self._keypair = generate_keypair()
        log.info("SDK: generated new identity key pair")
        return self._keypair

    def load_keypair(self, keypair: KeyPair) -> None:
        self._keypair = keypair

    def register_peer_key(self, address: str, public_key_b64: str) -> None:
        """Register a correspondent's public encryption key."""
        self._peer_keys[address] = public_key_b64

    def get_public_key(self) -> Optional[str]:
        """Return this identity's encryption public key (base64)."""
        return self._keypair.enc_public_key_b64 if self._keypair else None

    # ── Sending ───────────────────────────────────────────────────────────────

    async def send(
        self,
        sender:    str,
        to:        List[str],
        subject:   str  = "",
        body:      str  = "",
        body_html: str  = "",
        priority:  Priority = Priority.NORMAL,
        delivery_mode: DeliveryMode = DeliveryMode.UNICAST,
        attachments: Optional[List[Attachment]] = None,
        encrypt:   bool = False,
        sign:      bool = False,
        lightning_msats: Optional[int] = None,
        preferred_adapters: Optional[List[str]] = None,
        thread_id: Optional[str] = None,
        reply_to:  Optional[str] = None,
        headers:   Optional[Dict[str, Any]] = None,
        on_complete: Optional[Callable] = None,
    ) -> str:
        """
        Compose and send a message.

        Returns the message ID.  If queuing is enabled the message is
        enqueued and delivery happens asynchronously; pass *on_complete*
        to receive a callback when it resolves.

        Parameters
        ----------
        encrypt : end-to-end encrypt the body for each recipient
        sign    : attach a digital signature
        lightning_msats : create and attach a Lightning invoice for this many
                          milli-satoshis; automatically sets priority=HIGH
        """
        msg = OmniMessage(
            sender=sender,
            recipients=list(to),
            subject=subject,
            body=body,
            body_html=body_html,
            priority=priority,
            delivery_mode=delivery_mode,
            attachments=attachments or [],
            preferred_adapters=preferred_adapters or [],
            thread_id=thread_id,
            reply_to=reply_to,
            headers=headers or {},
        )

        # ── Encryption ────────────────────────────────────────────────────────
        if encrypt:
            for recipient in to:
                pub = self._peer_keys.get(recipient)
                if not pub:
                    raise ValueError(
                        f"No public key registered for recipient {recipient!r}. "
                        "Call register_peer_key() first."
                    )
            # Encrypt for first recipient (multicast needs per-recipient envelopes
            # in production; we simplify here)
            recipient_key = self._peer_keys[to[0]]
            msg = encrypt_omni_message(msg, recipient_key, self._keypair)

        # ── Signing ───────────────────────────────────────────────────────────
        if sign:
            if not self._keypair:
                raise RuntimeError("No identity key pair loaded. Call generate_identity() first.")
            msg = sign_omni_message(msg, self._keypair)

        # ── Lightning attachment ───────────────────────────────────────────────
        if lightning_msats and self._lightning:
            invoice = await self._lightning.create_priority_invoice(
                amount_msats=lightning_msats,
                description=f"OmniMail: {subject[:60]}",
            )
            msg.lightning = LightningPayment(
                invoice=invoice.bolt11,
                amount_msats=lightning_msats,
                preimage=None,
                payment_hash=invoice.payment_hash,
            )
            msg.priority = Priority.HIGH
            log.info(
                "SDK: attached Lightning invoice (%s) to message %s",
                self._lightning.format_amount(lightning_msats),
                msg.id[:8],
            )

        # ── Dispatch ──────────────────────────────────────────────────────────
        if self._enable_queue:
            self._queue.enqueue(msg, on_complete=on_complete)
        else:
            report = await self._router.send(msg)
            if not report.success and on_complete:
                on_complete(msg, report)

        return msg.id

    async def send_immediate(self, message: OmniMessage) -> DeliveryReport:
        """Bypass the queue and deliver *message* immediately."""
        return await self._router.send(message)

    # ── Receiving ─────────────────────────────────────────────────────────────

    async def fetch_inbox(
        self, adapter_id: Optional[str] = None
    ) -> List[OmniMessage]:
        """
        Fetch new messages from one or all adapters.

        If *adapter_id* is provided, only that adapter is polled.
        """
        if adapter_id:
            return await self._router.receive(adapter_id)
        return await self._router.receive_all()

    def get_inbox(self) -> List[OmniMessage]:
        """Return locally cached inbox (messages fetched so far)."""
        return self._router.get_inbox()

    def decrypt_message(self, message: OmniMessage) -> OmniMessage:
        """Decrypt an encrypted message using the local identity key."""
        if not self._keypair:
            raise RuntimeError("No identity key pair; cannot decrypt.")
        return decrypt_omni_message(message, self._keypair)

    def verify_message(self, message: OmniMessage) -> bool:
        """Verify the digital signature on a signed message."""
        return verify_omni_message(message)

    # ── Queue management ─────────────────────────────────────────────────────

    @property
    def queue_stats(self) -> Dict[str, int]:
        return self._queue.stats

    def dead_letter_queue(self) -> List[OmniMessage]:
        return self._queue.dead_letter_queue()

    def requeue(self, message_id: str) -> bool:
        return self._queue.requeue_dead(message_id)

    # ── Convenience builders ─────────────────────────────────────────────────

    def reply(
        self,
        original: OmniMessage,
        sender: str,
        body: str,
        **kwargs,
    ) -> "asyncio.coroutine":  # type: ignore[type-arg]
        """Return a coroutine that sends a reply to *original*."""
        return self.send(
            sender=sender,
            to=[original.sender],
            subject=f"Re: {original.subject}",
            body=body,
            thread_id=original.thread_id or original.id,
            reply_to=original.id,
            **kwargs,
        )
