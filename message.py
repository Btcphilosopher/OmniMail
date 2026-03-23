"""
omnimail.core.message
─────────────────────
Transport-agnostic message schema for the OmniMail protocol.

Every message traversing the OmniMail network is represented by an
OmniMessage.  Adapters serialise/deserialise to their native wire
format; the canonical in-memory form is always an OmniMessage.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────────────────────────────────────

class MessageType(str, Enum):
    """Top-level content type carried in the envelope."""
    PLAINTEXT   = "plaintext"
    HTML        = "html"
    ENCRYPTED   = "encrypted"      # ciphertext blob
    SIGNED      = "signed"         # cleartext + detached sig
    MULTIPART   = "multipart"      # multiple body parts


class Priority(str, Enum):
    """Delivery priority; HIGH requires a valid Lightning invoice."""
    LOW    = "low"
    NORMAL = "normal"
    HIGH   = "high"       # Lightning-backed fast-lane


class DeliveryMode(str, Enum):
    """Addressing mode."""
    UNICAST   = "unicast"    # one recipient
    MULTICAST = "multicast"  # explicit list of recipients
    BROADCAST = "broadcast"  # all subscribers of a topic


class TransportStatus(str, Enum):
    """Per-adapter delivery outcome."""
    PENDING   = "pending"
    SENT      = "sent"
    DELIVERED = "delivered"
    FAILED    = "failed"
    RETRYING  = "retrying"


# ──────────────────────────────────────────────────────────────────────────────
# Sub-structures
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Attachment:
    """Binary or text attachment embedded in a message."""
    filename:     str
    content_type: str                       # MIME type
    data:         bytes = field(repr=False) # raw bytes
    size:         int   = 0
    checksum:     str   = ""                # SHA-256 hex

    def __post_init__(self) -> None:
        if not self.size:
            self.size = len(self.data)
        if not self.checksum:
            self.checksum = hashlib.sha256(self.data).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        import base64
        return {
            "filename":     self.filename,
            "content_type": self.content_type,
            "data":         base64.b64encode(self.data).decode(),
            "size":         self.size,
            "checksum":     self.checksum,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Attachment":
        import base64
        return cls(
            filename=d["filename"],
            content_type=d["content_type"],
            data=base64.b64decode(d["data"]),
            size=d.get("size", 0),
            checksum=d.get("checksum", ""),
        )


@dataclass
class RoutingHop:
    """Records a single step in the message routing history."""
    adapter:   str           # adapter id that processed the hop
    timestamp: float         # Unix epoch float
    status:    TransportStatus
    note:      str = ""      # optional human-readable note

    def to_dict(self) -> Dict[str, Any]:
        return {
            "adapter":   self.adapter,
            "timestamp": self.timestamp,
            "status":    self.status.value,
            "note":      self.note,
        }


@dataclass
class LightningPayment:
    """Optional Lightning Network micropayment attached to a message."""
    invoice:       str            # BOLT-11 encoded invoice
    amount_msats:  int            # milli-satoshis
    preimage:      Optional[str]  # payment preimage (set after payment)
    paid:          bool = False
    payment_hash:  str  = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invoice":      self.invoice,
            "amount_msats": self.amount_msats,
            "preimage":     self.preimage,
            "paid":         self.paid,
            "payment_hash": self.payment_hash,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Core envelope
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class OmniMessage:
    """
    The canonical OmniMail protocol envelope.

    Adapters translate between OmniMessage and their own wire format.
    The `id` is globally unique; `thread_id` groups replies together.
    """

    # ── Addressing ────────────────────────────────────────────────────────────
    sender:       str
    recipients:   List[str]                   # list of OmniMail addresses
    subject:      str = ""

    # ── Content ───────────────────────────────────────────────────────────────
    body:         str  = ""                   # plaintext or ciphertext
    body_html:    str  = ""                   # optional HTML companion
    message_type: MessageType = MessageType.PLAINTEXT
    attachments:  List[Attachment] = field(default_factory=list)

    # ── Routing / Metadata ────────────────────────────────────────────────────
    id:           str   = field(default_factory=lambda: str(uuid.uuid4()))
    thread_id:    Optional[str]  = None
    reply_to:     Optional[str]  = None       # message-id being replied to
    timestamp:    float          = field(default_factory=time.time)
    ttl:          int            = 86400      # seconds; 0 = no expiry
    priority:     Priority       = Priority.NORMAL
    delivery_mode:DeliveryMode   = DeliveryMode.UNICAST
    topic:        Optional[str]  = None       # for BROADCAST mode

    # ── Transport hints ───────────────────────────────────────────────────────
    preferred_adapters: List[str] = field(default_factory=list)
    routing_history:    List[RoutingHop] = field(default_factory=list)

    # ── Encryption / Auth ─────────────────────────────────────────────────────
    signature:          Optional[str]  = None  # detached sig (base64)
    encryption_algo:    Optional[str]  = None  # e.g. "x25519-xchacha20poly1305"
    sender_public_key:  Optional[str]  = None  # base64 public key

    # ── Payment ───────────────────────────────────────────────────────────────
    lightning:    Optional[LightningPayment] = None

    # ── Arbitrary extension headers ───────────────────────────────────────────
    headers:      Dict[str, Any] = field(default_factory=dict)

    # ── Internal state ────────────────────────────────────────────────────────
    _status:      TransportStatus = field(default=TransportStatus.PENDING,
                                          compare=False, repr=False)

    # ─────────────────────────────────────────────────────────────────────────

    @property
    def is_expired(self) -> bool:
        if self.ttl == 0:
            return False
        return time.time() > (self.timestamp + self.ttl)

    def canonical_bytes(self) -> bytes:
        """Deterministic serialisation used for signing / hashing."""
        payload = {
            "id":        self.id,
            "sender":    self.sender,
            "recipients":sorted(self.recipients),
            "subject":   self.subject,
            "body":      self.body,
            "timestamp": self.timestamp,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def fingerprint(self) -> str:
        """SHA-256 of the canonical bytes."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":                 self.id,
            "thread_id":          self.thread_id,
            "reply_to":           self.reply_to,
            "sender":             self.sender,
            "recipients":         self.recipients,
            "subject":            self.subject,
            "body":               self.body,
            "body_html":          self.body_html,
            "message_type":       self.message_type.value,
            "attachments":        [a.to_dict() for a in self.attachments],
            "timestamp":          self.timestamp,
            "ttl":                self.ttl,
            "priority":           self.priority.value,
            "delivery_mode":      self.delivery_mode.value,
            "topic":              self.topic,
            "preferred_adapters": self.preferred_adapters,
            "routing_history":    [h.to_dict() for h in self.routing_history],
            "signature":          self.signature,
            "encryption_algo":    self.encryption_algo,
            "sender_public_key":  self.sender_public_key,
            "lightning":          self.lightning.to_dict() if self.lightning else None,
            "headers":            self.headers,
            "status":             self._status.value,
            "fingerprint":        self.fingerprint(),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "OmniMessage":
        msg = cls(
            sender=d["sender"],
            recipients=d["recipients"],
            subject=d.get("subject", ""),
            body=d.get("body", ""),
            body_html=d.get("body_html", ""),
            message_type=MessageType(d.get("message_type", "plaintext")),
            attachments=[Attachment.from_dict(a) for a in d.get("attachments", [])],
            id=d.get("id", str(uuid.uuid4())),
            thread_id=d.get("thread_id"),
            reply_to=d.get("reply_to"),
            timestamp=d.get("timestamp", time.time()),
            ttl=d.get("ttl", 86400),
            priority=Priority(d.get("priority", "normal")),
            delivery_mode=DeliveryMode(d.get("delivery_mode", "unicast")),
            topic=d.get("topic"),
            preferred_adapters=d.get("preferred_adapters", []),
            signature=d.get("signature"),
            encryption_algo=d.get("encryption_algo"),
            sender_public_key=d.get("sender_public_key"),
            headers=d.get("headers", {}),
        )
        if d.get("lightning"):
            ln = d["lightning"]
            msg.lightning = LightningPayment(
                invoice=ln["invoice"],
                amount_msats=ln["amount_msats"],
                preimage=ln.get("preimage"),
                paid=ln.get("paid", False),
                payment_hash=ln.get("payment_hash", ""),
            )
        status_raw = d.get("status", "pending")
        msg._status = TransportStatus(status_raw)
        return msg

    @classmethod
    def from_json(cls, raw: str) -> "OmniMessage":
        return cls.from_dict(json.loads(raw))

    def __repr__(self) -> str:
        return (
            f"OmniMessage(id={self.id[:8]}…, "
            f"from={self.sender!r}, "
            f"to={self.recipients}, "
            f"subject={self.subject!r})"
        )
