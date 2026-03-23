"""
omnimail.api.server
────────────────────
FastAPI-based REST + WebSocket API for OmniMail.

Endpoints
─────────
POST   /messages/send           – compose and send a message
GET    /messages/inbox          – list cached inbox
GET    /messages/{id}           – get single message
GET    /messages/inbox/fetch    – poll adapters for new messages
POST   /messages/{id}/reply     – reply to a message
DELETE /messages/inbox          – clear inbox cache

GET    /adapters                – list registered adapters
POST   /adapters/{id}/health    – check adapter health

GET    /queue/stats             – queue metrics
GET    /queue/dead-letter       – dead-letter queue
POST   /queue/{id}/requeue      – re-attempt a dead-letter message

POST   /keys/generate           – generate a new key pair
POST   /keys/peer               – register a peer's public key

POST   /lightning/invoice       – create a Lightning invoice
POST   /lightning/verify/{hash} – check if a payment hash is settled

WS     /ws                      – real-time message stream

Run with::
    uvicorn omnimail.api.server:create_app --factory --reload
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    _FASTAPI = True
except ImportError:
    _FASTAPI = False

from omnimail.client.sdk import OmniMailSDK
from omnimail.core.message import OmniMessage, Priority, DeliveryMode
from omnimail.adapters.memory_adapter import MemoryAdapter

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic request/response models
# ──────────────────────────────────────────────────────────────────────────────

if _FASTAPI:
    class SendRequest(BaseModel):
        sender:             str
        to:                 List[str]
        subject:            str = ""
        body:               str = ""
        body_html:          str = ""
        priority:           str = "normal"
        encrypt:            bool = False
        sign:               bool = False
        lightning_msats:    Optional[int] = None
        preferred_adapters: List[str] = []
        headers:            Dict[str, Any] = {}

    class PeerKeyRequest(BaseModel):
        address:        str
        public_key_b64: str

    class LightningInvoiceRequest(BaseModel):
        amount_msats: int = 1000
        description:  str = "OmniMail priority message"

    class MessageResponse(BaseModel):
        id:           str
        sender:       str
        recipients:   List[str]
        subject:      str
        body:         str
        body_html:    str
        message_type: str
        timestamp:    float
        priority:     str
        status:       str
        fingerprint:  str
        has_signature: bool
        has_lightning: bool


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket connection manager
# ──────────────────────────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self) -> None:
        self._connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.remove(ws)

    async def broadcast(self, data: dict) -> None:
        dead = []
        for conn in self._connections:
            try:
                await conn.send_json(data)
            except Exception:
                dead.append(conn)
        for d in dead:
            self._connections.remove(d)


# ──────────────────────────────────────────────────────────────────────────────
# App factory
# ──────────────────────────────────────────────────────────────────────────────

def create_app(sdk: Optional[OmniMailSDK] = None) -> "FastAPI":
    """
    Create a FastAPI application wired to *sdk*.

    If *sdk* is not provided a default SDK with a single in-memory
    adapter is created (useful for running the demo standalone).
    """
    if not _FASTAPI:
        raise ImportError("fastapi and pydantic are required: pip install fastapi pydantic")

    if sdk is None:
        sdk = OmniMailSDK(enable_queue=True)
        sdk.register_adapter("memory", MemoryAdapter())

    ws_manager = ConnectionManager()

    app = FastAPI(
        title="OmniMail API",
        description="Next-generation transport-agnostic messaging protocol",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Startup / Shutdown ────────────────────────────────────────────────────

    @app.on_event("startup")
    async def on_startup():
        await sdk.start()
        log.info("OmniMail API server started")

    @app.on_event("shutdown")
    async def on_shutdown():
        await sdk.stop()

    # ── Helper ────────────────────────────────────────────────────────────────

    def _serialize(msg: OmniMessage) -> Dict[str, Any]:
        d = msg.to_dict()
        d["has_signature"] = bool(msg.signature)
        d["has_lightning"] = msg.lightning is not None
        # Don't expose attachment raw bytes in list views
        for att in d.get("attachments", []):
            att.pop("data", None)
        return d

    # ── Messages ──────────────────────────────────────────────────────────────

    @app.post("/messages/send")
    async def send_message(req: SendRequest):
        """Compose and queue a message for delivery."""
        try:
            msg_id = await sdk.send(
                sender=req.sender,
                to=req.to,
                subject=req.subject,
                body=req.body,
                body_html=req.body_html,
                priority=Priority(req.priority),
                encrypt=req.encrypt,
                sign=req.sign,
                lightning_msats=req.lightning_msats,
                preferred_adapters=req.preferred_adapters,
                headers=req.headers,
            )
            return {"status": "queued", "message_id": msg_id}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/messages/inbox")
    async def get_inbox():
        """Return the cached inbox."""
        return [_serialize(m) for m in sdk.get_inbox()]

    @app.get("/messages/inbox/fetch")
    async def fetch_inbox(adapter: Optional[str] = None):
        """Poll adapters for new messages and return them."""
        msgs = await sdk.fetch_inbox(adapter)
        # Broadcast via WebSocket
        for m in msgs:
            await ws_manager.broadcast({"event": "new_message", "message": _serialize(m)})
        return [_serialize(m) for m in msgs]

    @app.get("/messages/{message_id}")
    async def get_message(message_id: str):
        inbox = sdk.get_inbox()
        for msg in inbox:
            if msg.id == message_id:
                return _serialize(msg)
        raise HTTPException(status_code=404, detail="Message not found")

    @app.post("/messages/{message_id}/reply")
    async def reply_to_message(message_id: str, body: str = Body(...)):
        """Reply to a specific message by ID."""
        inbox = sdk.get_inbox()
        original = next((m for m in inbox if m.id == message_id), None)
        if not original:
            raise HTTPException(status_code=404, detail="Original message not found")
        reply_id = await sdk.reply(original, sender="me@omnimail", body=body)
        return {"status": "queued", "reply_id": reply_id}

    @app.delete("/messages/inbox")
    async def clear_inbox():
        sdk._router.clear_inbox()
        return {"status": "cleared"}

    # ── Adapters ──────────────────────────────────────────────────────────────

    @app.get("/adapters")
    async def list_adapters():
        return [
            {
                "id":               aid,
                "type":             type(a).__name__,
                "priority_weight":  a.priority_weight,
                "supports_lightning": a.supports_lightning,
            }
            for aid, a in sdk._router.adapters.items()
        ]

    @app.post("/adapters/{adapter_id}/health")
    async def check_health(adapter_id: str):
        adapter = sdk._router.adapters.get(adapter_id)
        if not adapter:
            raise HTTPException(status_code=404, detail="Adapter not found")
        healthy = await adapter.health_check()
        return {"adapter": adapter_id, "healthy": healthy}

    # ── Queue ─────────────────────────────────────────────────────────────────

    @app.get("/queue/stats")
    async def queue_stats():
        return sdk.queue_stats

    @app.get("/queue/dead-letter")
    async def dead_letter():
        return [_serialize(m) for m in sdk.dead_letter_queue()]

    @app.post("/queue/{message_id}/requeue")
    async def requeue(message_id: str):
        success = sdk.requeue(message_id)
        return {"requeued": success}

    # ── Keys ──────────────────────────────────────────────────────────────────

    @app.post("/keys/generate")
    async def generate_keys():
        kp = sdk.generate_identity()
        return {
            "enc_public_key":  kp.enc_public_key_b64,
            "sig_public_key":  kp.sig_public_key_b64,
            "note": "Private keys are held in memory only; store them securely.",
        }

    @app.post("/keys/peer")
    async def register_peer(req: PeerKeyRequest):
        sdk.register_peer_key(req.address, req.public_key_b64)
        return {"status": "registered", "address": req.address}

    # ── Lightning ─────────────────────────────────────────────────────────────

    @app.post("/lightning/invoice")
    async def create_invoice(req: LightningInvoiceRequest):
        if not sdk._lightning:
            raise HTTPException(
                status_code=503,
                detail="Lightning service not configured"
            )
        inv = await sdk._lightning.create_priority_invoice(
            req.amount_msats, req.description
        )
        return {
            "bolt11":       inv.bolt11,
            "payment_hash": inv.payment_hash,
            "amount_msats": inv.amount_msats,
            "amount_human": sdk._lightning.format_amount(inv.amount_msats),
            "expiry":       inv.expiry,
        }

    @app.post("/lightning/verify/{payment_hash}")
    async def verify_payment(payment_hash: str):
        if not sdk._lightning:
            raise HTTPException(status_code=503, detail="Lightning service not configured")
        from omnimail.core.message import LightningPayment as LP
        stub = LP(invoice="", amount_msats=0, preimage=None,
                  payment_hash=payment_hash)
        settled = await sdk._lightning.verify_payment(stub)
        return {"payment_hash": payment_hash, "settled": settled}

    # ── WebSocket ─────────────────────────────────────────────────────────────

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """
        Real-time message stream.

        Emits JSON events:
          • ``{"event": "new_message", "message": {...}}`` – incoming message
          • ``{"event": "queue_stats", "stats": {...}}``   – periodic stats
        """
        await ws_manager.connect(websocket)
        try:
            while True:
                # Keep-alive + periodic stats
                await asyncio.sleep(10)
                await websocket.send_json({
                    "event": "queue_stats",
                    "stats": sdk.queue_stats,
                })
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)

    # ── Health ────────────────────────────────────────────────────────────────

    @app.get("/health")
    async def health():
        return {
            "status":   "ok",
            "adapters": len(sdk._router.adapters),
            "queue":    sdk.queue_stats,
        }

    return app
