"""
omnimail.core.router
─────────────────────
Intelligent routing engine.

The Router maintains a registry of named adapters and, given an OmniMessage,
selects the best sequence of transports to attempt.  If a preferred adapter
fails the router falls back automatically, records every hop, and surfaces
a structured DeliveryReport.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from omnimail.core.message import (
    OmniMessage,
    RoutingHop,
    TransportStatus,
    Priority,
    DeliveryMode,
)

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AdapterResult:
    """Outcome from a single adapter attempt."""
    adapter_id: str
    success:    bool
    status:     TransportStatus
    note:       str  = ""
    duration:   float = 0.0


@dataclass
class DeliveryReport:
    """Aggregated result for one send() call."""
    message_id:  str
    success:     bool
    attempts:    List[AdapterResult] = field(default_factory=list)
    final_adapter: Optional[str] = None
    total_time:  float = 0.0

    @property
    def failed_adapters(self) -> List[str]:
        return [a.adapter_id for a in self.attempts if not a.success]


# ──────────────────────────────────────────────────────────────────────────────
# Routing strategy
# ──────────────────────────────────────────────────────────────────────────────

class RoutingStrategy:
    """
    Determines the ordered list of adapters to try for a given message.

    Override this class to implement custom routing logic (e.g. cost-based,
    capability-based, recipient-domain-based, etc.).
    """

    def rank(
        self,
        message: OmniMessage,
        available: Dict[str, "BaseAdapter"],  # type: ignore[name-defined]
    ) -> List[str]:
        """
        Return an ordered list of adapter IDs to attempt, most-preferred first.
        """
        # Start with any adapter explicitly requested by the sender
        ordered: List[str] = []

        for aid in message.preferred_adapters:
            if aid in available:
                ordered.append(aid)

        # HIGH priority messages get the Lightning-capable adapter first
        if message.priority == Priority.HIGH and message.lightning:
            for aid, adapter in available.items():
                if getattr(adapter, "supports_lightning", False) and aid not in ordered:
                    ordered.insert(0, aid)

        # Fill remaining adapters by their declared priority weight
        remaining = sorted(
            ((aid, getattr(a, "priority_weight", 50))
             for aid, a in available.items() if aid not in ordered),
            key=lambda x: x[1],
            reverse=True,
        )
        ordered.extend(aid for aid, _ in remaining)

        return ordered


# ──────────────────────────────────────────────────────────────────────────────
# Router
# ──────────────────────────────────────────────────────────────────────────────

class Router:
    """
    Central routing engine for the OmniMail protocol.

    Usage::

        router = Router()
        router.register("smtp", SMTPAdapter(...))
        router.register("matrix", MatrixAdapter(...))

        report = await router.send(message)
    """

    def __init__(self, strategy: Optional[RoutingStrategy] = None) -> None:
        self._adapters:  Dict[str, "BaseAdapter"] = {}  # type: ignore
        self._strategy   = strategy or RoutingStrategy()
        self._inbox:     List[OmniMessage] = []  # simple in-memory store

    # ── Adapter registry ──────────────────────────────────────────────────────

    def register(self, adapter_id: str, adapter: "BaseAdapter") -> None:  # type: ignore
        """Register a transport adapter under a given ID."""
        if adapter_id in self._adapters:
            log.warning("Router: overwriting adapter %r", adapter_id)
        self._adapters[adapter_id] = adapter
        log.info("Router: registered adapter %r (%s)", adapter_id, type(adapter).__name__)

    def unregister(self, adapter_id: str) -> None:
        self._adapters.pop(adapter_id, None)

    @property
    def adapters(self) -> Dict[str, "BaseAdapter"]:  # type: ignore
        return dict(self._adapters)

    # ── Sending ───────────────────────────────────────────────────────────────

    async def send(self, message: OmniMessage) -> DeliveryReport:
        """
        Attempt delivery of *message* via ranked adapters.

        Returns a DeliveryReport; never raises (errors are captured in the
        report).
        """
        if not self._adapters:
            raise RuntimeError("Router has no registered adapters")

        if message.is_expired:
            log.warning("Router: refusing to route expired message %s", message.id)
            return DeliveryReport(
                message_id=message.id,
                success=False,
                attempts=[AdapterResult("_router", False, TransportStatus.FAILED,
                                        "Message TTL expired")],
            )

        t_start = time.monotonic()
        report  = DeliveryReport(message_id=message.id, success=False)
        ranked  = self._strategy.rank(message, self._adapters)

        log.info("Router: sending %s via adapter order %s", message.id[:8], ranked)

        if message.delivery_mode == DeliveryMode.BROADCAST:
            # Send via *all* adapters in parallel; report overall success
            results = await asyncio.gather(
                *[self._try_adapter(aid, message) for aid in ranked],
                return_exceptions=False,
            )
            report.attempts.extend(results)
            report.success = any(r.success for r in results)
        else:
            # Try adapters sequentially; stop on first success
            for aid in ranked:
                result = await self._try_adapter(aid, message)
                report.attempts.append(result)
                if result.success:
                    report.success = True
                    report.final_adapter = aid
                    break

        report.total_time = time.monotonic() - t_start
        message._status = (
            TransportStatus.SENT if report.success else TransportStatus.FAILED
        )

        log.info(
            "Router: %s %s (%.2fs, adapter=%s)",
            message.id[:8],
            "SENT" if report.success else "FAILED",
            report.total_time,
            report.final_adapter,
        )
        return report

    async def _try_adapter(
        self, adapter_id: str, message: OmniMessage
    ) -> AdapterResult:
        adapter = self._adapters.get(adapter_id)
        if adapter is None:
            return AdapterResult(adapter_id, False, TransportStatus.FAILED,
                                 "Adapter not found")

        t0 = time.monotonic()
        try:
            await adapter.send(message)
            status = TransportStatus.SENT
            success = True
            note = "OK"
        except Exception as exc:
            status  = TransportStatus.FAILED
            success = False
            note    = str(exc)
            log.warning("Router: adapter %r failed: %s", adapter_id, exc)

        hop = RoutingHop(
            adapter=adapter_id,
            timestamp=time.time(),
            status=status,
            note=note,
        )
        message.routing_history.append(hop)

        return AdapterResult(
            adapter_id=adapter_id,
            success=success,
            status=status,
            note=note,
            duration=time.monotonic() - t0,
        )

    # ── Receiving ─────────────────────────────────────────────────────────────

    async def receive(self, adapter_id: str) -> List[OmniMessage]:
        """Poll a specific adapter for new messages."""
        adapter = self._adapters.get(adapter_id)
        if not adapter:
            raise KeyError(f"Unknown adapter: {adapter_id!r}")
        messages = await adapter.receive()
        self._inbox.extend(messages)
        return messages

    async def receive_all(self) -> List[OmniMessage]:
        """Poll every registered adapter and merge results into the inbox."""
        all_msgs: List[OmniMessage] = []
        for aid in list(self._adapters):
            try:
                msgs = await self.receive(aid)
                all_msgs.extend(msgs)
            except Exception as exc:
                log.warning("Router: receive error on %r: %s", aid, exc)
        return all_msgs

    def get_inbox(self) -> List[OmniMessage]:
        return list(self._inbox)

    def clear_inbox(self) -> None:
        self._inbox.clear()
