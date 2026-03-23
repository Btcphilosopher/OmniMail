"""
omnimail.queue.message_queue
─────────────────────────────
Persistent-style message queue with retry, back-off, and dead-letter
support.

The queue is intentionally lightweight and in-process; swap it out for
Redis Streams or RabbitMQ in production by subclassing ``MessageQueue``
and overriding the ``_store_*`` / ``_load_*`` hooks.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

from omnimail.core.message import OmniMessage, TransportStatus
from omnimail.core.router import DeliveryReport, Router

log = logging.getLogger(__name__)

Callback = Callable[[OmniMessage, DeliveryReport], None]


class QueueItemState(str, Enum):
    WAITING   = "waiting"
    SENDING   = "sending"
    SENT      = "sent"
    RETRYING  = "retrying"
    DEAD      = "dead"       # exceeded max retries → dead-letter


@dataclass
class QueueItem:
    message:     OmniMessage
    enqueued_at: float = field(default_factory=time.time)
    attempts:    int   = 0
    max_retries: int   = 3
    next_retry:  float = 0.0      # epoch when next attempt is allowed
    state:       QueueItemState = QueueItemState.WAITING
    last_error:  str = ""
    report:      Optional[DeliveryReport] = None

    @property
    def is_ready(self) -> bool:
        return self.state in (QueueItemState.WAITING, QueueItemState.RETRYING) \
               and time.time() >= self.next_retry

    def schedule_retry(self, error: str) -> None:
        self.attempts  += 1
        self.last_error = error
        if self.attempts > self.max_retries:
            self.state = QueueItemState.DEAD
            log.warning(
                "Queue: message %s moved to dead-letter after %d attempts",
                self.message.id[:8], self.attempts,
            )
        else:
            delay = min(2 ** self.attempts, 300)   # capped exponential back-off
            self.next_retry = time.time() + delay
            self.state = QueueItemState.RETRYING
            log.info(
                "Queue: will retry %s in %.0fs (attempt %d/%d)",
                self.message.id[:8], delay, self.attempts, self.max_retries,
            )


class MessageQueue:
    """
    Async message queue that drives the Router.

    Features
    --------
    • Configurable per-message retry counts with exponential back-off
    • Dead-letter queue for repeatedly-failing messages
    • Per-message callbacks on success/failure
    • Graceful drain on shutdown
    • Basic metrics
    """

    def __init__(
        self,
        router:      Router,
        max_retries: int = 3,
        poll_interval: float = 0.5,   # seconds between queue scans
    ) -> None:
        self._router        = router
        self._max_retries   = max_retries
        self._poll_interval = poll_interval
        self._queue:     Dict[str, QueueItem] = {}        # message_id → item
        self._dead:      List[QueueItem]       = []
        self._sent:      List[QueueItem]       = []
        self._callbacks: Dict[str, Callback]   = {}       # message_id → cb
        self._running    = False
        self._task:      Optional[asyncio.Task] = None

    # ── Metrics ───────────────────────────────────────────────────────────────

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "waiting":  sum(1 for i in self._queue.values()
                            if i.state == QueueItemState.WAITING),
            "retrying": sum(1 for i in self._queue.values()
                            if i.state == QueueItemState.RETRYING),
            "sent":     len(self._sent),
            "dead":     len(self._dead),
        }

    # ── Enqueueing ────────────────────────────────────────────────────────────

    def enqueue(
        self,
        message: OmniMessage,
        max_retries: Optional[int] = None,
        on_complete: Optional[Callback] = None,
    ) -> str:
        """
        Add a message to the queue.

        Returns the message ID.  If *on_complete* is provided it will be
        called (in the event loop) with (message, report) when the
        message is either successfully sent or moved to dead-letter.
        """
        item = QueueItem(
            message=message,
            max_retries=max_retries if max_retries is not None else self._max_retries,
        )
        self._queue[message.id] = item
        if on_complete:
            self._callbacks[message.id] = on_complete
        log.info("Queue: enqueued %s (retries=%d)", message.id[:8], item.max_retries)
        return message.id

    def get_item(self, message_id: str) -> Optional[QueueItem]:
        return (
            self._queue.get(message_id)
            or next((i for i in self._dead if i.message.id == message_id), None)
            or next((i for i in self._sent if i.message.id == message_id), None)
        )

    # ── Worker loop ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the background worker coroutine."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._worker_loop())
        log.info("Queue: worker started")

    async def stop(self, drain: bool = True) -> None:
        """Stop the worker; optionally drain pending messages first."""
        self._running = False
        if drain:
            await self._drain()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        s = self.stats
        log.info("Queue: worker stopped (waiting=%d, retrying=%d, sent=%d, dead=%d)",
                 s["waiting"], s["retrying"], s["sent"], s["dead"])

    async def _worker_loop(self) -> None:
        while self._running:
            await self._process_ready()
            await asyncio.sleep(self._poll_interval)

    async def _drain(self) -> None:
        """Block until all waiting/retrying items are resolved."""
        while any(
            i.state in (QueueItemState.WAITING, QueueItemState.RETRYING)
            for i in self._queue.values()
        ):
            await self._process_ready()
            await asyncio.sleep(self._poll_interval)

    async def _process_ready(self) -> None:
        ready = [i for i in self._queue.values() if i.is_ready]
        if not ready:
            return

        tasks = [self._attempt(item) for item in ready]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Move completed items out of the active queue
        for item in list(self._queue.values()):
            if item.state == QueueItemState.SENT:
                self._sent.append(self._queue.pop(item.message.id))
            elif item.state == QueueItemState.DEAD:
                self._dead.append(self._queue.pop(item.message.id))

    async def _attempt(self, item: QueueItem) -> None:
        item.state = QueueItemState.SENDING
        try:
            report = await self._router.send(item.message)
            item.report = report
            if report.success:
                item.state = QueueItemState.SENT
                log.info("Queue: sent %s", item.message.id[:8])
                self._fire_callback(item)
            else:
                failed_adapters = ", ".join(report.failed_adapters)
                item.schedule_retry(f"All adapters failed: {failed_adapters}")
                if item.state == QueueItemState.DEAD:
                    self._fire_callback(item)
        except Exception as exc:
            item.schedule_retry(str(exc))
            if item.state == QueueItemState.DEAD:
                self._fire_callback(item)

    def _fire_callback(self, item: QueueItem) -> None:
        cb = self._callbacks.pop(item.message.id, None)
        if cb and item.report:
            try:
                cb(item.message, item.report)
            except Exception as exc:
                log.warning("Queue: callback error: %s", exc)

    # ── Dead-letter management ────────────────────────────────────────────────

    def dead_letter_queue(self) -> List[OmniMessage]:
        return [i.message for i in self._dead]

    def requeue_dead(self, message_id: str) -> bool:
        """Move a dead-letter message back to active queue."""
        for i, item in enumerate(self._dead):
            if item.message.id == message_id:
                item.attempts = 0
                item.state    = QueueItemState.WAITING
                item.next_retry = 0.0
                self._dead.pop(i)
                self._queue[message_id] = item
                log.info("Queue: requeued dead-letter %s", message_id[:8])
                return True
        return False
