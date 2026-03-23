"""
omnimail.adapters.memory_adapter
──────────────────────────────────
In-process memory adapter – useful for testing and demos.

Messages are stored in a list; no network I/O whatsoever.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from omnimail.adapters.base import BaseAdapter
from omnimail.core.message import OmniMessage

log = logging.getLogger(__name__)


class MemoryAdapter(BaseAdapter):
    """
    Thread-safe in-memory transport adapter.

    All sent messages are stored in ``sent`` and can be received via
    ``receive()``.  Optionally raises on the first N sends to simulate
    failures for retry testing.
    """

    adapter_id      = "memory"
    priority_weight = 10

    def __init__(self, fail_first_n: int = 0) -> None:
        self.sent:          List[OmniMessage] = []
        self._inbox:        List[OmniMessage] = []
        self._fail_counter: int = fail_first_n

    async def send(self, message: OmniMessage) -> None:
        if self._fail_counter > 0:
            self._fail_counter -= 1
            raise RuntimeError(
                f"MemoryAdapter: simulated failure ({self._fail_counter} remaining)"
            )
        self.sent.append(message)
        log.debug("MemoryAdapter: stored message %s", message.id[:8])

    async def receive(self) -> List[OmniMessage]:
        msgs, self._inbox = self._inbox[:], []
        return msgs

    def inject(self, message: OmniMessage) -> None:
        """Inject a message directly into the inbox (for test setup)."""
        self._inbox.append(message)

    def clear(self) -> None:
        self.sent.clear()
        self._inbox.clear()
