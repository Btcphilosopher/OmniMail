"""
omnimail.adapters.matrix_adapter
──────────────────────────────────
Matrix (matrix.org) transport adapter for OmniMail.

Sends OmniMessages as Matrix room events, using the ``m.room.message``
event type with a custom ``omnimail`` msgtype for structured payloads.
Receiving polls the sync endpoint for new events.

Requires: pip install aiohttp
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    import aiohttp
    _AIOHTTP = True
except ImportError:
    _AIOHTTP = False

from omnimail.adapters.base import BaseAdapter
from omnimail.core.message import OmniMessage, MessageType

log = logging.getLogger(__name__)


class MatrixAdapter(BaseAdapter):
    """
    Matrix homeserver transport adapter.

    Parameters
    ----------
    homeserver  : full URL of the Matrix homeserver (e.g. ``"https://matrix.org"``)
    access_token: Matrix bearer access token
    default_room: Matrix room ID to use when no room is specified in headers
    user_id     : full Matrix user ID (``@user:homeserver``)
    """

    adapter_id      = "matrix"
    priority_weight = 60

    #: Custom Matrix event type used to carry OmniMail payloads
    OMNIMAIL_EVENT_TYPE = "io.omnimail.message"

    def __init__(
        self,
        homeserver:    str,
        access_token:  str,
        default_room:  str,
        user_id:       str = "",
    ) -> None:
        self.homeserver    = homeserver.rstrip("/")
        self.access_token  = access_token
        self.default_room  = default_room
        self.user_id       = user_id
        self._since_token: Optional[str] = None   # Matrix sync "since" token
        self._session:     Optional[Any] = None   # aiohttp.ClientSession

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        if _AIOHTTP:
            self._session = aiohttp.ClientSession(
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            log.info("MatrixAdapter: connected to %s", self.homeserver)

    async def disconnect(self) -> None:
        if self._session:
            await self._session.close()

    async def health_check(self) -> bool:
        if not _AIOHTTP:
            return False
        url = f"{self.homeserver}/_matrix/client/v3/versions"
        try:
            async with self._session.get(url) as resp:
                return resp.status == 200
        except Exception:
            return False

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    def _room_for(self, message: OmniMessage) -> str:
        """Determine Matrix room from message headers or default."""
        return message.headers.get("matrix_room_id", self.default_room)

    def _build_event_content(self, message: OmniMessage) -> Dict[str, Any]:
        """
        Build a Matrix m.room.message event body carrying the full
        OmniMail payload in a structured field.
        """
        # Human-readable fallback for Matrix clients that don't know OmniMail
        display_body = f"[OmniMail] {message.subject}\n\n{message.body}"
        if message.message_type == MessageType.ENCRYPTED:
            display_body = f"[OmniMail Encrypted] {message.subject}"

        return {
            "msgtype":       "m.text",
            "body":          display_body,
            "format":        "io.omnimail",
            "omnimail":      message.to_dict(),   # full structured payload
        }

    # ── Send ──────────────────────────────────────────────────────────────────

    async def send(self, message: OmniMessage) -> None:
        if not _AIOHTTP:
            raise RuntimeError("aiohttp is required for MatrixAdapter")

        room_id  = self._room_for(message)
        txn_id   = str(uuid.uuid4()).replace("-", "")
        url      = (
            f"{self.homeserver}/_matrix/client/v3"
            f"/rooms/{room_id}/send/m.room.message/{txn_id}"
        )
        content  = self._build_event_content(message)

        async with self._session.put(url, json=content) as resp:
            if resp.status not in (200, 201):
                body = await resp.text()
                raise RuntimeError(
                    f"Matrix send failed [{resp.status}]: {body[:200]}"
                )
            data = await resp.json()
            event_id = data.get("event_id", "?")
            log.info(
                "MatrixAdapter: sent %s → room=%s event=%s",
                message.id[:8], room_id, event_id,
            )

    # ── Receive ───────────────────────────────────────────────────────────────

    async def receive(self) -> List[OmniMessage]:
        if not _AIOHTTP:
            return []
        return await self._sync_poll()

    async def _sync_poll(self) -> List[OmniMessage]:
        """Call /_matrix/client/v3/sync and harvest OmniMail events."""
        params: Dict[str, Any] = {"timeout": 5000, "full_state": "false"}
        if self._since_token:
            params["since"] = self._since_token

        url = f"{self.homeserver}/_matrix/client/v3/sync"
        try:
            async with self._session.get(url, params=params) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
        except Exception as exc:
            log.warning("MatrixAdapter sync error: %s", exc)
            return []

        self._since_token = data.get("next_batch", self._since_token)
        return self._parse_sync_response(data)

    def _parse_sync_response(self, data: Dict[str, Any]) -> List[OmniMessage]:
        messages: List[OmniMessage] = []
        rooms_joined = data.get("rooms", {}).get("join", {})

        for _room_id, room_data in rooms_joined.items():
            timeline = room_data.get("timeline", {}).get("events", [])
            for event in timeline:
                if event.get("type") != "m.room.message":
                    continue
                content = event.get("content", {})
                if "omnimail" in content:
                    # Rich OmniMail payload – deserialise directly
                    try:
                        msg = OmniMessage.from_dict(content["omnimail"])
                        messages.append(msg)
                        continue
                    except Exception as exc:
                        log.warning("MatrixAdapter: bad OmniMail payload: %s", exc)

                # Fallback: wrap generic Matrix message as OmniMail
                sender = event.get("sender", "unknown")
                body   = content.get("body", "")
                ts     = event.get("origin_server_ts", time.time() * 1000) / 1000.0
                msg = OmniMessage(
                    id=event.get("event_id", str(uuid.uuid4())),
                    sender=sender,
                    recipients=[self.user_id] if self.user_id else ["unknown"],
                    subject="(Matrix message)",
                    body=body,
                    timestamp=ts,
                    headers={"matrix_room_id": _room_id},
                )
                messages.append(msg)

        return messages

    def can_deliver_to(self, address: str) -> bool:
        return address.startswith("@") and ":" in address

    def address_scheme(self) -> str:
        return "matrix"
